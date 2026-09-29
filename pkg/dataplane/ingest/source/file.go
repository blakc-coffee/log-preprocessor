// Package source contains the ingest sources: file, UDP, TCP, TLS and HTTP.
//
// Every source does the same three things — read bytes, frame them, submit
// them — and differs only in where the bytes come from and how backpressure
// reaches the sender.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/frame"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// FileMode selects one-shot or following behaviour.
type FileMode string

const (
	// ModeOnce reads each file start to end and finishes. This is what the
	// fixture round-trip test and `ingestd --once` use.
	ModeOnce FileMode = "once"
	// ModeTail follows files as they grow.
	ModeTail FileMode = "tail"
)

// MultilineConfig groups lines into one record. See frame.NewMultiline.
type MultilineConfig struct {
	// Start is an RE2 pattern matching the first line of a record.
	Start *regexp.Regexp
	// MaxLines bounds one record. Zero means the frame package's default.
	MaxLines int
	// Timeout releases a record whose continuation never arrives. Zero
	// disables it. The decoder cannot notice time passing while blocked on a
	// read, so the source owns this clock.
	Timeout time.Duration
}

// FileConfig configures a file source.
type FileConfig struct {
	// ID is the source_id stamped on every record from these files.
	ID string
	// Paths are the files to read. Globs are expanded at Run.
	Paths []string
	Mode  FileMode
	// Framing defaults to frame.ModeLF.
	Framing       frame.Mode
	Multiline     *MultilineConfig
	MaxFrameBytes int
	// Now stamps ReceivedAt. Tests replace it.
	Now func() time.Time
	Log *slog.Logger
}

// File reads records out of files on disk.
type File struct {
	cfg FileConfig
}

var _ ingest.Source = (*File)(nil)

// NewFile validates the configuration and returns a file source.
func NewFile(cfg FileConfig) (*File, error) {
	if cfg.ID == "" {
		return nil, errors.New("source: file source needs an id")
	}
	if len(cfg.Paths) == 0 {
		return nil, errors.New("source: file source needs at least one path")
	}
	switch cfg.Mode {
	case "":
		cfg.Mode = ModeOnce
	case ModeOnce, ModeTail:
	default:
		return nil, fmt.Errorf("source: unknown file mode %q", cfg.Mode)
	}
	if cfg.Framing == "" {
		cfg.Framing = frame.ModeLF
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &File{cfg: cfg}, nil
}

// ID implements ingest.Source.
func (f *File) ID() string { return f.cfg.ID }

// Run reads every configured file once.
//
// Tail mode is not implemented yet; NewFile accepts it so configuration can be
// written against it, and Run says so plainly rather than silently doing
// something else.
func (f *File) Run(ctx context.Context, sink ingest.Sink) error {
	if f.cfg.Mode == ModeTail {
		return errors.New("source: file tail mode is not implemented yet")
	}

	paths, err := f.expand()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		f.cfg.Log.Warn("file source matched no files", "source", f.cfg.ID, "paths", f.cfg.Paths)
		return nil
	}

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := f.readOnce(ctx, sink, path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

// expand resolves globs and makes every path absolute, because Origin.Addr is
// the de-duplication key and a relative path is ambiguous the moment the
// process changes directory.
func (f *File) expand() ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range f.cfg.Paths {
		matches, err := filepath.Glob(p)
		if err != nil {
			return nil, fmt.Errorf("bad path pattern %q: %w", p, err)
		}
		if matches == nil {
			// Not a glob, or matched nothing. Keep it so a missing file is
			// reported by name rather than silently skipped.
			matches = []string{p}
		}
		for _, m := range matches {
			abs, err := filepath.Abs(m)
			if err != nil {
				return nil, err
			}
			if !seen[abs] {
				seen[abs] = true
				out = append(out, abs)
			}
		}
	}
	return out, nil
}

// readOnce streams one file through the framer into a stream of its own, so
// records from different files never interleave.
func (f *File) readOnce(ctx context.Context, sink ingest.Sink, path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	dec, err := f.decoder(fh)
	if err != nil {
		return err
	}

	st := sink.NewStream(f.cfg.ID)
	defer st.Close()

	n := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fr, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		rec := types.RawRecord{
			SourceID:   f.cfg.ID,
			ReceivedAt: f.cfg.Now().UTC(),
			Origin: types.Origin{
				Kind: types.OriginFile,
				Addr: path,
				// The offset of the record's first byte in the file. This is
				// what lets a downstream consumer collapse the duplicates an
				// at-least-once tail replay produces.
				Offset: fr.Offset,
			},
			Term: fr.Term,
			Frag: fr.Frag,
			Raw:  fr.Raw,
		}
		if err := st.Submit(ctx, rec); err != nil {
			return err
		}
		n++
	}

	// Flush before returning so the file's last record is durable before the
	// next file starts, which keeps `--once` meaning what it says.
	if err := st.Flush(ctx); err != nil {
		return err
	}
	f.cfg.Log.Info("file read", "source", f.cfg.ID, "path", path, "records", n)
	return nil
}

// decoder builds the framing stack for a file.
func (f *File) decoder(r io.Reader) (frame.Decoder, error) {
	opts := frame.Options{MaxFrameBytes: f.cfg.MaxFrameBytes}
	dec, err := frame.New(f.cfg.Framing, r, opts)
	if err != nil {
		return nil, err
	}
	if f.cfg.Multiline == nil {
		return dec, nil
	}
	return frame.NewMultiline(dec, frame.MultilineOptions{
		Start:         f.cfg.Multiline.Start,
		MaxLines:      f.cfg.Multiline.MaxLines,
		MaxFrameBytes: f.cfg.MaxFrameBytes,
	})
}
