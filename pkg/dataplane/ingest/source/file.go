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
	"strings"
	"sync"
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
	// From decides where a tail starts when there is no checkpoint.
	From FileFrom
	// CheckpointDir persists tail positions so a restart resumes rather than
	// re-reading. Empty disables checkpointing, which makes a restart re-read
	// the whole file.
	CheckpointDir string
	// CheckpointEvery is how many records between checkpoints. Zero means
	// DefaultCheckpointEvery. It bounds how much is re-read after a crash.
	CheckpointEvery int
	// PollInterval is how often a tailed file is checked for new data or for
	// having been rotated. Zero means DefaultPollInterval.
	PollInterval time.Duration

	// Now stamps ReceivedAt. Tests replace it.
	Now func() time.Time
	Log *slog.Logger
}

// FileFrom decides where a tail begins when no checkpoint applies.
type FileFrom string

const (
	// FromBeginning reads the whole file. The default, because skipping
	// existing content is a choice an operator should have to make.
	FromBeginning FileFrom = "beginning"
	// FromEnd reads only what arrives after startup.
	FromEnd FileFrom = "end"
)

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
	switch cfg.From {
	case "":
		cfg.From = FromBeginning
	case FromBeginning, FromEnd:
	default:
		return nil, fmt.Errorf("source: unknown `from` %q: want beginning or end", cfg.From)
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

// Mode reports whether this source reads once or follows. `ingestd --once`
// uses it to know which sources it should wait for.
func (f *File) Mode() FileMode { return f.cfg.Mode }

// Run reads the configured files.
//
// In `once` mode each file is read start to end and Run returns. In `tail`
// mode each file gets a goroutine that follows it until ctx is done, across
// rotations and truncations.
func (f *File) Run(ctx context.Context, sink ingest.Sink) error {
	paths, err := f.expand()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		f.cfg.Log.Warn("file source matched no files", "source", f.cfg.ID, "paths", f.cfg.Paths)
		return nil
	}

	if f.cfg.Mode == ModeTail {
		return f.runAllTails(ctx, sink, paths)
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

// runAllTails follows every path concurrently. One file per goroutine and one
// stream per file, so a slow or stalled file cannot hold up the others and
// each file's records keep their order.
func (f *File) runAllTails(ctx context.Context, sink ingest.Sink, paths []string) error {
	var wg sync.WaitGroup
	errs := make([]error, len(paths))
	for i, path := range paths {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			if err := f.runTail(ctx, sink, path); err != nil {
				errs[i] = fmt.Errorf("%s: %w", path, err)
			}
		}(i, path)
	}
	wg.Wait()
	return errors.Join(errs...)
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
		if len(matches) == 0 {
			if strings.ContainsAny(p, "*?[") {
				// A pattern matching nothing is normal: a log directory may
				// simply be empty right now, and with tail mode files appear
				// later.
				f.cfg.Log.Warn("path pattern matched no files",
					"source", f.cfg.ID, "pattern", p)
				continue
			}
			// A literal path is a promise that a file is there. Keep it, so
			// the failure names the file rather than silently reading
			// nothing - a typo in a path is otherwise invisible.
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

	dec, _, err := f.decoder(fh)
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

// decoder builds the framing stack for a file. It also returns the multiline
// decoder, when there is one, so the caller can drive its timeout.
func (f *File) decoder(r io.Reader) (frame.Decoder, *frame.Multiline, error) {
	opts := frame.Options{MaxFrameBytes: f.cfg.MaxFrameBytes}
	dec, err := frame.New(f.cfg.Framing, r, opts)
	if err != nil {
		return nil, nil, err
	}
	if f.cfg.Multiline == nil {
		return dec, nil, nil
	}
	ml, err := frame.NewMultiline(dec, frame.MultilineOptions{
		Start:         f.cfg.Multiline.Start,
		MaxLines:      f.cfg.Multiline.MaxLines,
		MaxFrameBytes: f.cfg.MaxFrameBytes,
		Now:           f.cfg.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	return ml, ml, nil
}

// watchMultilineTimeout releases a record whose continuation never arrives.
//
// Without it the last event before a source goes quiet is held indefinitely -
// which is exactly the event someone is trying to read during an incident. The
// decoder cannot do this itself: Next blocks on the reader, so it never
// notices time passing while it waits.
//
// Returns a stop function the caller must call before closing the stream.
func (f *File) watchMultilineTimeout(ctx context.Context, ml *frame.Multiline, submit func(frame.Frame) error) func() {
	if ml == nil || f.cfg.Multiline == nil || f.cfg.Multiline.Timeout <= 0 {
		return func() {}
	}
	timeout := f.cfg.Multiline.Timeout

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Check more often than the timeout, so a record is released within
		// roughly the timeout rather than up to twice it.
		tick := time.NewTicker(timeout / 2)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-tick.C:
				fr, ok := ml.FlushIfOlderThan(timeout)
				if !ok {
					continue
				}
				if err := submit(fr); err != nil {
					f.cfg.Log.Error("submitting a timed-out multiline record",
						"source", f.cfg.ID, "err", err)
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}
