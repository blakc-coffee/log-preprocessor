package source

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/frame"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Tail defaults.
const (
	// DefaultPollInterval is how often a file is checked for new data or for
	// having been rotated. Polling rather than fsnotify: the fallback has to
	// exist and be correct anyway because bind mounts break inotify, and
	// 500ms is far below anything that matters when the vault seals every
	// 5-30 seconds. See DECISIONS.log.
	DefaultPollInterval = 500 * time.Millisecond
	// DefaultCheckpointEvery bounds how much gets re-read after a crash.
	DefaultCheckpointEvery = 1000
	defaultCheckpointAfter = time.Second
)

// errRotated unwinds the framer when the file underneath it has been replaced.
var errRotated = errors.New("source: file rotated")

// runTail follows one file until ctx is done.
//
// The shape is: hand the framer a reader that never says EOF, so a partial
// line is held by the framer until its terminator arrives rather than being
// emitted as a truncated record. Rotation and truncation unwind that reader
// with errRotated, and the loop reopens.
func (f *File) runTail(ctx context.Context, sink ingest.Sink, path string) error {
	log := f.cfg.Log.With("source", f.cfg.ID, "path", path)

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := f.followOnce(ctx, sink, path, log)
		switch {
		case err == nil, errors.Is(err, errRotated):
			// Reopen: either the file was replaced, or it vanished and we are
			// waiting for it to come back.
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil
		case errors.Is(err, os.ErrNotExist):
			// A file named explicitly may not exist yet, or may be between
			// rotations. Waiting is right; failing would make a log rotation
			// take the source down.
			log.Debug("waiting for the file to appear")
		default:
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(f.pollInterval()):
		}
	}
}

func (f *File) pollInterval() time.Duration {
	if f.cfg.PollInterval > 0 {
		return f.cfg.PollInterval
	}
	return DefaultPollInterval
}

// followOnce reads one incarnation of the file, returning errRotated when the
// file on disk is no longer the one it has open.
func (f *File) followOnce(ctx context.Context, sink ingest.Sink, path string, log *slog.Logger) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	dev, ino, err := fileID(fh)
	if err != nil {
		return err
	}
	fp, fpLen, err := fingerprint(fh)
	if err != nil {
		return err
	}

	start, err := f.startOffset(fh, path, dev, ino, log)
	if err != nil {
		return err
	}
	if _, err := fh.Seek(start, io.SeekStart); err != nil {
		return err
	}

	r := &tailReader{
		f: fh, ctx: ctx, poll: f.pollInterval(),
		path: path, dev: dev, ino: ino, offset: start,
		onTruncate: f.countTruncation,
	}
	dec, ml, err := f.decoder(r)
	if err != nil {
		return err
	}

	st := sink.NewStream(f.cfg.ID)
	defer st.Close()

	t := &tailer{
		file: f, stream: st, log: log, path: path,
		dev: dev, ino: ino, fingerprint: fp, fingerprintLen: fpLen, base: start,
	}

	// The multiline timeout runs alongside the read loop, because the read
	// loop is blocked waiting for data that may never come.
	stopTimer := f.watchMultilineTimeout(ctx, ml, func(fr frame.Frame) error {
		return t.submit(ctx, fr)
	})
	defer stopTimer()

	return t.pump(ctx, dec, r)
}

// startOffset decides where to begin: a matching checkpoint, the end of the
// file, or the beginning.
func (f *File) startOffset(fh *os.File, path string, dev, ino uint64, log *slog.Logger) (int64, error) {
	if f.cfg.CheckpointDir != "" {
		cp, err := loadCheckpoint(f.cfg.CheckpointDir, path)
		if err != nil {
			return 0, err
		}
		ok, err := cp.matches(fh, dev, ino)
		if err != nil {
			return 0, err
		}
		if ok {
			size, err := fileSize(fh)
			if err != nil {
				return 0, err
			}
			if cp.Offset <= size {
				log.Info("resuming from checkpoint", "offset", cp.Offset)
				return cp.Offset, nil
			}
			// The checkpoint is past the end: the file was truncated while we
			// were away. Start over rather than seek into nothing.
			log.Warn("checkpoint is beyond the end of the file, restarting from 0",
				"checkpoint_offset", cp.Offset, "size", size)
			return 0, nil
		}
		if cp != nil {
			log.Info("checkpoint does not match this file, starting fresh")
		}
	}

	if f.cfg.From == FromEnd {
		// Only for a file we have never seen. A checkpoint always wins, or
		// restarting would skip everything written while the process was down.
		return fileSize(fh)
	}
	return 0, nil
}

// tailer carries the per-incarnation state of a followed file.
type tailer struct {
	file   *File
	stream ingest.Stream
	log    *slog.Logger
	path   string

	dev, ino       uint64
	fingerprint    string
	fingerprintLen int
	// base is the file offset the framer's offsets are relative to.
	base int64

	// mu guards the position fields, which the read loop and the multiline
	// timeout goroutine both advance.
	mu sync.Mutex
	// pending is the file offset after the last record submitted, which
	// becomes the checkpoint once the stream is flushed.
	pending int64
	since   int
	lastAt  time.Time
}

// pump moves records from the decoder into the stream, checkpointing as it
// goes.
func (t *tailer) pump(ctx context.Context, dec frame.Decoder, r *tailReader) error {
	t.mu.Lock()
	t.pending = t.base
	t.lastAt = time.Now()
	t.mu.Unlock()

	for {
		fr, err := dec.Next()
		if err != nil {
			// A rotation or EOF at shutdown: flush what is held and record
			// where we got to.
			if flushErr := t.checkpointNow(ctx); flushErr != nil {
				return flushErr
			}
			return err
		}

		if err := t.submit(ctx, fr); err != nil {
			return err
		}

		t.mu.Lock()
		due := t.since >= t.file.checkpointEvery() || time.Since(t.lastAt) >= defaultCheckpointAfter
		t.mu.Unlock()
		if due {
			if err := t.checkpointNow(ctx); err != nil {
				return err
			}
		}
	}
}

// submit turns a frame into a record and queues it, advancing the position
// the next checkpoint will record.
//
// The multiline timeout goroutine calls this too, so it takes the lock: two
// goroutines advancing `pending` without one would write a checkpoint that
// skips or repeats a record.
func (t *tailer) submit(ctx context.Context, fr frame.Frame) error {
	rec := types.RawRecord{
		SourceID:   t.file.cfg.ID,
		ReceivedAt: t.file.cfg.Now().UTC(),
		Origin: types.Origin{
			Kind:   types.OriginFile,
			Addr:   t.path,
			Offset: uint64(t.base) + fr.Offset,
		},
		Term: fr.Term,
		Frag: fr.Frag,
		Raw:  fr.Raw,
	}
	if err := t.stream.Submit(ctx, rec); err != nil {
		return err
	}

	t.mu.Lock()
	// The next record starts after this one's terminator.
	if next := t.base + int64(fr.Offset) + int64(len(fr.Raw)) + int64(terminatorLen(fr.Term)); next > t.pending {
		t.pending = next
	}
	t.since++
	t.mu.Unlock()
	return nil
}

// checkpointNow flushes the stream and then records the position.
//
// The order is the whole point: flushing is what makes the records durable,
// and a checkpoint written before the flush could skip records a crash then
// erased. Writing it after means a crash re-reads them instead, which is the
// direction that loses nothing.
func (t *tailer) checkpointNow(ctx context.Context) error {
	if err := t.stream.Flush(ctx); err != nil {
		return err
	}

	t.mu.Lock()
	t.since = 0
	t.lastAt = time.Now()
	offset := t.pending
	t.mu.Unlock()

	if t.file.cfg.CheckpointDir == "" {
		return nil
	}
	if err := saveCheckpoint(t.file.cfg.CheckpointDir, checkpoint{
		Path: t.path, Dev: t.dev, Inode: t.ino,
		Fingerprint: t.fingerprint, FingerprintLen: t.fingerprintLen,
		Offset: offset,
	}); err != nil {
		return err
	}
	t.file.countCheckpoint()
	return nil
}

func (f *File) checkpointEvery() int {
	if f.cfg.CheckpointEvery > 0 {
		return f.cfg.CheckpointEvery
	}
	return DefaultCheckpointEvery
}

// ------------------------------------------------------------ tailReader

// tailReader turns a file into a stream that does not end.
//
// At the end of the file it waits and retries instead of returning io.EOF,
// which is what lets the framer hold a partial line until its terminator
// arrives. A framer that saw EOF would emit the half-written line as a
// complete record, and the next read would emit the rest as a second one -
// splitting an event in two at exactly the moment a writer was mid-write.
type tailReader struct {
	f    *os.File
	ctx  context.Context
	poll time.Duration

	path     string
	dev, ino uint64
	offset   int64
	// onTruncate reports a file shrinking below the read offset, which is
	// normal under copytruncate rotation and worth counting either way.
	onTruncate func()

	mu    sync.Mutex
	ended bool
}

func (t *tailReader) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(p)
		if n > 0 {
			t.offset += int64(n)
			return n, nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}

		// At the end of what has been written. Before waiting, check whether
		// the file we have open is still the file at this path.
		if err := t.checkIdentity(); err != nil {
			return 0, err
		}

		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case <-time.After(t.poll):
		}
	}
}

// checkIdentity detects rotation and truncation.
func (t *tailReader) checkIdentity() error {
	fi, statErr := os.Stat(t.path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			// Renamed away or deleted, and not yet replaced. Whatever is left
			// in our open handle has been read, so let go.
			return errRotated
		}
		return statErr
	}

	// Truncation: the file is shorter than where we are reading. A rotator
	// that copies and truncates does this, and continuing would read
	// whatever lands at our stale offset as if it followed what came before.
	if fi.Size() < t.offset {
		t.onTruncate()
		return errRotated
	}

	dev, ino, err := statID(fi)
	if err != nil {
		return err
	}
	if dev != t.dev || ino != t.ino {
		// Renamed and replaced. Our handle still points at the old file, and
		// anything already written to it has been read.
		return errRotated
	}
	return nil
}

func terminatorLen(t types.Terminator) int {
	switch t {
	case types.TermLF, types.TermNUL:
		return 1
	case types.TermCRLF:
		return 2
	}
	return 0
}

// fileID returns the device and inode of an open file.
func fileID(f *os.File) (uint64, uint64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	return statID(fi)
}

func statID(fi os.FileInfo) (uint64, uint64, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Not a Unix filesystem. Rotation detection then rests on size and
		// the fingerprint alone, which is weaker but not wrong.
		return 0, 0, nil
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

func fileSize(f *os.File) (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
