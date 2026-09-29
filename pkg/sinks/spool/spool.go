// Package spool implements a bounded, append-only, crash-safe disk queue.
package spool

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/blakc-coffee/log-preprocessor/pkg/sinks"
	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

const (
	magic                 = "ULPSPL01"
	defaultMaxBytes int64 = 1 << 30
)

// Config configures durable buffering.
type Config struct {
	Dir      string
	MaxBytes int64
}

// Queue stores each batch as one immutable segment, ordered by sequence number.
type Queue struct {
	mu              sync.Mutex
	dir             string
	maxBytes, bytes int64
	next            uint64
	files           []string
	closed          bool
}

// Open loads an existing queue and removes incomplete temporary files.
func Open(cfg Config) (*Queue, error) {
	if cfg.Dir == "" {
		return nil, errors.New("spool: Dir is required")
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: cfg.Dir, maxBytes: cfg.MaxBytes, next: 1}
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		p := filepath.Join(cfg.Dir, name)
		if strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(p)
			continue
		}
		if !strings.HasSuffix(name, ".spool") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		q.bytes += info.Size()
		q.files = append(q.files, p)
		n, _ := strconv.ParseUint(strings.TrimSuffix(name, ".spool"), 10, 64)
		if n >= q.next {
			q.next = n + 1
		}
	}
	sort.Strings(q.files)
	return q, nil
}

// Enqueue durably appends a batch. It never removes or modifies event data.
func (q *Queue) Enqueue(ctx context.Context, batch []types.NormalizedEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	buf := make([]byte, len(magic)+8+len(payload)+4)
	copy(buf, magic)
	binary.BigEndian.PutUint64(buf[len(magic):], uint64(len(payload)))
	copy(buf[len(magic)+8:], payload)
	binary.BigEndian.PutUint32(buf[len(buf)-4:], crc32.ChecksumIEEE(payload))
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return sinks.ErrClosed
	}
	if q.bytes+int64(len(buf)) > q.maxBytes {
		return sinks.ErrSpoolFull
	}
	base := fmt.Sprintf("%020d", q.next)
	tmp := filepath.Join(q.dir, base+".tmp")
	final := filepath.Join(q.dir, base+".spool")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(buf); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, final); err != nil {
		return err
	}
	if err = syncDir(q.dir); err != nil {
		return err
	}
	ok = true
	q.next++
	q.bytes += int64(len(buf))
	q.files = append(q.files, final)
	return nil
}

// Peek reads the oldest batch without removing it.
func (q *Queue) Peek(ctx context.Context) ([]types.NormalizedEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil, sinks.ErrClosed
	}
	if len(q.files) == 0 {
		return nil, io.EOF
	}
	return readFile(q.files[0])
}

// Ack removes the oldest batch after successful downstream delivery.
func (q *Queue) Ack() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return sinks.ErrClosed
	}
	if len(q.files) == 0 {
		return io.EOF
	}
	p := q.files[0]
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	if err = os.Remove(p); err != nil {
		return err
	}
	if err = syncDir(q.dir); err != nil {
		return err
	}
	q.bytes -= info.Size()
	q.files = q.files[1:]
	return nil
}

// Bytes returns current durable queue bytes.
func (q *Queue) Bytes() int64 { q.mu.Lock(); defer q.mu.Unlock(); return q.bytes }

// Len returns the number of queued batches.
func (q *Queue) Len() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.files) }

// Close prevents new operations. Existing segments remain durable.
func (q *Queue) Close() error { q.mu.Lock(); defer q.mu.Unlock(); q.closed = true; return nil }

func readFile(path string) ([]types.NormalizedEvent, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < len(magic)+12 || string(b[:len(magic)]) != magic {
		return nil, errors.New("spool: corrupt segment header")
	}
	n := binary.BigEndian.Uint64(b[len(magic):])
	if n > uint64(len(b)-len(magic)-12) {
		return nil, errors.New("spool: corrupt segment length")
	}
	payload := b[len(magic)+8 : len(magic)+8+int(n)]
	want := binary.BigEndian.Uint32(b[len(magic)+8+int(n):])
	if crc32.ChecksumIEEE(payload) != want {
		return nil, errors.New("spool: checksum mismatch")
	}
	var out []types.NormalizedEvent
	if err = json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func syncDir(path string) error {
	// Windows does not permit FlushFileBuffers on directory handles. Atomic
	// rename still applies there; directory fsync is enforced on Unix.
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
