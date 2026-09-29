// Package fanout dispatches events to independent bounded sink workers.
package fanout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/sinks"
	"github.com/blakc-coffee/log-preprocessor/pkg/sinks/spool"
	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Config controls bounded delivery and retry behavior.
type Config struct {
	QueueEvents, BatchEvents                               int
	BatchInterval, RetryWindow, InitialBackoff, MaxBackoff time.Duration
	SpoolRoot                                              string
	SpoolMaxBytes                                          int64
}

// Metrics is a dependency-free snapshot of per-sink health.
type Metrics struct {
	LagEvents, ErrorsTotal, SpoolBytes, BatchEvents int64
	LastWrite                                       time.Duration
	Healthy                                         bool
}
type worker struct {
	sink                                 types.Sink
	ch                                   chan types.NormalizedEvent
	spool                                *spool.Queue
	cfg                                  Config
	done                                 chan struct{}
	lag, errs, spooled, batch, lastNanos atomic.Int64
	healthy                              atomic.Bool
	finalMu                              sync.Mutex
	finalErr                             error
}

// Fanout owns one worker and bounded queue per target sink.
type Fanout struct {
	ctx     context.Context
	cancel  context.CancelFunc
	workers []*worker
	mu      sync.Mutex
	closed  bool
}

// New starts independent sink workers.
func New(targets []types.Sink, cfg Config) (*Fanout, error) {
	if len(targets) == 0 {
		return nil, errors.New("fanout: at least one sink is required")
	}
	defaults(&cfg)
	ctx, cancel := context.WithCancel(context.Background())
	f := &Fanout{ctx: ctx, cancel: cancel}
	for _, target := range targets {
		if target == nil {
			cancel()
			return nil, errors.New("fanout: nil sink")
		}
		dir := cfg.SpoolRoot
		if dir == "" {
			cancel()
			return nil, errors.New("fanout: SpoolRoot is required")
		}
		q, err := spool.Open(spool.Config{Dir: filepath.Join(dir, safeName(target.Name())), MaxBytes: cfg.SpoolMaxBytes})
		if err != nil {
			cancel()
			return nil, err
		}
		w := &worker{sink: target, ch: make(chan types.NormalizedEvent, cfg.QueueEvents), spool: q, cfg: cfg, done: make(chan struct{})}
		w.healthy.Store(true)
		f.workers = append(f.workers, w)
		go w.run(ctx)
	}
	return f, nil
}

// Write copies and enqueues every event for every sink. A full target queue
// back-pressures the caller; no event is discarded.
func (f *Fanout) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return sinks.ErrClosed
	}
	results := make(chan error, len(f.workers))
	for _, w := range f.workers {
		go func(w *worker) {
			for _, e := range batch {
				select {
				case w.ch <- e:
					w.lag.Add(1)
				case <-ctx.Done():
					results <- ctx.Err()
					return
				case <-f.ctx.Done():
					results <- sinks.ErrClosed
					return
				}
			}
			results <- nil
		}(w)
	}
	for range f.workers {
		if err := <-results; err != nil {
			return err
		}
	}
	return nil
}

// Flush waits until memory queues and durable spools are empty, then flushes targets.
func (f *Fanout) Flush(ctx context.Context) error {
	for {
		empty := true
		for _, w := range f.workers {
			if w.lag.Load() != 0 || w.spool.Len() != 0 {
				empty = false
				break
			}
		}
		if empty {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	for _, w := range f.workers {
		if err := w.sink.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close drains queues, closes workers, and closes all sinks.
func (f *Fanout) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()
	f.cancel()
	var first error
	for _, w := range f.workers {
		<-w.done
		w.finalMu.Lock()
		if w.finalErr != nil && first == nil {
			first = w.finalErr
		}
		w.finalMu.Unlock()
		if err := w.sink.Close(); err != nil && first == nil {
			first = err
		}
		_ = w.spool.Close()
	}
	return first
}

// Metrics returns a per-sink snapshot.
func (f *Fanout) Metrics() map[string]Metrics {
	out := map[string]Metrics{}
	for _, w := range f.workers {
		out[w.sink.Name()] = Metrics{LagEvents: w.lag.Load(), ErrorsTotal: w.errs.Load(), SpoolBytes: w.spool.Bytes(), BatchEvents: w.batch.Load(), LastWrite: time.Duration(w.lastNanos.Load()), Healthy: w.healthy.Load()}
	}
	return out
}

func (w *worker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.BatchInterval)
	defer ticker.Stop()
	batch := make([]types.NormalizedEvent, 0, w.cfg.BatchEvents)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		copyBatch := append([]types.NormalizedEvent(nil), batch...)
		batch = batch[:0]
		w.deliver(ctx, copyBatch)
		w.lag.Add(-int64(len(copyBatch)))
	}
	for {
		select {
		case e := <-w.ch:
			batch = append(batch, e)
			if len(batch) >= w.cfg.BatchEvents {
				flush()
			}
		case <-ticker.C:
			flush()
			w.drain(ctx)
		case <-ctx.Done():
			for {
				select {
				case e := <-w.ch:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}
func (w *worker) deliver(ctx context.Context, b []types.NormalizedEvent) {
	start := time.Now()
	deadline := start.Add(w.cfg.RetryWindow)
	backoff := w.cfg.InitialBackoff
retry:
	for {
		if ctx.Err() != nil {
			break
		}
		err := w.sink.Write(ctx, b)
		if err == nil {
			w.healthy.Store(true)
			w.batch.Add(int64(len(b)))
			w.lastNanos.Store(int64(time.Since(start)))
			return
		}
		w.errs.Add(1)
		if classified, ok := err.(interface{ Retryable() bool }); ok && !classified.Retryable() {
			// The sink has durably dead-lettered the batch. Retrying here would
			// duplicate the dead letter and cannot repair bad data/configuration.
			w.healthy.Store(false)
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		jitter := time.Duration(rand.Int63n(int64(backoff/4 + 1)))
		select {
		case <-ctx.Done():
			break retry
		case <-time.After(backoff + jitter):
		}
		backoff *= 2
		if backoff > w.cfg.MaxBackoff {
			backoff = w.cfg.MaxBackoff
		}
	}
	if err := w.spool.Enqueue(context.Background(), b); err != nil {
		w.healthy.Store(false)
		for err != nil {
			if ctx.Err() != nil {
				w.finalMu.Lock()
				w.finalErr = fmt.Errorf("fanout %s: batch could not be delivered or spooled: %w", w.sink.Name(), err)
				w.finalMu.Unlock()
				return
			}
			timer := time.NewTimer(w.cfg.MaxBackoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				continue
			case <-timer.C:
			}
			if writeErr := w.sink.Write(ctx, b); writeErr == nil {
				w.healthy.Store(true)
				w.batch.Add(int64(len(b)))
				return
			}
			w.errs.Add(1)
			err = w.spool.Enqueue(context.Background(), b)
		}
	} else {
		w.spooled.Add(int64(len(b)))
	}
}
func (w *worker) drain(ctx context.Context) {
	for {
		b, err := w.spool.Peek(ctx)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			w.healthy.Store(false)
			return
		}
		if err = w.sink.Write(ctx, b); err != nil {
			w.errs.Add(1)
			w.healthy.Store(false)
			return
		}
		if err = w.spool.Ack(); err != nil {
			w.healthy.Store(false)
			return
		}
		w.healthy.Store(true)
	}
}
func defaults(c *Config) {
	if c.QueueEvents <= 0 {
		c.QueueEvents = 10000
	}
	if c.BatchEvents <= 0 {
		c.BatchEvents = 5000
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = time.Second
	}
	if c.RetryWindow <= 0 {
		c.RetryWindow = 2 * time.Minute
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = 100 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.SpoolMaxBytes <= 0 {
		c.SpoolMaxBytes = 1 << 30
	}
}
func safeName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "sink"
	}
	return string(out)
}
