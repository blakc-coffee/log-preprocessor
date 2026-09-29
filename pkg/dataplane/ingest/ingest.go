// Package ingest turns bytes arriving from devices into durable, vaulted
// records, and hands them downstream.
//
// # The rule that never bends
//
// A record leaves this package only after the vault has said it is durable.
// Everything else here exists to serve that: the batching, the bounded output
// channel, the backpressure. Parsing can be wrong and be fixed later by
// replaying from the vault, but only if the bytes were stored first.
//
// # Backpressure, not dropping
//
// Every queue is bounded. When downstream is slow the output channel fills,
// which blocks the stream, which blocks the source, which stops reading its
// socket — and the sender feels it through the TCP window or a stalled HTTP
// body read. Nothing is discarded to keep up. UDP is the exception the design
// cannot fix: a datagram the kernel drops never reached us, so the counters
// are exposed and the limit is stated rather than hidden.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/sniff"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Defaults.
const (
	// DefaultBatchRecords and DefaultBatchDelay bound how long a record waits
	// to be written with its neighbours. The vault does its own group commit
	// across streams; this only amortises the per-call overhead within one.
	DefaultBatchRecords = 256
	DefaultBatchDelay   = time.Millisecond
	DefaultOutBuffer    = 4096
)

// Config configures a Pipeline.
type Config struct {
	// OutBuffer is the capacity of the downstream channel. It is what turns
	// a slow consumer into backpressure rather than unbounded memory growth.
	OutBuffer int
	// BatchRecords and BatchDelay decide when a stream flushes.
	BatchRecords int
	BatchDelay   time.Duration
	// Now stamps ReceivedAt. Tests replace it; nothing else should.
	Now func() time.Time
	// Registerer receives the ingest collectors. Nil means no metrics.
	Registerer prometheus.Registerer
}

func (c *Config) setDefaults() {
	if c.OutBuffer <= 0 {
		c.OutBuffer = DefaultOutBuffer
	}
	if c.BatchRecords <= 0 {
		c.BatchRecords = DefaultBatchRecords
	}
	if c.BatchDelay <= 0 {
		c.BatchDelay = DefaultBatchDelay
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Sink hands out streams. A source asks for one per connection, file or
// request.
type Sink interface {
	NewStream(sourceID string) Stream
}

// Stream accepts records from one source in order.
//
// Ordering is preserved within a stream and not across them, which is what
// lets every connection run concurrently while a single file's records keep
// their sequence.
type Stream interface {
	// Submit queues a record. It may block: that is the backpressure path,
	// and a Submit that returned instead of blocking would be a drop.
	Submit(ctx context.Context, r types.RawRecord) error
	// Flush writes whatever is queued and waits for durability.
	Flush(ctx context.Context) error
	// Close flushes and releases the stream. Sources must defer it.
	Close() error
}

// Source produces records. It owns its own goroutines and returns when ctx is
// done or it hits a fatal error.
type Source interface {
	ID() string
	Run(ctx context.Context, sink Sink) error
}

// Pipeline wires sources to the vault and to the downstream channel.
type Pipeline struct {
	cfg     Config
	vault   types.Vault
	out     chan<- types.RawEvent
	log     *slog.Logger
	metrics *Metrics

	mu      sync.Mutex
	sources []Source
	streams []*stream
	closed  bool
}

var _ Sink = (*Pipeline)(nil)

// New builds a pipeline. out is written to only after the vault confirms
// durability, and is closed when Run returns.
func New(cfg Config, v types.Vault, out chan<- types.RawEvent, log *slog.Logger) (*Pipeline, error) {
	if v == nil {
		return nil, errors.New("ingest: a vault is required")
	}
	if out == nil {
		return nil, errors.New("ingest: an output channel is required")
	}
	cfg.setDefaults()
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Pipeline{cfg: cfg, vault: v, out: out, log: log, metrics: NewMetrics(cfg.Registerer)}, nil
}

// Metrics exposes the collectors, so sources can record against the same set
// the pipeline uses rather than registering their own.
func (p *Pipeline) Metrics() *Metrics { return p.metrics }

// AddSource registers a source. It must be called before Run.
func (p *Pipeline) AddSource(s Source) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources = append(p.sources, s)
}

// NewStream implements Sink.
func (p *Pipeline) NewStream(sourceID string) Stream {
	s := &stream{p: p, sourceID: sourceID, kind: "unknown"}
	p.mu.Lock()
	p.streams = append(p.streams, s)
	p.mu.Unlock()
	return s
}

// Run starts every source and blocks until they all return.
//
// On the way out it flushes every stream that a source left open, so a source
// that exits without closing cleanly still cannot lose an accepted record, and
// then closes the output channel to signal the end of the stream downstream.
func (p *Pipeline) Run(ctx context.Context) error {
	p.mu.Lock()
	sources := append([]Source(nil), p.sources...)
	p.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, len(sources))
	for i, src := range sources {
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			if err := src.Run(ctx, p); err != nil && !errors.Is(err, context.Canceled) {
				errs[i] = fmt.Errorf("source %s: %w", src.ID(), err)
				p.log.Error("source stopped", "source", src.ID(), "err", err)
			}
		}(i, src)
	}
	wg.Wait()

	flushErr := p.closeStreams()
	close(p.out)

	if err := errors.Join(errs...); err != nil {
		return err
	}
	return flushErr
}

// closeStreams flushes anything a source left behind.
func (p *Pipeline) closeStreams() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	streams := append([]*stream(nil), p.streams...)
	p.mu.Unlock()

	var errs []error
	for _, s := range streams {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ------------------------------------------------------------------- stream

// stream batches records for one source and writes them through the vault.
//
// Two locks, and the order between them is the whole correctness argument:
//
//	writeMu  held across a flush, and acquired BEFORE the batch is detached.
//	mu       guards the batch itself, held only for appends and detaches.
//
// Detaching under writeMu is what makes writes happen in the order records
// were appended. Detaching outside it lets a timer flush and a full-batch
// flush interleave, which reorders records within one stream — and a
// fragment run split across two out-of-order writes reassembles into
// garbage downstream.
//
// It also means Close blocks until any in-flight timer flush has finished,
// so the pipeline can close the output channel without racing a send.
type stream struct {
	p        *Pipeline
	sourceID string
	// kind is the source type (udp, tcp, tls, http, file), used as a metric
	// label. It is derived from the record's origin rather than configured,
	// so it cannot disagree with where the bytes actually came from.
	kind string

	writeMu sync.Mutex

	mu     sync.Mutex
	batch  []types.RawRecord
	timer  *time.Timer
	closed bool
	// flushErr latches the first failure. Once the vault is failed, every
	// later Submit must report it rather than queueing into a void.
	flushErr error
}

var _ Stream = (*stream)(nil)

// Submit queues a record, flushing when the batch is full.
//
// The batch is also flushed by a timer armed on the first record, so a stream
// that goes quiet after one line does not hold it indefinitely. Without that,
// a device sending one message a minute would see each one sit in memory,
// undurable, until the next arrived.
func (s *stream) Submit(ctx context.Context, r types.RawRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("ingest: stream is closed")
	}
	if s.flushErr != nil {
		err := s.flushErr
		s.mu.Unlock()
		return err
	}

	s.batch = append(s.batch, r)
	if len(s.batch) == 1 {
		s.arm()
		s.kind = originKind(r.Origin.Kind)
	}
	full := len(s.batch) >= s.p.cfg.BatchRecords
	s.mu.Unlock()

	if !full {
		return nil
	}
	return s.flushNow(ctx)
}

// flushNow writes whatever is queued, serialised against every other flush of
// this stream.
func (s *stream) flushNow(ctx context.Context) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	batch, kind := s.detach()
	s.mu.Unlock()

	return s.write(ctx, batch, kind)
}

// originKind names a source type for metric labels.
func originKind(k types.OriginKind) string {
	switch k {
	case types.OriginFile:
		return "file"
	case types.OriginUDP:
		return "udp"
	case types.OriginTCP:
		return "tcp"
	case types.OriginTLS:
		return "tls"
	case types.OriginHTTP:
		return "http"
	}
	return "unknown"
}

// arm schedules a flush for a batch that may not fill. The caller holds s.mu.
//
// A timer rather than a goroutine per stream: with max_conns at 1024 that
// would be a thousand goroutines doing nothing but waiting, and the runtime
// timer heap already exists.
func (s *stream) arm() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.p.cfg.BatchDelay, s.flushFromTimer)
}

// detach takes the queued batch and disarms the timer, and reports the source
// kind alongside it. The caller holds s.mu.
//
// The kind travels with the batch rather than being read later, because write
// runs outside the lock: reading s.kind there is a data race against the next
// Submit setting it.
func (s *stream) detach() ([]types.RawRecord, string) {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	batch := s.batch
	s.batch = nil
	return batch, s.kind
}

func (s *stream) flushFromTimer() {
	s.mu.Lock()
	empty := s.closed || len(s.batch) == 0
	s.mu.Unlock()
	if empty {
		return
	}

	// flushNow re-checks under writeMu, so a Close that lands in between
	// simply leaves this with nothing to write.
	if err := s.flushNow(context.Background()); err != nil {
		s.mu.Lock()
		if s.flushErr == nil {
			s.flushErr = err
		}
		s.mu.Unlock()
		s.p.log.Error("batch flush failed", "source", s.sourceID, "err", err)
	}
}

// write is the vault-before-forward step, and the only place records leave
// this package.
func (s *stream) write(ctx context.Context, batch []types.RawRecord, kind string) error {
	if len(batch) == 0 {
		return nil
	}

	receipts, err := s.p.vault.PutBatch(ctx, batch)
	if err != nil {
		return err
	}
	if len(receipts) != len(batch) {
		return fmt.Errorf("ingest: vault returned %d receipts for %d records", len(receipts), len(batch))
	}

	// Durable. Only now does anything go downstream.
	m := s.p.metrics
	label := m.Source(s.sourceID)
	for i, r := range batch {
		m.Records.WithLabelValues(label, kind).Inc()
		m.Bytes.WithLabelValues(label, kind).Add(float64(len(r.Raw)))
		if r.Frag != types.FragNone {
			m.Fragments.WithLabelValues(label).Inc()
		}
		// The hint is computed here, after storage, which is the point: it is
		// advisory, so it must be impossible for it to influence what was
		// stored. A parser may ignore it and must be correct when it is wrong.
		ev := types.RawEvent{RawRecord: r, Receipt: receipts[i], Hint: sniff.Detect(r.Raw)}
		select {
		case s.p.out <- ev:
			m.OutQueue.Set(float64(len(s.p.out)))
		case <-ctx.Done():
			// The record is durable and can be replayed from the vault by
			// RecordID, so stopping here loses nothing. Say which record, so
			// an operator knows where the stream resumes.
			return fmt.Errorf("ingest: shutting down with record %d durable but not forwarded: %w",
				receipts[i].ID, ctx.Err())
		}
	}
	return nil
}

// Flush writes whatever is queued.
func (s *stream) Flush(ctx context.Context) error {
	s.mu.Lock()
	err := s.flushErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.flushNow(ctx)
}

// Close flushes and releases the stream. It is idempotent.
//
// Acquiring writeMu is what makes it safe for the pipeline to close the
// output channel afterwards: a timer flush that is already mid-send finishes
// before Close returns.
func (s *stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	err := s.flushErr
	s.mu.Unlock()

	if err != nil {
		return err
	}
	// Deliberately context.Background: a stream being closed during shutdown
	// still owes the vault whatever it accepted.
	return s.flushNow(context.Background())
}
