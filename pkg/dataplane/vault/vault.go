// Package vault is the durable, hash-chained store for raw log records.
//
// Requirements (a) and (d) - never lose a record, and be able to prove what it
// originally said - are satisfied here or nowhere. Parsers can be wrong and be
// fixed later, but only if the raw bytes were kept exactly.
//
// # What is guaranteed, and tested
//
//   - A record acknowledged by Put in sync=always survives process death and
//     reads back byte for byte.
//   - Bytes out equal bytes in, including invalid UTF-8, NULs and CR/LF
//     variants. Terminators are recorded, not stripped.
//   - Any single-record edit, deletion or reordering, and any segment deletion
//     or swap, is caught by VerifyChain(deep) given an intact ledger.
//   - Reopening after a crash never yields a corrupt segment: a torn tail is
//     truncated and the remainder is sealed.
//
// # What is NOT claimed
//
//   - Power-loss durability. The crash tests kill the process; they do not cut
//     power, and they say nothing about the disk's own write cache. We rely on
//     fsync being honest and state that plainly.
//   - Tamper-proof storage. This is tamper-EVIDENT. Someone with write access
//     to the whole directory can rewrite it consistently. Only a chain head
//     held somewhere else defeats that - see Head.
//
// # Layout
//
//	<dir>/LOCK                    flock, one process at a time
//	<dir>/chain.log               append-only JSONL ledger, one line per seal
//	<dir>/seg-000000000001.wal    header || framed records || footer-once-sealed
package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/record"
)

// SyncMode decides when a write is considered durable.
type SyncMode string

const (
	// SyncAlways fsyncs before acknowledging. Only this mode makes the
	// acknowledgement mean "on disk", and it is the default for that reason.
	SyncAlways SyncMode = "always"
	// SyncInterval acknowledges immediately and fsyncs on a timer. Faster, and
	// up to one interval of acknowledged records can be lost. Any benchmark
	// run in this mode must say so.
	SyncInterval SyncMode = "interval"
	// SyncNone never fsyncs. Benchmarks only. Never use it for anything whose
	// loss would matter.
	SyncNone SyncMode = "none"
)

// Options configures a vault. The zero value is not usable; Dir is required
// and everything else has a default.
type Options struct {
	Dir  string
	Sync SyncMode

	SyncInterval        time.Duration
	GroupCommitMaxDelay time.Duration
	GroupCommitMaxBytes int

	SegmentMaxBytes   int64
	SegmentMaxRecords int
	SealInterval      time.Duration

	MaxFrameBytes int

	// ReadOnly opens the vault without taking the write lock or starting the
	// writer. `vaultctl verify` uses it so an operator can inspect a vault
	// another process is writing to.
	ReadOnly bool

	// Now supplies timestamps. Tests set it for determinism.
	Now func() time.Time
	// Logger receives structured events. Raw payload is never logged.
	Logger *slog.Logger
	// Registerer receives the vault's collectors. Nil means no metrics.
	Registerer prometheus.Registerer
}

func (o *Options) setDefaults() {
	if o.Sync == "" {
		o.Sync = SyncAlways
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = 100 * time.Millisecond
	}
	if o.GroupCommitMaxDelay < 0 {
		o.GroupCommitMaxDelay = 0
	}
	if o.GroupCommitMaxBytes <= 0 {
		o.GroupCommitMaxBytes = 4 << 20
	}
	if o.SegmentMaxBytes <= 0 {
		o.SegmentMaxBytes = 64 << 20
	}
	if o.SegmentMaxRecords <= 0 {
		o.SegmentMaxRecords = 250_000
	}
	if o.SealInterval <= 0 {
		o.SealInterval = 30 * time.Second
	}
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = 1 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

func (o Options) validate() error {
	if o.Dir == "" {
		return errors.New("vault: Dir is required")
	}
	switch o.Sync {
	case SyncAlways, SyncInterval, SyncNone:
	default:
		return fmt.Errorf("vault: unknown sync mode %q", o.Sync)
	}
	return nil
}

// segState is the in-memory view of one segment file.
type segState struct {
	id       uint64
	firstSeq types.RecordID
	prev     [32]byte

	file *os.File
	size int64 // bytes written, excluding any footer

	count  int
	leaves [][32]byte // kept only while active; recomputed on demand once sealed

	sealed bool
	// recovered marks a segment sealed by crash recovery rather than cleanly.
	recovered bool
	root      [32]byte
	chain     [32]byte
	sealedAt  time.Time
}

// issue is one piece of structural damage found while opening read-only.
type issue struct {
	segment uint64
	reason  string
}

// loc says where a record lives and what its payload hashes to.
type loc struct {
	seg    int
	off    int64
	rawSHA [32]byte
}

// Vault is the on-disk types.Vault.
type Vault struct {
	opts Options
	lock *os.File
	dir  *os.File // held open so the directory itself can be fsynced

	mu     sync.RWMutex
	segs   []*segState
	index  []loc
	byHash map[[32]byte]types.RecordID
	seals  []types.SegmentSeal
	head   [32]byte
	// failed is terminal. After a write or fsync error every call returns
	// ErrFailed and the process must restart: see commit().
	failed error
	closed bool
	// issues holds structural damage found during a read-only open. A writer
	// refuses to open at all in that situation; a reader records it so
	// VerifyChain can report which segment is wrong. See corruptf.
	issues []issue

	ledger  *os.File
	metrics *Metrics

	// leafCache holds recomputed leaf arrays for recently proved segments, so
	// a burst of lineage requests against one segment reads the file once.
	leafCache map[uint64][][32]byte
	leafOrder []uint64

	reqs     chan *commitReq
	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

var _ types.Vault = (*Vault)(nil)

type commitReq struct {
	recs []types.RawRecord
	resp chan commitResp
}

type commitResp struct {
	receipts []types.Receipt
	err      error
}

// leafCacheSize is how many sealed segments' leaf arrays are kept. Proofs are
// served from the newest segments in practice, and an unbounded cache would
// defeat the point of not keeping every leaf in memory.
const leafCacheSize = 4

// Open opens or creates a vault.
//
// It takes an exclusive flock on <dir>/LOCK, so a second writer fails fast
// rather than interleaving into the same segments. Recovery of a partially
// written segment happens here; see recover.go.
func Open(opts Options) (*Vault, error) {
	// Defaults first, then validate. The other way round rejects every
	// caller that leaves Sync empty and expects the documented default,
	// which is exactly what vaultctl does.
	opts.setDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	v := &Vault{
		opts:      opts,
		metrics:   NewMetrics(opts.Registerer),
		byHash:    map[[32]byte]types.RecordID{},
		leafCache: map[uint64][][32]byte{},
		reqs:      make(chan *commitReq),
		stop:      make(chan struct{}),
		stopped:   make(chan struct{}),
	}

	if !opts.ReadOnly {
		lock, err := os.OpenFile(filepath.Join(opts.Dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return nil, fmt.Errorf("vault: %s is already open by another process: %w", opts.Dir, err)
		}
		v.lock = lock
	}

	dir, err := os.Open(opts.Dir)
	if err != nil {
		v.releaseLock()
		return nil, err
	}
	v.dir = dir

	if err := v.recover(); err != nil {
		v.dir.Close()
		v.releaseLock()
		return nil, err
	}

	if !opts.ReadOnly {
		go v.writer()
	} else {
		close(v.stopped)
	}
	return v, nil
}

func (v *Vault) releaseLock() {
	if v.lock != nil {
		syscall.Flock(int(v.lock.Fd()), syscall.LOCK_UN)
		v.lock.Close()
		v.lock = nil
	}
}

func (v *Vault) active() *segState {
	if len(v.segs) == 0 {
		return nil
	}
	s := v.segs[len(v.segs)-1]
	if s.sealed {
		return nil
	}
	return s
}

// openSegment creates the next segment file and fsyncs both it and the
// directory, so the file's existence survives a crash before its first record
// does. The caller holds v.mu.
func (v *Vault) openSegment() error {
	id := uint64(len(v.segs)) + 1
	first := types.RecordID(len(v.index)) + 1

	h := header{Segment: id, FirstSeq: first, PrevChain: v.head, CreatedAt: v.opts.Now().UTC()}
	path := filepath.Join(v.opts.Dir, segmentName(id, "wal"))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(h.encode()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := v.dir.Sync(); err != nil {
		f.Close()
		return err
	}

	v.segs = append(v.segs, &segState{
		id: id, firstSeq: first, prev: v.head, file: f, size: HeaderSize,
	})
	return nil
}

// ---------------------------------------------------------------- write path

// Put stores one record.
func (v *Vault) Put(ctx context.Context, r types.RawRecord) (types.Receipt, error) {
	rs, err := v.PutBatch(ctx, []types.RawRecord{r})
	if err != nil {
		return types.Receipt{}, err
	}
	return rs[0], nil
}

// PutBatch stores several records, which receive contiguous RecordIDs, and
// returns only once they are durable in the configured sync mode.
//
// The batch is all-or-nothing. It becomes one write and, in sync=always, one
// fsync, so a partially applied batch is not a state the vault can be in.
func (v *Vault) PutBatch(ctx context.Context, rs []types.RawRecord) ([]types.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, nil
	}

	v.mu.RLock()
	err, closed := v.failed, v.closed
	v.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	if closed {
		return nil, types.ErrClosed
	}
	if v.opts.ReadOnly {
		return nil, errors.New("vault: opened read-only")
	}

	// Validate before queueing, so an oversize record is rejected without
	// occupying the writer or consuming sequence numbers.
	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	for i, r := range rs {
		if n := record.EncodedLen(r); n > maxBody {
			return nil, fmt.Errorf("%w: record %d is %d bytes, cap is %d",
				types.ErrRecordTooLarge, i, n, maxBody)
		}
	}

	req := &commitReq{recs: rs, resp: make(chan commitResp, 1)}
	select {
	case v.reqs <- req:
	case <-v.stopped:
		return nil, types.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case resp := <-req.resp:
		return resp.receipts, resp.err
	case <-ctx.Done():
		// The commit is already in flight and will complete; the caller has
		// simply stopped waiting. It is not cancelled, because a half-written
		// batch is exactly what PutBatch promises cannot happen.
		return nil, ctx.Err()
	}
}

// writer is the single goroutine that touches the segment files. Having one
// writer is what makes group commit possible: concurrent PutBatch calls
// coalesce into one write and one fsync.
func (v *Vault) writer() {
	defer close(v.stopped)

	sealTicker := time.NewTicker(v.opts.SealInterval)
	defer sealTicker.Stop()

	var syncTimer *time.Timer
	var syncC <-chan time.Time
	if v.opts.Sync == SyncInterval {
		syncTimer = time.NewTimer(v.opts.SyncInterval)
		syncC = syncTimer.C
		defer syncTimer.Stop()
	}

	for {
		select {
		case <-v.stop:
			// Flush anything already queued before shutting down: it was
			// accepted, so it must not be dropped.
			for {
				select {
				case req := <-v.reqs:
					v.commit(v.gather(req))
				default:
					v.finalSync()
					return
				}
			}

		case req := <-v.reqs:
			v.commit(v.gather(req))

		case <-syncC:
			v.periodicSync()
			syncTimer.Reset(v.opts.SyncInterval)

		case <-sealTicker.C:
			v.mu.Lock()
			if s := v.active(); s != nil && s.count > 0 {
				if err := v.sealLocked(s); err != nil {
					v.failLocked(err)
				}
			}
			v.mu.Unlock()
		}
	}
}

// gather collects concurrent requests into one group, which becomes one write
// and one fsync. This is where the throughput difference between 50k/s and
// 200k/s lives: without it every record pays for its own fsync.
func (v *Vault) gather(first *commitReq) []*commitReq {
	group := []*commitReq{first}
	bytes := groupBytes(first)

	if v.opts.GroupCommitMaxDelay <= 0 {
		// No delay configured: take whatever is already queued and go.
		for bytes < v.opts.GroupCommitMaxBytes {
			select {
			case req := <-v.reqs:
				group = append(group, req)
				bytes += groupBytes(req)
			default:
				return group
			}
		}
		return group
	}

	deadline := time.NewTimer(v.opts.GroupCommitMaxDelay)
	defer deadline.Stop()
	for bytes < v.opts.GroupCommitMaxBytes {
		select {
		case req := <-v.reqs:
			group = append(group, req)
			bytes += groupBytes(req)
		case <-deadline.C:
			return group
		case <-v.stop:
			return group
		}
	}
	return group
}

func groupBytes(r *commitReq) int {
	n := 0
	for _, rec := range r.recs {
		n += record.EncodedLen(rec) + record.FrameOverhead
	}
	return n
}

// commit writes a group of requests as one write, syncs according to the mode,
// publishes the records, and replies to every caller.
func (v *Vault) commit(group []*commitReq) {
	started := time.Now()
	v.mu.Lock()

	if v.failed != nil {
		err := v.failed
		v.mu.Unlock()
		replyAll(group, nil, err)
		return
	}
	if v.active() == nil {
		if err := v.openSegment(); err != nil {
			v.failLocked(err)
			err = v.failed
			v.mu.Unlock()
			replyAll(group, nil, err)
			return
		}
	}
	seg := v.active()

	// Encode everything first. A batch that cannot be encoded must not have
	// written a single byte.
	base := types.RecordID(len(v.index)) + 1
	seq := base
	var buf []byte
	offsets := make([]int64, 0, 16)
	perReq := make([][]types.Receipt, len(group))
	bodies := make([][]byte, 0, 16)

	for gi, req := range group {
		receipts := make([]types.Receipt, len(req.recs))
		for i, r := range req.recs {
			body, err := record.Encode(nil, seq, r)
			if err != nil {
				v.mu.Unlock()
				replyAll(group, nil, err)
				return
			}
			offsets = append(offsets, seg.size+int64(len(buf)))
			buf = record.AppendFramed(buf, body)
			bodies = append(bodies, body)
			receipts[i] = types.Receipt{
				ID: seq, RawSHA256: sha256.Sum256(r.Raw), Segment: seg.id,
			}
			seq++
		}
		perReq[gi] = receipts
	}

	// One write for the whole group.
	if _, err := seg.file.WriteAt(buf, seg.size); err != nil {
		v.failLocked(err)
		err = v.failed
		v.mu.Unlock()
		replyAll(group, nil, err)
		return
	}
	if v.opts.Sync == SyncAlways {
		fsyncStart := time.Now()
		if err := seg.file.Sync(); err == nil {
			v.metrics.FsyncSeconds.Observe(time.Since(fsyncStart).Seconds())
		} else {
			// Never retry a failed fsync. After one, the kernel may already
			// have dropped the dirty pages, so a retry that "succeeded" would
			// be a lie about data that is gone.
			v.failLocked(err)
			err = v.failed
			v.mu.Unlock()
			replyAll(group, nil, err)
			return
		}
	}

	// Durable (in the configured sense). Publish.
	seg.size += int64(len(buf))
	v.metrics.Puts.Add(float64(len(bodies)))
	v.metrics.GroupSize.Observe(float64(len(bodies)))
	v.metrics.ActiveBytes.Set(float64(seg.size))
	for i, body := range bodies {
		id := base + types.RecordID(i)
		rawSHA := sha256.Sum256(decodedRaw(body))
		v.index = append(v.index, loc{seg: len(v.segs) - 1, off: offsets[i], rawSHA: rawSHA})
		v.byHash[rawSHA] = id
		seg.leaves = append(seg.leaves, merkle.LeafHash(body))
		seg.count++
	}

	var sealErr error
	if v.shouldSeal(seg) {
		sealErr = v.sealLocked(seg)
		if sealErr != nil {
			v.failLocked(sealErr)
			sealErr = v.failed
		}
	}
	v.mu.Unlock()

	if sealErr != nil {
		replyAll(group, nil, sealErr)
		return
	}
	// Observed once per batch rather than per record: the latency a caller
	// experiences is the batch's, and per-record observations would make the
	// histogram claim a thousand fast writes where there was one.
	v.metrics.PutLatency.Observe(time.Since(started).Seconds())
	for gi, req := range group {
		req.resp <- commitResp{receipts: perReq[gi]}
	}
}

// decodedRaw pulls the payload back out of an encoded body, so the raw hash is
// computed from what was actually stored rather than from the caller's slice.
// A mismatch would mean the codec changed the bytes, which is the one thing it
// must never do.
func decodedRaw(body []byte) []byte {
	_, r, err := record.Decode(body)
	if err != nil {
		// Unreachable: this body was produced by Encode a few lines earlier.
		panic("vault: a just-encoded record did not decode: " + err.Error())
	}
	return r.Raw
}

func replyAll(group []*commitReq, rs []types.Receipt, err error) {
	for _, req := range group {
		req.resp <- commitResp{receipts: rs, err: err}
	}
}

// failLocked puts the vault into its terminal failed state. The caller holds
// v.mu.
func (v *Vault) failLocked(err error) {
	if v.failed != nil {
		return
	}
	v.failed = fmt.Errorf("%w: %v", types.ErrFailed, err)
	v.metrics.Failed.Set(1)
	v.opts.Logger.Error("vault entered failed state, restart required", "err", err)
}

func (v *Vault) shouldSeal(s *segState) bool {
	return s.size >= v.opts.SegmentMaxBytes || s.count >= v.opts.SegmentMaxRecords
}

// sealLocked computes the segment's root, writes the footer, appends the
// ledger line, and opens the next segment. The caller holds v.mu.
//
// The order matters: footer, fsync, ledger, fsync. A crash between the footer
// and the ledger leaves a sealed segment with no ledger line, which recovery
// repairs. The reverse order would leave a ledger line describing a segment
// that was never sealed, which it could not.
func (v *Vault) sealLocked(s *segState) error {
	if s.sealed || s.count == 0 {
		return nil
	}
	sealStart := time.Now()

	s.root = merkle.Root(s.leaves)
	s.prev = v.head
	count := uint64(s.count)
	s.chain = merkle.ChainHash(s.prev, s.root, s.id, count)
	s.sealedAt = v.opts.Now().UTC()
	lastSeq := s.firstSeq + types.RecordID(count) - 1

	f := footer{Count: count, LastSeq: lastSeq, Root: s.root, Chain: s.chain, SealedAt: s.sealedAt}
	if _, err := s.file.WriteAt(f.encode(), s.size); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}

	seal := types.SegmentSeal{
		Segment: s.id, FirstSeq: uint64(s.firstSeq), LastSeq: uint64(lastSeq),
		Count: count, Root: s.root, Prev: s.prev, Chain: s.chain, SealedAt: s.sealedAt,
		Recovered: s.recovered,
	}
	if err := v.appendLedger(seal); err != nil {
		return err
	}

	s.sealed = true
	s.leaves = nil // recomputed from the file if a proof needs them
	v.head = s.chain
	v.seals = append(v.seals, seal)
	v.metrics.SegmentsSealed.Inc()
	v.metrics.SealSeconds.Observe(time.Since(sealStart).Seconds())
	v.metrics.ActiveBytes.Set(0)
	v.opts.Logger.Info("segment sealed",
		"segment", s.id, "records", count, "root", hex.EncodeToString(s.root[:]))
	return nil
}

// ledgerLine is one line of chain.log.
type ledgerLine struct {
	Segment  uint64 `json:"segment"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	Count    uint64 `json:"count"`
	Root     string `json:"root"`
	Prev     string `json:"prev"`
	Chain    string `json:"chain"`
	SealedAt string `json:"sealed_at"`
	// Recovered marks a segment sealed by crash recovery rather than cleanly.
	Recovered bool `json:"recovered"`
}

func (v *Vault) appendLedger(s types.SegmentSeal) error {
	if v.ledger == nil {
		f, err := os.OpenFile(filepath.Join(v.opts.Dir, "chain.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		v.ledger = f
	}
	line, err := json.Marshal(ledgerLine{
		Segment: s.Segment, FirstSeq: s.FirstSeq, LastSeq: s.LastSeq, Count: s.Count,
		Root:  hex.EncodeToString(s.Root[:]),
		Prev:  hex.EncodeToString(s.Prev[:]),
		Chain: hex.EncodeToString(s.Chain[:]),
		// RFC 3339 nano UTC, per the project's JSON conventions.
		SealedAt:  s.SealedAt.UTC().Format(time.RFC3339Nano),
		Recovered: s.Recovered,
	})
	if err != nil {
		return err
	}
	if _, err := v.ledger.Write(append(line, '\n')); err != nil {
		return err
	}
	return v.ledger.Sync()
}

// periodicSync is the sync=interval timer. Its error is terminal, like any
// other fsync error.
func (v *Vault) periodicSync() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failed != nil {
		return
	}
	if s := v.active(); s != nil {
		if err := s.file.Sync(); err != nil {
			v.failLocked(err)
		}
	}
}

// finalSync flushes on the way out, whatever the mode. A graceful stop is the
// one case where sync=interval and sync=none still owe the caller a flush.
func (v *Vault) finalSync() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failed != nil {
		return
	}
	if s := v.active(); s != nil && s.file != nil {
		if err := s.file.Sync(); err != nil {
			v.failLocked(err)
		}
	}
}

// Close stops the writer, seals the active segment and releases the lock.
// It is idempotent.
func (v *Vault) Close() error {
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return nil
	}
	v.closed = true
	v.mu.Unlock()

	if !v.opts.ReadOnly {
		v.stopOnce.Do(func() { close(v.stop) })
		<-v.stopped
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var firstErr error
	if v.failed == nil {
		if s := v.active(); s != nil && s.count > 0 {
			// A clean shutdown seals, so no record is left outside the chain.
			if err := v.sealLocked(s); err != nil {
				firstErr = err
			}
		}
	}
	for _, s := range v.segs {
		if s.file != nil {
			if err := s.file.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			s.file = nil
		}
	}
	if v.ledger != nil {
		v.ledger.Close()
		v.ledger = nil
	}
	if v.dir != nil {
		v.dir.Close()
		v.dir = nil
	}
	v.releaseLock()
	return firstErr
}
