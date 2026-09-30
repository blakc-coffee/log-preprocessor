// Package memvault is an in-memory implementation of the vault contract.
//
// It exists so the rest of the system does not have to wait for the on-disk
// vault. It is a reference implementation rather than a stub: it uses the same
// record codec and the same Merkle and chain hashes, so for the same records
// in the same order it produces the same leaf hashes, the same segment roots
// and the same chain head as the real vault. A component developed against
// memvault sees the proofs it will see in production.
//
// What it does not do is persist anything, which is the whole of the real
// vault's difficulty: no WAL, no group commit, no fsync, no recovery, no
// compaction. Put returns once the record is in memory, so "durable" here
// means "the process still has it". Use it for development and tests, never
// for anything whose loss would matter.
//
// Both implementations are held to the same behaviour by
// pkg/dataplane/vault/vaulttest.
package memvault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// DefaultSealEvery is how many records fill a segment by default.
const DefaultSealEvery = 1000

// Options configures a memvault.
type Options struct {
	// SealEvery is the record count at which the active segment is sealed.
	// Zero means DefaultSealEvery. Small values are useful in tests, because
	// a proof only exists once a segment is sealed.
	SealEvery int
	// MaxFrameBytes caps a record's payload, matching the ingest limit of the
	// same name. Zero means 1 MiB.
	MaxFrameBytes int
	// Now supplies seal timestamps. Zero means time.Now. Tests set it to keep
	// output deterministic.
	Now func() time.Time
}

func (o *Options) setDefaults() {
	if o.SealEvery <= 0 {
		o.SealEvery = DefaultSealEvery
	}
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = 1 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// segment is one group of records that will be sealed under a single Merkle
// root.
type segment struct {
	id       uint64
	firstSeq types.RecordID
	bodies   [][]byte
	leaves   [][32]byte

	sealed   bool
	root     [32]byte
	prev     [32]byte
	chain    [32]byte
	sealedAt time.Time
}

// loc points at where a record lives.
type loc struct {
	seg    int
	i      int
	rawSHA [32]byte
}

// Vault is an in-memory types.Vault.
type Vault struct {
	opts Options

	mu     sync.RWMutex
	segs   []*segment
	index  []loc // indexed by seq-1
	byHash map[[32]byte]types.RecordID
	seals  []types.SegmentSeal
	head   [32]byte
	closed bool
}

// compile-time proof that this really satisfies the contract.
var _ types.Vault = (*Vault)(nil)

// New returns an empty in-memory vault.
func New(opts Options) *Vault {
	opts.setDefaults()
	v := &Vault{opts: opts, byHash: map[[32]byte]types.RecordID{}}
	v.openSegment()
	return v
}

// openSegment starts a new active segment. The caller holds the lock, or is
// the constructor.
func (v *Vault) openSegment() {
	v.segs = append(v.segs, &segment{
		id:       uint64(len(v.segs)) + 1,
		firstSeq: types.RecordID(len(v.index)) + 1,
		prev:     v.head,
	})
}

func (v *Vault) active() *segment { return v.segs[len(v.segs)-1] }

// Put stores one record.
func (v *Vault) Put(ctx context.Context, r types.RawRecord) (types.Receipt, error) {
	rs, err := v.PutBatch(ctx, []types.RawRecord{r})
	if err != nil {
		return types.Receipt{}, err
	}
	return rs[0], nil
}

// PutBatch stores several records, which receive contiguous RecordIDs.
//
// The batch is all-or-nothing: if any record is rejected, none are stored.
// The real vault needs that property because a batch is one write and one
// fsync, and callers rely on contiguous ids.
func (v *Vault) PutBatch(ctx context.Context, rs []types.RawRecord) ([]types.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, types.ErrClosed
	}

	// Encode everything before mutating anything, so a bad record in the
	// middle of a batch cannot leave the vault half-written.
	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	bodies := make([][]byte, len(rs))
	base := types.RecordID(len(v.index)) + 1
	for i, r := range rs {
		if n := record.EncodedLen(r); n > maxBody {
			return nil, fmt.Errorf("%w: record %d is %d bytes, cap is %d",
				types.ErrRecordTooLarge, i, n, maxBody)
		}
		body, err := record.Encode(nil, base+types.RecordID(i), r)
		if err != nil {
			return nil, err
		}
		bodies[i] = body
	}

	receipts := make([]types.Receipt, len(rs))
	for i, body := range bodies {
		seq := base + types.RecordID(i)
		seg := v.active()
		seg.bodies = append(seg.bodies, body)
		seg.leaves = append(seg.leaves, merkle.LeafHash(body))

		rawSHA := sha256.Sum256(rs[i].Raw)
		v.index = append(v.index, loc{seg: len(v.segs) - 1, i: len(seg.bodies) - 1, rawSHA: rawSHA})
		// Newest wins, matching the real vault's newest-to-oldest search.
		v.byHash[rawSHA] = seq

		receipts[i] = types.Receipt{ID: seq, RawSHA256: rawSHA, Segment: seg.id}

		if len(seg.bodies) >= v.opts.SealEvery {
			v.seal(seg)
		}
	}
	return receipts, nil
}

// seal closes a segment and opens the next. The caller holds the lock.
// An empty segment is never sealed: the next one is opened lazily instead.
func (v *Vault) seal(seg *segment) {
	if seg.sealed || len(seg.bodies) == 0 {
		return
	}
	seg.root = merkle.Root(seg.leaves)
	seg.prev = v.head
	count := uint64(len(seg.bodies))
	seg.chain = merkle.ChainHash(seg.prev, seg.root, seg.id, count)
	seg.sealedAt = v.opts.Now().UTC()
	seg.sealed = true
	v.head = seg.chain

	v.seals = append(v.seals, types.SegmentSeal{
		Segment:  seg.id,
		FirstSeq: uint64(seg.firstSeq),
		LastSeq:  uint64(seg.firstSeq) + count - 1,
		Count:    count,
		Root:     seg.root,
		Prev:     seg.prev,
		Chain:    seg.chain,
		SealedAt: seg.sealedAt,
	})
	v.openSegment()
}

// lookup resolves a RecordID. The caller holds at least a read lock.
func (v *Vault) lookup(id types.RecordID) (*segment, loc, error) {
	if id == 0 || uint64(id) > uint64(len(v.index)) {
		return nil, loc{}, types.ErrNotFound
	}
	l := v.index[id-1]
	return v.segs[l.seg], l, nil
}

// Get returns a record exactly as it was stored.
func (v *Vault) Get(ctx context.Context, id types.RecordID) (types.RawRecord, types.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return types.RawRecord{}, types.Receipt{}, types.ErrClosed
	}

	seg, l, err := v.lookup(id)
	if err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}
	seq, r, err := record.Decode(seg.bodies[l.i])
	if err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}
	if seq != id {
		// Only reachable through a bug in this package, but a vault that hands
		// back the wrong record is the one failure it must never have.
		return types.RawRecord{}, types.Receipt{}, fmt.Errorf("memvault: record %d decoded as %d", id, seq)
	}
	return r, types.Receipt{ID: id, RawSHA256: l.rawSHA, Segment: seg.id}, nil
}

// GetByHash returns the raw bytes whose SHA-256 is sum.
func (v *Vault) GetByHash(ctx context.Context, sum [32]byte) ([]byte, error) {
	v.mu.RLock()
	id, ok := v.byHash[sum]
	v.mu.RUnlock()
	if !ok {
		return nil, types.ErrNotFound
	}
	r, _, err := v.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return r.Raw, nil
}

// Scan walks records in order from `from`, for replay. It stops on the first
// error fn returns, and passes that error back unchanged.
func (v *Vault) Scan(ctx context.Context, from types.RecordID, fn func(types.RawRecord, types.Receipt) error) error {
	if from == 0 {
		from = 1
	}
	v.mu.RLock()
	last := types.RecordID(len(v.index))
	closed := v.closed
	v.mu.RUnlock()
	if closed {
		return types.ErrClosed
	}

	for id := from; id <= last; id++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, rc, err := v.Get(ctx, id)
		if err != nil {
			return err
		}
		if err := fn(r, rc); err != nil {
			return err
		}
	}
	return nil
}

// Proof returns an inclusion proof, or ErrNotSealed while the record's segment
// is still active. An unsealed segment has no root, so there is nothing
// honest to prove against yet.
func (v *Vault) Proof(ctx context.Context, id types.RecordID) (types.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return types.InclusionProof{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return types.InclusionProof{}, types.ErrClosed
	}

	seg, l, err := v.lookup(id)
	if err != nil {
		return types.InclusionProof{}, err
	}
	if !seg.sealed {
		return types.InclusionProof{}, types.ErrNotSealed
	}
	return types.InclusionProof{
		Segment:   seg.id,
		LeafIndex: uint64(l.i),
		TreeSize:  uint64(len(seg.leaves)),
		LeafHash:  seg.leaves[l.i],
		Path:      merkle.Path(seg.leaves, uint64(l.i)),
		Root:      seg.root,
		PrevChain: seg.prev,
		Chain:     seg.chain,
	}, nil
}

// Verify checks one record against its segment root and chain link.
func (v *Vault) Verify(ctx context.Context, id types.RecordID) (types.VerifyResult, error) {
	p, err := v.Proof(ctx, id)
	if err == types.ErrNotSealed {
		// Not an error: the record is stored, its segment simply has no root
		// yet. Callers distinguish on Sealed, not on err.
		return types.VerifyResult{OK: true, Sealed: false}, nil
	}
	if err != nil {
		return types.VerifyResult{}, err
	}

	v.mu.RLock()
	seg, l, err := v.lookup(id)
	var body []byte
	if err == nil {
		body = seg.bodies[l.i]
	}
	v.mu.RUnlock()
	if err != nil {
		return types.VerifyResult{}, err
	}

	if got := merkle.LeafHash(body); got != p.LeafHash {
		return types.VerifyResult{Sealed: true, Reason: "record does not match its leaf hash"}, nil
	}
	if !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root) {
		return types.VerifyResult{Sealed: true, Reason: "inclusion proof does not verify against the segment root"}, nil
	}
	if !merkle.VerifyChainLink(p) {
		return types.VerifyResult{Sealed: true, Reason: "segment chain link does not verify"}, nil
	}
	return types.VerifyResult{OK: true, Sealed: true, Proof: &p}, nil
}

// VerifyChain walks the ledger from chain_0. A deep check also recomputes
// every segment root from the records themselves, which is what catches a
// modified record rather than a modified ledger.
func (v *Vault) VerifyChain(ctx context.Context, deep bool) (types.ChainReport, error) {
	if err := ctx.Err(); err != nil {
		return types.ChainReport{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return types.ChainReport{}, types.ErrClosed
	}

	rep := types.ChainReport{OK: true, Deep: deep, Segments: len(v.seals), Head: v.head}

	var prev [32]byte
	var wantSeq uint64 = 1
	for i, s := range v.seals {
		bad := func(reason string) types.ChainReport {
			return types.ChainReport{
				Deep: deep, Segments: len(v.seals), Head: v.head,
				FirstBad: s.Segment, Reason: reason,
			}
		}
		if s.Segment != uint64(i+1) {
			return bad(fmt.Sprintf("segment ids are not consecutive: expected %d, found %d", i+1, s.Segment)), nil
		}
		if s.FirstSeq != wantSeq {
			return bad(fmt.Sprintf("segment %d starts at %d, expected %d", s.Segment, s.FirstSeq, wantSeq)), nil
		}
		if s.Count == 0 || s.LastSeq != s.FirstSeq+s.Count-1 {
			return bad(fmt.Sprintf("segment %d sequence range is inconsistent with its count", s.Segment)), nil
		}
		if s.Prev != prev {
			return bad(fmt.Sprintf("segment %d does not follow the previous chain hash", s.Segment)), nil
		}
		if merkle.ChainHash(s.Prev, s.Root, s.Segment, s.Count) != s.Chain {
			return bad(fmt.Sprintf("segment %d chain hash does not recompute", s.Segment)), nil
		}
		if deep {
			seg := v.segs[i]
			leaves := make([][32]byte, len(seg.bodies))
			for j, body := range seg.bodies {
				if _, _, err := record.Decode(body); err != nil {
					return bad(fmt.Sprintf("segment %d record %d does not decode: %v", s.Segment, j, err)), nil
				}
				leaves[j] = merkle.LeafHash(body)
			}
			if merkle.Root(leaves) != s.Root {
				return bad(fmt.Sprintf("segment %d root does not match its records", s.Segment)), nil
			}
		}
		prev = s.Chain
		wantSeq = s.LastSeq + 1
		rep.Records += s.Count
	}

	if prev != v.head {
		rep.OK = false
		rep.Reason = "the ledger does not lead to the recorded chain head"
	}
	return rep, nil
}

// Seals returns the ledger, oldest first.
func (v *Vault) Seals(ctx context.Context) ([]types.SegmentSeal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, types.ErrClosed
	}
	return append([]types.SegmentSeal(nil), v.seals...), nil
}

// Head returns the chain head and the highest sealed RecordID. Records above
// sealedThrough are stored but not yet covered by a root.
func (v *Vault) Head(ctx context.Context) ([32]byte, types.RecordID, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return [32]byte{}, 0, types.ErrClosed
	}
	var through types.RecordID
	if n := len(v.seals); n > 0 {
		through = types.RecordID(v.seals[n-1].LastSeq)
	}
	return v.head, through, nil
}

// Close seals the active segment. It is idempotent.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.seal(v.active())
	v.closed = true
	return nil
}
