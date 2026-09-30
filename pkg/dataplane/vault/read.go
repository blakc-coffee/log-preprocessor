package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// The read path. Every read verifies the record's CRC, so a bit that rotted on
// disk is reported rather than returned.

// check is the guard every read starts with.
func (v *Vault) check() error {
	if v.failed != nil {
		return v.failed
	}
	if v.closed {
		return types.ErrClosed
	}
	return nil
}

// readAt reads and decodes one framed record at a known offset. The caller
// holds at least a read lock.
func (v *Vault) readAt(s *segState, off int64) (types.RecordID, types.RawRecord, error) {
	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)

	// The length prefix says how much to read, so this is two reads rather
	// than one guess. The length is capped before it is used.
	var hdr [record.FrameOverhead]byte
	if _, err := v.readSeg(s, hdr[:], off); err != nil {
		return 0, types.RawRecord{}, err
	}
	length := int(uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	if length > maxBody {
		return 0, types.RawRecord{}, fmt.Errorf("%w: record at offset %d declares %d bytes",
			record.ErrTooLarge, off, length)
	}

	buf := make([]byte, record.FrameOverhead+length)
	if _, err := v.readSeg(s, buf, off); err != nil {
		return 0, types.RawRecord{}, err
	}
	body, _, err := record.ParseFramed(buf, maxBody)
	if err != nil {
		return 0, types.RawRecord{}, fmt.Errorf("segment %d offset %d: %w", s.id, off, err)
	}
	return record.Decode(body)
}

// Get returns a record exactly as it was stored.
func (v *Vault) Get(ctx context.Context, id types.RecordID) (types.RawRecord, types.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}

	if id == 0 || uint64(id) > uint64(len(v.index)) {
		return types.RawRecord{}, types.Receipt{}, types.ErrNotFound
	}
	l := v.index[id-1]
	s := v.segs[l.seg]

	seq, r, err := v.readAt(s, l.off)
	if err != nil {
		return types.RawRecord{}, types.Receipt{}, err
	}
	if seq != id {
		// The index and the file disagree, which is either corruption or a
		// bug. Either way, handing back the wrong record is the one failure a
		// vault must never have.
		return types.RawRecord{}, types.Receipt{}, fmt.Errorf(
			"vault: index says record %d is at segment %d offset %d, but that record is %d",
			id, s.id, l.off, seq)
	}
	return r, types.Receipt{ID: id, RawSHA256: l.rawSHA, Segment: s.id}, nil
}

// ErrHashIndexDisabled is returned by GetByHash when the vault was opened with
// DisableHashIndex.
var ErrHashIndexDisabled = errors.New("vault: hash index is disabled")

// GetByHash returns the raw bytes whose SHA-256 is sum. Newest wins when the
// same payload was stored more than once.
//
// The in-memory map covers segments still stored as WALs. Compacted segments
// keep their hashes in a .hix file instead, searched newest to oldest.
func (v *Vault) GetByHash(ctx context.Context, sum [32]byte) ([]byte, error) {
	if v.opts.DisableHashIndex {
		return nil, ErrHashIndexDisabled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	v.mu.RLock()
	if err := v.check(); err != nil {
		v.mu.RUnlock()
		return nil, err
	}
	best, found := v.byHash[sum]

	// The newest compacted occurrence, if any.
	for i := len(v.segs) - 1; i >= 0; i-- {
		s := v.segs[i]
		if !s.compacted || s.hix == nil {
			continue
		}
		seq, ok, err := s.hix.lookup(sum)
		if err != nil {
			v.mu.RUnlock()
			return nil, err
		}
		if ok {
			// Segments are searched newest first, so this is the newest
			// compacted hit. The map may still hold something newer if a
			// later segment has not been compacted yet.
			if id := types.RecordID(seq); !found || id > best {
				best, found = id, true
			}
			break
		}
	}
	v.mu.RUnlock()

	if !found {
		return nil, types.ErrNotFound
	}
	r, _, err := v.Get(ctx, best)
	if err != nil {
		return nil, err
	}
	return r.Raw, nil
}

// Scan walks records in RecordID order from `from`, for replay. It stops on
// the first error the callback returns and passes it back unchanged.
func (v *Vault) Scan(ctx context.Context, from types.RecordID, fn func(types.RawRecord, types.Receipt) error) error {
	if from == 0 {
		from = 1
	}
	v.mu.RLock()
	err := v.check()
	last := types.RecordID(len(v.index))
	v.mu.RUnlock()
	if err != nil {
		return err
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

// leavesOf returns a sealed segment's leaf hashes, recomputing them from the
// file on a cache miss. Keeping every segment's leaves in memory would not
// scale, and keeping none would make a burst of lineage requests re-read the
// same segment repeatedly. The caller holds v.mu for writing, because a miss
// mutates the cache.
func (v *Vault) leavesOf(s *segState) ([][32]byte, error) {
	if !s.sealed {
		return s.leaves, nil
	}
	if ls, ok := v.leafCache[s.id]; ok {
		return ls, nil
	}

	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	leaves := make([][32]byte, 0, s.count)
	off := int64(HeaderSize)
	for i := 0; i < s.count; i++ {
		var hdr [record.FrameOverhead]byte
		if _, err := v.readSeg(s, hdr[:], off); err != nil {
			return nil, err
		}
		length := int(uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
		if length > maxBody {
			return nil, fmt.Errorf("%w: segment %d offset %d declares %d bytes",
				record.ErrTooLarge, s.id, off, length)
		}
		buf := make([]byte, record.FrameOverhead+length)
		if _, err := v.readSeg(s, buf, off); err != nil {
			return nil, err
		}
		body, n, err := record.ParseFramed(buf, maxBody)
		if err != nil {
			return nil, fmt.Errorf("segment %d offset %d: %w", s.id, off, err)
		}
		leaves = append(leaves, merkle.LeafHash(body))
		off += int64(n)
	}

	v.leafCache[s.id] = leaves
	v.leafOrder = append(v.leafOrder, s.id)
	for len(v.leafOrder) > leafCacheSize {
		delete(v.leafCache, v.leafOrder[0])
		v.leafOrder = v.leafOrder[1:]
	}
	return leaves, nil
}

// Proof returns an inclusion proof, or ErrNotSealed while the record's segment
// is still active.
//
// ErrNotSealed is not a failure. A segment has no root until it is sealed, so
// there is nothing honest to prove against yet; lineage is resolved lazily for
// exactly this reason (decision D2).
func (v *Vault) Proof(ctx context.Context, id types.RecordID) (types.InclusionProof, error) {
	if err := ctx.Err(); err != nil {
		return types.InclusionProof{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return types.InclusionProof{}, err
	}

	if id == 0 || uint64(id) > uint64(len(v.index)) {
		return types.InclusionProof{}, types.ErrNotFound
	}
	l := v.index[id-1]
	s := v.segs[l.seg]
	if !s.sealed {
		return types.InclusionProof{}, types.ErrNotSealed
	}

	leaves, err := v.leavesOf(s)
	if err != nil {
		return types.InclusionProof{}, err
	}
	idx := uint64(id - s.firstSeq)
	if idx >= uint64(len(leaves)) {
		return types.InclusionProof{}, fmt.Errorf(
			"vault: record %d is index %d in segment %d, which holds %d records",
			id, idx, s.id, len(leaves))
	}
	return types.InclusionProof{
		Segment:   s.id,
		LeafIndex: idx,
		TreeSize:  uint64(len(leaves)),
		LeafHash:  leaves[idx],
		Path:      merkle.Path(leaves, idx),
		Root:      s.root,
		PrevChain: s.prev,
		Chain:     s.chain,
	}, nil
}

// Verify checks one record against its segment root and chain link, reading
// the record back off disk rather than trusting anything in memory.
func (v *Vault) Verify(ctx context.Context, id types.RecordID) (types.VerifyResult, error) {
	p, err := v.Proof(ctx, id)
	if err == types.ErrNotSealed {
		// Stored and intact; its segment simply has no root yet. Callers
		// distinguish on Sealed, not on err.
		return types.VerifyResult{OK: true, Sealed: false}, nil
	}
	if err != nil {
		return types.VerifyResult{}, err
	}

	v.mu.RLock()
	l := v.index[id-1]
	s := v.segs[l.seg]
	v.mu.RUnlock()

	body, err := v.bodyAt(s, l.off)
	if err != nil {
		return types.VerifyResult{Sealed: true, Reason: err.Error()}, nil
	}
	if got := merkle.LeafHash(body); got != p.LeafHash {
		return v.verifyFailed("record does not match its leaf hash"), nil
	}
	if !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root) {
		return v.verifyFailed("inclusion proof does not verify against the segment root"), nil
	}
	if !merkle.VerifyChainLink(p) {
		return v.verifyFailed("segment chain link does not verify"), nil
	}

	// The footer's root must also be the one the ledger recorded, or the file
	// and the ledger disagree about what this segment contains.
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, seal := range v.seals {
		if seal.Segment == s.id && seal.Root != p.Root {
			return v.verifyFailed("segment root does not match the ledger"), nil
		}
	}
	return types.VerifyResult{OK: true, Sealed: true, Proof: &p}, nil
}

// verifyFailed records the failure and builds the result. Every verification
// failure is counted, because a non-zero vault_verify_failures_total means
// tampering or corruption and should page someone.
func (v *Vault) verifyFailed(reason string) types.VerifyResult {
	v.metrics.VerifyFailures.Inc()
	return types.VerifyResult{Sealed: true, Reason: reason}
}

// bodyAt reads one record's encoded body, CRC checked.
func (v *Vault) bodyAt(s *segState, off int64) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	var hdr [record.FrameOverhead]byte
	if _, err := v.readSeg(s, hdr[:], off); err != nil {
		return nil, err
	}
	length := int(uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	if length > maxBody {
		return nil, fmt.Errorf("%w: record at offset %d declares %d bytes", record.ErrTooLarge, off, length)
	}
	buf := make([]byte, record.FrameOverhead+length)
	if _, err := v.readSeg(s, buf, off); err != nil {
		return nil, err
	}
	body, _, err := record.ParseFramed(buf, maxBody)
	return body, err
}

// VerifyChain walks the ledger from chain_0.
//
// Shallow: segment ids are consecutive, sequence ranges are contiguous, each
// chain hash recomputes from the one before, and every footer agrees with its
// ledger line.
//
// Deep: additionally re-reads every record of every segment, checks its CRC,
// and recomputes each segment's Merkle root. That is what catches an edited
// record, as opposed to an edited ledger.
//
// It cannot detect a consistent rewrite of the whole directory, or deletion of
// the newest sealed segment together with its ledger line, unless the chain
// head was exported elsewhere.
func (v *Vault) VerifyChain(ctx context.Context, deep bool) (types.ChainReport, error) {
	if err := ctx.Err(); err != nil {
		return types.ChainReport{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return types.ChainReport{}, err
	}

	// Damage found while opening outranks anything the ledger walk can say:
	// the ledger may look perfectly consistent precisely because it was the
	// thing that was edited.
	if len(v.issues) > 0 {
		return types.ChainReport{
			Deep: deep, Segments: len(v.seals), Head: v.head,
			FirstBad: v.issues[0].segment, Reason: v.issues[0].reason,
		}, nil
	}

	rep := types.ChainReport{OK: true, Deep: deep, Segments: len(v.seals), Head: v.head}
	var prev [32]byte
	var wantSeq uint64 = 1

	for i, s := range v.seals {
		bad := func(reason string) types.ChainReport {
			v.metrics.VerifyFailures.Inc()
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

		seg := v.segs[i]
		if seg.id != s.Segment {
			return bad(fmt.Sprintf("segment %d is missing from disk", s.Segment)), nil
		}
		// The footer on disk must say the same thing as the ledger line.
		// Editing one without the other is two rows of the tamper matrix.
		if seg.root != s.Root {
			return bad(fmt.Sprintf("segment %d footer root does not match the ledger", s.Segment)), nil
		}
		if seg.chain != s.Chain {
			return bad(fmt.Sprintf("segment %d footer chain hash does not match the ledger", s.Segment)), nil
		}

		if deep {
			leaves, err := v.leavesOf(seg)
			if err != nil {
				return bad(fmt.Sprintf("segment %d could not be re-read: %v", s.Segment, err)), nil
			}
			if uint64(len(leaves)) != s.Count {
				return bad(fmt.Sprintf("segment %d holds %d records, ledger says %d",
					s.Segment, len(leaves), s.Count)), nil
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
	if err := v.check(); err != nil {
		return nil, err
	}
	return append([]types.SegmentSeal(nil), v.seals...), nil
}

// Head returns the chain head and the highest sealed RecordID.
//
// Copying this value somewhere the vault's owner cannot reach is what turns
// tamper-evidence into something a full rewrite of the directory cannot paper
// over. Records above sealedThrough are stored but not yet covered by a root.
func (v *Vault) Head(ctx context.Context) ([32]byte, types.RecordID, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return [32]byte{}, 0, err
	}
	var through types.RecordID
	if n := len(v.seals); n > 0 {
		through = types.RecordID(v.seals[n-1].LastSeq)
	}
	return v.head, through, nil
}
