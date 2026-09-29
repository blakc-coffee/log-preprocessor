package vault

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Recovery, run under Open.
//
// The governing rule: a record that was acknowledged must survive, and a
// record that was not acknowledged may be dropped, but the vault must never
// come up in a state where it cannot tell the two apart. A torn tail - the
// last write interrupted partway - is the ordinary outcome of a crash and is
// repaired by truncating to the last intact record boundary. Anything else
// wrong with a segment is corruption, and Open refuses rather than guessing.

// ErrCorrupt means the vault cannot be opened safely. Refusing is deliberate:
// a vault that silently repaired structural damage would be a vault whose
// guarantees nobody could check afterwards.
var ErrCorrupt = errors.New("vault: corrupt")

// corruptf reports structural damage.
//
// For a writer, that is fatal: Open refuses, because continuing to append to a
// vault whose history is already broken only buries the evidence.
//
// For a read-only open it is recorded and recovery continues, because that is
// the case an operator is in when something has gone wrong - `vaultctl verify`
// has to be able to open a tampered vault in order to say what is wrong with
// it. A vault that only refused would make the tamper matrix unreportable, and
// an exit code of "could not open" is far less useful than one naming the
// segment.
func (v *Vault) corruptf(segment uint64, format string, args ...any) error {
	err := fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
	if !v.opts.ReadOnly {
		return err
	}
	v.opts.Logger.Warn("structural damage found during a read-only open",
		"segment", segment, "err", err)
	v.issues = append(v.issues, issue{segment: segment, reason: err.Error()})
	return nil
}

// recover rebuilds in-memory state from the directory. The vault is not yet
// shared, so no locking is needed.
func (v *Vault) recover() error {
	if !v.opts.ReadOnly {
		v.cleanStaleCompaction()
	}
	seals, err := v.readLedger()
	if err != nil {
		return err
	}

	ids, err := v.listSegments()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		if len(seals) > 0 {
			return v.corruptf(0, "chain.log describes %d segments but none are on disk", len(seals))
		}
		return nil // fresh vault; the first segment opens on the first write
	}
	for i, id := range ids {
		if id != uint64(i+1) {
			if err := v.corruptf(id, "segment ids are not consecutive from 1: expected %d, found %d", i+1, id); err != nil {
				return err
			}
		}
	}

	for i, id := range ids {
		last := i == len(ids)-1
		skipped, err := v.recoverSegment(id, last, seals)
		if err != nil {
			return err
		}
		if skipped && !last {
			return v.corruptf(id, "segment %d was never initialised but is not the last", id)
		}
	}

	// Anything the ledger claims beyond what is on disk is unexplained.
	if len(v.seals) < len(seals) {
		return v.corruptf(0, "chain.log has %d sealed segments, only %d are on disk",
			len(seals), len(v.seals))
	}
	return nil
}

// readLedger parses chain.log, tolerating one torn final line.
//
// A torn last line is expected: appending it is not atomic, so a crash can cut
// it. A torn line anywhere else means the file was edited, which is not
// something a crash does.
func (v *Vault) readLedger() ([]types.SegmentSeal, error) {
	path := filepath.Join(v.opts.Dir, "chain.log")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var seals []types.SegmentSeal
	var good int64 // bytes of intact ledger

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		raw := sc.Bytes()
		var l ledgerLine
		s, err := parseLedgerLine(raw, &l)
		if err != nil {
			// Only forgivable as the final line. Peek: if anything follows,
			// the damage is not a torn append.
			if sc.Scan() {
				if cerr := v.corruptf(0, "chain.log line %d is malformed and is not the last line: %v",
					len(seals)+1, err); cerr != nil {
					return nil, cerr
				}
				break
			}
			v.opts.Logger.Warn("truncating a torn final line from chain.log",
				"bytes", int64(len(raw)), "err", err)
			break
		}
		seals = append(seals, s)
		good += int64(len(raw)) + 1
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Drop the torn tail so the next append starts at a line boundary.
	if !v.opts.ReadOnly {
		if fi, err := f.Stat(); err == nil && fi.Size() != good {
			if err := os.Truncate(path, good); err != nil {
				return nil, err
			}
		}
	}
	return seals, nil
}

func parseLedgerLine(raw []byte, l *ledgerLine) (types.SegmentSeal, error) {
	var s types.SegmentSeal
	if err := json.Unmarshal(raw, l); err != nil {
		return s, err
	}
	root, err := unhex32(l.Root)
	if err != nil {
		return s, fmt.Errorf("root: %w", err)
	}
	prev, err := unhex32(l.Prev)
	if err != nil {
		return s, fmt.Errorf("prev: %w", err)
	}
	chain, err := unhex32(l.Chain)
	if err != nil {
		return s, fmt.Errorf("chain: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, l.SealedAt)
	if err != nil {
		return s, fmt.Errorf("sealed_at: %w", err)
	}
	if l.Segment == 0 || l.Count == 0 {
		return s, errors.New("segment and count must be non-zero")
	}
	return types.SegmentSeal{
		Segment: l.Segment, FirstSeq: l.FirstSeq, LastSeq: l.LastSeq, Count: l.Count,
		Root: root, Prev: prev, Chain: chain, SealedAt: at.UTC(), Recovered: l.Recovered,
	}, nil
}

func unhex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// listSegments returns the segment ids present, in ascending order.
func (v *Vault) listSegments() ([]uint64, error) {
	entries, err := os.ReadDir(v.opts.Dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	seen := map[uint64]bool{}
	for _, e := range entries {
		name := e.Name()
		var ext string
		switch {
		case strings.HasSuffix(name, ".wal"):
			ext = ".wal"
		case strings.HasSuffix(name, ".zst"):
			ext = ".zst"
		default:
			continue // .hix, .tmp, chain.log, LOCK
		}
		if !strings.HasPrefix(name, "seg-") {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ext), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: unparseable segment file %q", ErrCorrupt, name)
		}
		// A segment can exist as both while a compaction is between its
		// final rename and deleting the WAL. It is one segment.
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// recoverSegment opens one segment, validates it, and rebuilds its index.
// It reports whether the segment was skipped as never-initialised.
func (v *Vault) recoverSegment(id uint64, isLast bool, seals []types.SegmentSeal) (bool, error) {
	// A .zst is only ever renamed into place after being verified, so its
	// presence means the segment was compacted.
	if _, err := os.Stat(zstPath(v.opts.Dir, id)); err == nil {
		return v.recoverCompacted(id, seals)
	}
	path := filepath.Join(v.opts.Dir, segmentName(id, "wal"))
	flags := os.O_RDWR
	if v.opts.ReadOnly {
		flags = os.O_RDONLY
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return false, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false, err
	}

	// A file too short to hold a header was created and then interrupted
	// before the header was fsynced. That is not corruption: openSegment
	// creates the file, writes the header and fsyncs, and a crash inside that
	// window leaves a segment no record was ever acknowledged into.
	//
	// Treat it as never having existed. The id is then free again and the
	// next write recreates it properly. Refusing to open here would mean a
	// crash landing in a few microseconds of segment rollover left a vault
	// that could not be started.
	if fi.Size() < HeaderSize {
		f.Close()
		if !isLast {
			return true, nil // the caller reports this as corruption
		}
		v.opts.Logger.Warn("discarding a segment that was created but never initialised",
			"segment", id, "bytes", fi.Size())
		if !v.opts.ReadOnly {
			if err := os.Remove(path); err != nil {
				return false, err
			}
		}
		return true, nil
	}

	hdrBuf := make([]byte, HeaderSize)
	if _, err := f.ReadAt(hdrBuf, 0); err != nil {
		f.Close()
		return false, v.corruptf(id, "segment %d has no readable header: %v", id, err)
	}
	h, err := decodeHeader(hdrBuf)
	if err != nil {
		f.Close()
		return false, v.corruptf(id, "segment %d header: %v", id, err)
	}
	if h.Segment != id {
		f.Close()
		return false, v.corruptf(id, "file %s contains segment %d", segmentName(id, "wal"), h.Segment)
	}
	if want := types.RecordID(len(v.index)) + 1; h.FirstSeq != want {
		f.Close()
		return false, v.corruptf(id, "segment %d starts at sequence %d, expected %d", id, h.FirstSeq, want)
	}
	if h.PrevChain != v.head {
		f.Close()
		return false, v.corruptf(id, "segment %d does not follow the previous chain hash", id)
	}

	s := &segState{id: id, firstSeq: h.FirstSeq, prev: h.PrevChain, file: f, size: HeaderSize}

	// A valid footer means the segment was sealed cleanly.
	sealed := false
	var ftr footer
	if fi.Size() >= HeaderSize+FooterSize {
		tail := make([]byte, FooterSize)
		if _, err := f.ReadAt(tail, fi.Size()-FooterSize); err == nil {
			if ftr, err = decodeFooter(tail); err == nil {
				sealed = true
			}
		}
	}

	limit := fi.Size()
	if sealed {
		limit -= FooterSize
	}
	leaves, offsets, hashes, end, tornAt := v.scanRecords(s, limit)

	if sealed {
		if tornAt >= 0 {
			if err := v.corruptf(id, "sealed segment %d has a damaged record at offset %d", id, tornAt); err != nil {
				return false, err
			}
		}
		if uint64(len(leaves)) != ftr.Count {
			if err := v.corruptf(id, "sealed segment %d holds %d records, its footer says %d",
				id, len(leaves), ftr.Count); err != nil {
				return false, err
			}
		}
		if merkle.Root(leaves) != ftr.Root {
			if err := v.corruptf(id, "sealed segment %d does not match its footer root", id); err != nil {
				return false, err
			}
		}
	} else if !isLast {
		// Only the final segment can be unsealed. One in the middle means a
		// segment was removed or the directory was rearranged.
		if err := v.corruptf(id, "segment %d is not the last but has no footer", id); err != nil {
			return false, err
		}
	}

	// Publish the records that survived.
	s.count = len(leaves)
	s.size = end
	for i := range offsets {
		v.index = append(v.index, loc{seg: len(v.segs), off: offsets[i], rawSHA: hashes[i]})
		if !v.opts.DisableHashIndex {
			v.byHash[hashes[i]] = s.firstSeq + types.RecordID(i)
		}
	}

	switch {
	case sealed:
		s.sealed, s.root, s.chain, s.sealedAt = true, ftr.Root, ftr.Chain, ftr.SealedAt
		v.head = ftr.Chain
		if err := v.adoptSeal(s, ftr, seals); err != nil {
			return false, err
		}

	case tornAt >= 0 || (isLast && len(leaves) > 0):
		// The last segment was still open. Truncate any torn tail, then seal
		// it, so the vault comes up with everything it has inside the chain.
		if tornAt >= 0 {
			v.opts.Logger.Warn("truncating a torn record tail",
				"segment", id, "offset", tornAt, "bytes_dropped", limit-end)
		}
		if !v.opts.ReadOnly {
			if err := f.Truncate(end); err != nil {
				return false, err
			}
			if err := f.Sync(); err != nil {
				return false, err
			}
		}
		s.leaves = leaves
		v.segs = append(v.segs, s)
		if !v.opts.ReadOnly {
			if err := v.sealRecovered(s, tornAt >= 0); err != nil {
				return false, err
			}
		}
		return false, nil

	case len(leaves) == 0:
		// An empty, unsealed segment: the file was created but nothing was
		// ever committed to it. It carries no records, so it can simply be
		// reused as the active segment.
		s.leaves = leaves
		v.segs = append(v.segs, s)
		return false, nil
	}

	v.segs = append(v.segs, s)
	return false, nil
}

// scanRecords walks a segment's records up to limit. It returns the leaf
// hashes, their offsets, their raw hashes, the offset just past the last
// intact record, and the offset where damage started (-1 if none).
func (v *Vault) scanRecords(s *segState, limit int64) (leaves [][32]byte, offsets []int64, hashes [][32]byte, end int64, tornAt int64) {
	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	off := int64(HeaderSize)
	expect := s.firstSeq

	for off < limit {
		// Read the length prefix first and then exactly that much, rather
		// than speculatively reading max_frame_bytes for every record. A
		// corpus of 200-byte syslog lines would otherwise allocate a
		// megabyte per record to recover.
		var hdr [record.FrameOverhead]byte
		if int64(len(hdr)) > limit-off {
			return leaves, offsets, hashes, off, off
		}
		if _, err := v.readSeg(s, hdr[:], off); err != nil {
			return leaves, offsets, hashes, off, off
		}
		length := int(uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
		if length > maxBody || int64(record.FrameOverhead+length) > limit-off {
			return leaves, offsets, hashes, off, off
		}
		buf := make([]byte, record.FrameOverhead+length)
		if _, err := v.readSeg(s, buf, off); err != nil {
			return leaves, offsets, hashes, off, off
		}
		body, n, err := record.ParseFramed(buf, maxBody)
		if err != nil {
			return leaves, offsets, hashes, off, off
		}
		seq, r, err := record.Decode(body)
		if err != nil || seq != expect {
			// A record that decodes but carries the wrong sequence number is
			// not a torn write; it is the tail of an earlier, longer file
			// showing through, and it stops the scan just the same.
			return leaves, offsets, hashes, off, off
		}
		leaves = append(leaves, merkle.LeafHash(body))
		offsets = append(offsets, off)
		hashes = append(hashes, sha256.Sum256(r.Raw))
		off += int64(n)
		expect++
	}
	return leaves, offsets, hashes, off, -1
}

// adoptSeal reconciles a sealed segment's footer with the ledger.
//
// The one repairable case is a segment sealed with no ledger line: the crash
// landed between the footer fsync and the ledger append. The line is appended
// now. Any other disagreement is corruption, because no crash produces it.
func (v *Vault) adoptSeal(s *segState, f footer, seals []types.SegmentSeal) error {
	seal := types.SegmentSeal{
		Segment: s.id, FirstSeq: uint64(s.firstSeq), LastSeq: uint64(f.LastSeq),
		Count: f.Count, Root: f.Root, Prev: s.prev, Chain: f.Chain, SealedAt: f.SealedAt,
	}

	idx := len(v.seals)
	if idx < len(seals) {
		l := seals[idx]
		if l.Segment != s.id || l.Root != f.Root || l.Chain != f.Chain ||
			l.Count != f.Count || l.FirstSeq != uint64(s.firstSeq) || l.LastSeq != uint64(f.LastSeq) {
			if err := v.corruptf(s.id, "segment %d footer disagrees with its chain.log line", s.id); err != nil {
				return err
			}
		}
		seal.Recovered = l.Recovered
		v.seals = append(v.seals, seal)
		return nil
	}

	// Sealed on disk, absent from the ledger. Only legitimate for the newest
	// sealed segment: a gap further back would mean lines were removed.
	if idx != len(seals) {
		if err := v.corruptf(s.id, "segment %d is sealed but missing from chain.log", s.id); err != nil {
			return err
		}
	}
	v.opts.Logger.Warn("chain.log is missing a line for a sealed segment, appending it",
		"segment", s.id, "root", hex.EncodeToString(f.Root[:]))
	if !v.opts.ReadOnly {
		if err := v.appendLedger(seal); err != nil {
			return err
		}
	}
	v.seals = append(v.seals, seal)
	return nil
}

// sealRecovered seals a segment that was still open when the process died.
//
// The recovered flag is set on the segment before sealing, not patched on
// afterwards, so the ledger line on disk and the seal in memory say the same
// thing. An operator can then see which segments a crash closed, and that
// answer survives the next reopen.
func (v *Vault) sealRecovered(s *segState, truncated bool) error {
	s.recovered = true
	if err := v.sealLocked(s); err != nil {
		return err
	}
	v.opts.Logger.Info("sealed a segment left open by a crash",
		"segment", s.id, "records", s.count, "tail_truncated", truncated)
	return nil
}

// cleanStaleCompaction removes what an interrupted compaction leaves behind.
//
// Temporaries are never complete and are always safe to delete. A .hix with no
// .zst beside it is an orphan of a compaction that renamed the index but was
// interrupted before renaming the .zst, which is the last step: the segment is
// still a WAL and the index describes nothing.
func (v *Vault) cleanStaleCompaction() {
	entries, err := os.ReadDir(v.opts.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "seg-") {
			continue
		}
		path := filepath.Join(v.opts.Dir, name)
		switch {
		case strings.HasSuffix(name, ".zst.tmp"), strings.HasSuffix(name, ".hix.tmp"):
			v.opts.Logger.Warn("removing a temporary left by an interrupted compaction", "file", name)
			os.Remove(path)
		case strings.HasSuffix(name, ".hix"):
			zst := strings.TrimSuffix(path, ".hix") + ".zst"
			if _, err := os.Stat(zst); errors.Is(err, os.ErrNotExist) {
				v.opts.Logger.Warn("removing an orphaned hash index", "file", name)
				os.Remove(path)
			}
		}
	}
}

// recoverCompacted opens a segment stored as a .zst.
//
// A compacted segment is always sealed, so unlike a WAL there is no torn tail
// to repair: anything wrong with it is corruption. It is verified as thoroughly
// as a WAL is - every block checksummed and decompressed, every record parsed,
// the Merkle root recomputed against the footer - because "it opened" must
// mean the same thing for both.
func (v *Vault) recoverCompacted(id uint64, seals []types.SegmentSeal) (bool, error) {
	zst := zstPath(v.opts.Dir, id)
	wal := walPath(v.opts.Dir, id)

	f, err := os.Open(zst)
	if err != nil {
		return false, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false, err
	}
	fail := func(format string, args ...any) (bool, error) {
		f.Close()
		return false, v.corruptf(id, format, args...)
	}

	hdrBuf := make([]byte, HeaderSize)
	if _, err := f.ReadAt(hdrBuf, 0); err != nil {
		return fail("compacted segment %d has no readable header: %v", id, err)
	}
	h, err := decodeHeader(hdrBuf)
	if err != nil {
		return fail("compacted segment %d header: %v", id, err)
	}
	if h.Segment != id {
		return fail("file %s contains segment %d", segmentName(id, "zst"), h.Segment)
	}
	if want := types.RecordID(len(v.index)) + 1; h.FirstSeq != want {
		return fail("segment %d starts at sequence %d, expected %d", id, h.FirstSeq, want)
	}
	if h.PrevChain != v.head {
		return fail("segment %d does not follow the previous chain hash", id)
	}

	if fi.Size() < HeaderSize+FooterSize {
		return fail("compacted segment %d is %d bytes", id, fi.Size())
	}
	tail := make([]byte, FooterSize)
	if _, err := f.ReadAt(tail, fi.Size()-FooterSize); err != nil {
		return fail("compacted segment %d has no readable footer: %v", id, err)
	}
	ftr, err := decodeFooter(tail)
	if err != nil {
		// A compacted segment is only created from a sealed one. A missing or
		// damaged footer here is not an interrupted write.
		return fail("compacted segment %d footer: %v", id, err)
	}

	blocks, err := walkBlocks(f, fi.Size())
	if err != nil {
		return fail("compacted segment %d: %v", id, err)
	}
	s := &segState{
		id: id, firstSeq: h.FirstSeq, prev: h.PrevChain,
		file: f, compacted: true, blocks: blocks,
	}

	limit := blocks[len(blocks)-1].logEnd()
	leaves, offsets, hashes, _, tornAt := v.scanRecords(s, limit)
	if tornAt >= 0 {
		return fail("compacted segment %d has a damaged record at logical offset %d", id, tornAt)
	}
	if uint64(len(leaves)) != ftr.Count {
		return fail("compacted segment %d holds %d records, its footer says %d", id, len(leaves), ftr.Count)
	}
	if merkle.Root(leaves) != ftr.Root {
		return fail("compacted segment %d does not match its footer root", id)
	}

	// The .zst has now proven itself, so a leftover .wal is redundant. Only
	// at this point is it safe to remove: had the .zst failed, the .wal might
	// be the only good copy.
	if _, err := os.Stat(wal); err == nil && !v.opts.ReadOnly {
		v.opts.Logger.Warn("removing a WAL whose compacted copy verified", "segment", id)
		if err := os.Remove(wal); err != nil {
			f.Close()
			return false, err
		}
	}

	if !v.opts.DisableHashIndex {
		if err := v.attachHix(s, hashes); err != nil {
			f.Close()
			return false, err
		}
	}

	s.count = len(leaves)
	for i := range offsets {
		v.index = append(v.index, loc{seg: len(v.segs), off: offsets[i], rawSHA: hashes[i]})
	}
	s.sealed, s.root, s.chain, s.sealedAt = true, ftr.Root, ftr.Chain, ftr.SealedAt
	v.head = ftr.Chain
	if err := v.adoptSeal(s, ftr, seals); err != nil {
		f.Close()
		return false, err
	}
	v.segs = append(v.segs, s)
	return false, nil
}

// attachHix gives a compacted segment a hash index that is known to be right.
//
// The expected content is derived from the records just verified. If the .hix
// on disk matches it byte for byte it is used as it is. If it is missing or
// differs it is derived data that has gone wrong, not evidence of tampering
// (the records are what carry the integrity claim, and those were just
// checked), so a writer repairs it and a read-only open answers from memory.
func (v *Vault) attachHix(s *segState, hashes [][32]byte) error {
	path := hixPath(v.opts.Dir, s.id)
	want := encodeHix(hashes, s.firstSeq)

	have, err := os.ReadFile(path)
	if err == nil && bytes.Equal(have, want) {
		idx, err := openHixFile(path)
		if err != nil {
			return err
		}
		s.hix = idx
		return nil
	}

	if v.opts.ReadOnly {
		s.hix = memHix(want)
		return nil
	}
	if err == nil {
		v.opts.Logger.Warn("rebuilding a hash index that did not match its segment", "segment", s.id)
	} else {
		v.opts.Logger.Warn("rebuilding a missing hash index", "segment", s.id)
	}
	if err := writeFileAtomic(v.opts.Dir, path, want, v.dir.Sync); err != nil {
		return err
	}
	idx, err := openHixFile(path)
	if err != nil {
		return err
	}
	s.hix = idx
	return nil
}
