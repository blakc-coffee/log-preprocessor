package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Internal tests: these reach into compaction's unexported pieces, because the
// interesting failures are ones a well-behaved Open can never produce.

func internalVault(t *testing.T, n, sealEvery int) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := Open(Options{
		Dir: dir, Sync: SyncNone, SegmentMaxRecords: sealEvery,
		SealInterval: time.Hour, CompactBlockBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	for i := 0; i < n; i++ {
		raw := bytes.Repeat([]byte{byte('a' + i%26)}, 40+i%17)
		if _, err := v.Put(context.Background(), types.RawRecord{
			SourceID: "s", ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(), Raw: raw,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return v, dir
}

// recompress rewrites every block of a .zst through transform, recomputing all
// the checksums, and returns the new file. It is the strongest forgery
// available, so what it produces is well-formed in every way the file format
// can check.
func recompress(t *testing.T, path string, transform func(block int, data []byte) []byte) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	defer enc.Close()

	out := append([]byte(nil), b[:HeaderSize]...)
	off, end := HeaderSize, len(b)-FooterSize
	for i := 0; off < end; i++ {
		compLen := int(binary.BigEndian.Uint32(b[off:]))
		data, err := dec.DecodeAll(b[off+blockPrefixSize:off+blockPrefixSize+compLen], nil)
		if err != nil {
			t.Fatal(err)
		}
		data = transform(i, data)
		comp := enc.EncodeAll(data, nil)
		var pre [blockPrefixSize]byte
		binary.BigEndian.PutUint32(pre[0:4], uint32(len(comp)))
		binary.BigEndian.PutUint32(pre[4:8], uint32(len(data)))
		binary.BigEndian.PutUint32(pre[8:12], crc32.Checksum(comp, castagnoliBlock))
		out = append(out, pre[:]...)
		out = append(out, comp...)
		off += blockPrefixSize + compLen
	}
	return append(out, b[len(b)-FooterSize:]...)
}

// TestVerifyCompactedRejectsALossyFile is the verify-before-delete guard,
// tested directly: a compacted file that is well-formed in every way its format
// can check, but is MISSING a record, must not verify.
//
// This is the failure the whole procedure exists to prevent. Nothing else would
// notice: every checksum is valid, the block table walks cleanly, every record
// that remains parses. Only the Merkle root, recomputed over what is actually
// there, knows.
func TestVerifyCompactedRejectsALossyFile(t *testing.T) {
	v, dir := internalVault(t, 25, 10)
	s := v.segs[0]
	if err := v.compactSegment(s); err != nil {
		t.Fatalf("a healthy compaction failed: %v", err)
	}
	path := zstPath(dir, 1)
	b, _ := os.ReadFile(path)
	hdr, ftrBytes := b[:HeaderSize], b[len(b)-FooterSize:]
	ftr, err := decodeFooter(ftrBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the untouched file verifies, so what follows is about the edit.
	if _, err := verifyCompacted(path, hdr, ftrBytes, ftr, s.firstSeq, 1<<20); err != nil {
		t.Fatalf("a good compacted file does not verify: %v", err)
	}

	edits := map[string]func(int, []byte) []byte{
		"the last record of the first block dropped": func(i int, d []byte) []byte {
			if i != 0 {
				return d
			}
			// Find the last record boundary and cut there.
			last, pos := 0, 0
			for pos < len(d) {
				_, n, err := record.ParseFramed(d[pos:], 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				last, pos = pos, pos+n
			}
			return d[:last]
		},
		"a payload byte changed and its record CRC repaired": func(i int, d []byte) []byte {
			if i != 0 {
				return d
			}
			bodyLen := int(binary.BigEndian.Uint32(d[0:4]))
			body := d[record.FrameOverhead : record.FrameOverhead+bodyLen]
			body[len(body)-1] ^= 0x01
			binary.BigEndian.PutUint32(d[4:8], record.CRC(body))
			return d
		},
		"two records swapped": func(i int, d []byte) []byte {
			if i != 0 {
				return d
			}
			_, n1, _ := record.ParseFramed(d, 1<<20)
			_, n2, _ := record.ParseFramed(d[n1:], 1<<20)
			out := append([]byte(nil), d[n1:n1+n2]...)
			out = append(out, d[:n1]...)
			return append(out, d[n1+n2:]...)
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			forged := recompress(t, path, edit)
			fp := t.TempDir() + "/forged.zst"
			if err := os.WriteFile(fp, forged, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyCompacted(fp, hdr, ftrBytes, ftr, s.firstSeq, 1<<20); err == nil {
				t.Fatal("a compacted file that does not reproduce the segment verified")
			}
		})
	}
}

// TestFailedCompactionLeavesTheWALAlone: a compaction that cannot complete must
// leave the vault exactly as it found it. A source record that fails its CRC is
// the simplest way to make it fail, and the state afterwards is what matters.
func TestFailedCompactionLeavesTheWALAlone(t *testing.T) {
	v, dir := internalVault(t, 25, 10)
	s := v.segs[0]

	// Damage a record in the sealed WAL on disk.
	wal := walPath(dir, 1)
	b, err := os.ReadFile(wal)
	if err != nil {
		t.Fatal(err)
	}
	b[HeaderSize+20] ^= 0x01
	if err := os.WriteFile(wal, b, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := v.compactSegment(s); err == nil {
		t.Fatal("compacting a segment with a damaged record succeeded")
	}
	if _, err := os.Stat(wal); err != nil {
		t.Errorf("the WAL was removed after a failed compaction: %v", err)
	}
	for _, p := range []string{zstPath(dir, 1), zstPath(dir, 1) + ".tmp", hixPath(dir, 1), hixPath(dir, 1) + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was left behind by a failed compaction", p)
		}
	}
	if s.compacted {
		t.Error("the segment was switched to compacted despite the failure")
	}

	// And, crucially, a failed compaction is not a failed vault.
	if v.failed != nil {
		t.Errorf("a failed compaction put the vault into %v", v.failed)
	}
	if _, err := v.Put(context.Background(), types.RawRecord{Raw: []byte("still accepting writes")}); err != nil {
		t.Errorf("the vault stopped accepting writes after a failed compaction: %v", err)
	}
}

// TestFailedSegmentIsNotRetried tests the guard directly: once a segment has
// failed to compact, nextToCompact must skip it, or a permanent fault (a bad
// disk, a full volume) becomes a busy loop hammering the very disk that is
// already struggling. The flag clears on the next Open, which is when a
// persistent cause is most likely to have been fixed.
func TestFailedSegmentIsNotRetried(t *testing.T) {
	v, _ := internalVault(t, 25, 10) // segments 1 and 2 sealed, 3 active

	first := v.nextToCompact()
	if first == nil || first.id != 1 {
		t.Fatalf("nextToCompact = %v, want segment 1", first)
	}

	v.mu.Lock()
	first.compactFailed = true
	v.mu.Unlock()

	next := v.nextToCompact()
	if next == nil || next.id != 2 {
		t.Fatalf("after segment 1 failed, nextToCompact = %v, want segment 2", next)
	}

	v.mu.Lock()
	next.compactFailed = true
	v.mu.Unlock()
	if got := v.nextToCompact(); got != nil {
		t.Errorf("nextToCompact = segment %d with every sealed segment marked failed", got.id)
	}

	// The active segment is never a candidate: it is still being written.
	v.mu.RLock()
	active := v.segs[len(v.segs)-1]
	v.mu.RUnlock()
	if active.sealed {
		t.Fatal("the fixture's last segment is unexpectedly sealed")
	}
}

// ------------------------------------------------------------ file format

func TestWalkBlocksRejectsHostilePrefixes(t *testing.T) {
	mk := func(pre []byte) *bytes.Reader {
		b := make([]byte, HeaderSize)
		b = append(b, pre...)
		return bytes.NewReader(append(b, make([]byte, FooterSize)...))
	}
	prefix := func(comp, uncomp uint32) []byte {
		p := make([]byte, blockPrefixSize+8)
		binary.BigEndian.PutUint32(p[0:4], comp)
		binary.BigEndian.PutUint32(p[4:8], uncomp)
		return p
	}

	cases := map[string][]byte{
		"zero compressed length":   prefix(0, 100),
		"zero decompressed length": prefix(8, 0),
		"absurd decompressed":      prefix(8, 0xFFFFFFF0),
		"absurd compressed":        prefix(0xFFFFFFF0, 100),
		"runs past the footer":     prefix(1<<20, 100),
	}
	for name, pre := range cases {
		r := mk(pre)
		if _, err := walkBlocks(r, r.Size()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: got %v, want ErrCorrupt", name, err)
		}
	}

	// A file with no blocks at all is corruption, not an empty segment.
	empty := bytes.NewReader(make([]byte, HeaderSize+FooterSize))
	if _, err := walkBlocks(empty, empty.Size()); err == nil {
		t.Error("a compacted segment with no blocks was accepted")
	}
	short := bytes.NewReader(make([]byte, 10))
	if _, err := walkBlocks(short, short.Size()); err == nil {
		t.Error("a file shorter than a header and footer was accepted")
	}
}

// TestDecodeBlockChecksBeforeDecompressing: a flipped bit is reported as a
// checksum failure rather than as whatever the decoder makes of garbage.
func TestDecodeBlockChecksBeforeDecompressing(t *testing.T) {
	enc, _ := zstd.NewWriter(nil)
	defer enc.Close()
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()

	data := bytes.Repeat([]byte("hello "), 100)
	comp := enc.EncodeAll(data, nil)
	build := func(compLen, uncompLen, crc uint32, body []byte) ([]byte, block) {
		buf := make([]byte, blockPrefixSize)
		binary.BigEndian.PutUint32(buf[0:4], compLen)
		binary.BigEndian.PutUint32(buf[4:8], uncompLen)
		binary.BigEndian.PutUint32(buf[8:12], crc)
		buf = append(buf, body...)
		return buf, block{compOff: 0, compLen: compLen, uncompLen: uncompLen}
	}
	goodCRC := crc32.Checksum(comp, castagnoliBlock)

	buf, b := build(uint32(len(comp)), uint32(len(data)), goodCRC, comp)
	got, err := decodeBlock(bytes.NewReader(buf), b, dec)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("a good block failed to decode: %v", err)
	}

	t.Run("bad checksum", func(t *testing.T) {
		buf, b := build(uint32(len(comp)), uint32(len(data)), goodCRC^1, comp)
		if _, err := decodeBlock(bytes.NewReader(buf), b, dec); !errors.Is(err, ErrCorrupt) {
			t.Errorf("got %v, want ErrCorrupt", err)
		}
	})
	t.Run("wrong decompressed length", func(t *testing.T) {
		buf, b := build(uint32(len(comp)), uint32(len(data)+1), goodCRC, comp)
		if _, err := decodeBlock(bytes.NewReader(buf), b, dec); !errors.Is(err, ErrCorrupt) {
			t.Errorf("got %v, want ErrCorrupt: a block that decompresses to a different size than its prefix claims", err)
		}
	})
	t.Run("garbage that carries a valid checksum", func(t *testing.T) {
		junk := bytes.Repeat([]byte{0xAA}, 64)
		buf, b := build(uint32(len(junk)), 100, crc32.Checksum(junk, castagnoliBlock), junk)
		if _, err := decodeBlock(bytes.NewReader(buf), b, dec); !errors.Is(err, ErrCorrupt) {
			t.Errorf("got %v, want ErrCorrupt", err)
		}
	})
}

// ------------------------------------------------------------- hash index

func TestHashIndexLookup(t *testing.T) {
	h := func(b byte) [32]byte { return sha256.Sum256([]byte{b}) }

	hashes := [][32]byte{h(1), h(2), h(3), h(2), h(4)} // h(2) appears twice
	const first = 100
	idx := memHix(encodeHix(hashes, first))

	if idx.n != len(hashes) {
		t.Fatalf("index holds %d entries, want %d", idx.n, len(hashes))
	}

	for b, want := range map[byte]uint64{1: 100, 3: 102, 4: 104} {
		got, ok, err := idx.lookup(h(b))
		if err != nil || !ok || got != want {
			t.Errorf("lookup(h(%d)) = %d, %v, %v; want %d", b, got, ok, err, want)
		}
	}

	// A payload stored twice resolves to the NEWEST record, matching every
	// other newest-wins rule in the vault.
	got, ok, err := idx.lookup(h(2))
	if err != nil || !ok || got != 103 {
		t.Errorf("lookup of a duplicated payload = %d, %v, %v; want the newest, 103", got, ok, err)
	}

	for _, missing := range []byte{0, 5, 200} {
		if _, ok, _ := idx.lookup(h(missing)); ok {
			t.Errorf("found a hash that was never stored (%d)", missing)
		}
	}

	empty := memHix(nil)
	if _, ok, err := empty.lookup(h(1)); ok || err != nil {
		t.Errorf("lookup in an empty index = %v, %v", ok, err)
	}
}

func TestHixIsSortedAndDeterministic(t *testing.T) {
	var hashes [][32]byte
	for i := 0; i < 500; i++ {
		hashes = append(hashes, sha256.Sum256([]byte{byte(i), byte(i >> 8)}))
	}
	a, b := encodeHix(hashes, 1), encodeHix(hashes, 1)
	if !bytes.Equal(a, b) {
		t.Error("two encodings of the same hashes differ")
	}
	if len(a) != len(hashes)*hixEntrySize {
		t.Fatalf("size %d, want %d", len(a), len(hashes)*hixEntrySize)
	}
	for i := hixEntrySize; i < len(a); i += hixEntrySize {
		if bytes.Compare(a[i-hixEntrySize:i-hixEntrySize+32], a[i:i+32]) > 0 {
			t.Fatalf("entry %d is out of order", i/hixEntrySize)
		}
	}
}

// TestBlockCacheEvicts: bounded memory is a requirement, not a nicety.
func TestBlockCacheEvicts(t *testing.T) {
	c := newBlockCache(3)
	for i := 0; i < 10; i++ {
		c.put(cacheKey{seg: 1, idx: i}, []byte{byte(i)})
	}
	if _, ok := c.get(cacheKey{seg: 1, idx: 0}); ok {
		t.Error("the oldest block was not evicted")
	}
	if _, ok := c.get(cacheKey{seg: 1, idx: 9}); !ok {
		t.Error("the newest block was evicted")
	}
	if c.ll.Len() != 3 {
		t.Errorf("cache holds %d blocks, want 3", c.ll.Len())
	}

	c.put(cacheKey{seg: 2, idx: 0}, []byte{1})
	c.drop(2)
	if _, ok := c.get(cacheKey{seg: 2, idx: 0}); ok {
		t.Error("drop did not forget a segment's blocks")
	}
}

// BenchmarkCompact measures rewriting one sealed segment as a .zst, including
// the read-back verification that gates deleting the WAL — the verification is
// part of the cost of compacting safely, so it is part of the number.
//
// sync=none: this measures compaction, not fsync, and building the fixture with
// per-batch fsyncs would dominate the setup for no reason. (compactSegment does
// its own fsyncs, which are real.)
func BenchmarkCompact(b *testing.B) {
	const n = 20_000
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := b.TempDir()
		v, err := Open(Options{
			Dir: dir, Sync: SyncNone, SegmentMaxRecords: n, SealInterval: time.Hour,
		})
		if err != nil {
			b.Fatal(err)
		}
		batch := make([]types.RawRecord, 500)
		for written := 0; written < n; written += len(batch) {
			for j := range batch {
				batch[j] = types.RawRecord{
					SourceID: "syslog-udp", ReceivedAt: time.Unix(1790566200, 0).UTC(),
					Raw: []byte("<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built inbound TCP connection " +
						"for outside:203.0.113.183/389 to inside:10.2.2.73/43857"),
				}
			}
			if _, err := v.PutBatch(context.Background(), batch); err != nil {
				b.Fatal(err)
			}
		}
		info, err := os.Stat(walPath(dir, 1))
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(info.Size())
		b.StartTimer()

		if err := v.compactSegment(v.segs[0]); err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		v.Close()
		b.StartTimer()
	}
}
