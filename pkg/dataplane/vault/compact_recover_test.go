package vault_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

const (
	fxRecords   = 60
	fxSealEvery = 15
	fxSegments  = fxRecords / fxSealEvery
)

func zstFile(dir string, id int) string {
	return filepath.Join(dir, segName(id)[:len(segName(id))-4]+".zst")
}
func hixFile(dir string, id int) string {
	return filepath.Join(dir, segName(id)[:len(segName(id))-4]+".hix")
}
func walFile(dir string, id int) string { return filepath.Join(dir, segName(id)) }

// compactedFixture builds a vault of fxSegments compacted segments. The count
// is a multiple of the segment size, so closing seals nothing further and every
// segment is compacted.
func compactedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(copts(dir, fxSealEvery))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < fxRecords; i++ {
		if _, err := v.Put(context.Background(), bigRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitCompacted(t, dir, fxSegments)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// walFixture builds the same vault uncompacted, and returns its directory.
func walFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	v := open(t, dir, fxSealEvery)
	for i := 0; i < fxRecords; i++ {
		if _, err := v.Put(context.Background(), bigRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustVerify(t *testing.T, o vault.Options) {
	t.Helper()
	v, err := vault.Open(o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer v.Close()
	rep, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain failed at segment %d: %s", rep.FirstBad, rep.Reason)
	}
	if rep.Records != fxRecords {
		t.Fatalf("chain covers %d records, want %d", rep.Records, fxRecords)
	}
	for i := 0; i < fxRecords; i++ {
		got, _, err := v.Get(context.Background(), types.RecordID(i+1))
		if err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
		if !bytes.Equal(got.Raw, bigRec(i).Raw) {
			t.Fatalf("record %d came back changed", i+1)
		}
	}
}

// ------------------------------------------------- interrupted compactions

// TestStaleCompactionTempsAreRemoved: a crash mid-compaction leaves .tmp
// files. They are never complete and are always safe to delete.
func TestStaleCompactionTempsAreRemoved(t *testing.T) {
	dir := compactedFixture(t)
	junk := []string{
		filepath.Join(dir, "seg-000000000002.zst.tmp"),
		filepath.Join(dir, "seg-000000000002.hix.tmp"),
		filepath.Join(dir, "seg-000000000099.zst.tmp"),
	}
	for _, j := range junk {
		writeFile(t, j, []byte("half written"))
	}

	mustVerify(t, copts(dir, fxSealEvery))

	for _, j := range junk {
		if _, err := os.Stat(j); err == nil {
			t.Errorf("%s survived reopening", filepath.Base(j))
		}
	}
}

// TestOrphanedHashIndexIsRemoved: the .hix is renamed before the .zst, so a
// crash between the two leaves an index describing a segment that is still a
// WAL. It describes nothing and must not linger.
func TestOrphanedHashIndexIsRemoved(t *testing.T) {
	dir := walFixture(t)
	orphan := hixFile(dir, 2)
	writeFile(t, orphan, bytes.Repeat([]byte{0xAB}, 400))

	mustVerify(t, opts(dir, fxSealEvery))

	if _, err := os.Stat(orphan); err == nil {
		t.Error("an orphaned .hix survived reopening")
	}
	if _, err := os.Stat(walFile(dir, 2)); err != nil {
		t.Errorf("the segment's WAL was damaged: %v", err)
	}
}

// bothStates builds a vault where segment 2 exists as BOTH a .wal and a .zst:
// the state a crash leaves between the final rename and deleting the WAL.
func bothStates(t *testing.T) string {
	t.Helper()
	src := walFixture(t)
	saved := readFile(t, walFile(src, 2))

	v, err := vault.Open(copts(src, fxSealEvery))
	if err != nil {
		t.Fatal(err)
	}
	waitCompacted(t, src, fxSegments)
	v.Close()

	writeFile(t, walFile(src, 2), saved)
	return src
}

// TestBothWALAndZstPreferTheVerifiedZst: the interrupted-compaction window. The
// .zst proves itself, then the redundant .wal is removed.
func TestBothWALAndZstPreferTheVerifiedZst(t *testing.T) {
	dir := bothStates(t)

	t.Run("read-only never deletes anything", func(t *testing.T) {
		mustVerify(t, vault.Options{Dir: dir, ReadOnly: true})
		if _, err := os.Stat(walFile(dir, 2)); err != nil {
			t.Error("a read-only open deleted the WAL")
		}
	})

	t.Run("a writer removes the redundant WAL", func(t *testing.T) {
		mustVerify(t, copts(dir, fxSealEvery))
		if _, err := os.Stat(walFile(dir, 2)); err == nil {
			t.Error("the redundant WAL survived a writer open")
		}
	})
}

// TestNeverDeleteTheOnlyGoodCopy is the case the whole "verify the .zst first"
// ordering exists for. If both files exist and the .zst is damaged, the .wal
// may be the only good copy of that segment; deleting it because "the .zst
// wins" would turn a recoverable situation into data loss.
func TestNeverDeleteTheOnlyGoodCopy(t *testing.T) {
	dir := bothStates(t)

	b := readFile(t, zstFile(dir, 2))
	b[vault.HeaderSize+40] ^= 0x01 // inside the first compressed block
	writeFile(t, zstFile(dir, 2), b)

	if v, err := vault.Open(copts(dir, fxSealEvery)); err == nil {
		v.Close()
		t.Fatal("a writer opened a vault whose compacted segment is damaged")
	}
	if _, err := os.Stat(walFile(dir, 2)); err != nil {
		t.Fatalf("the WAL was deleted although the .zst beside it is bad: %v", err)
	}
	if got := readFile(t, walFile(dir, 2)); len(got) == 0 {
		t.Fatal("the WAL was emptied")
	}
}

// ------------------------------------------------ derived files self-heal

// TestMissingHashIndexIsRebuilt: the .hix is derived from the records, which
// were just verified, so a missing one is repaired rather than treated as
// damage. A read-only open answers from memory instead of writing.
func TestMissingHashIndexIsRebuilt(t *testing.T) {
	dir := compactedFixture(t)
	if err := os.Remove(hixFile(dir, 2)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bigRec(fxSealEvery + 1).Raw) // a record in segment 2

	t.Run("read-only answers from memory and writes nothing", func(t *testing.T) {
		v, err := vault.Open(vault.Options{Dir: dir, ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()
		raw, err := v.GetByHash(context.Background(), sum)
		if err != nil {
			t.Fatalf("GetByHash with a missing .hix: %v", err)
		}
		if !bytes.Equal(raw, bigRec(fxSealEvery+1).Raw) {
			t.Error("wrong bytes")
		}
		if _, err := os.Stat(hixFile(dir, 2)); err == nil {
			t.Error("a read-only open wrote a file")
		}
	})

	t.Run("a writer repairs it", func(t *testing.T) {
		mustVerify(t, copts(dir, fxSealEvery))
		if _, err := os.Stat(hixFile(dir, 2)); err != nil {
			t.Errorf("the .hix was not rebuilt: %v", err)
		}
	})
}

// TestTamperedHashIndexIsNotATamper. The .hix is a lookup aid, not evidence:
// the records carry the integrity claim and were just verified. Editing it
// must not raise a false tamper alarm, and must not make GetByHash lie.
func TestTamperedHashIndexIsNotATamper(t *testing.T) {
	dir := compactedFixture(t)
	b := readFile(t, hixFile(dir, 3))
	for i := range b {
		b[i] ^= 0xFF
	}
	writeFile(t, hixFile(dir, 3), b)

	mustVerify(t, copts(dir, fxSealEvery))

	v, err := vault.Open(vault.Options{Dir: dir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	sum := sha256.Sum256(bigRec(2*fxSealEvery + 2).Raw)
	raw, err := v.GetByHash(context.Background(), sum)
	if err != nil {
		t.Fatalf("GetByHash after a corrupted .hix: %v", err)
	}
	if !bytes.Equal(raw, bigRec(2*fxSealEvery+2).Raw) {
		t.Error("GetByHash returned the wrong bytes after the .hix was corrupted")
	}
}

// ------------------------------------------------------------- tamper matrix

// forgeBlock rewrites one compressed block so that a payload byte inside it is
// changed, with EVERYTHING that can be recomputed recomputed: the record's CRC,
// the block's CRC, and the length prefix. It is the strongest forgery an
// attacker with write access and no access to the chain can mount, and the
// only thing left to catch it is the Merkle root.
func forgeBlock(t *testing.T, path string) {
	t.Helper()
	b := readFile(t, path)
	hdr, ftr := b[:vault.HeaderSize], b[len(b)-vault.FooterSize:]

	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	out := append([]byte(nil), hdr...)
	off := vault.HeaderSize
	end := len(b) - vault.FooterSize
	forged := false
	for off < end {
		compLen := int(binary.BigEndian.Uint32(b[off:]))
		comp := b[off+12 : off+12+compLen]
		data, err := dec.DecodeAll(comp, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !forged {
			// Flip a byte inside the first record's payload, then repair the
			// record's own CRC so it still parses.
			bodyLen := int(binary.BigEndian.Uint32(data[0:4]))
			body := data[record.FrameOverhead : record.FrameOverhead+bodyLen]
			body[len(body)-1] ^= 0x01
			binary.BigEndian.PutUint32(data[4:8], record.CRC(body))
			forged = true
		}
		newComp := enc.EncodeAll(data, nil)
		var pre [12]byte
		binary.BigEndian.PutUint32(pre[0:4], uint32(len(newComp)))
		binary.BigEndian.PutUint32(pre[4:8], uint32(len(data)))
		binary.BigEndian.PutUint32(pre[8:12], crc32.Checksum(newComp, crc32.MakeTable(crc32.Castagnoli)))
		out = append(out, pre[:]...)
		out = append(out, newComp...)
		off += 12 + compLen
	}
	out = append(out, ftr...)
	writeFile(t, path, out)
}

// TestCompactedTamperMatrix: compaction must not open a hole in tamper
// evidence. Every one of these has to fail VerifyChain(deep).
func TestCompactedTamperMatrix(t *testing.T) {
	t.Run("a flipped byte in a compressed block", func(t *testing.T) {
		dir := compactedFixture(t)
		b := readFile(t, zstFile(dir, 2))
		b[vault.HeaderSize+40] ^= 0x01
		writeFile(t, zstFile(dir, 2), b)
		assertChainFails(t, dir, "a flipped byte in a compressed block")
	})

	t.Run("a block forged with every checksum recomputed", func(t *testing.T) {
		dir := compactedFixture(t)
		forgeBlock(t, zstFile(dir, 2))
		// Sanity: the forgery really is well-formed, so the open must get as
		// far as the Merkle root before anything rejects it.
		assertChainFails(t, dir, "a forged block with valid CRCs")
	})

	t.Run("a truncated compacted segment", func(t *testing.T) {
		dir := compactedFixture(t)
		b := readFile(t, zstFile(dir, 2))
		writeFile(t, zstFile(dir, 2), b[:len(b)-vault.FooterSize-30])
		assertChainFails(t, dir, "a truncated .zst")
	})

	t.Run("a deleted compacted segment", func(t *testing.T) {
		dir := compactedFixture(t)
		if err := os.Remove(zstFile(dir, 2)); err != nil {
			t.Fatal(err)
		}
		assertChainFails(t, dir, "a deleted .zst")
	})

	t.Run("two compacted segments swapped", func(t *testing.T) {
		dir := compactedFixture(t)
		a, c := readFile(t, zstFile(dir, 2)), readFile(t, zstFile(dir, 3))
		writeFile(t, zstFile(dir, 2), c)
		writeFile(t, zstFile(dir, 3), a)
		assertChainFails(t, dir, "two swapped .zst files")
	})

	t.Run("an edited footer root", func(t *testing.T) {
		dir := compactedFixture(t)
		b := readFile(t, zstFile(dir, 2))
		b[len(b)-vault.FooterSize+24] ^= 0x01
		writeFile(t, zstFile(dir, 2), b)
		assertChainFails(t, dir, "an edited .zst footer root")
	})

	t.Run("an edited segment header", func(t *testing.T) {
		dir := compactedFixture(t)
		b := readFile(t, zstFile(dir, 3))
		b[28] ^= 0x01
		writeFile(t, zstFile(dir, 3), b)
		assertChainFails(t, dir, "an edited .zst header")
	})

	t.Run("a block length prefix inflated to demand gigabytes", func(t *testing.T) {
		// The decompressed length comes from the file, so a hostile value must
		// be rejected before anything allocates against it.
		dir := compactedFixture(t)
		b := readFile(t, zstFile(dir, 2))
		binary.BigEndian.PutUint32(b[vault.HeaderSize+4:], 0xFFFFFFF0)
		writeFile(t, zstFile(dir, 2), b)
		assertChainFails(t, dir, "an inflated block length")
	})

	t.Run("a compacted segment replaced by a same-named WAL from another vault", func(t *testing.T) {
		dir := compactedFixture(t)
		other := walFixture(t)
		// The WAL is well-formed and even carries the right records, but it
		// is a different file with different timestamps in its header.
		writeFile(t, walFile(dir, 2), readFile(t, walFile(other, 2)))
		// Both exist: the .zst is verified and wins, the WAL is discarded.
		// This must NOT be reported as tampering - it is the crash window.
		mustVerify(t, vault.Options{Dir: dir, ReadOnly: true})
	})
}
