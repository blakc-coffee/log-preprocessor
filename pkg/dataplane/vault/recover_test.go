package vault_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
)

// snapshot copies a vault directory as it currently stands on disk, skipping
// the lock file.
//
// This is how a crash is simulated without killing anything: in sync=always
// every acknowledged record is already fsynced, so a copy taken mid-run is
// byte-identical to what a kill -9 would have left behind, including the
// unsealed active segment. The real 200-cycle kill -9 suite comes at M5; this
// gives the same on-disk states deterministically and in milliseconds.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "LOCK" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// crashed writes n records and returns a snapshot of the directory taken while
// the active segment is still open.
func crashed(t *testing.T, n, sealEvery int) string {
	t.Helper()
	dir := t.TempDir()
	v := open(t, dir, sealEvery)
	putN(t, v, n)
	snap := snapshot(t, dir)
	v.Close()
	return snap
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// openTampered opens a vault read-only, which is what `vaultctl verify` does.
// A writer refuses to open damaged storage; a reader has to be able to, or the
// damage cannot be reported.
func openTampered(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	o := opts(dir, 4)
	o.ReadOnly = true
	v, err := vault.Open(o)
	if err != nil {
		t.Fatalf("read-only open of a damaged vault failed, so the damage cannot be reported: %v", err)
	}
	return v
}

// assertChainFails is the assertion the whole tamper matrix reduces to.
func assertChainFails(t *testing.T, dir, what string) {
	t.Helper()
	v := openTampered(t, dir)
	defer v.Close()

	rep, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		return // refusing outright is also a detection
	}
	if rep.OK {
		t.Errorf("UNDETECTED TAMPER: %s passed VerifyChain(deep)", what)
		return
	}
	if rep.Reason == "" {
		t.Errorf("%s was detected but reported no reason", what)
	}
	t.Logf("%s -> detected at segment %d: %s", what, rep.FirstBad, rep.Reason)
}

// TestRecoveryAfterCrash proves the ordinary case: a process that died with an
// unsealed segment comes back with every acknowledged record intact, and the
// segment sealed and marked as recovered.
func TestRecoveryAfterCrash(t *testing.T) {
	const n, sealEvery = 25, 8
	snap := crashed(t, n, sealEvery)

	v := open(t, snap, sealEvery)
	defer v.Close()

	for i := 0; i < n; i++ {
		got, _, err := v.Get(context.Background(), types.RecordID(i+1))
		if err != nil {
			t.Fatalf("record %d lost across the crash: %v", i+1, err)
		}
		if !bytes.Equal(got.Raw, rec(i).Raw) {
			t.Errorf("record %d came back as %x, want %x", i+1, got.Raw, rec(i).Raw)
		}
	}

	rep, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain broken after recovery at segment %d: %s", rep.FirstBad, rep.Reason)
	}
	if rep.Records != n {
		t.Errorf("chain covers %d records after recovery, want %d", rep.Records, n)
	}

	// The segment the crash left open must be marked, so an operator can see
	// which segments were closed by recovery rather than cleanly.
	seals, err := v.Seals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if last := seals[len(seals)-1]; !last.Recovered {
		t.Errorf("segment %d was sealed by recovery but is not flagged recovered", last.Segment)
	}
}

// TestTornTailAtEveryOffset is the durability claim under a microscope: the
// last write is cut at every possible byte, and recovery must drop exactly the
// torn record and keep every record before it.
//
// A record lost here is a record that was acknowledged and then vanished,
// which is the one failure the vault exists to prevent. A record kept that was
// never complete is just as bad, because its CRC would fail on every later
// read.
func TestTornTailAtEveryOffset(t *testing.T) {
	const n, sealEvery = 12, 100 // one segment, never sealed
	snap := crashed(t, n, sealEvery)

	segPath := filepath.Join(snap, "seg-000000000001.wal")
	full := readFile(t, segPath)

	for cut := 1; cut < len(full); cut++ {
		t.Run("", func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "seg-000000000001.wal"), full[:cut])

			v, err := vault.Open(opts(dir, sealEvery))
			if err != nil {
				// Only legitimate while the header itself is incomplete:
				// without a header there is no segment to recover.
				if cut < vault.HeaderSize {
					return
				}
				t.Fatalf("cut at %d of %d: %v", cut, len(full), err)
			}
			defer v.Close()

			// Every record that is wholly present must still be readable and
			// correct; nothing beyond the cut may survive.
			kept := 0
			for i := 0; i < n; i++ {
				got, _, err := v.Get(context.Background(), types.RecordID(i+1))
				if err != nil {
					break
				}
				if !bytes.Equal(got.Raw, rec(i).Raw) {
					t.Fatalf("cut at %d: record %d survived but is wrong", cut, i+1)
				}
				kept++
			}

			rep, err := v.VerifyChain(context.Background(), true)
			if err != nil {
				t.Fatalf("cut at %d: %v", cut, err)
			}
			if !rep.OK {
				t.Fatalf("cut at %d: chain broken after recovery: %s", cut, rep.Reason)
			}
			if rep.Records != uint64(kept) {
				t.Fatalf("cut at %d: chain covers %d records but %d are readable", cut, rep.Records, kept)
			}
		})
	}
}

// TestTruncatedLedgerTail covers the crash window inside the ledger append
// itself. A torn final line is expected and is truncated; the seal it
// described is recovered from the segment footer.
func TestTruncatedLedgerTail(t *testing.T) {
	const sealEvery = 4
	snap := crashed(t, 12, sealEvery)

	path := filepath.Join(snap, "chain.log")
	full := readFile(t, path)
	// Cut the last line in half.
	lines := bytes.Split(bytes.TrimSuffix(full, []byte("\n")), []byte("\n"))
	partial := bytes.Join(lines[:len(lines)-1], []byte("\n"))
	partial = append(partial, '\n')
	partial = append(partial, lines[len(lines)-1][:len(lines[len(lines)-1])/2]...)
	writeFile(t, path, partial)

	v := open(t, snap, sealEvery)
	defer v.Close()

	rep, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a torn final ledger line was not repaired: %s", rep.Reason)
	}
	if rep.Records != 12 {
		t.Errorf("chain covers %d records, want 12", rep.Records)
	}
}

// TestMissingLedgerLineIsRepaired covers the crash window between the footer
// fsync and the ledger append: the segment is sealed on disk but the ledger
// never learned about it. That is the one ledger inconsistency a crash can
// actually produce, so it is the only one that gets repaired.
func TestMissingLedgerLineIsRepaired(t *testing.T) {
	const sealEvery = 4
	snap := crashed(t, 12, sealEvery)

	path := filepath.Join(snap, "chain.log")
	lines := bytes.Split(bytes.TrimSuffix(readFile(t, path), []byte("\n")), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected several ledger lines, got %d", len(lines))
	}
	writeFile(t, path, append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n'))

	v := open(t, snap, sealEvery)
	defer v.Close()

	rep, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a sealed segment missing its ledger line was not repaired: %s", rep.Reason)
	}
	if rep.Segments != len(lines) {
		t.Errorf("chain has %d segments after repair, want %d", rep.Segments, len(lines))
	}

	// And the repair must be on disk, not only in memory.
	if got := len(bytes.Split(bytes.TrimSuffix(readFile(t, path), []byte("\n")), []byte("\n"))); got != len(lines) {
		t.Errorf("chain.log has %d lines after the repair, want %d", got, len(lines))
	}
}

// ------------------------------------------------------------ tamper matrix
//
// Success metric: zero undetected modifications. Each of these is a way
// someone with write access to the directory could try to change history.
// None of them may pass VerifyChain(deep).

func TestTamperMatrix(t *testing.T) {
	const sealEvery = 4
	const records = 16

	// build returns a fresh, cleanly closed vault directory to damage.
	build := func(t *testing.T) string {
		dir := t.TempDir()
		v := open(t, dir, sealEvery)
		putN(t, v, records)
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	seg := func(dir string, id int) string {
		return filepath.Join(dir, segName(id))
	}

	t.Run("one flipped byte in a record", func(t *testing.T) {
		dir := build(t)
		b := readFile(t, seg(dir, 2))
		// Well past the header, inside the first record's payload.
		b[vault.HeaderSize+40] ^= 0x01
		writeFile(t, seg(dir, 2), b)
		assertChainFails(t, dir, "a flipped byte in a record")
	})

	t.Run("record deleted", func(t *testing.T) {
		dir := build(t)
		b := readFile(t, seg(dir, 2))
		// Drop 64 bytes from the middle of the record area.
		cut := append(append([]byte{}, b[:vault.HeaderSize+32]...), b[vault.HeaderSize+96:]...)
		writeFile(t, seg(dir, 2), cut)
		assertChainFails(t, dir, "a deleted record")
	})

	t.Run("segment truncated", func(t *testing.T) {
		dir := build(t)
		b := readFile(t, seg(dir, 2))
		writeFile(t, seg(dir, 2), b[:len(b)-vault.FooterSize-20])
		assertChainFails(t, dir, "a truncated sealed segment")
	})

	t.Run("middle segment deleted", func(t *testing.T) {
		dir := build(t)
		if err := os.Remove(seg(dir, 2)); err != nil {
			t.Fatal(err)
		}
		assertChainFails(t, dir, "a deleted middle segment")
	})

	t.Run("two segments swapped", func(t *testing.T) {
		dir := build(t)
		a, b := readFile(t, seg(dir, 2)), readFile(t, seg(dir, 3))
		writeFile(t, seg(dir, 2), b)
		writeFile(t, seg(dir, 3), a)
		assertChainFails(t, dir, "two swapped segments")
	})

	t.Run("footer root edited", func(t *testing.T) {
		dir := build(t)
		b := readFile(t, seg(dir, 2))
		// The footer's root field starts 24 bytes into the footer.
		b[len(b)-vault.FooterSize+24] ^= 0x01
		writeFile(t, seg(dir, 2), b)
		assertChainFails(t, dir, "an edited footer root")
	})

	t.Run("ledger root edited", func(t *testing.T) {
		dir := build(t)
		path := filepath.Join(dir, "chain.log")
		text := string(readFile(t, path))
		i := strings.Index(text, `"root":"`)
		if i < 0 {
			t.Fatal(`no "root" field in chain.log`)
		}
		at := i + len(`"root":"`)
		flipped := byte('a')
		if text[at] == 'a' {
			flipped = 'b'
		}
		writeFile(t, path, []byte(text[:at]+string(flipped)+text[at+1:]))
		assertChainFails(t, dir, "an edited ledger root")
	})

	t.Run("ledger line removed from the middle", func(t *testing.T) {
		dir := build(t)
		path := filepath.Join(dir, "chain.log")
		lines := bytes.Split(bytes.TrimSuffix(readFile(t, path), []byte("\n")), []byte("\n"))
		if len(lines) < 3 {
			t.Fatalf("need at least 3 ledger lines, got %d", len(lines))
		}
		kept := append(append([][]byte{}, lines[:1]...), lines[2:]...)
		writeFile(t, path, append(bytes.Join(kept, []byte("\n")), '\n'))
		assertChainFails(t, dir, "a ledger line removed from the middle")
	})

	t.Run("chain.log emptied", func(t *testing.T) {
		dir := build(t)
		writeFile(t, filepath.Join(dir, "chain.log"), nil)
		assertChainFails(t, dir, "an emptied chain.log")
	})

	t.Run("segment header prev_chain edited", func(t *testing.T) {
		dir := build(t)
		b := readFile(t, seg(dir, 3))
		// prev_chain starts 28 bytes into the header. Editing it also breaks
		// the header CRC, which is the point: the header is checksummed so
		// that a segment cannot be quietly relocated in the chain.
		b[28] ^= 0x01
		writeFile(t, seg(dir, 3), b)
		assertChainFails(t, dir, "an edited segment header")
	})
}

// segName mirrors the on-disk naming for the tests.
func segName(id int) string {
	s := "000000000000"
	d := ""
	for n := id; n > 0; n /= 10 {
		d = string(rune('0'+n%10)) + d
	}
	if d == "" {
		d = "0"
	}
	return "seg-" + s[:len(s)-len(d)] + d + ".wal"
}

// TestWriterRefusesDamagedVault is the other half of the read-only leniency:
// a writer must NOT open a vault whose history is already broken, because
// appending to it would bury the evidence under valid-looking new chain links.
func TestWriterRefusesDamagedVault(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 4)
	putN(t, v, 16)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, segName(2))); err != nil {
		t.Fatal(err)
	}

	if v2, err := vault.Open(opts(dir, 4)); err == nil {
		v2.Close()
		t.Fatal("a writer opened a vault with a missing segment")
	}
}

// TestUninitialisedSegmentIsDiscarded is a regression test for a crash window
// the 200-cycle suite found only under -race, at cycle 123.
//
// openSegment creates the file, writes the 72-byte header, and fsyncs. A crash
// inside those few microseconds leaves a segment file shorter than a header,
// which no record was ever acknowledged into. Recovery called that fatal
// corruption and refused to open the vault at all — so a crash landing in a
// microsecond-wide window of segment rollover produced a vault that could not
// be started again.
//
// It is treated as never having existed: the file is removed and the id is
// free for the next write.
func TestUninitialisedSegmentIsDiscarded(t *testing.T) {
	for _, size := range []int{0, 1, vault.HeaderSize - 1} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			dir := t.TempDir()
			v := open(t, dir, 4)
			receipts := putN(t, v, 9)
			if err := v.Close(); err != nil {
				t.Fatal(err)
			}

			// A partially created segment beyond the last real one.
			next := filepath.Join(dir, segName(4))
			if err := os.WriteFile(next, make([]byte, size), 0o600); err != nil {
				t.Fatal(err)
			}

			v2, err := vault.Open(opts(dir, 4))
			if err != nil {
				t.Fatalf("a vault with a %d-byte uninitialised segment would not open: %v", size, err)
			}
			defer v2.Close()

			// Everything acknowledged before the crash is still there.
			for i, rc := range receipts {
				got, _, err := v2.Get(context.Background(), rc.ID)
				if err != nil {
					t.Fatalf("record %d was lost: %v", rc.ID, err)
				}
				if !bytes.Equal(got.Raw, rec(i).Raw) {
					t.Errorf("record %d came back changed", rc.ID)
				}
			}
			rep, err := v2.VerifyChain(context.Background(), true)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK {
				t.Fatalf("chain broken: %s", rep.Reason)
			}

			// And writing continues from where it left off.
			rc, err := v2.Put(context.Background(), rec(99))
			if err != nil {
				t.Fatal(err)
			}
			if want := types.RecordID(len(receipts) + 1); rc.ID != want {
				t.Errorf("the first record after recovery got id %d, want %d", rc.ID, want)
			}
		})
	}
}

// TestUninitialisedMiddleSegmentIsStillCorruption: only the LAST segment can
// be uninitialised. One in the middle means a segment was removed, which is
// not something a crash does.
func TestUninitialisedMiddleSegmentIsStillCorruption(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 4)
	putN(t, v, 16)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, segName(2)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if v2, err := vault.Open(opts(dir, 4)); err == nil {
		v2.Close()
		t.Fatal("a writer opened a vault with an empty middle segment")
	}
}
