package vault_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/vaulttest"
)

// fixedNow keeps seal timestamps deterministic.
func fixedNow() func() time.Time {
	n := int64(0)
	return func() time.Time {
		n++
		return time.Unix(1790566200+n, 0).UTC()
	}
}

func opts(dir string, sealEvery int) vault.Options {
	return vault.Options{
		Dir:               dir,
		Sync:              vault.SyncAlways,
		SegmentMaxRecords: sealEvery,
		// Kept far away so record count is the only seal trigger the tests
		// have to reason about.
		SegmentMaxBytes: 1 << 30,
		SealInterval:    time.Hour,
		Now:             fixedNow(),
	}
}

func open(t *testing.T, dir string, sealEvery int) *vault.Vault {
	t.Helper()
	v, err := vault.Open(opts(dir, sealEvery))
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	return v
}

// TestConformance is the whole point: the on-disk vault and memvault are held
// to one definition of correct, so code developed against memvault behaves
// the same when it is switched over.
func TestConformance(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 8,
		New: func(t *testing.T) types.Vault {
			v := open(t, t.TempDir(), 8)
			t.Cleanup(func() { v.Close() })
			return v
		},
	})
}

// TestConformanceTinySegments runs it again at the smallest legal segment
// size, where nearly every write seals and opens a file. Segment-boundary
// bugs hide there.
func TestConformanceTinySegments(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 2,
		New: func(t *testing.T) types.Vault {
			v := open(t, t.TempDir(), 2)
			t.Cleanup(func() { v.Close() })
			return v
		},
	})
}

// TestConformanceGroupCommit runs it with a real group-commit delay, so the
// coalescing path is covered rather than only the drain-what-is-queued one.
func TestConformanceGroupCommit(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 8,
		New: func(t *testing.T) types.Vault {
			o := opts(t.TempDir(), 8)
			o.GroupCommitMaxDelay = 2 * time.Millisecond
			v, err := vault.Open(o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			return v
		},
	})
}

func TestConformanceSyncModes(t *testing.T) {
	for _, mode := range []vault.SyncMode{vault.SyncInterval, vault.SyncNone} {
		t.Run(string(mode), func(t *testing.T) {
			vaulttest.Run(t, vaulttest.Factory{
				SealEvery: 8,
				New: func(t *testing.T) types.Vault {
					o := opts(t.TempDir(), 8)
					o.Sync = mode
					o.SyncInterval = time.Millisecond
					v, err := vault.Open(o)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { v.Close() })
					return v
				},
			})
		})
	}
}

// ------------------------------------------------------------ durability

func rec(i int) types.RawRecord {
	return types.RawRecord{
		SourceID:   "syslog-udp",
		ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
		Origin:     types.Origin{Kind: types.OriginUDP, Addr: "10.1.4.7:51544", Offset: uint64(i)},
		Term:       types.TermLF,
		Raw:        []byte{byte(i), 0x00, 0xFF, byte(i >> 8)},
	}
}

func putN(t *testing.T, v types.Vault, n int) []types.Receipt {
	t.Helper()
	var out []types.Receipt
	for i := 0; i < n; i++ {
		rc, err := v.Put(context.Background(), rec(i))
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		out = append(out, rc)
	}
	return out
}

// TestReopen is the durability claim in its simplest form: everything written
// before a clean close is still there, byte for byte, afterwards.
func TestReopen(t *testing.T) {
	dir := t.TempDir()

	v := open(t, dir, 8)
	receipts := putN(t, v, 25)
	headBefore, throughBefore, err := v.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	v2 := open(t, dir, 8)
	defer v2.Close()

	for i, rc := range receipts {
		got, gotRc, err := v2.Get(context.Background(), rc.ID)
		if err != nil {
			t.Fatalf("after reopen, record %d: %v", rc.ID, err)
		}
		if string(got.Raw) != string(rec(i).Raw) {
			t.Errorf("record %d came back as %x, want %x", rc.ID, got.Raw, rec(i).Raw)
		}
		if gotRc.RawSHA256 != rc.RawSHA256 {
			t.Errorf("record %d: raw hash changed across reopen", rc.ID)
		}
	}

	// Close seals the active segment, so the head must have moved past where
	// it was before the close and must cover every record.
	head, through, err := v2.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head == headBefore {
		t.Error("the head did not move when Close sealed the active segment")
	}
	if through != types.RecordID(len(receipts)) {
		t.Errorf("sealedThrough is %d after reopen, want %d", through, len(receipts))
	}
	if throughBefore >= through {
		t.Errorf("sealedThrough did not advance: %d before close, %d after reopen", throughBefore, through)
	}

	rep, err := v2.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain failed after reopen at segment %d: %s", rep.FirstBad, rep.Reason)
	}
	if rep.Records != uint64(len(receipts)) {
		t.Errorf("chain covers %d records after reopen, want %d", rep.Records, len(receipts))
	}

	// Writing continues from where it left off.
	rc, err := v2.Put(context.Background(), rec(99))
	if err != nil {
		t.Fatal(err)
	}
	if want := types.RecordID(len(receipts) + 1); rc.ID != want {
		t.Errorf("the first record after reopen got id %d, want %d", rc.ID, want)
	}
}

// TestReopenEmpty covers the boundary where a vault was created but nothing
// was ever written to it.
func TestReopenEmpty(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 8)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	v2 := open(t, dir, 8)
	defer v2.Close()
	if rc := putN(t, v2, 1)[0]; rc.ID != 1 {
		t.Errorf("first record in a reopened empty vault got id %d, want 1", rc.ID)
	}
}

// TestSecondOpenIsRefused proves the flock works. Two writers sharing one
// directory would interleave into the same segments, and no amount of hashing
// afterwards would sort that out.
func TestSecondOpenIsRefused(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 8)
	defer v.Close()

	if v2, err := vault.Open(opts(dir, 8)); err == nil {
		v2.Close()
		t.Fatal("a second writer opened the same vault directory")
	}
}

// TestReadOnlyOpenWhileWriting proves an operator can inspect a vault another
// process is writing to, which is what `vaultctl verify` needs.
func TestReadOnlyOpenWhileWriting(t *testing.T) {
	dir := t.TempDir()
	w := open(t, dir, 4)
	defer w.Close()
	putN(t, w, 12)

	o := opts(dir, 4)
	o.ReadOnly = true
	r, err := vault.Open(o)
	if err != nil {
		t.Fatalf("read-only open of a vault being written: %v", err)
	}
	defer r.Close()

	rep, err := r.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain failed on a read-only open: %s", rep.Reason)
	}
	if _, err := r.Put(context.Background(), rec(0)); err == nil {
		t.Error("a read-only vault accepted a write")
	}
}

// TestFilePermissions: the vault holds raw log data, which routinely contains
// credentials and personal data. It must not be world-readable.
func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 4)
	putN(t, v, 9)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no files were created")
	}
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o, want no group or other access", e.Name(), perm)
		}
	}
}

// TestSegmentFilesOnDisk checks the layout an operator and the tamper tests
// both depend on: one .wal per segment, a chain.log line per seal, and a LOCK.
func TestSegmentFilesOnDisk(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir, 4)
	putN(t, v, 12)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"LOCK", "chain.log",
		"seg-000000000001.wal", "seg-000000000002.wal", "seg-000000000003.wal"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}

	ledger, err := os.ReadFile(filepath.Join(dir, "chain.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range ledger {
		if b == '\n' {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("chain.log has %d lines, want 3", lines)
	}
	if ledger[len(ledger)-1] != '\n' {
		t.Error("chain.log does not end with a newline, so the next append would corrupt a line")
	}
}

// TestSealInterval proves the time-based seal trigger fires, so a quiet source
// does not leave records outside the chain indefinitely.
func TestSealInterval(t *testing.T) {
	o := opts(t.TempDir(), 1_000_000) // never seal on count
	o.SealInterval = 20 * time.Millisecond
	v, err := vault.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	rc := putN(t, v, 3)[2]

	// Poll rather than sleep-and-assert: the tick is asynchronous, and a
	// fixed sleep is either flaky or slow.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := v.Proof(context.Background(), rc.ID); err == nil {
			return
		} else if err != types.ErrNotSealed {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the seal interval never fired")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestLargeRecords exercises the sizes oversize.log pins, so the segment write
// path is known to handle a 1.5 MiB record rather than only syslog lines.
func TestLargeRecords(t *testing.T) {
	o := opts(t.TempDir(), 4)
	o.MaxFrameBytes = 2 << 20
	v, err := vault.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	sizes := []int{70 << 10, 1 << 20, 1<<20 + 1<<19}
	var ids []types.RecordID
	for _, n := range sizes {
		r := rec(0)
		r.Raw = make([]byte, n)
		for i := range r.Raw {
			r.Raw[i] = byte(i)
		}
		rc, err := v.Put(context.Background(), r)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		ids = append(ids, rc.ID)
	}
	for i, id := range ids {
		got, _, err := v.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Raw) != sizes[i] {
			t.Errorf("record %d came back with %d bytes, want %d", id, len(got.Raw), sizes[i])
		}
		for j, b := range got.Raw {
			if b != byte(j) {
				t.Fatalf("record %d differs at byte %d", id, j)
			}
		}
	}
}

// TestAgreesWithMemvault is the claim memvault's package doc makes, asserted
// rather than assumed: for the same records in the same order, the two
// implementations produce the same leaf hashes, the same segment roots, the
// same chain head and interchangeable inclusion proofs.
//
// That is what makes it safe for Parsing, Frontend and Packaging to develop
// against memvault and switch to the real vault at Gate 1. If it ever stops
// being true, a proof captured during development stops verifying in
// production, and this is the test that says so first.
func TestAgreesWithMemvault(t *testing.T) {
	const n, sealEvery = 30, 7

	disk := open(t, t.TempDir(), sealEvery)
	defer disk.Close()
	mem := memvault.New(memvault.Options{SealEvery: sealEvery, Now: fixedNow()})
	defer mem.Close()

	for i := 0; i < n; i++ {
		r := rec(i)
		a, err := disk.Put(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		b, err := mem.Put(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if a.ID != b.ID {
			t.Fatalf("record %d: disk id %d, memory id %d", i, a.ID, b.ID)
		}
		if a.RawSHA256 != b.RawSHA256 {
			t.Fatalf("record %d: the two vaults hashed the payload differently", i)
		}
		if a.Segment != b.Segment {
			t.Fatalf("record %d: disk put it in segment %d, memory in %d", i, a.Segment, b.Segment)
		}
	}

	// Same chain head means every leaf, every root and every link matched.
	dh, dThrough, err := disk.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mh, mThrough, err := mem.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dh != mh {
		t.Fatalf("chain heads differ:\n  disk   %x\n  memory %x", dh, mh)
	}
	if dThrough != mThrough {
		t.Errorf("sealedThrough differs: disk %d, memory %d", dThrough, mThrough)
	}

	dSeals, err := disk.Seals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mSeals, err := mem.Seals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dSeals) != len(mSeals) {
		t.Fatalf("disk has %d seals, memory has %d", len(dSeals), len(mSeals))
	}
	for i := range dSeals {
		d, m := dSeals[i], mSeals[i]
		if d.Root != m.Root || d.Chain != m.Chain || d.Prev != m.Prev ||
			d.Count != m.Count || d.FirstSeq != m.FirstSeq || d.LastSeq != m.LastSeq {
			t.Errorf("segment %d seals differ:\n  disk   %+v\n  memory %+v", i+1, d, m)
		}
	}

	// A proof issued by one must verify against the other's root, which is
	// the property a component actually relies on when it switches over.
	for id := types.RecordID(1); id <= types.RecordID(sealEvery*(n/sealEvery)); id++ {
		dp, err := disk.Proof(context.Background(), id)
		if err != nil {
			t.Fatalf("disk proof %d: %v", id, err)
		}
		mp, err := mem.Proof(context.Background(), id)
		if err != nil {
			t.Fatalf("memory proof %d: %v", id, err)
		}
		if dp.LeafHash != mp.LeafHash || dp.Root != mp.Root || dp.Chain != mp.Chain ||
			dp.LeafIndex != mp.LeafIndex || dp.TreeSize != mp.TreeSize {
			t.Fatalf("record %d: the two vaults issued different proofs", id)
		}
		if len(dp.Path) != len(mp.Path) {
			t.Fatalf("record %d: path lengths differ", id)
		}
		for i := range dp.Path {
			if dp.Path[i] != mp.Path[i] {
				t.Fatalf("record %d: path element %d differs", id, i)
			}
		}
		if !merkle.VerifyInclusion(dp.LeafHash, dp.LeafIndex, dp.TreeSize, dp.Path, mp.Root) {
			t.Fatalf("record %d: the disk vault's proof does not verify against memvault's root", id)
		}
	}
}
