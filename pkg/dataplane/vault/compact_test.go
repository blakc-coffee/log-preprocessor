package vault_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/vaulttest"
)

// copts is opts with compaction on and a block size small enough that every
// segment spans several blocks, so block boundaries are exercised constantly.
func copts(dir string, sealEvery int) vault.Options {
	o := opts(dir, sealEvery)
	o.Compact = true
	o.CompactBlockBytes = 512
	return o
}

// bigRec is a realistic record: an ASA-shaped line, with the awkward ones
// mixed in so compaction is checked against the payloads that break naive
// code, not only against text.
func bigRec(i int) types.RawRecord {
	r := types.RawRecord{
		SourceID:   fmt.Sprintf("src-%d", i%3),
		ReceivedAt: time.Unix(1790566200+int64(i), int64(i)).UTC(),
		Origin:     types.Origin{Kind: types.OriginFile, Addr: "/var/log/asa.log", Offset: uint64(i) * 200},
		Term:       []types.Terminator{types.TermLF, types.TermCRLF, types.TermNone}[i%3],
	}
	switch i % 11 {
	case 3:
		r.Raw = nil // empty
	case 5:
		r.Raw = []byte{0xFF, 0xFE, 0x00, '\r', '\n', 0x1b, byte(i)} // hostile bytes
	case 7:
		r.Raw = bytes.Repeat([]byte(fmt.Sprintf("big-%d-", i)), 300) // larger than a block
	default:
		r.Raw = []byte(fmt.Sprintf(
			"<166>Sep 28 2026 09:00:%02d asa01 : %%ASA-6-302013: Built inbound TCP connection %d for outside:203.0.113.%d/389 to inside:10.2.2.%d/43857",
			i%60, 1000+i, i%250, i%250))
	}
	return r
}

// waitCompacted blocks until n segments exist as .zst, no compaction
// temporaries remain, and no segment exists as BOTH a .zst and a .wal.
//
// That last condition is the one that is easy to forget. A compaction renames
// the .zst into place and only afterwards deletes the .wal, so for a moment the
// segment is both, and a test that saw "n .zst files" in that window would go
// on to assert something about a directory that is about to change.
//
// Polling rather than sleeping: a fixed sleep is either flaky or slow.
func waitCompacted(t *testing.T, dir string, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		zst, tmp, both := 0, 0, 0
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, e := range entries {
			names[e.Name()] = true
		}
		for name := range names {
			switch {
			case strings.HasSuffix(name, ".zst"):
				zst++
				if names[strings.TrimSuffix(name, ".zst")+".wal"] {
					both++
				}
			case strings.HasSuffix(name, ".tmp"):
				tmp++
			}
		}
		if zst >= n && tmp == 0 && both == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d compacted segments; have %d (%d temporaries)", n, zst, tmp)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func countExt(t *testing.T, dir, ext string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ext) {
			n++
		}
	}
	return n
}

// TestCompactedReadsEqualWALReads is the test that matters.
//
// A compaction that dropped or altered a record would be silent: nothing would
// fail until someone asked for that record. So this reads every record, its
// receipt, every proof, the ledger and the chain head from a vault stored as
// WALs, compacts it, and requires all of it to be identical afterwards.
func TestCompactedReadsEqualWALReads(t *testing.T) {
	const n, sealEvery = 137, 20
	dir := t.TempDir()
	ctx := context.Background()

	// Build as WALs.
	v := open(t, dir, sealEvery)
	var want []types.RawRecord
	var wantRc []types.Receipt
	for i := 0; i < n; i++ {
		r := bigRec(i)
		want = append(want, r)
		rc, err := v.Put(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		wantRc = append(wantRc, rc)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if countExt(t, dir, ".zst") != 0 {
		t.Fatal("the fixture vault was compacted before the test asked for it")
	}

	// Everything about the uncompacted vault, recorded up front.
	ro, err := vault.Open(vault.Options{Dir: dir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	headBefore, throughBefore, _ := ro.Head(ctx)
	sealsBefore, _ := ro.Seals(ctx)
	proofsBefore := map[types.RecordID]types.InclusionProof{}
	for id := types.RecordID(1); id <= types.RecordID(n); id++ {
		if p, err := ro.Proof(ctx, id); err == nil {
			proofsBefore[id] = p
		}
	}
	ro.Close()

	// Compact.
	wals := countExt(t, dir, ".wal")
	c, err := vault.Open(copts(dir, sealEvery))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitCompacted(t, dir, wals) // every existing segment was sealed by the Close above

	if got := countExt(t, dir, ".wal"); got != 0 {
		t.Errorf("%d .wal files remain after compaction", got)
	}
	if got := countExt(t, dir, ".hix"); got != wals {
		t.Errorf("%d .hix files, want one per compacted segment (%d)", got, wals)
	}

	// Every record, byte for byte, with the same receipt.
	for i, r := range want {
		id := types.RecordID(i + 1)
		got, rc, err := c.Get(ctx, id)
		if err != nil {
			t.Fatalf("record %d after compaction: %v", id, err)
		}
		if !bytes.Equal(got.Raw, r.Raw) {
			t.Fatalf("record %d: raw changed by compaction\n got %x\nwant %x", id, got.Raw, r.Raw)
		}
		if got.SourceID != r.SourceID || got.Term != r.Term || got.Origin != r.Origin ||
			!got.ReceivedAt.Equal(r.ReceivedAt) {
			t.Fatalf("record %d: metadata changed by compaction:\n got %+v\nwant %+v", id, got, r)
		}
		if rc != wantRc[i] {
			t.Fatalf("record %d: receipt changed by compaction:\n got %+v\nwant %+v", id, rc, wantRc[i])
		}
		if sum := sha256.Sum256(r.Raw); rc.RawSHA256 != sum {
			t.Fatalf("record %d: receipt hash does not match its payload", id)
		}
	}

	// The chain must be exactly what it was: compaction changes storage, not
	// what the storage commits to.
	headAfter, throughAfter, err := c.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if headAfter != headBefore || throughAfter != throughBefore {
		t.Errorf("the chain head changed by compacting:\n before %x@%d\n after  %x@%d",
			headBefore, throughBefore, headAfter, throughAfter)
	}
	sealsAfter, _ := c.Seals(ctx)
	if len(sealsAfter) != len(sealsBefore) {
		t.Fatalf("%d seals after, %d before", len(sealsAfter), len(sealsBefore))
	}
	for i := range sealsBefore {
		if sealsAfter[i] != sealsBefore[i] {
			t.Errorf("seal %d changed by compacting:\n before %+v\n after  %+v", i+1, sealsBefore[i], sealsAfter[i])
		}
	}

	// Every proof is identical, and verifies with no vault.
	for id, before := range proofsBefore {
		after, err := c.Proof(ctx, id)
		if err != nil {
			t.Fatalf("proof %d after compaction: %v", id, err)
		}
		if after.Root != before.Root || after.Chain != before.Chain || after.LeafHash != before.LeafHash ||
			after.LeafIndex != before.LeafIndex || len(after.Path) != len(before.Path) {
			t.Fatalf("proof %d changed by compacting", id)
		}
		if !merkle.VerifyInclusion(after.LeafHash, after.LeafIndex, after.TreeSize, after.Path, after.Root) {
			t.Fatalf("proof %d does not verify after compaction", id)
		}
	}

	rep, err := c.VerifyChain(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain broken by compaction at segment %d: %s", rep.FirstBad, rep.Reason)
	}
	// Close sealed the final partial segment, so the chain covers everything.
	if rep.Records != uint64(n) {
		t.Errorf("chain covers %d records, want %d", rep.Records, n)
	}

	// Scan from every boundary, including mid-block.
	for _, from := range []types.RecordID{1, 2, sealEvery, sealEvery + 1, n / 2, n} {
		var ids []types.RecordID
		if err := c.Scan(ctx, from, func(_ types.RawRecord, rc types.Receipt) error {
			ids = append(ids, rc.ID)
			return nil
		}); err != nil {
			t.Fatalf("scan from %d: %v", from, err)
		}
		if len(ids) != n-int(from)+1 {
			t.Errorf("scan from %d yielded %d records, want %d", from, len(ids), n-int(from)+1)
		}
	}

	// GetByHash resolves through the .hix for compacted segments.
	for i := 0; i < n; i += 7 {
		sum := sha256.Sum256(want[i].Raw)
		raw, err := c.GetByHash(ctx, sum)
		if err != nil {
			t.Fatalf("GetByHash for record %d: %v", i+1, err)
		}
		if !bytes.Equal(raw, want[i].Raw) {
			t.Errorf("GetByHash for record %d returned different bytes", i+1)
		}
	}
}

// TestCompactionConformance runs the whole shared suite against a vault that
// is compacting underneath it, so the two implementations are still held to one
// definition of correct. Records are read while segments are in every state:
// still WAL, mid-compaction, and compacted.
func TestCompactionConformance(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 8,
		New: func(t *testing.T) types.Vault {
			v, err := vault.Open(copts(t.TempDir(), 8))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			return v
		},
	})
}

// TestCompactionShrinksRepetitiveData: the point of the feature.
//
// It uses the default 256 KiB block. With the tiny blocks the other tests use
// to force many block boundaries, zstd has almost nothing to work with and the
// 40-byte-per-record .hix dominates, so the vault comes out larger — which is
// worth knowing, and is why block size is configurable and defaults large.
func TestCompactionShrinksRepetitiveData(t *testing.T) {
	const n, sealEvery = 2000, 500
	dir := t.TempDir()

	v := open(t, dir, sealEvery)
	for i := 0; i < n; i++ {
		if _, err := v.Put(context.Background(), bigRec(1+i*11)); err != nil { // the plain ASA lines
			t.Fatal(err)
		}
	}
	v.Close()
	before := dirBytes(t, dir)

	o := opts(dir, sealEvery)
	o.Compact = true // default block size
	c, err := vault.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitCompacted(t, dir, n/sealEvery)

	after := dirBytes(t, dir)
	hix := dirBytesExt(t, dir, ".hix")
	data := after - hix

	// Reported both ways because they are different claims, and the gap
	// between them is a real finding: the hash index is 40 bytes per record of
	// incompressible SHA-256, which on records that compress this well costs
	// MORE than the compressed record it indexes. Here the data compresses
	// ~6x and the index is over half the resulting directory.
	t.Logf("%d ASA-shaped records, default 256 KiB blocks, zstd level %d:", n, vault.DefaultZstdLevel)
	t.Logf("  data only          %7d -> %7d bytes  (%.1fx)", before, data, float64(before)/float64(data))
	t.Logf("  with the .hix      %7d -> %7d bytes  (%.1fx); the .hix is %d bytes, %.0f%% of the result",
		before, after, float64(before)/float64(after), hix, 100*float64(hix)/float64(after))

	if data*3 > before {
		t.Errorf("compression saved less than 3x on repetitive data: %d -> %d bytes", before, data)
	}
}

func dirBytesExt(t *testing.T, dir, ext string) int64 {
	t.Helper()
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	return total
}

func dirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "LOCK" || e.Name() == "chain.log" {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	return total
}

// TestCompactedVaultReopens covers both open modes. A compacted segment has to
// verify as thoroughly as a WAL does on the way in - "it opened" must mean the
// same thing for both.
func TestCompactedVaultReopens(t *testing.T) {
	const n, sealEvery = 90, 15
	dir := t.TempDir()
	ctx := context.Background()

	v, err := vault.Open(copts(dir, sealEvery))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := v.Put(ctx, bigRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitCompacted(t, dir, n/sealEvery-1) // the last segment may still be compacting
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []struct {
		name string
		o    vault.Options
	}{
		{"writer", copts(dir, sealEvery)},
		{"read-only", vault.Options{Dir: dir, ReadOnly: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			r, err := vault.Open(mode.o)
			if err != nil {
				t.Fatalf("a compacted vault would not reopen: %v", err)
			}
			defer r.Close()

			for i := 0; i < n; i++ {
				got, _, err := r.Get(ctx, types.RecordID(i+1))
				if err != nil {
					t.Fatalf("record %d: %v", i+1, err)
				}
				if !bytes.Equal(got.Raw, bigRec(i).Raw) {
					t.Fatalf("record %d came back changed", i+1)
				}
			}
			rep, err := r.VerifyChain(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK {
				t.Fatalf("chain failed after reopen: %s", rep.Reason)
			}
		})
	}
}

// TestCompactionWhileWriting: the compactor runs on its own goroutine against
// segments the writer has just sealed, while readers are active. Run under
// -race this is the check that the segment switch-over is properly locked.
func TestCompactionWhileWriting(t *testing.T) {
	const n, sealEvery = 300, 10
	dir := t.TempDir()
	ctx := context.Background()

	v, err := vault.Open(copts(dir, sealEvery))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	done := make(chan struct{})
	readerErr := make(chan error, 1)
	go func() {
		defer close(readerErr)
		for {
			select {
			case <-done:
				return
			default:
			}
			// Hammer reads of everything written so far while segments are
			// switching from WAL to compacted underneath.
			var last types.RecordID
			if err := v.Scan(ctx, 1, func(r types.RawRecord, rc types.Receipt) error {
				last = rc.ID
				if sum := sha256.Sum256(r.Raw); sum != rc.RawSHA256 {
					return fmt.Errorf("record %d does not match its receipt", rc.ID)
				}
				return nil
			}); err != nil {
				readerErr <- err
				return
			}
			_ = last
		}
	}()

	for i := 0; i < n; i++ {
		if _, err := v.Put(ctx, bigRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	if err := <-readerErr; err != nil {
		t.Fatalf("a concurrent reader failed while compaction ran: %v", err)
	}

	waitCompacted(t, dir, n/sealEvery)
	rep, err := v.VerifyChain(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain broken: %s", rep.Reason)
	}
}

// TestHashIndexCanBeDisabled: a deployment that never looks records up by
// payload hash can decline to pay the memory for it.
func TestHashIndexCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	o := copts(dir, 5)
	o.DisableHashIndex = true

	v, err := vault.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for i := 0; i < 20; i++ {
		if _, err := v.Put(context.Background(), bigRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitCompacted(t, dir, 3)

	sum := sha256.Sum256(bigRec(0).Raw)
	if _, err := v.GetByHash(context.Background(), sum); err != vault.ErrHashIndexDisabled {
		t.Errorf("got %v, want ErrHashIndexDisabled", err)
	}
	if n := countExt(t, dir, ".hix"); n != 0 {
		t.Errorf("%d .hix files were written with the hash index disabled", n)
	}

	// Everything else still works.
	if _, _, err := v.Get(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
}

func TestCompactionOptionsValidated(t *testing.T) {
	o := copts(t.TempDir(), 5)
	o.CompactBlockBytes = vault.MaxCompactBlockBytes + 1
	if v, err := vault.Open(o); err == nil {
		v.Close()
		t.Error("an oversize CompactBlockBytes was accepted")
	}
	o = copts(t.TempDir(), 5)
	o.ZstdLevel = 99
	if v, err := vault.Open(o); err == nil {
		v.Close()
		t.Error("an out-of-range ZstdLevel was accepted")
	}
}

var _ = filepath.Join
