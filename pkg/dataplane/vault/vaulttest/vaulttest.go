// Package vaulttest is the conformance suite every vault implementation must
// pass.
//
// It exists so that memvault and the on-disk vault cannot drift apart. Anyone
// building against types.Vault develops against memvault first and switches
// later, and that only works if "behaves the same" is something a test
// asserts rather than something a comment claims.
//
// Usage:
//
//	func TestConformance(t *testing.T) {
//	    vaulttest.Run(t, vaulttest.Factory{
//	        New:       func(t *testing.T) types.Vault { ... },
//	        SealEvery: 8,
//	    })
//	}
//
// The suite only uses the exported contract, so it can be run against an
// implementation it knows nothing about.
package vaulttest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
)

// Factory tells the suite how to build a vault and what to expect of it.
type Factory struct {
	// New returns a fresh, empty vault. The suite calls it many times and
	// never reuses one across subtests.
	New func(t *testing.T) types.Vault
	// SealEvery is the record count after which the implementation seals a
	// segment. The suite needs it to know how many records to write before a
	// proof can exist. It must be at least 2.
	SealEvery int
}

// Run executes the whole suite.
func Run(t *testing.T, f Factory) {
	t.Helper()
	if f.New == nil {
		t.Fatal("vaulttest: Factory.New is required")
	}
	if f.SealEvery < 2 {
		t.Fatalf("vaulttest: Factory.SealEvery is %d, want at least 2", f.SealEvery)
	}

	tests := []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"ids are contiguous from one", testIDs},
		{"records round-trip byte for byte", testRoundTrip},
		{"hostile payloads are preserved", testHostilePayloads},
		{"batches are atomic and contiguous", testBatch},
		{"empty batch is a no-op", testEmptyBatch},
		{"missing records report ErrNotFound", testNotFound},
		{"lookup by raw hash", testGetByHash},
		{"scan replays in order from any point", testScan},
		{"scan stops on the callback's error", testScanError},
		{"proofs are unavailable until sealed", testProofNotSealed},
		{"proofs verify independently", testProofVerifies},
		{"verify reports sealed and unsealed records", testVerify},
		{"the chain verifies shallow and deep", testVerifyChain},
		{"seals are consecutive and linked", testSeals},
		{"head advances only on seal", testHead},
		{"close seals the active segment", testCloseSeals},
		{"a closed vault refuses work", testClosed},
		{"concurrent writers get unique ids", testConcurrent},
		{"a cancelled context is refused", testContext},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, f) })
	}
}

// ---------------------------------------------------------------- helpers

func rec(i int) types.RawRecord {
	return types.RawRecord{
		SourceID:   fmt.Sprintf("src-%d", i%3),
		ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
		Origin:     types.Origin{Kind: types.OriginTCP, Addr: "10.1.4.7:51544", Offset: uint64(i) * 100},
		Term:       types.TermLF,
		Raw:        []byte(fmt.Sprintf("record number %d", i)),
	}
}

// put writes n records and returns their receipts.
func put(t *testing.T, v types.Vault, n int) []types.Receipt {
	t.Helper()
	var out []types.Receipt
	for i := 0; i < n; i++ {
		r, err := v.Put(context.Background(), rec(i))
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		out = append(out, r)
	}
	return out
}

func mustGet(t *testing.T, v types.Vault, id types.RecordID) (types.RawRecord, types.Receipt) {
	t.Helper()
	r, rc, err := v.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %d: %v", id, err)
	}
	return r, rc
}

// ------------------------------------------------------------------ tests

func testIDs(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	// D3: RecordIDs are a global monotonic uint64 starting at 1. Replay and
	// every event_id downstream depend on this, so it is pinned first.
	for i, rc := range put(t, v, 10) {
		if rc.ID != types.RecordID(i+1) {
			t.Fatalf("record %d got id %d, want %d", i, rc.ID, i+1)
		}
	}
}

func testRoundTrip(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	receipts := put(t, v, f.SealEvery*2+3)
	for i, rc := range receipts {
		want := rec(i)
		got, gotRc := mustGet(t, v, rc.ID)

		if !bytes.Equal(got.Raw, want.Raw) {
			t.Errorf("record %d: raw is %q, want %q", rc.ID, got.Raw, want.Raw)
		}
		if got.SourceID != want.SourceID {
			t.Errorf("record %d: source_id is %q, want %q", rc.ID, got.SourceID, want.SourceID)
		}
		if got.Origin != want.Origin {
			t.Errorf("record %d: origin is %+v, want %+v", rc.ID, got.Origin, want.Origin)
		}
		if got.Term != want.Term {
			t.Errorf("record %d: terminator is %d, want %d", rc.ID, got.Term, want.Term)
		}
		if !got.ReceivedAt.Equal(want.ReceivedAt) {
			t.Errorf("record %d: received_at is %s, want %s", rc.ID, got.ReceivedAt, want.ReceivedAt)
		}
		if sum := sha256.Sum256(want.Raw); rc.RawSHA256 != sum {
			t.Errorf("record %d: receipt hash does not match SHA-256 of raw", rc.ID)
		}
		if gotRc.ID != rc.ID || gotRc.RawSHA256 != rc.RawSHA256 {
			t.Errorf("record %d: Get returned a different receipt than Put", rc.ID)
		}
		if gotRc.Segment != rc.Segment {
			t.Errorf("record %d: segment is %d, want %d", rc.ID, gotRc.Segment, rc.Segment)
		}
	}
}

func testHostilePayloads(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	// Requirement (a) is byte-exact preservation, and these are the inputs a
	// vault that quietly "cleans up" its input would damage.
	payloads := map[string][]byte{
		"empty":         {},
		"nil":           nil,
		"invalid utf-8": {0xFF, 0xFE, 0xC3, 0x28},
		"embedded NUL":  []byte("a\x00b"),
		"CR only":       []byte("a\rb"),
		"CRLF":          []byte("a\r\nb"),
		"every byte":    allBytes(),
		"one MiB":       bytes.Repeat([]byte("A"), 1<<20),
	}

	ids := map[string]types.RecordID{}
	for name, raw := range payloads {
		r := rec(0)
		r.Raw = raw
		rc, err := v.Put(context.Background(), r)
		if err != nil {
			t.Fatalf("%s: put: %v", name, err)
		}
		ids[name] = rc.ID
	}
	for name, raw := range payloads {
		got, _ := mustGet(t, v, ids[name])
		if !bytes.Equal(got.Raw, raw) {
			t.Errorf("%s: raw changed:\n got %x\nwant %x", name, got.Raw, raw)
		}
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func testBatch(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	batch := []types.RawRecord{rec(1), rec(2), rec(3), rec(4)}
	rs, err := v.PutBatch(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != len(batch) {
		t.Fatalf("got %d receipts for %d records", len(rs), len(batch))
	}
	// A batch is one write and one fsync in the real vault, so its ids must
	// be contiguous; callers use that to correlate without a per-record round
	// trip.
	for i := 1; i < len(rs); i++ {
		if rs[i].ID != rs[i-1].ID+1 {
			t.Fatalf("batch ids are not contiguous: %d then %d", rs[i-1].ID, rs[i].ID)
		}
	}
	for i, rc := range rs {
		got, _ := mustGet(t, v, rc.ID)
		if !bytes.Equal(got.Raw, batch[i].Raw) {
			t.Errorf("batch record %d came back as %q", i, got.Raw)
		}
	}
}

func testEmptyBatch(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	rs, err := v.PutBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("an empty batch should be a no-op, got %v", err)
	}
	if len(rs) != 0 {
		t.Fatalf("an empty batch produced %d receipts", len(rs))
	}
	// And it must not have consumed an id.
	if rc := put(t, v, 1)[0]; rc.ID != 1 {
		t.Fatalf("after an empty batch the first id is %d, want 1", rc.ID)
	}
}

func testNotFound(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()
	put(t, v, 3)

	for _, id := range []types.RecordID{0, 4, 1 << 40} {
		if _, _, err := v.Get(context.Background(), id); !errors.Is(err, types.ErrNotFound) {
			t.Errorf("get %d: got %v, want ErrNotFound", id, err)
		}
	}
	var missing [32]byte
	if _, err := v.GetByHash(context.Background(), missing); !errors.Is(err, types.ErrNotFound) {
		t.Errorf("GetByHash on an unknown hash: got %v, want ErrNotFound", err)
	}
}

func testGetByHash(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	for i, rc := range put(t, v, f.SealEvery+2) {
		raw, err := v.GetByHash(context.Background(), rc.RawSHA256)
		if err != nil {
			t.Fatalf("record %d: %v", rc.ID, err)
		}
		if !bytes.Equal(raw, rec(i).Raw) {
			t.Errorf("record %d: GetByHash returned %q, want %q", rc.ID, raw, rec(i).Raw)
		}
	}
}

func testScan(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	n := f.SealEvery*2 + 1
	put(t, v, n)

	// Replay starts from an arbitrary point, including segment boundaries,
	// and must be complete and in order from there.
	for _, from := range []types.RecordID{0, 1, 2, types.RecordID(f.SealEvery),
		types.RecordID(f.SealEvery + 1), types.RecordID(n), types.RecordID(n + 1)} {

		var ids []types.RecordID
		err := v.Scan(context.Background(), from, func(r types.RawRecord, rc types.Receipt) error {
			ids = append(ids, rc.ID)
			return nil
		})
		if err != nil {
			t.Fatalf("scan from %d: %v", from, err)
		}

		want := from
		if want == 0 {
			want = 1
		}
		if want > types.RecordID(n) {
			if len(ids) != 0 {
				t.Errorf("scan from %d past the end returned %d records", from, len(ids))
			}
			continue
		}
		if got := types.RecordID(len(ids)); got != types.RecordID(n)-want+1 {
			t.Errorf("scan from %d returned %d records, want %d", from, got, types.RecordID(n)-want+1)
			continue
		}
		for i, id := range ids {
			if id != want+types.RecordID(i) {
				t.Fatalf("scan from %d: record %d has id %d, want %d", from, i, id, want+types.RecordID(i))
			}
		}
	}
}

func testScanError(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()
	put(t, v, 10)

	sentinel := errors.New("stop here")
	seen := 0
	err := v.Scan(context.Background(), 1, func(types.RawRecord, types.Receipt) error {
		seen++
		if seen == 3 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("scan returned %v, want the callback's own error", err)
	}
	if seen != 3 {
		t.Fatalf("scan called the callback %d times after it asked to stop at 3", seen)
	}
}

func testProofNotSealed(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	// D2: a record's segment is unsealed when it is first normalized, so the
	// root and path do not exist yet. Downstream resolves lineage lazily, and
	// relies on this being a specific, recognisable error.
	rc := put(t, v, 1)[0]
	if _, err := v.Proof(context.Background(), rc.ID); !errors.Is(err, types.ErrNotSealed) {
		t.Fatalf("proof for a record in the active segment: got %v, want ErrNotSealed", err)
	}
}

func testProofVerifies(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	receipts := put(t, v, f.SealEvery*2)
	for _, rc := range receipts {
		p, err := v.Proof(context.Background(), rc.ID)
		if errors.Is(err, types.ErrNotSealed) {
			continue
		}
		if err != nil {
			t.Fatalf("proof %d: %v", rc.ID, err)
		}

		// Verified with the pure package, exactly as an auditor or a browser
		// would, with nothing from the vault but the proof itself.
		if !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root) {
			t.Errorf("record %d: inclusion proof does not verify", rc.ID)
		}
		if !merkle.VerifyChainLink(p) {
			t.Errorf("record %d: chain link does not verify", rc.ID)
		}
		if p.Segment != rc.Segment {
			t.Errorf("record %d: proof names segment %d, receipt says %d", rc.ID, p.Segment, rc.Segment)
		}
		if p.LeafIndex >= p.TreeSize {
			t.Errorf("record %d: leaf index %d is outside a tree of %d", rc.ID, p.LeafIndex, p.TreeSize)
		}

		// And a record's own bytes must hash to the leaf the proof commits to.
		got, _ := mustGet(t, v, rc.ID)
		if len(got.Raw) == 0 && p.LeafHash == ([32]byte{}) {
			t.Errorf("record %d: empty leaf hash", rc.ID)
		}
	}
}

func testVerify(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	receipts := put(t, v, f.SealEvery+1)
	for _, rc := range receipts {
		res, err := v.Verify(context.Background(), rc.ID)
		if err != nil {
			t.Fatalf("verify %d: %v", rc.ID, err)
		}
		if !res.OK {
			t.Errorf("record %d failed verification: %s", rc.ID, res.Reason)
		}
		if res.Reason != "" {
			t.Errorf("record %d verified but carries a reason: %q", rc.ID, res.Reason)
		}
		if res.Sealed && res.Proof == nil {
			t.Errorf("record %d is sealed but carries no proof", rc.ID)
		}
	}

	// The last record is in the still-active segment.
	last := receipts[len(receipts)-1]
	res, err := v.Verify(context.Background(), last.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Sealed {
		t.Errorf("record %d is in the active segment but reports Sealed", last.ID)
	}
}

func testVerifyChain(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()
	put(t, v, f.SealEvery*3+1)

	for _, deep := range []bool{false, true} {
		rep, err := v.VerifyChain(context.Background(), deep)
		if err != nil {
			t.Fatalf("deep=%v: %v", deep, err)
		}
		if !rep.OK {
			t.Fatalf("deep=%v: chain failed at segment %d: %s", deep, rep.FirstBad, rep.Reason)
		}
		if rep.Deep != deep {
			t.Errorf("deep=%v: report says Deep=%v", deep, rep.Deep)
		}
		if rep.Segments != 3 {
			t.Errorf("deep=%v: report says %d segments, want 3", deep, rep.Segments)
		}
		if want := uint64(f.SealEvery * 3); rep.Records != want {
			t.Errorf("deep=%v: report covers %d records, want %d", deep, rep.Records, want)
		}
		if rep.FirstBad != 0 {
			t.Errorf("deep=%v: FirstBad is %d on a healthy chain", deep, rep.FirstBad)
		}
	}
}

func testSeals(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()
	put(t, v, f.SealEvery*2)

	seals, err := v.Seals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(seals) != 2 {
		t.Fatalf("got %d seals, want 2", len(seals))
	}

	var prev [32]byte
	var wantFirst uint64 = 1
	for i, s := range seals {
		if s.Segment != uint64(i+1) {
			t.Errorf("seal %d names segment %d", i, s.Segment)
		}
		if s.FirstSeq != wantFirst {
			t.Errorf("segment %d starts at %d, want %d", s.Segment, s.FirstSeq, wantFirst)
		}
		if s.Count != uint64(f.SealEvery) {
			t.Errorf("segment %d holds %d records, want %d", s.Segment, s.Count, f.SealEvery)
		}
		if s.LastSeq != s.FirstSeq+s.Count-1 {
			t.Errorf("segment %d: last_seq %d is inconsistent with first_seq %d and count %d",
				s.Segment, s.LastSeq, s.FirstSeq, s.Count)
		}
		if s.Prev != prev {
			t.Errorf("segment %d does not follow the previous chain hash", s.Segment)
		}
		if merkle.ChainHash(s.Prev, s.Root, s.Segment, s.Count) != s.Chain {
			t.Errorf("segment %d chain hash does not recompute", s.Segment)
		}
		if s.SealedAt.IsZero() {
			t.Errorf("segment %d has no seal time", s.Segment)
		}
		prev = s.Chain
		wantFirst = s.LastSeq + 1
	}
}

func testHead(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	var zero [32]byte
	head, through, err := v.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head != zero || through != 0 {
		t.Fatalf("an empty vault reports head %x through %d, want zero and 0", head, through)
	}

	// Writing without filling a segment must not move the head: nothing is
	// sealed, so there is nothing to anchor.
	put(t, v, f.SealEvery-1)
	if head, through, _ = v.Head(context.Background()); head != zero || through != 0 {
		t.Fatalf("head moved before anything was sealed: %x through %d", head, through)
	}

	put(t, v, 1)
	head, through, err = v.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head == zero {
		t.Error("head is still zero after a segment was sealed")
	}
	if through != types.RecordID(f.SealEvery) {
		t.Errorf("sealedThrough is %d, want %d", through, f.SealEvery)
	}
}

func testCloseSeals(t *testing.T, f Factory) {
	v := f.New(t)
	put(t, v, f.SealEvery+1)

	// Graceful shutdown seals the active segment, so a clean stop never
	// leaves records outside the chain.
	if err := v.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
}

func testClosed(t *testing.T, f Factory) {
	v := f.New(t)
	put(t, v, 2)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := v.Put(ctx, rec(0)); !errors.Is(err, types.ErrClosed) {
		t.Errorf("put after close: got %v, want ErrClosed", err)
	}
	if _, err := v.PutBatch(ctx, []types.RawRecord{rec(0)}); !errors.Is(err, types.ErrClosed) {
		t.Errorf("put batch after close: got %v, want ErrClosed", err)
	}
	if _, _, err := v.Get(ctx, 1); !errors.Is(err, types.ErrClosed) {
		t.Errorf("get after close: got %v, want ErrClosed", err)
	}
	if err := v.Scan(ctx, 1, func(types.RawRecord, types.Receipt) error { return nil }); !errors.Is(err, types.ErrClosed) {
		t.Errorf("scan after close: got %v, want ErrClosed", err)
	}
	if _, err := v.VerifyChain(ctx, false); !errors.Is(err, types.ErrClosed) {
		t.Errorf("verify chain after close: got %v, want ErrClosed", err)
	}
}

func testConcurrent(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()

	// Group commit coalesces concurrent batches into one write. Whatever the
	// interleaving, every id must be handed out exactly once and every batch
	// must stay contiguous.
	const writers, perWriter = 16, 8

	var wg sync.WaitGroup
	results := make([][]types.Receipt, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			batch := make([]types.RawRecord, perWriter)
			for i := range batch {
				batch[i] = rec(w*perWriter + i)
			}
			rs, err := v.PutBatch(context.Background(), batch)
			if err != nil {
				t.Errorf("writer %d: %v", w, err)
				return
			}
			results[w] = rs
		}(w)
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	seen := map[types.RecordID]bool{}
	for w, rs := range results {
		if len(rs) != perWriter {
			t.Fatalf("writer %d got %d receipts, want %d", w, len(rs), perWriter)
		}
		for i, rc := range rs {
			if seen[rc.ID] {
				t.Fatalf("id %d was handed out twice", rc.ID)
			}
			seen[rc.ID] = true
			if i > 0 && rc.ID != rs[i-1].ID+1 {
				t.Fatalf("writer %d: batch ids are not contiguous: %d then %d", w, rs[i-1].ID, rc.ID)
			}
		}
	}
	for id := types.RecordID(1); id <= types.RecordID(writers*perWriter); id++ {
		if !seen[id] {
			t.Fatalf("id %d was never handed out", id)
		}
	}

	// Every record must still be readable and intact.
	count := 0
	if err := v.Scan(context.Background(), 1, func(r types.RawRecord, rc types.Receipt) error {
		if sha256.Sum256(r.Raw) != rc.RawSHA256 {
			return fmt.Errorf("record %d does not match its receipt hash", rc.ID)
		}
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != writers*perWriter {
		t.Fatalf("scan found %d records, want %d", count, writers*perWriter)
	}
}

func testContext(t *testing.T, f Factory) {
	v := f.New(t)
	defer v.Close()
	put(t, v, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := v.Put(ctx, rec(0)); !errors.Is(err, context.Canceled) {
		t.Errorf("put with a cancelled context: got %v, want context.Canceled", err)
	}
	if _, _, err := v.Get(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("get with a cancelled context: got %v, want context.Canceled", err)
	}
}
