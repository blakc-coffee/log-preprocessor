package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
)

// fnSource turns a function into a Source, so a test can drive the pipeline
// without a socket or a file.
type fnSource struct {
	id  string
	run func(ctx context.Context, sink ingest.Sink) error
}

func (f fnSource) ID() string { return f.id }
func (f fnSource) Run(ctx context.Context, sink ingest.Sink) error {
	return f.run(ctx, sink)
}

func rec(i int) types.RawRecord {
	return types.RawRecord{
		SourceID:   "test",
		ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
		Origin:     types.Origin{Kind: types.OriginTCP, Addr: "10.1.4.7:5140", Offset: uint64(i)},
		Term:       types.TermLF,
		Raw:        []byte(fmt.Sprintf("record %d", i)),
	}
}

// newPipeline wires a pipeline to an in-memory vault.
func newPipeline(t *testing.T, cfg ingest.Config, outCap int) (*ingest.Pipeline, chan types.RawEvent, *memvault.Vault) {
	t.Helper()
	v := memvault.New(memvault.Options{SealEvery: 1000})
	out := make(chan types.RawEvent, outCap)
	p, err := ingest.New(cfg, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, out, v
}

// TestSubmitIsDurableBeforeItIsVisible restates the package's one rule in the
// smallest possible test: an event on the channel is always already in the
// vault.
func TestSubmitIsDurableBeforeItIsVisible(t *testing.T) {
	p, out, v := newPipeline(t, ingest.Config{}, 64)
	defer v.Close()

	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		for i := 0; i < 10; i++ {
			if err := st.Submit(ctx, rec(i)); err != nil {
				return err
			}
		}
		return st.Flush(ctx)
	}})

	var got []types.RawEvent
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range out {
			// Reading it back proves durability rather than trusting the
			// receipt that came with it.
			if _, _, err := v.Get(context.Background(), ev.ID); err != nil {
				t.Errorf("record %d was forwarded but is not in the vault: %v", ev.ID, err)
			}
			got = append(got, ev)
		}
	}()

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if len(got) != 10 {
		t.Fatalf("%d events, want 10", len(got))
	}
	for i, ev := range got {
		if ev.ID != types.RecordID(i+1) {
			t.Errorf("event %d has id %d", i, ev.ID)
		}
		if string(ev.Raw) != fmt.Sprintf("record %d", i) {
			t.Errorf("event %d is %q", i, ev.Raw)
		}
		if ev.Hint != types.HintUnknown {
			t.Errorf("event %d carries hint %q; sniffing is M4, so it must be unknown", i, ev.Hint)
		}
	}
}

// TestBatchTimerFlushesAQuietStream. Without a timer, a device sending one
// message a minute would have each one sit in memory, undurable, until the
// next arrived — which is precisely the data a crash would then lose.
func TestBatchTimerFlushesAQuietStream(t *testing.T) {
	p, out, v := newPipeline(t, ingest.Config{
		BatchRecords: 1000, // far more than we submit, so only the timer can flush
		BatchDelay:   5 * time.Millisecond,
	}, 8)
	defer v.Close()

	flushed := make(chan struct{})
	p.AddSource(fnSource{id: "quiet", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("quiet")
		defer st.Close()
		if err := st.Submit(ctx, rec(0)); err != nil {
			return err
		}
		// Do not flush, do not close: wait for the timer to do it.
		select {
		case <-flushed:
		case <-ctx.Done():
		}
		return nil
	}})

	go func() {
		<-out // the timer's flush makes this arrive
		close(flushed)
	}()

	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the batch timer never flushed a stream that went quiet")
	}
	for range out {
	}
}

// TestBackpressure proves a slow consumer stalls the source rather than
// growing a queue. Requirement: every queue is bounded and overload
// back-pressures, never drops.
func TestBackpressure(t *testing.T) {
	const cap, total = 4, 200

	p, out, v := newPipeline(t, ingest.Config{OutBuffer: cap, BatchRecords: 1}, cap)
	defer v.Close()

	var submitted atomic.Int64
	p.AddSource(fnSource{id: "fast", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("fast")
		defer st.Close()
		for i := 0; i < total; i++ {
			if err := st.Submit(ctx, rec(i)); err != nil {
				return err
			}
			submitted.Add(1)
		}
		return nil
	}})

	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()

	// While nothing is draining, the source must stall within a bounded
	// distance of the channel capacity rather than racing ahead.
	time.Sleep(50 * time.Millisecond)
	if n := submitted.Load(); n > cap+8 {
		t.Errorf("the source submitted %d records into a channel of %d with no consumer; "+
			"backpressure is not reaching it", n, cap)
	}

	received := 0
	for range out {
		received++
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if received != total {
		t.Errorf("received %d records, want %d — backpressure must delay, never drop", received, total)
	}
}

// TestShutdownLosesNothingAccepted: on cancellation, every record a Submit
// returned success for must be in the vault. Accepting a record and then
// dropping it during shutdown is indistinguishable from data loss.
func TestShutdownLosesNothingAccepted(t *testing.T) {
	p, out, v := newPipeline(t, ingest.Config{OutBuffer: 64, BatchRecords: 16}, 64)
	defer v.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var accepted atomic.Int64

	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		for i := 0; ; i++ {
			if err := st.Submit(ctx, rec(i)); err != nil {
				return nil // cancelled: stop accepting
			}
			accepted.Add(1)
			if i == 50 {
				cancel()
			}
		}
	}})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range out {
		}
	}()
	if err := p.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wg.Wait()

	// Everything Submit said yes to has to be readable.
	n := accepted.Load()
	if n == 0 {
		t.Fatal("nothing was accepted")
	}
	stored := 0
	if err := v.Scan(context.Background(), 1, func(types.RawRecord, types.Receipt) error {
		stored++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if int64(stored) < n {
		t.Errorf("Submit accepted %d records but only %d are in the vault", n, stored)
	}
}

// TestVaultFailurePropagates: once the vault is failed the source must be told,
// not left writing into a void. A source that kept accepting would be
// acknowledging records to a device that are going nowhere.
func TestVaultFailurePropagates(t *testing.T) {
	out := make(chan types.RawEvent, 16)
	p, err := ingest.New(ingest.Config{BatchRecords: 1}, failingVault{}, out, nil)
	if err != nil {
		t.Fatal(err)
	}

	var submitErr error
	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		submitErr = st.Submit(ctx, rec(0))
		return nil
	}})

	go func() {
		for range out {
		}
	}()
	// Run reports the failure too; the point is that Submit did not succeed.
	_ = p.Run(context.Background())

	if submitErr == nil {
		t.Fatal("Submit succeeded against a failed vault")
	}
	if !errors.Is(submitErr, types.ErrFailed) {
		t.Errorf("got %v, want ErrFailed", submitErr)
	}
}

// failingVault is a vault that refuses every write.
type failingVault struct{}

func (failingVault) Put(context.Context, types.RawRecord) (types.Receipt, error) {
	return types.Receipt{}, types.ErrFailed
}
func (failingVault) PutBatch(context.Context, []types.RawRecord) ([]types.Receipt, error) {
	return nil, types.ErrFailed
}
func (failingVault) Get(context.Context, types.RecordID) (types.RawRecord, types.Receipt, error) {
	return types.RawRecord{}, types.Receipt{}, types.ErrFailed
}
func (failingVault) GetByHash(context.Context, [32]byte) ([]byte, error) { return nil, types.ErrFailed }
func (failingVault) Scan(context.Context, types.RecordID, func(types.RawRecord, types.Receipt) error) error {
	return types.ErrFailed
}
func (failingVault) Proof(context.Context, types.RecordID) (types.InclusionProof, error) {
	return types.InclusionProof{}, types.ErrFailed
}
func (failingVault) Verify(context.Context, types.RecordID) (types.VerifyResult, error) {
	return types.VerifyResult{}, types.ErrFailed
}
func (failingVault) VerifyChain(context.Context, bool) (types.ChainReport, error) {
	return types.ChainReport{}, types.ErrFailed
}
func (failingVault) Seals(context.Context) ([]types.SegmentSeal, error) { return nil, types.ErrFailed }
func (failingVault) Head(context.Context) ([32]byte, types.RecordID, error) {
	return [32]byte{}, 0, types.ErrFailed
}
func (failingVault) Close() error { return nil }

// TestConcurrentStreamsKeepTheirOrder: records interleave across streams but
// never within one. A file's lines arriving out of order would make
// Origin.Offset useless as a de-duplication key.
func TestConcurrentStreamsKeepTheirOrder(t *testing.T) {
	const streams, per = 8, 50

	p, out, v := newPipeline(t, ingest.Config{OutBuffer: 128, BatchRecords: 8}, 128)
	defer v.Close()

	for s := 0; s < streams; s++ {
		id := fmt.Sprintf("src-%d", s)
		p.AddSource(fnSource{id: id, run: func(ctx context.Context, sink ingest.Sink) error {
			st := sink.NewStream(id)
			defer st.Close()
			for i := 0; i < per; i++ {
				r := rec(i)
				r.SourceID = id
				r.Origin.Offset = uint64(i)
				if err := st.Submit(ctx, r); err != nil {
					return err
				}
			}
			return nil
		}})
	}

	seen := map[string][]uint64{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range out {
			seen[ev.SourceID] = append(seen[ev.SourceID], ev.Origin.Offset)
		}
	}()
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if len(seen) != streams {
		t.Fatalf("saw %d sources, want %d", len(seen), streams)
	}
	for id, offsets := range seen {
		if len(offsets) != per {
			t.Errorf("%s: %d records, want %d", id, len(offsets), per)
			continue
		}
		for i, off := range offsets {
			if off != uint64(i) {
				t.Errorf("%s: record %d arrived out of order (offset %d)", id, i, off)
				break
			}
		}
	}
}

// TestOutputChannelIsClosed: downstream ranges over the channel, so a pipeline
// that returned without closing it would hang the data plane on shutdown.
func TestOutputChannelIsClosed(t *testing.T) {
	p, out, v := newPipeline(t, ingest.Config{}, 4)
	defer v.Close()
	p.AddSource(fnSource{id: "s", run: func(context.Context, ingest.Sink) error { return nil }})

	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-out; ok {
		t.Fatal("the output channel yielded a value")
	}
}

func TestNewValidates(t *testing.T) {
	out := make(chan types.RawEvent)
	if _, err := ingest.New(ingest.Config{}, nil, out, nil); err == nil {
		t.Error("a pipeline was built with no vault")
	}
	if _, err := ingest.New(ingest.Config{}, memvault.New(memvault.Options{}), nil, nil); err == nil {
		t.Error("a pipeline was built with no output channel")
	}
}

// TestFlushesDoNotInterleave is a regression test.
//
// The batch timer and a full-batch flush could both detach and write at once,
// so two batches from ONE stream reached the vault out of the order their
// records were appended. The visible damage was worse than reordering: an
// oversize record's fragment run was split across two out-of-order writes and
// reassembled into garbage, and the race detector separately caught the
// pipeline closing the output channel while a timer flush was still sending.
//
// The fix is that the batch is detached while holding the write lock, so
// detach order is write order. This drives a stream with a one-nanosecond
// batch delay — the timer is firing essentially continuously — while Submit
// also trips the size trigger, which is the exact interleaving that broke.
func TestFlushesDoNotInterleave(t *testing.T) {
	const total = 400

	p, out, v := newPipeline(t, ingest.Config{
		OutBuffer:    8,
		BatchRecords: 4,
		BatchDelay:   time.Nanosecond,
	}, 8)
	defer v.Close()

	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		for i := 0; i < total; i++ {
			r := rec(i)
			r.Origin.Offset = uint64(i)
			if err := st.Submit(ctx, r); err != nil {
				return err
			}
		}
		return nil
	}})

	var offsets []uint64
	var ids []types.RecordID
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range out {
			offsets = append(offsets, ev.Origin.Offset)
			ids = append(ids, ev.ID)
		}
	}()
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if len(offsets) != total {
		t.Fatalf("%d records, want %d", len(offsets), total)
	}
	for i := range offsets {
		if offsets[i] != uint64(i) {
			t.Fatalf("record %d arrived with offset %d: the stream reordered", i, offsets[i])
		}
		// RecordIDs are assigned by the vault in write order, so if they are
		// not ascending the batches themselves were written out of order.
		if ids[i] != types.RecordID(i+1) {
			t.Fatalf("record %d got id %d, want %d: batches were written out of order",
				i, ids[i], i+1)
		}
	}
}
