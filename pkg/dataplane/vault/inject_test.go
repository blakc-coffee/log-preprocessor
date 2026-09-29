package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Failure injection.
//
// The vault's I/O failure policy is the part of the design that is easiest to
// state and hardest to trust: any write or fsync error is terminal, and a
// failed fsync is NEVER retried, because afterwards the kernel may already have
// dropped the dirty pages and a retry that "succeeded" would be a lie about
// data that is gone.
//
// A crash test cannot check that. The process dying is not the disk erroring.
// These tests make a specific call fail — the Nth write, the Nth fsync, the
// ledger append — and assert what the vault does next.

var errInjected = errors.New("injected I/O failure")

// faultFile wraps a real file and fails calls on demand.
type faultFile struct {
	fileIO

	mu sync.Mutex
	// failWriteAt and failSyncAt are 1-based call numbers; 0 means never.
	failWriteAt, failSyncAt int
	writes, syncs           int
	// syncsAfterFailure counts fsyncs attempted once one has already failed.
	// It must stay zero: a failed fsync is never retried.
	syncsAfterFailure int
	failed            bool
}

func (f *faultFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	f.writes++
	fail := f.failWriteAt != 0 && f.writes == f.failWriteAt
	if fail {
		f.failed = true
	}
	f.mu.Unlock()
	if fail {
		return 0, errInjected
	}
	return f.fileIO.WriteAt(p, off)
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	fail := f.failWriteAt != 0 && f.writes == f.failWriteAt
	if fail {
		f.failed = true
	}
	f.mu.Unlock()
	if fail {
		return 0, errInjected
	}
	return f.fileIO.Write(p)
}

func (f *faultFile) Sync() error {
	f.mu.Lock()
	f.syncs++
	if f.failed {
		f.syncsAfterFailure++
	}
	fail := f.failSyncAt != 0 && f.syncs == f.failSyncAt
	if fail {
		f.failed = true
	}
	f.mu.Unlock()
	if fail {
		return errInjected
	}
	return f.fileIO.Sync()
}

func (f *faultFile) retried() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncsAfterFailure
}

// injector hands out faultFiles for the segment and ledger files, keyed by
// file name, so a test can say "fail the third fsync of segment 2".
type injector struct {
	mu    sync.Mutex
	files map[string]*faultFile
	plan  map[string]faultPlan
}

type faultPlan struct{ writeAt, syncAt int }

func newInjector() *injector {
	return &injector{files: map[string]*faultFile{}, plan: map[string]faultPlan{}}
}

// on schedules a failure for the named file (e.g. "seg-000000000001.wal" or
// "chain.log"). Calls are counted from the file's creation.
func (in *injector) on(name string, writeAt, syncAt int) {
	in.mu.Lock()
	in.plan[name] = faultPlan{writeAt: writeAt, syncAt: syncAt}
	in.mu.Unlock()
}

func (in *injector) file(name string) *faultFile {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.files[name]
}

func (in *injector) open(path string, flag int, perm os.FileMode) (fileIO, error) {
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	in.mu.Lock()
	defer in.mu.Unlock()
	p := in.plan[name]
	ff := &faultFile{fileIO: f, failWriteAt: p.writeAt, failSyncAt: p.syncAt}
	in.files[name] = ff
	return ff, nil
}

func injectedVault(t *testing.T, dir string, in *injector, sealEvery int) (*Vault, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	v, err := Open(Options{
		Dir: dir, Sync: SyncAlways, SegmentMaxRecords: sealEvery,
		SealInterval: time.Hour, Registerer: reg, openFile: in.open,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, reg
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name && f.GetType() == dto.MetricType_GAUGE {
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

func putRec(v *Vault, i int) (types.Receipt, error) {
	return v.Put(context.Background(), types.RawRecord{
		SourceID: "inject", ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
		Raw: []byte{byte(i), 'p', 'a', 'y', 'l', 'o', 'a', 'd', byte(i >> 8)},
	})
}

// afterFailure is everything that must be true once the vault has failed.
func afterFailure(t *testing.T, v *Vault, reg *prometheus.Registry, what string) {
	t.Helper()
	ctx := context.Background()

	// Every later call is refused, including reads: after a failed fsync the
	// in-memory state may be ahead of the disk, and serving from it would be
	// serving data that might not survive.
	if _, err := putRec(v, 999); !errors.Is(err, types.ErrFailed) {
		t.Errorf("%s: a put after the failure returned %v, want ErrFailed", what, err)
	}
	if _, _, err := v.Get(ctx, 1); !errors.Is(err, types.ErrFailed) {
		t.Errorf("%s: a get after the failure returned %v, want ErrFailed", what, err)
	}
	if _, err := v.VerifyChain(ctx, false); !errors.Is(err, types.ErrFailed) {
		t.Errorf("%s: VerifyChain after the failure returned %v, want ErrFailed", what, err)
	}
	if got := gaugeValue(t, reg, "vault_failed"); got != 1 {
		t.Errorf("%s: vault_failed is %v, want 1", what, got)
	}
}

// reopenAndCheck proves recovery: everything acknowledged before the failure is
// intact, the chain verifies, and the vault accepts writes again.
func reopenAndCheck(t *testing.T, dir string, acked []types.Receipt, what string) {
	t.Helper()
	v, err := Open(Options{Dir: dir, Sync: SyncAlways, SegmentMaxRecords: 100, SealInterval: time.Hour})
	if err != nil {
		t.Fatalf("%s: the vault would not reopen after the failure: %v", what, err)
	}
	defer v.Close()

	ctx := context.Background()
	for i, rc := range acked {
		got, _, err := v.Get(ctx, rc.ID)
		if err != nil {
			t.Fatalf("%s: acknowledged record %d is gone: %v", what, rc.ID, err)
		}
		want := []byte{byte(i), 'p', 'a', 'y', 'l', 'o', 'a', 'd', byte(i >> 8)}
		if !bytes.Equal(got.Raw, want) {
			t.Fatalf("%s: record %d came back changed", what, rc.ID)
		}
	}
	rep, err := v.VerifyChain(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("%s: the chain is broken after recovery at segment %d: %s", what, rep.FirstBad, rep.Reason)
	}
	rc, err := v.Put(ctx, types.RawRecord{Raw: []byte("writable again")})
	if err != nil {
		t.Fatalf("%s: the reopened vault refuses writes: %v", what, err)
	}
	if uint64(rc.ID) <= uint64(len(acked)) {
		t.Fatalf("%s: the first record after recovery reused id %d", what, rc.ID)
	}
}

// TestFsyncFailureIsTerminalAndNeverRetried is the policy in one test.
func TestFsyncFailureIsTerminalAndNeverRetried(t *testing.T) {
	dir := t.TempDir()
	in := newInjector()
	// Sync 1 is openSegment's header fsync; sync 2 and 3 are the first two
	// commits; sync 4 is the third commit, which fails.
	in.on(segmentName(1, "wal"), 0, 4)
	v, reg := injectedVault(t, dir, in, 100)

	var acked []types.Receipt
	for i := 0; i < 2; i++ {
		rc, err := putRec(v, i)
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		acked = append(acked, rc)
	}

	_, err := putRec(v, 2)
	if !errors.Is(err, types.ErrFailed) {
		t.Fatalf("the put whose fsync failed returned %v, want ErrFailed", err)
	}

	afterFailure(t, v, reg, "fsync failure")

	// The heart of it. A failed fsync must not be attempted again on that
	// file: the kernel may already have dropped the dirty pages, so a retry
	// that "succeeded" would be reporting durability for data that is gone.
	if n := in.file(segmentName(1, "wal")).retried(); n != 0 {
		t.Errorf("fsync was attempted %d more time(s) after it failed", n)
	}
	v.Close()

	// The record whose fsync failed was never acknowledged, so it may or may
	// not be there - but everything that WAS acknowledged has to be.
	reopenAndCheck(t, dir, acked, "fsync failure")
}

// TestWriteFailureIsTerminal: the same, for a failed write.
func TestWriteFailureIsTerminal(t *testing.T) {
	dir := t.TempDir()
	in := newInjector()
	// Write 1 is the header; 2 and 3 are the first two commits; 4 fails.
	in.on(segmentName(1, "wal"), 4, 0)
	v, reg := injectedVault(t, dir, in, 100)

	var acked []types.Receipt
	for i := 0; i < 2; i++ {
		rc, err := putRec(v, i)
		if err != nil {
			t.Fatal(err)
		}
		acked = append(acked, rc)
	}
	if _, err := putRec(v, 2); !errors.Is(err, types.ErrFailed) {
		t.Fatalf("the put whose write failed returned %v, want ErrFailed", err)
	}
	afterFailure(t, v, reg, "write failure")
	v.Close()
	reopenAndCheck(t, dir, acked, "write failure")
}

// TestFailureDuringSealIsTerminal covers the seal window, where the ordering
// (footer, fsync, ledger, fsync) is the argument for correctness. Each of the
// four steps is failed in turn.
func TestFailureDuringSealIsTerminal(t *testing.T) {
	const sealEvery = 3

	cases := []struct {
		name string
		plan func(in *injector)
	}{
		// The segment file's calls, in order: header write (1), then one
		// write per commit (2,3,4) and the footer (5). Syncs: header (1),
		// commits (2,3,4), footer (5).
		{"the footer write fails", func(in *injector) { in.on(segmentName(1, "wal"), 5, 0) }},
		{"the footer fsync fails", func(in *injector) { in.on(segmentName(1, "wal"), 0, 5) }},
		{"the ledger append fails", func(in *injector) { in.on("chain.log", 1, 0) }},
		{"the ledger fsync fails", func(in *injector) { in.on("chain.log", 0, 1) }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			in := newInjector()
			c.plan(in)
			v, reg := injectedVault(t, dir, in, sealEvery)

			var acked []types.Receipt
			var sealErr error
			for i := 0; i < sealEvery; i++ {
				rc, err := putRec(v, i)
				if err != nil {
					sealErr = err
					break
				}
				acked = append(acked, rc)
			}

			// The batch that triggers the seal reports the failure, because
			// the seal is part of making it durable.
			if !errors.Is(sealErr, types.ErrFailed) {
				t.Fatalf("the put that triggered the failing seal returned %v, want ErrFailed", sealErr)
			}
			afterFailure(t, v, reg, c.name)
			v.Close()

			// Whatever was acknowledged before the seal began survives. The
			// records in the failing batch were never acknowledged.
			reopenAndCheck(t, dir, acked, c.name)
		})
	}
}

// TestFailureIsReportedToEveryWaitingCaller: group commit coalesces callers, so
// one failed fsync fails all of them. None may be told it succeeded.
func TestFailureIsReportedToEveryWaitingCaller(t *testing.T) {
	dir := t.TempDir()
	in := newInjector()
	in.on(segmentName(1, "wal"), 0, 2) // the first commit's fsync
	v, _ := injectedVault(t, dir, in, 1000)
	defer v.Close()

	const callers = 12
	errs := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := putRec(v, i)
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	failures := 0
	for err := range errs {
		if err == nil {
			// A caller that raced in AFTER the failed commit would also see
			// ErrFailed, so nil means it was in the group that fsynced OK -
			// which is only possible if it committed before the failure. With
			// the very first fsync failing, that is impossible.
			t.Error("a caller was told its record was durable although the fsync failed")
			continue
		}
		if !errors.Is(err, types.ErrFailed) {
			t.Errorf("a caller got %v, want ErrFailed", err)
		}
		failures++
	}
	if failures != callers {
		t.Errorf("%d of %d callers saw the failure", failures, callers)
	}
}

// TestFailedVaultDoesNotSealOnClose: a failed vault must not try to write a
// footer or a ledger line on the way out. It cannot trust what it has, and a
// seal built on unfsynced pages would commit the chain to data that may not
// exist.
func TestFailedVaultDoesNotSealOnClose(t *testing.T) {
	dir := t.TempDir()
	in := newInjector()
	in.on(segmentName(1, "wal"), 0, 3)
	v, _ := injectedVault(t, dir, in, 100)

	if _, err := putRec(v, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := putRec(v, 1); !errors.Is(err, types.ErrFailed) {
		t.Fatalf("got %v, want ErrFailed", err)
	}
	v.Close()

	// No ledger line was written for a segment the vault no longer trusts.
	ledger, err := os.ReadFile(filepath.Join(dir, "chain.log"))
	if err == nil && strings.TrimSpace(string(ledger)) != "" {
		t.Errorf("a failed vault appended to the ledger on Close: %q", ledger)
	}
}
