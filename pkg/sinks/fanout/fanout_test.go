package fanout

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/types"
)

type testSink struct {
	name string
	fail atomic.Bool
	mu   sync.Mutex
	ids  []string
}

func (s *testSink) Name() string { return s.name }
func (s *testSink) Write(_ context.Context, b []types.NormalizedEvent) error {
	if s.fail.Load() {
		return errors.New("offline")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range b {
		s.ids = append(s.ids, e.EventID)
	}
	return nil
}
func (s *testSink) Flush(context.Context) error { return nil }
func (s *testSink) Close() error                { return nil }
func (s *testSink) count() int                  { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ids) }

func TestFailingTargetSpoolsWithoutBlockingHealthyTarget(t *testing.T) {
	good := &testSink{name: "good"}
	bad := &testSink{name: "bad"}
	bad.fail.Store(true)
	f, err := New([]types.Sink{bad, good}, Config{QueueEvents: 4, BatchEvents: 1, BatchInterval: 10 * time.Millisecond, RetryWindow: time.Millisecond, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, SpoolRoot: t.TempDir(), SpoolMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.Write(context.Background(), []types.NormalizedEvent{{EventID: "1"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for good.count() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if good.count() != 1 {
		t.Fatal("healthy target did not progress")
	}
	for f.Metrics()["bad"].SpoolBytes == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.Metrics()["bad"].SpoolBytes == 0 {
		t.Fatal("failed target was not spooled")
	}
	bad.fail.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = f.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if bad.count() != 1 {
		t.Fatalf("drained count=%d", bad.count())
	}
}
