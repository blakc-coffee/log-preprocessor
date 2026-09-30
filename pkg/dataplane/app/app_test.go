package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/app"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	"github.com/dark-14100/sluice/pkg/dataplane/store"
	types "github.com/dark-14100/sluice/pkg/types"
)

type countSink struct {
	fail   bool
	writes int
}

func (s *countSink) Name() string                { return "count" }
func (s *countSink) Flush(context.Context) error { return nil }
func (s *countSink) Close() error                { return nil }
func (s *countSink) Write(_ context.Context, b []types.NormalizedEvent) error {
	if s.fail {
		return errors.New("disk full")
	}
	s.writes += len(b)
	return nil
}

const testParser = `id: app_test
version: 1.0.0
vendor: test
product: app
timezone: "+00:00"
match: {signature: "^message="}
ocsf_defaults: {class_uid: 1001, category_uid: 1, activity_id: 0, type_uid: 100100}
extractors:
  - id: event
    kind: kv
    map:
      - {from: message, to: message, type: string}
`

// A sink failure must not leave the event in the store: on replay the store would
// call it delivered and the sink would never see it.
func TestSinkFailureIsRetriedAfterReplay(t *testing.T) {
	ctx := context.Background()
	reg := registry.New(parsers.New(), "")
	if _, err := reg.Add([]byte(testParser), true); err != nil {
		t.Fatal(err)
	}
	events, sink := store.New(), &countSink{fail: true}
	a := app.New(reg, events, nil, nil, sink)
	raw := types.RawEvent{RawRecord: types.RawRecord{SourceID: "s", ReceivedAt: time.Now().UTC(), Raw: []byte("message=one")}}

	if err := a.Process(ctx, raw); err == nil {
		t.Fatal("sink failure must surface")
	}
	if events.Count() != 0 {
		t.Fatalf("store has %d events after a failed sink write, want 0", events.Count())
	}
	sink.fail = false
	for i := 0; i < 2; i++ { // second pass is a replay of a stored event
		if err := a.Process(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	if sink.writes != 1 || events.Count() != 1 {
		t.Fatalf("writes=%d events=%d, want 1/1", sink.writes, events.Count())
	}
}
