package replay_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/app"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/quarantine"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/registry"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/replay"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/store"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func parserYAML(version, signature, key string) []byte {
	return []byte(fmt.Sprintf(`id: replay_test
version: %s
vendor: test
product: replay
timezone: "+00:00"
match: {signature: %q}
ocsf_defaults: {class_uid: 1001, category_uid: 1, activity_id: 0, type_uid: 100100}
extractors:
  - id: event
    kind: kv
    map:
      - {from: %s, to: message, type: string}
`, version, signature, key))
}

func TestQuarantineReplayOnlyProcessesOpenRecordsAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	v := memvault.New(memvault.Options{})
	t.Cleanup(func() { _ = v.Close() })
	records := []types.RawRecord{
		{SourceID: "source", ReceivedAt: time.Now().UTC(), Raw: []byte("unknown=one")},
		{SourceID: "source", ReceivedAt: time.Now().UTC(), Raw: []byte("message=two")},
	}
	receipts, err := v.PutBatch(ctx, records)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(parsers.New(), "")
	if _, err := reg.Add(parserYAML("1.0.0", "^message=", "message"), true); err != nil {
		t.Fatal(err)
	}
	events, quarantined := store.New(), quarantine.New()
	pipeline := app.New(reg, events, quarantined, nil)
	for i := range records {
		if err := pipeline.Process(ctx, types.RawEvent{RawRecord: records[i], Receipt: receipts[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if events.Count() != 1 || quarantined.OpenCount() != 1 {
		t.Fatalf("before replay events=%d open=%d, want 1/1", events.Count(), quarantined.OpenCount())
	}
	if _, err := reg.Add(parserYAML("1.0.1", "^unknown=", "unknown"), true); err != nil {
		t.Fatal(err)
	}

	m := replay.New(v, pipeline)
	first := wait(t, m, m.Start(ctx, "quarantine", "").JobID)
	if first.Processed != 1 || first.Succeeded != 1 || first.Failed != 0 {
		t.Fatalf("first replay = %+v", first)
	}
	if events.Count() != 2 || quarantined.OpenCount() != 0 {
		t.Fatalf("after replay events=%d open=%d, want 2/0", events.Count(), quarantined.OpenCount())
	}
	second := wait(t, m, m.Start(ctx, "quarantine", "").JobID)
	if second.Processed != 0 || events.Count() != 2 {
		t.Fatalf("second replay = %+v, events=%d", second, events.Count())
	}
}

func wait(t *testing.T, m *replay.Manager, id string) replay.Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := m.Get(id)
		if ok && (job.State == "done" || job.State == "failed") {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("replay %s did not finish", id)
	return replay.Job{}
}
