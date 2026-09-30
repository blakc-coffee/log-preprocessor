package admin_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dark-14100/sluice/contracts"
	"github.com/dark-14100/sluice/contracts/integration"
	"github.com/dark-14100/sluice/pkg/dataplane/admin"
	"github.com/dark-14100/sluice/pkg/dataplane/app"
	"github.com/dark-14100/sluice/pkg/dataplane/identity"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/quarantine"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	"github.com/dark-14100/sluice/pkg/dataplane/replay"
	"github.com/dark-14100/sluice/pkg/dataplane/store"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/memvault"
	types "github.com/dark-14100/sluice/pkg/types"
)

const testParser = `id: test_parser
version: 1.0.0
vendor: test
product: test
timezone: "+00:00"
match:
  signature: '^message='
ocsf_defaults:
  class_uid: 4001
  category_uid: 4
  activity_id: 0
  type_uid: 400100
  severity_id: 1
  action_id: 0
  src_endpoint: {}
  dst_endpoint: {}
  connection_info: {}
extractors:
  - id: message
    kind: kv
    map:
      - {from: message, to: message, type: string}
`

func TestServerResponsesConformToAdminContract(t *testing.T) {
	contractDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(contractDir, "uef.schema.json"), contracts.SchemaJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(contractDir)
	ctx := context.Background()
	v := memvault.New(memvault.Options{SealEvery: 1})
	t.Cleanup(func() { _ = v.Close() })

	record := types.RawRecord{
		SourceID:   "test-source",
		ReceivedAt: time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC),
		Origin:     types.Origin{Kind: types.OriginFile, Addr: "/tmp/test.log"},
		Term:       types.TermLF,
		Raw:        []byte("message=hello"),
	}
	receipt, err := v.Put(ctx, record)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New(parsers.New(), t.TempDir())
	if _, err := reg.Add([]byte(testParser), true); err != nil {
		t.Fatal(err)
	}
	events := store.New()
	q := quarantine.New()
	pipeline := app.New(reg, events, q, nil)
	if err := pipeline.Process(ctx, types.RawEvent{RawRecord: record, Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
	resolver := identity.New(identity.Config{})
	replays := replay.New(v, pipeline)
	srv := httptest.NewServer(admin.New(v, pipeline, reg, replays, resolver))
	t.Cleanup(srv.Close)
	api := integration.NewHTTP(srv.URL)

	if _, err := api.Telemetry(); err != nil {
		t.Fatal(err)
	}
	gotEvents, err := api.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(gotEvents) != 1 {
		t.Fatalf("events = %d, want 1", len(gotEvents))
	}
	id := gotEvents[0].EventID
	if _, err := api.Raw(id); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Lineage(id); err != nil {
		t.Fatal(err)
	}
	if _, err := api.VerifyChain(true); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Timeline("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Parsers(); err != nil {
		t.Fatal(err)
	}
	if _, err := api.DryRun(testParser, "test-source"); err != nil {
		t.Fatal(err)
	}
	patch := strings.Replace(testParser, "version: 1.0.0", "version: 1.0.0\nbase_version: 1.0.0", 1)
	if _, err := api.Approve(patch, "admin-test", false); err != nil {
		t.Fatal(err)
	}
}
