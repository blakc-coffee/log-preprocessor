//go:build !windows

package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/sluice/pkg/dataplane/app"
	"github.com/blakc-coffee/sluice/pkg/dataplane/parsers"
	"github.com/blakc-coffee/sluice/pkg/dataplane/quarantine"
	"github.com/blakc-coffee/sluice/pkg/dataplane/registry"
	"github.com/blakc-coffee/sluice/pkg/dataplane/replay"
	"github.com/blakc-coffee/sluice/pkg/dataplane/store"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

const replayRecordCount = 500

// replayResult is the minimum observable result required from the real replay
// manager once pkg/dataplane/app is merged.
type replayResult struct {
	Processed       int
	Succeeded       int
	QuarantineOpen  int
	NormalizedCount int
}

// replayHarness is deliberately defined in tests rather than implemented by a
// mock. The Gate 2 adapter must drive the real app, registry, quarantine, and
// replay manager.
type replayHarness interface {
	IngestUnknown(context.Context, string) (int, error)
	RegisterPending(context.Context, []byte) (string, error)
	ApproveAndReplay(context.Context, string) (replayResult, error)
	RawRecord(context.Context, int) ([]byte, error)
}

type realReplayHarness struct {
	app         *app.App
	vault       types.Vault
	registry    *registry.Registry
	store       *store.Store
	quarantine  *quarantine.Store
	replayMgr   *replay.Manager
	pendingID   string
	pendingYAML []byte
}

func newRealReplayHarness(t *testing.T) *realReplayHarness {
	t.Helper()
	v, err := vault.Open(vault.Options{Dir: filepath.Join(t.TempDir(), "vault"), Sync: vault.SyncAlways, SegmentMaxRecords: replayRecordCount})
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(parsers.New(), "")
	events := store.New()
	quarantined := quarantine.New()
	pipeline := app.New(reg, events, quarantined, nil)
	h := &realReplayHarness{app: pipeline, vault: v, registry: reg, store: events, quarantine: quarantined}
	h.replayMgr = replay.New(v, pipeline)
	t.Cleanup(func() {
		if err := errors.Join(pipeline.Close(), v.Close()); err != nil {
			t.Errorf("close replay harness: %v", err)
		}
	})
	return h
}

func (h *realReplayHarness) IngestUnknown(ctx context.Context, path string) (int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	manifestRaw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "manifest.json"))
	if err != nil {
		return 0, err
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return 0, err
	}
	records := make([]types.RawRecord, 0, replayRecordCount)
	for _, item := range manifest.Records {
		if item.SourceFile != filepath.Base(path) {
			continue
		}
		if item.ByteStart < 0 || item.ByteEnd < item.ByteStart || item.ByteEnd > len(body) {
			return 0, fmt.Errorf("invalid fixture range [%d:%d]", item.ByteStart, item.ByteEnd)
		}
		records = append(records, types.RawRecord{
			SourceID:   "palo-alto-unknown",
			ReceivedAt: time.Date(2026, 9, 28, 9, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60)),
			Origin:     types.Origin{Kind: types.OriginFile, Addr: path, Offset: uint64(item.ByteStart)},
			Term:       fixtureTerm(item.Terminator),
			Raw:        append([]byte(nil), body[item.ByteStart:item.ByteEnd]...),
		})
	}
	if len(records) != replayRecordCount {
		return 0, fmt.Errorf("fixture records=%d, want %d", len(records), replayRecordCount)
	}
	receipts, err := h.vault.PutBatch(ctx, records)
	if err != nil {
		return 0, err
	}
	for i := range records {
		if err := h.app.Process(ctx, types.RawEvent{RawRecord: records[i], Receipt: receipts[i]}); err != nil {
			return 0, err
		}
	}
	return h.quarantine.OpenCount(), nil
}

func (h *realReplayHarness) RegisterPending(_ context.Context, src []byte) (string, error) {
	p, err := parsers.New().Load(src)
	if err != nil {
		return "", err
	}
	if h.registry.Has(p.ID()) {
		return "", fmt.Errorf("parser %s already exists", p.ID())
	}
	h.pendingID = p.ID()
	h.pendingYAML = append([]byte(nil), src...)
	return p.ID(), nil
}

func (h *realReplayHarness) ApproveAndReplay(ctx context.Context, parserID string) (replayResult, error) {
	if parserID == "" || parserID != h.pendingID || len(h.pendingYAML) == 0 {
		return replayResult{}, errors.New("parser is not pending")
	}
	approved, err := h.registry.Approve(h.pendingYAML)
	if err != nil {
		return replayResult{}, err
	}
	if approved.ID() != parserID {
		return replayResult{}, fmt.Errorf("approved parser=%s, want %s", approved.ID(), parserID)
	}
	job := h.replayMgr.Start(ctx, "quarantine", "")
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return replayResult{}, ctx.Err()
		case <-deadline.C:
			return replayResult{}, errors.New("replay timed out")
		case <-ticker.C:
			current, ok := h.replayMgr.Get(job.JobID)
			if !ok || current.State == "queued" || current.State == "running" {
				continue
			}
			if current.State != "done" || current.Error != nil {
				return replayResult{}, fmt.Errorf("replay failed: %+v", current)
			}
			for id := types.RecordID(1); id <= replayRecordCount; id++ {
				event, ok := h.store.CurrentByRecord(id)
				_, classOK := event.OCSF["class_uid"]
				metadata, metadataOK := event.OCSF["metadata"].(map[string]any)
				_, versionOK := metadata["version"]
				if !ok || event.EventID == "" || event.ParserID != parserID || event.SchemaVersion == "" || event.OCSF == nil || !classOK || !metadataOK || !versionOK {
					return replayResult{}, fmt.Errorf("record %d has invalid normalized event: %+v", id, event)
				}
				_, receipt, err := h.vault.Get(ctx, id)
				if err != nil {
					return replayResult{}, err
				}
				if event.RawSHA256 != hex.EncodeToString(receipt.RawSHA256[:]) {
					return replayResult{}, fmt.Errorf("record %d raw hash changed", id)
				}
			}
			return replayResult{Processed: current.Processed, Succeeded: current.Succeeded, QuarantineOpen: h.quarantine.OpenCount(), NormalizedCount: h.store.Count()}, nil
		}
	}
}

func (h *realReplayHarness) RawRecord(ctx context.Context, id int) ([]byte, error) {
	record, _, err := h.vault.Get(ctx, types.RecordID(id))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), record.Raw...), nil
}

func TestPaloAltoReplayAcceptance(t *testing.T) {
	assertPaloAltoReplay(t, newRealReplayHarness(t))
}

// assertPaloAltoReplay is the Phase 2 acceptance contract. Keeping the exact
// assertions here makes the integration adapter mechanical without claiming a
// mock is an end-to-end pass.
func assertPaloAltoReplay(t *testing.T, h replayHarness) {
	t.Helper()
	ctx := context.Background()
	fixture := filepath.Join("..", "testdata", "palo_alto_unknown.log")
	wantRaw := readManifestRecords(t, fixture)

	quarantined, err := h.IngestUnknown(ctx, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if quarantined != replayRecordCount {
		t.Fatalf("quarantined=%d, want %d", quarantined, replayRecordCount)
	}

	parserYAML, err := os.ReadFile(filepath.Join("testdata", "parsers", "palo_alto_traffic.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	parserID, err := h.RegisterPending(ctx, parserYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.ApproveAndReplay(ctx, parserID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Processed != replayRecordCount || result.Succeeded != replayRecordCount || result.NormalizedCount != replayRecordCount || result.QuarantineOpen != 0 {
		t.Fatalf("replay result=%+v, want processed=succeeded=normalized=%d and quarantine_open=0", result, replayRecordCount)
	}
	for i, want := range wantRaw {
		got, err := h.RawRecord(ctx, i+1)
		if err != nil {
			t.Fatalf("raw record %d: %v", i+1, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("raw record %d changed during replay", i+1)
		}
	}
}

func TestReplayFixtureContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "parsers", "palo_alto_traffic.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		ID         string `yaml:"id"`
		Version    string `yaml:"version"`
		Extractors []any  `yaml:"extractors"`
	}
	if err := yaml.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	if header.ID != "palo_alto_traffic" || header.Version != "1.0.0" || len(header.Extractors) == 0 {
		t.Fatalf("unexpected parser header: id=%q version=%q extractors=%d", header.ID, header.Version, len(header.Extractors))
	}
	records := readManifestRecords(t, filepath.Join("..", "testdata", "palo_alto_unknown.log"))
	if len(records) != replayRecordCount {
		t.Fatalf("fixture records=%d, want %d", len(records), replayRecordCount)
	}
}

func readManifestRecords(t *testing.T, path string) [][]byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Records []struct {
			SourceFile string `json:"source_file"`
			ByteStart  int    `json:"byte_start"`
			ByteEnd    int    `json:"byte_end"`
		} `json:"records"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)
	var records [][]byte
	for _, record := range manifest.Records {
		if record.SourceFile != name {
			continue
		}
		if record.ByteStart < 0 || record.ByteEnd < record.ByteStart || record.ByteEnd > len(body) {
			t.Fatalf("manifest range [%d:%d] outside %s (%d bytes)", record.ByteStart, record.ByteEnd, path, len(body))
		}
		records = append(records, append([]byte(nil), body[record.ByteStart:record.ByteEnd]...))
	}
	return records
}
