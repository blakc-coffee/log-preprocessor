package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
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
	if runtime.GOOS == "windows" {
		t.Skip("byte-offset fixture check runs on Linux; Git for Windows may translate fixture line endings")
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
