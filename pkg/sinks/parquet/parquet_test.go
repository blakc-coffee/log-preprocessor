package parquet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func TestAtomicPartitionAndTypedProjection(t *testing.T) {
	root := t.TempDir()
	enc := func(f io.Writer, rows []Row) error { return json.NewEncoder(f).Encode(rows) }
	s, err := New(Config{Root: root, RowsPerFile: 1, Encoder: enc})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	e := types.NormalizedEvent{EventID: "7.p@1", RecordID: 7, RawSHA256: strings.Repeat("ab", 32), Vendor: "A/B", EventTime: &now, ReceivedAt: now, OCSF: map[string]any{"src_endpoint": map[string]any{"ip": "1.2.3.4"}}}
	if err = s.Write(context.Background(), []types.NormalizedEvent{e}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(root, "dt=2026-09-29", "vendor=A_B", "*.parquet"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("files=%v err=%v", matches, err)
	}
	if temps, _ := filepath.Glob(filepath.Join(root, "**", "*.tmp")); len(temps) != 0 {
		t.Fatalf("temp files: %v", temps)
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var rows []Row
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].SrcIP != "1.2.3.4" {
		t.Fatalf("row=%+v", rows[0])
	}
}
