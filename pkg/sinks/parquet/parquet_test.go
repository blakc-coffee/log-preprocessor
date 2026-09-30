package parquet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/types"
	parquetgo "github.com/parquet-go/parquet-go"
)

func TestAtomicPartitionAndTypedProjection(t *testing.T) {
	root := t.TempDir()
	s, err := New(Config{Root: root, RowsPerFile: 1})
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
	if len(b) < 8 || !bytes.Equal(b[:4], []byte("PAR1")) || !bytes.Equal(b[len(b)-4:], []byte("PAR1")) {
		t.Fatalf("file does not have Apache Parquet magic bytes")
	}
	rows, err := parquetgo.ReadFile[Row](matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SrcIP != "1.2.3.4" {
		t.Fatalf("row=%+v", rows[0])
	}
	if rows[0].RawSHA256 != [32]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab} {
		t.Fatalf("raw sha256 changed: %x", rows[0].RawSHA256)
	}
	assertZstdColumns(t, matches[0])
}

func TestDefaultEncoderRoundTripsTypedRows(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 34, 56, 123456000, time.UTC)
	want := []Row{{
		EventID: "event-1", RecordID: 42, Segment: 3, RawSHA256: [32]byte{1, 2, 3},
		SourceID: "source", Vendor: "vendor", Product: "product", ParserID: "parser",
		ParserVersion: "1.2.3", TemplateID: "template", EventTime: now, ReceivedAt: now,
		SeverityID: 4, ActionID: 2, ActivityID: 7, ClassUID: 1001, SrcIP: "192.0.2.1",
		DstIP: "198.51.100.2", SrcPort: 12345, DstPort: 443, Proto: "tcp", BytesIn: 12,
		BytesOut: 34, User: "analyst", Host: "sensor", Confidence: 0.99,
		IntegrityFlags: []string{"raw_verified", "chain_verified"}, TimeFromReceipt: true,
		Current: true, ExtrasJSON: `{"unmapped":{"key":"value"}}`,
	}}
	var encoded bytes.Buffer
	if err := encodeParquet(&encoded, want); err != nil {
		t.Fatal(err)
	}
	got, err := parquetgo.Read[Row](bytes.NewReader(encoded.Bytes()), int64(encoded.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch\nwant: %#v\n got: %#v", want, got)
	}
}

func assertZstdColumns(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	file, err := parquetgo.OpenFile(f, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range file.Metadata().RowGroups {
		for _, column := range group.Columns {
			if got := column.MetaData.Codec.String(); got != "ZSTD" {
				t.Fatalf("column %v compression=%s, want ZSTD", column.MetaData.PathInSchema, got)
			}
		}
	}
}
