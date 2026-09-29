package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestParseWorkersAndQuantile(t *testing.T) {
	w, err := parseWorkers("1,2,8")
	if err != nil || len(w) != 3 || w[2] != 8 {
		t.Fatalf("workers=%v err=%v", w, err)
	}
	if got := quantile([]int64{9, 1, 5, 3, 7}, .5); got != 5 {
		t.Fatalf("median=%d", got)
	}
}

func TestPipelineMeasurementAndReports(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	records, err := loadRecords(filepath.Join(filepath.Dir(source), "..", "..", "testdata", "sample"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := measurePipeline(records, 1, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if r.Events == 0 || r.EPS <= 0 || r.VaultZstdRatio <= 0 {
		t.Fatalf("invalid result: %+v", r)
	}
	path := filepath.Join(t.TempDir(), "benchmark_report.json")
	if err := writeResults(path, []result{r}); err != nil {
		t.Fatal(err)
	}
	for _, report := range []string{path, filepath.Join(filepath.Dir(path), "benchmark_report.md")} {
		if info, err := os.Stat(report); err != nil || info.Size() == 0 {
			t.Fatalf("report %s: info=%v err=%v", report, info, err)
		}
	}
}
