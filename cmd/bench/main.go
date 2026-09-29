// Command bench measures the offline parser/normalizer path using sacred
// fixture bytes and writes reproducible JSON and Markdown reports.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	StartedAt       time.Time `json:"started_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Workers         int       `json:"workers"`
	Measurement     string    `json:"measurement"`
	Transport       string    `json:"transport,omitempty"`
	Address         string    `json:"address,omitempty"`
	SyncMode        string    `json:"sync_mode,omitempty"`
	StoreMode       string    `json:"store_mode,omitempty"`
	Events          int64     `json:"events"`
	Normalized      int64     `json:"normalized"`
	Quarantined     int64     `json:"quarantined"`
	Bytes           int64     `json:"bytes"`
	EPS             float64   `json:"eps"`
	P50Micros       float64   `json:"p50_micros"`
	P95Micros       float64   `json:"p95_micros"`
	P99Micros       float64   `json:"p99_micros"`
	PeakRSSBytes    int64     `json:"peak_rss_bytes,omitempty"`
	PeakRSSSource   string    `json:"peak_rss_source"`
	VaultZstdRatio  float64   `json:"vault_zstd_ratio"`
	ParquetRatio    float64   `json:"parquet_ratio"`
	GoVersion       string    `json:"go_version"`
	GOOS            string    `json:"goos"`
	GOARCH          string    `json:"goarch"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var fixtures string
	fs.StringVar(&fixtures, "corpus", "testdata/sample", "fixture corpus directory")
	fs.StringVar(&fixtures, "fixtures", "testdata/sample", "alias for --corpus")
	workersRaw := fs.String("workers", "1", "comma-separated worker counts")
	duration := fs.Duration("duration", 60*time.Second, "measurement duration")
	out := fs.String("out", "benchmarks/results/benchmark_report.json", "JSON result path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 {
		return errors.New("duration must be positive")
	}
	records, err := loadRecords(fixtures)
	if err != nil {
		return err
	}
	workers, err := parseWorkers(*workersRaw)
	if err != nil {
		return err
	}
	results := make([]result, 0, len(workers))
	for _, n := range workers {
		r, err := measurePipeline(records, n, *duration)
		if err != nil {
			return err
		}
		results = append(results, r)
		fmt.Fprintf(stdout, "workers=%d events=%d normalized=%d quarantined=%d eps=%.0f p50=%.3fus p95=%.3fus p99=%.3fus peak_rss=%d (%s) parquet=%.2fx vault_zstd=%.2fx\n", r.Workers, r.Events, r.Normalized, r.Quarantined, r.EPS, r.P50Micros, r.P95Micros, r.P99Micros, r.PeakRSSBytes, r.PeakRSSSource, r.ParquetRatio, r.VaultZstdRatio)
	}
	if err = writeResults(*out, results); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "report:", *out)
	return nil
}

func loadRecords(dir string) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "manifest.json" && e.Name() != "identity_truth.json" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)
	var records [][]byte
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		r := bufio.NewReader(f)
		for {
			line, readErr := r.ReadBytes('\n')
			if len(line) > 0 {
				records = append(records, append([]byte(nil), line...))
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				f.Close()
				return nil, readErr
			}
		}
		f.Close()
	}
	if len(records) == 0 {
		return nil, errors.New("fixture corpus contains no records")
	}
	return records, nil
}

func measure(records [][]byte, network, address string, workers int, duration time.Duration, syncMode, storeMode string) (result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	started := time.Now().UTC()
	var next, events, totalBytes atomic.Int64
	latencies := make(chan int64, workers*1024)
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout(network, address, 3*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				record := records[int(next.Add(1)-1)%len(records)]
				before := time.Now()
				if _, err = conn.Write(record); err != nil {
					errCh <- err
					return
				}
				elapsed := time.Since(before).Microseconds()
				events.Add(1)
				totalBytes.Add(int64(len(record)))
				select {
				case latencies <- elapsed:
				default:
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	<-done
	close(latencies)
	select {
	case err := <-errCh:
		return result{}, err
	default:
	}
	samples := make([]int64, 0, len(latencies))
	for n := range latencies {
		samples = append(samples, n)
	}
	elapsed := time.Since(started)
	peak, source := peakRSS()
	return result{StartedAt: started, DurationSeconds: elapsed.Seconds(), Workers: workers, Measurement: "loopback socket write", Transport: network, Address: address, SyncMode: syncMode, StoreMode: storeMode, Events: events.Load(), Bytes: totalBytes.Load(), EPS: float64(events.Load()) / elapsed.Seconds(), P50Micros: float64(quantile(samples, .50)), P95Micros: float64(quantile(samples, .95)), P99Micros: float64(quantile(samples, .99)), PeakRSSBytes: peak, PeakRSSSource: source, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
}

func parseWorkers(raw string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid worker count %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}
func quantile(v []int64, q float64) int64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	i := int(float64(len(v)-1) * q)
	return v[i]
}
func writeResults(path string, results []result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(map[string]any{"claim": "in-process parser and normalizer throughput; compression ratios are measured from bounded representative samples", "results": results}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o640); err != nil {
		return err
	}
	return writeMarkdown(strings.TrimSuffix(path, filepath.Ext(path))+".md", results)
}

func writeMarkdown(path string, results []result) error {
	var b strings.Builder
	b.WriteString("# ULPF empirical benchmark\n\n")
	b.WriteString("In-process parser detection, extraction, normalization, and SHA-256 receipt throughput. Compression ratios use bounded representative samples.\n\n")
	if len(results) > 0 {
		fmt.Fprintf(&b, "- Started: %s\n- Platform: %s/%s, %s\n- Memory source: %s\n- Sync mode: %s (not a durable-fsync claim)\n\n", results[0].StartedAt.Format(time.RFC3339), results[0].GOOS, results[0].GOARCH, results[0].GoVersion, results[0].PeakRSSSource, results[0].SyncMode)
		if results[0].P50Micros == 0 || results[0].P95Micros == 0 {
			b.WriteString("Latency values of 0 indicate samples below the host clock's observable resolution.\n\n")
		}
	}
	b.WriteString("| Workers | EPS | p50 µs | p95 µs | p99 µs | Peak RSS bytes | Vault zstd | Parquet |\n")
	b.WriteString("|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %d | %.0f | %.3f | %.3f | %.3f | %d | %.2fx | %.2fx |\n", r.Workers, r.EPS, r.P50Micros, r.P95Micros, r.P99Micros, r.PeakRSSBytes, r.VaultZstdRatio, r.ParquetRatio)
	}
	return os.WriteFile(path, []byte(b.String()), 0o640)
}
