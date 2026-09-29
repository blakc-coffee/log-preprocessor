// Command bench drives byte-preserving fixture records into a loopback ingest
// socket and records measured ingress throughput and write latency.
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
	StartedAt                               time.Time `json:"started_at"`
	DurationSeconds                         float64   `json:"duration_seconds"`
	Workers                                 int       `json:"workers"`
	Transport, Address, SyncMode, StoreMode string
	Events                                  int64   `json:"events"`
	Bytes                                   int64   `json:"bytes"`
	EPS                                     float64 `json:"eps"`
	P50Micros                               int64   `json:"p50_micros"`
	P99Micros                               int64   `json:"p99_micros"`
	PeakRSSBytes                            int64   `json:"peak_rss_bytes,omitempty"`
	PeakRSSSource                           string  `json:"peak_rss_source"`
	GoVersion, GOOS, GOARCH                 string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "run" {
		return errors.New("usage: bench run [--fixtures DIR --transport tcp|udp --address HOST:PORT --workers 1,2,4,8 --duration 60s --out FILE]")
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixtures := fs.String("fixtures", "testdata/sample", "fixture directory")
	transport := fs.String("transport", "tcp", "tcp or udp")
	address := fs.String("address", "127.0.0.1:5514", "loopback ingest address")
	workersRaw := fs.String("workers", "1,2,4,8", "comma-separated worker counts")
	duration := fs.Duration("duration", 60*time.Second, "measurement duration")
	syncMode := fs.String("sync", "external", "target sync mode label")
	storeMode := fs.String("store", "external", "target store mode label")
	out := fs.String("out", "", "optional JSON result path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("address must be a literal loopback IP")
	}
	if *transport != "tcp" && *transport != "udp" {
		return errors.New("transport must be tcp or udp")
	}
	records, err := loadRecords(*fixtures)
	if err != nil {
		return err
	}
	workers, err := parseWorkers(*workersRaw)
	if err != nil {
		return err
	}
	results := make([]result, 0, len(workers))
	for _, n := range workers {
		r, err := measure(records, *transport, *address, n, *duration, *syncMode, *storeMode)
		if err != nil {
			return err
		}
		results = append(results, r)
		fmt.Fprintf(stdout, "workers=%d events=%d eps=%.0f p50=%dus p99=%dus peak_rss=%d (%s)\n", r.Workers, r.Events, r.EPS, r.P50Micros, r.P99Micros, r.PeakRSSBytes, r.PeakRSSSource)
	}
	if *out != "" {
		if err = writeResults(*out, results); err != nil {
			return err
		}
	}
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
	return result{StartedAt: started, DurationSeconds: elapsed.Seconds(), Workers: workers, Transport: network, Address: address, SyncMode: syncMode, StoreMode: storeMode, Events: events.Load(), Bytes: totalBytes.Load(), EPS: float64(events.Load()) / elapsed.Seconds(), P50Micros: quantile(samples, .50), P99Micros: quantile(samples, .99), PeakRSSBytes: peak, PeakRSSSource: source, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
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
func peakRSS() (int64, string) {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/self/status")
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "VmHWM:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						kb, _ := strconv.ParseInt(fields[1], 10, 64)
						return kb * 1024, "/proc/self/status VmHWM"
					}
				}
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Sys), "runtime.MemStats.Sys (RSS unavailable)"
}
func writeResults(path string, results []result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(map[string]any{"claim": "ingress socket measurement; not end-to-end pipeline throughput", "results": results}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o640)
}
