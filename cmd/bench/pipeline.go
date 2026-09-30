package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/blakc-coffee/sluice/contracts"
	"github.com/blakc-coffee/sluice/pkg/dataplane/normalizer"
	"github.com/blakc-coffee/sluice/pkg/dataplane/parsers"
	parquetsink "github.com/blakc-coffee/sluice/pkg/sinks/parquet"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

const compressionSampleLimit = 10000

func measurePipeline(records [][]byte, workers int, duration time.Duration) (result, error) {
	active, err := benchmarkParsers()
	if err != nil {
		return result{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	started := time.Now().UTC()
	var next, events, normalized, quarantined, totalBytes atomic.Int64
	latencies := make(chan int64, workers*65536)
	var sampleMu sync.Mutex
	var sampleCount atomic.Int64
	samples := make([]types.NormalizedEvent, 0, compressionSampleLimit)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				n := next.Add(1)
				raw := records[int(n-1)%len(records)]
				before := time.Now()
				record := types.RawRecord{SourceID: "benchmark", ReceivedAt: before.UTC(), Raw: raw}
				receipt := types.Receipt{ID: types.RecordID(n), Segment: 1, RawSHA256: sha256.Sum256(raw)}
				var event *types.NormalizedEvent
				for _, parser := range active {
					parsed, parseErr := parser.Parse(raw, record.ReceivedAt)
					if parseErr != nil {
						break
					}
					if parsed != nil {
						normalizedEvent := normalizer.Build(types.RawEvent{RawRecord: record, Receipt: receipt}, parser, parsed)
						event = &normalizedEvent
						break
					}
				}
				if event == nil {
					quarantined.Add(1)
				} else {
					normalized.Add(1)
					if sampleCount.Load() < compressionSampleLimit {
						sampleMu.Lock()
						if len(samples) < compressionSampleLimit {
							samples = append(samples, *event)
							sampleCount.Add(1)
						}
						sampleMu.Unlock()
					}
				}
				events.Add(1)
				totalBytes.Add(int64(len(raw)))
				select {
				case latencies <- time.Since(before).Nanoseconds():
				default:
				}
			}
		}()
	}
	wg.Wait()
	measuredElapsed := time.Since(started)
	close(latencies)
	latencySample := make([]int64, 0, len(latencies))
	for latency := range latencies {
		latencySample = append(latencySample, latency)
	}
	sort.Slice(latencySample, func(i, j int) bool { return latencySample[i] < latencySample[j] })
	peak, peakSource := peakRSS()
	vaultRatio, err := corpusZstdRatio(records)
	if err != nil {
		return result{}, err
	}
	parquetRatio, err := sampleParquetRatio(samples)
	if err != nil {
		return result{}, err
	}
	return result{
		StartedAt: started, DurationSeconds: measuredElapsed.Seconds(), Workers: workers,
		Measurement: "in-process parser detection, extraction, normalization, and SHA-256 ingest receipt",
		SyncMode:    "memory", StoreMode: "bounded compression sample", Events: events.Load(),
		Normalized: normalized.Load(), Quarantined: quarantined.Load(), Bytes: totalBytes.Load(),
		EPS: float64(events.Load()) / measuredElapsed.Seconds(), P50Micros: float64(quantile(latencySample, .50)) / 1000,
		P95Micros: float64(quantile(latencySample, .95)) / 1000, P99Micros: float64(quantile(latencySample, .99)) / 1000,
		PeakRSSBytes: peak, PeakRSSSource: peakSource, VaultZstdRatio: vaultRatio,
		ParquetRatio: parquetRatio, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}, nil
}

func benchmarkParsers() ([]*parsers.Parser, error) {
	engine := parsers.New()
	entries, err := contracts.DSLExamples.ReadDir("dsl/examples")
	if err != nil {
		return nil, err
	}
	active := make([]*parsers.Parser, 0, len(entries))
	for _, entry := range entries {
		src, err := contracts.DSLExamples.ReadFile("dsl/examples/" + entry.Name())
		if err != nil {
			return nil, err
		}
		parser, err := engine.Load(src)
		if err != nil {
			return nil, err
		}
		active = append(active, parser)
	}
	return active, nil
}

func corpusZstdRatio(records [][]byte) (float64, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return 0, err
	}
	defer encoder.Close()
	var raw []byte
	for _, record := range records {
		raw = append(raw, record...)
	}
	if len(raw) == 0 {
		return 0, errors.New("empty compression corpus")
	}
	compressed := encoder.EncodeAll(raw, nil)
	return float64(len(raw)) / float64(len(compressed)), nil
}

func sampleParquetRatio(events []types.NormalizedEvent) (float64, error) {
	if len(events) == 0 {
		return 0, nil
	}
	dir, err := os.MkdirTemp("", "ulpf-bench-parquet-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	sink, err := parquetsink.New(parquetsink.Config{Root: dir, RowsPerFile: len(events)})
	if err != nil {
		return 0, err
	}
	if err := sink.Write(context.Background(), events); err != nil {
		_ = sink.Close()
		return 0, err
	}
	if err := sink.Close(); err != nil {
		return 0, err
	}
	uncompressed := 0
	for _, event := range events {
		b, err := json.Marshal(event)
		if err != nil {
			return 0, err
		}
		uncompressed += len(b)
	}
	var parquetBytes int64
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".parquet" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		parquetBytes += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	if parquetBytes == 0 {
		return 0, errors.New("parquet sample produced no bytes")
	}
	return float64(uncompressed) / float64(parquetBytes), nil
}
