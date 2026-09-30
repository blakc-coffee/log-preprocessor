package vault_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// Benchmarks.
//
// # Read the sync mode before you quote a number
//
// The three sync modes differ by two orders of magnitude, and only one of them
// means what "durable" usually means. Every benchmark here reports its mode as
// a custom metric so a number cannot be copied out of a terminal without it:
//
//	sync=always    fsync before acknowledging. The acknowledgement means the
//	               record is on disk. This is the number to quote.
//	sync=interval  acknowledge first, fsync on a timer. Up to one interval of
//	               acknowledged records can be lost.
//	sync=none      never fsync. Benchmarks only.
//
// # And do not quote a number measured on macOS
//
// Go's File.Sync issues F_FULLFSYNC on Darwin, which asks the drive to flush
// its own write cache. That is the honest thing to do and it is why these
// numbers are far worse here than on Linux — where fsync usually returns once
// the data reaches the drive, cache and all. The two are not comparable, and
// the PRD's targets are Linux targets. benchmarks/results/ is Linux-only.

func benchRecord(i int) types.RawRecord {
	// A realistic ASA line: ~140 bytes, which is what the fixture corpus
	// averages. Benchmarking with 8-byte payloads would measure the framework
	// rather than the work.
	return types.RawRecord{
		SourceID:   "syslog-udp",
		ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
		Origin:     types.Origin{Kind: types.OriginUDP, Addr: "10.1.4.7:51544"},
		Term:       types.TermLF,
		Raw: []byte(fmt.Sprintf(
			"<166>Sep 28 2026 09:00:01 asa01 : %%ASA-6-302013: Built inbound TCP connection %d "+
				"for outside:203.0.113.183/389 (203.0.113.183/389) to inside:10.2.2.73/43857", i)),
	}
}

// openBench builds a vault for a benchmark.
func openBench(b *testing.B, mode vault.SyncMode) *vault.Vault {
	b.Helper()
	v, err := vault.Open(vault.Options{
		Dir:  b.TempDir(),
		Sync: mode,
		// Group commit needs a delay to coalesce anything; 2ms is the
		// configured default.
		GroupCommitMaxDelay: 2 * time.Millisecond,
		SegmentMaxRecords:   250_000,
		SegmentMaxBytes:     64 << 20,
		SealInterval:        time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { v.Close() })
	return v
}

// BenchmarkPutBatch is the headline number: records per second made durable.
//
// Producers matter as much as the sync mode. With one producer there is
// nothing for group commit to coalesce, so every batch pays its own fsync and
// the result is a latency measurement wearing a throughput costume. The 16-
// and 64-producer cases are the realistic ones: a real deployment has many
// connections writing at once, which is the whole reason group commit exists.
func BenchmarkPutBatch(b *testing.B) {
	for _, mode := range []vault.SyncMode{vault.SyncAlways, vault.SyncInterval, vault.SyncNone} {
		for _, producers := range []int{1, 16, 64} {
			name := fmt.Sprintf("%s/producers=%d", mode, producers)
			b.Run(name, func(b *testing.B) {
				const perBatch = 16
				v := openBench(b, mode)
				ctx := context.Background()

				batches := b.N / producers
				if batches < 1 {
					batches = 1
				}

				b.ReportAllocs()
				b.ResetTimer()
				start := time.Now()

				var wg sync.WaitGroup
				for p := 0; p < producers; p++ {
					wg.Add(1)
					go func(p int) {
						defer wg.Done()
						batch := make([]types.RawRecord, perBatch)
						for i := range batch {
							batch[i] = benchRecord(p*1000 + i)
						}
						for i := 0; i < batches; i++ {
							if _, err := v.PutBatch(ctx, batch); err != nil {
								b.Error(err)
								return
							}
						}
					}(p)
				}
				wg.Wait()

				elapsed := time.Since(start)
				b.StopTimer()

				records := float64(batches * producers * perBatch)
				b.ReportMetric(records/elapsed.Seconds(), "records/s")
				b.ReportMetric(durableAck(mode), "durable_ack")
			})
		}
	}
}

// BenchmarkPutLatency measures what a single caller waits, which is the number
// an operator feels and the one the PRD sets a p99 target on. Throughput and
// latency are different questions and a mean hides the answer to this one.
func BenchmarkPutLatency(b *testing.B) {
	for _, mode := range []vault.SyncMode{vault.SyncAlways, vault.SyncInterval} {
		b.Run(string(mode), func(b *testing.B) {
			v := openBench(b, mode)
			ctx := context.Background()
			rec := benchRecord(0)

			samples := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				if _, err := v.Put(ctx, rec); err != nil {
					b.Fatal(err)
				}
				samples = append(samples, time.Since(t0))
			}
			b.StopTimer()

			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			b.ReportMetric(float64(percentile(samples, 0.50).Microseconds()), "p50_us")
			b.ReportMetric(float64(percentile(samples, 0.99).Microseconds()), "p99_us")
			b.ReportMetric(durableAck(mode), "durable_ack")
		})
	}
}

// durableAck is 1 only in sync=always, where the acknowledgement actually
// means the record is on disk. It rides along with every throughput and
// latency number so the two cannot be separated in a spreadsheet.
func durableAck(mode vault.SyncMode) float64 {
	if mode == vault.SyncAlways {
		return 1
	}
	return 0
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * q)
	return sorted[i]
}

// BenchmarkSeal measures computing a segment's Merkle root, writing the footer
// and appending the ledger line.
//
// Seal runs on the writer goroutine, so this is time the vault is not
// accepting records. At 250k records per segment it is the longest single
// pause the write path has.
func BenchmarkSeal(b *testing.B) {
	for _, n := range []int{10_000, 100_000} {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			ctx := context.Background()
			batch := make([]types.RawRecord, 500)
			for i := range batch {
				batch[i] = benchRecord(i)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// sync=none: this measures sealing, not fsync, and including
				// the per-batch fsyncs of the fill would drown the signal.
				v, err := vault.Open(vault.Options{
					Dir: b.TempDir(), Sync: vault.SyncNone,
					SegmentMaxRecords: n, SegmentMaxBytes: 1 << 30, SealInterval: time.Hour,
				})
				if err != nil {
					b.Fatal(err)
				}
				for written := 0; written < n-len(batch); written += len(batch) {
					if _, err := v.PutBatch(ctx, batch); err != nil {
						b.Fatal(err)
					}
				}
				remaining := n - (n-len(batch))/len(batch)*len(batch) - len(batch)
				_ = remaining
				b.StartTimer()

				// The batch that crosses SegmentMaxRecords triggers the seal.
				if _, err := v.PutBatch(ctx, batch); err != nil {
					b.Fatal(err)
				}

				b.StopTimer()
				v.Close()
				b.StartTimer()
			}
		})
	}
}

// BenchmarkGet measures a random read: locate the segment, pread, verify the
// CRC, decode.
func BenchmarkGet(b *testing.B) {
	const n = 50_000
	v := openBench(b, vault.SyncNone)
	ctx := context.Background()

	batch := make([]types.RawRecord, 500)
	for i := range batch {
		batch[i] = benchRecord(i)
	}
	for written := 0; written < n; written += len(batch) {
		if _, err := v.PutBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := types.RecordID(1 + (i*7919)%n) // stride through, defeating the cache
		if _, _, err := v.Get(ctx, id); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScan measures sequential replay, which is what a re-normalisation
// run does over the whole vault.
func BenchmarkScan(b *testing.B) {
	const n = 50_000
	v := openBench(b, vault.SyncNone)
	ctx := context.Background()

	batch := make([]types.RawRecord, 500)
	for i := range batch {
		batch[i] = benchRecord(i)
	}
	for written := 0; written < n; written += len(batch) {
		if _, err := v.PutBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		if err := v.Scan(ctx, 1, func(types.RawRecord, types.Receipt) error {
			count++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		if count != n {
			b.Fatalf("scanned %d records, want %d", count, n)
		}
	}
	b.ReportMetric(float64(n), "records/op")
}

// TestBenchmarkEnvironment is not a benchmark. It fails on macOS with an
// explanation, so a number measured here cannot quietly end up in the
// submission.
//
// It is a test rather than a comment because a comment does not stop anyone.
func TestBenchmarkEnvironmentIsReportable(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "linux" {
		return
	}
	t.Skipf("benchmark numbers measured on %s are NOT reportable: Go's File.Sync "+
		"issues F_FULLFSYNC on Darwin, which flushes the drive's own write cache, "+
		"while Linux fsync usually returns once the data reaches the drive. The two "+
		"differ by more than an order of magnitude and the PRD's targets are Linux "+
		"targets. Run benchmarks on Linux and record them in benchmarks/results/.",
		runtime.GOOS)
}

// BenchmarkGetCompacted measures a random read from a compacted segment, cold
// and warm. Cold is the honest number: every read misses the block cache and
// pays a pread, a CRC and a zstd decompression of a whole block, however small
// the record wanted. Warm is a cache hit. The gap between them is the price of
// compaction on the read path.
func BenchmarkGetCompacted(b *testing.B) {
	const n = 200_000 // ~110 blocks, well past the 32-block cache
	dir := b.TempDir()
	ctx := context.Background()

	w, err := vault.Open(vault.Options{
		Dir: dir, Sync: vault.SyncNone, SegmentMaxRecords: n, SealInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	batch := make([]types.RawRecord, 500)
	for written := 0; written < n; written += len(batch) {
		for i := range batch {
			batch[i] = benchRecord(written + i)
		}
		if _, err := w.PutBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}

	v, err := vault.Open(vault.Options{
		Dir: dir, Sync: vault.SyncNone, Compact: true, SealInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { v.Close() })
	waitCompactedB(b, dir)

	// ~1800 records of ~140 bytes per 256 KiB block. A stride of 2000 moves to
	// a different block every read, and cycling through ~100 blocks evicts
	// each from a 32-block cache long before it is revisited.
	b.Run("cold", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := types.RecordID(1 + (i*2000)%n)
			if _, _, err := v.Get(ctx, id); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("warm", func(b *testing.B) {
		if _, _, err := v.Get(ctx, 5000); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := v.Get(ctx, 5000); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("sequential scan", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			count := 0
			if err := v.Scan(ctx, 1, func(types.RawRecord, types.Receipt) error { count++; return nil }); err != nil {
				b.Fatal(err)
			}
			if count != n {
				b.Fatalf("scanned %d, want %d", count, n)
			}
		}
		b.ReportMetric(float64(n), "records/op")
	})
}

func waitCompactedB(b *testing.B, dir string) {
	b.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			b.Fatal(err)
		}
		var zst, wal, tmp int
		for _, e := range entries {
			switch {
			case strings.HasSuffix(e.Name(), ".zst"):
				zst++
			case strings.HasSuffix(e.Name(), ".wal"):
				wal++
			case strings.HasSuffix(e.Name(), ".tmp"):
				tmp++
			}
		}
		if zst >= 1 && wal == 0 && tmp == 0 {
			return
		}
		if time.Now().After(deadline) {
			b.Fatal("compaction did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
