# ULPF empirical benchmark

In-process parser detection, extraction, normalization, and SHA-256 receipt throughput. Compression ratios use bounded representative samples.

- Started: 2026-09-29T15:42:55Z
- Platform: windows/amd64, go1.25.1
- Memory source: GetProcessMemoryInfo PeakWorkingSetSize
- Sync mode: memory (not a durable-fsync claim)

Latency values of 0 indicate samples below the host clock's observable resolution.

| Workers | EPS | p50 µs | p95 µs | p99 µs | Peak RSS bytes | Vault zstd | Parquet |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 86716 | 0.000 | 0.000 | 340.600 | 143179776 | 6.63x | 40.59x |
