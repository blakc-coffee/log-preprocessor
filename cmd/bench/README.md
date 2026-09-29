# ULPF benchmark load generator

`bench run` replays fixture records byte-for-byte to a loopback TCP or UDP
ingest socket and reports measured sender throughput, socket-write p50/p99, and
peak process memory. It refuses non-loopback targets.

These are ingress load-generator measurements, not end-to-end ULPF throughput.
The JSON output says so explicitly. End-to-end latency, zero-drop counts, and
vault verification require the data-plane app's commit tap and are not claimed
until that cross-workstream dependency is merged.

