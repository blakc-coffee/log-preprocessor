package vault

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics for the vault.
//
// The two that matter operationally are vault_failed and vault_fsync_seconds.
// The first is the only signal that the vault has stopped accepting writes at
// all, and it is a gauge rather than a counter because "it happened once an
// hour ago" and "it is happening now" are the same number otherwise. The
// second is where throughput goes: an fsync that has crept from 2 ms to 40 ms
// is the whole explanation for a drop in ingest rate.
type Metrics struct {
	Puts           prometheus.Counter
	PutLatency     prometheus.Histogram
	FsyncSeconds   prometheus.Histogram
	GroupSize      prometheus.Histogram
	ActiveBytes    prometheus.Gauge
	SegmentsSealed prometheus.Counter
	SealSeconds    prometheus.Histogram
	VerifyFailures prometheus.Counter
	Failed         prometheus.Gauge
}

// NewMetrics registers the vault collectors. A nil registerer gives a working
// Metrics that is never scraped, so the write path never nil-checks.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}

	newCounter := func(o prometheus.CounterOpts) prometheus.Counter {
		c := prometheus.NewCounter(o)
		reg.MustRegister(c)
		return c
	}
	newGauge := func(o prometheus.GaugeOpts) prometheus.Gauge {
		g := prometheus.NewGauge(o)
		reg.MustRegister(g)
		return g
	}
	newHistogram := func(o prometheus.HistogramOpts) prometheus.Histogram {
		h := prometheus.NewHistogram(o)
		reg.MustRegister(h)
		return h
	}

	// Latency buckets span microseconds to seconds: sync=none writes land in
	// the low microseconds, an fsync to an SSD in the low milliseconds, and a
	// struggling disk in the hundreds. Default buckets would put all three in
	// one bucket and say nothing.
	latency := []float64{
		50e-6, 100e-6, 250e-6, 500e-6,
		0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1, 2.5, 5,
	}

	return &Metrics{
		Puts: newCounter(prometheus.CounterOpts{
			Name: "vault_put_total",
			Help: "Records made durable.",
		}),
		PutLatency: newHistogram(prometheus.HistogramOpts{
			Name:    "vault_put_latency_seconds",
			Help:    "Time from a batch reaching the writer to it being acknowledged. In sync=always this includes the fsync; in sync=interval it does not, and the acknowledgement does not mean on-disk.",
			Buckets: latency,
		}),
		FsyncSeconds: newHistogram(prometheus.HistogramOpts{
			Name:    "vault_fsync_seconds",
			Help:    "Time spent in fsync. This is usually where throughput goes.",
			Buckets: latency,
		}),
		GroupSize: newHistogram(prometheus.HistogramOpts{
			Name:    "vault_group_size_records",
			Help:    "Records coalesced into one write and one fsync. A value stuck at 1 under load means group commit is not batching and throughput is paying one fsync per record.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096},
		}),
		ActiveBytes: newGauge(prometheus.GaugeOpts{
			Name: "vault_active_segment_bytes",
			Help: "Bytes in the segment currently being written. Compare against segment_max_bytes.",
		}),
		SegmentsSealed: newCounter(prometheus.CounterOpts{
			Name: "vault_segments_sealed_total",
			Help: "Segments sealed. Records are only covered by a Merkle root, and only provable, once their segment is sealed.",
		}),
		SealSeconds: newHistogram(prometheus.HistogramOpts{
			Name:    "vault_seal_seconds",
			Help:    "Time to compute a segment root, write the footer and append the ledger line. Seal happens on the writer goroutine, so this is time not spent accepting records.",
			Buckets: latency,
		}),
		VerifyFailures: newCounter(prometheus.CounterOpts{
			Name: "vault_verify_failures_total",
			Help: "Records or chain links that failed verification. Any non-zero value means tampering or corruption and should page someone.",
		}),
		Failed: newGauge(prometheus.GaugeOpts{
			Name: "vault_failed",
			Help: "1 when the vault has entered its terminal failed state and is refusing all writes. A restart is required. Alert on this.",
		}),
	}
}
