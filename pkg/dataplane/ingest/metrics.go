package ingest

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics for the ingest path.
//
// # Label cardinality is a correctness problem, not a tidiness one
//
// `source` is a label, and with `dynamic_sources: true` an HTTP client chooses
// it. An unbounded label is an unbounded number of time series, which is how a
// Prometheus server is taken down by the thing it is monitoring. Sources are
// therefore capped: past MaxSourceLabels distinct values, everything else folds
// into `other`. The records still carry their real source_id — only the metric
// label is collapsed, so nothing is lost that matters.

// MaxSourceLabels bounds how many distinct `source` label values are emitted.
const MaxSourceLabels = 50

// otherSource is where everything past the cap folds.
const otherSource = "other"

// Metrics holds the ingest collectors.
type Metrics struct {
	Records        *prometheus.CounterVec // by source, type
	Bytes          *prometheus.CounterVec // by source, type
	Fragments      *prometheus.CounterVec // by source
	FrameErrors    *prometheus.CounterVec // by source, reason
	Connections    *prometheus.GaugeVec   // by source
	Truncations    *prometheus.CounterVec // by source
	Checkpoints    *prometheus.CounterVec // by source
	OutQueue       prometheus.Gauge
	UDPKernelDrops prometheus.Gauge

	// limiter caps the source label space.
	limiter *labelLimiter
}

// NewMetrics registers the ingest collectors. A nil registerer is valid and
// gives a working Metrics that is simply never scraped, so callers never have
// to nil-check before recording.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	f := promauto(reg)

	return &Metrics{
		Records: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_records_total",
			Help: "Records accepted and made durable, by source and source type.",
		}, "source", "type"),
		Bytes: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_bytes_total",
			Help: "Raw payload bytes accepted, by source and source type. Excludes terminators, which are recorded rather than stored.",
		}, "source", "type"),
		Fragments: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_fragments_total",
			Help: "Fragments emitted for records larger than max_frame_bytes. Nothing is truncated; a rising count means oversize records, not loss.",
		}, "source"),
		FrameErrors: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_frame_errors_total",
			Help: "Connections closed on a framing violation, by reason. A sender to go and look at.",
		}, "source", "reason"),
		Connections: f.gaugeVec(prometheus.GaugeOpts{
			Name: "ingest_connections",
			Help: "Open connections, by source. Compare against limits.max_conns.",
		}, "source"),
		Truncations: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_file_truncations_total",
			Help: "Times a tailed file shrank below the read offset, by source. Normal with copytruncate rotation.",
		}, "source"),
		Checkpoints: f.counterVec(prometheus.CounterOpts{
			Name: "ingest_checkpoint_writes_total",
			Help: "Tail checkpoints written, by source. Each bounds how much is re-read after a crash.",
		}, "source"),
		OutQueue: f.gauge(prometheus.GaugeOpts{
			Name: "ingest_out_queue_depth",
			Help: "Records durable but not yet handed downstream. Sustained near out_buffer means the consumer is the bottleneck and sources are being back-pressured.",
		}),
		UDPKernelDrops: f.gauge(prometheus.GaugeOpts{
			Name: "ingest_udp_kernel_drops",
			Help: "Datagrams the kernel dropped before this process saw them (Linux only, from /proc/net/snmp). These are unrecoverable.",
		}),
		limiter: newLabelLimiter(MaxSourceLabels),
	}
}

// Source caps a source label. Use it for every label value that could come
// from the network.
func (m *Metrics) Source(id string) string {
	if m == nil {
		return id
	}
	return m.limiter.get(id)
}

// labelLimiter folds label values past a cap into a single bucket.
type labelLimiter struct {
	max int

	mu   sync.RWMutex
	seen map[string]bool
}

func newLabelLimiter(max int) *labelLimiter {
	return &labelLimiter{max: max, seen: map[string]bool{}}
}

func (l *labelLimiter) get(v string) string {
	l.mu.RLock()
	known := l.seen[v]
	full := len(l.seen) >= l.max
	l.mu.RUnlock()

	if known {
		return v
	}
	if full {
		return otherSource
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-check: another goroutine may have filled the last slot.
	if l.seen[v] {
		return v
	}
	if len(l.seen) >= l.max {
		return otherSource
	}
	l.seen[v] = true
	return v
}

// promauto is a small helper so the collector definitions above read as a
// list rather than as error handling.
type promFactory struct{ reg prometheus.Registerer }

func promauto(reg prometheus.Registerer) promFactory { return promFactory{reg} }

// register panics on a duplicate registration, which is a programming error
// (two Metrics on one registry), never a runtime condition.
func (f promFactory) counterVec(o prometheus.CounterOpts, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(o, labels)
	f.reg.MustRegister(c)
	return c
}

func (f promFactory) gaugeVec(o prometheus.GaugeOpts, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(o, labels)
	f.reg.MustRegister(g)
	return g
}

func (f promFactory) gauge(o prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(o)
	f.reg.MustRegister(g)
	return g
}
