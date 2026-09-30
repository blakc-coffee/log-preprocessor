package ingest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/memvault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// gather collects a registry into a name -> metric family map.
func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range families {
		out[f.GetName()] = f
	}
	return out
}

// TestSourceLabelsAreCapped is the property that protects the monitoring
// system from the thing it monitors.
//
// With dynamic_sources on, an HTTP client chooses the source id, and an
// unbounded label means an unbounded number of time series. Past the cap,
// everything folds into "other" — the records still carry their real
// source_id, only the label collapses.
func TestSourceLabelsAreCapped(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := ingest.NewMetrics(reg)

	// Well past the cap.
	seen := map[string]bool{}
	for i := 0; i < ingest.MaxSourceLabels*4; i++ {
		seen[m.Source(fmt.Sprintf("device-%d", i))] = true
	}

	if len(seen) > ingest.MaxSourceLabels+1 { // +1 for "other"
		t.Errorf("produced %d distinct labels from %d sources; the cap is %d",
			len(seen), ingest.MaxSourceLabels*4, ingest.MaxSourceLabels)
	}
	if !seen["other"] {
		t.Error("nothing folded into `other`, so the cap is not doing anything")
	}

	// A source seen before the cap keeps its own label forever.
	first := m.Source("device-0")
	if first != "device-0" {
		t.Errorf("an early source was relabelled to %q after the cap filled", first)
	}
}

// TestPipelineRecordsMetrics checks the collectors a dashboard actually reads.
func TestPipelineRecordsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	v := memvault.New(memvault.Options{SealEvery: 1000})
	defer v.Close()

	out := make(chan types.RawEvent, 64)
	p, err := ingest.New(ingest.Config{OutBuffer: 64, Registerer: reg}, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}

	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		for i := 0; i < 7; i++ {
			r := rec(i)
			r.Origin.Kind = types.OriginUDP
			if err := st.Submit(ctx, r); err != nil {
				return err
			}
		}
		return nil
	}})

	go func() {
		for range out {
		}
	}()
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	fams := gather(t, reg)
	records, ok := fams["ingest_records_total"]
	if !ok {
		t.Fatal("ingest_records_total was not registered")
	}
	var total float64
	for _, mm := range records.GetMetric() {
		total += mm.GetCounter().GetValue()
		labels := map[string]string{}
		for _, l := range mm.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["source"] != "s" {
			t.Errorf("source label is %q", labels["source"])
		}
		// The type label is derived from the record's origin rather than
		// from configuration, so it cannot disagree with where the bytes
		// actually came from.
		if labels["type"] != "udp" {
			t.Errorf("type label is %q, want udp", labels["type"])
		}
	}
	if total != 7 {
		t.Errorf("ingest_records_total is %v, want 7", total)
	}

	if _, ok := fams["ingest_bytes_total"]; !ok {
		t.Error("ingest_bytes_total was not registered")
	}
}

// TestMetricsAreOptional: a nil registerer must give a working pipeline, so
// no caller has to nil-check before recording.
func TestMetricsAreOptional(t *testing.T) {
	v := memvault.New(memvault.Options{})
	defer v.Close()
	out := make(chan types.RawEvent, 8)

	p, err := ingest.New(ingest.Config{OutBuffer: 8}, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AddSource(fnSource{id: "s", run: func(ctx context.Context, sink ingest.Sink) error {
		st := sink.NewStream("s")
		defer st.Close()
		return st.Submit(ctx, rec(0))
	}})

	go func() {
		for range out {
		}
	}()
	if err := p.Run(context.Background()); err != nil {
		t.Fatalf("a pipeline with no registerer failed: %v", err)
	}
}

// TestEveryDocumentedMetricExists guards the names PRD section 13 lists, which
// a dashboard will be written against. Renaming one silently breaks every
// query built on it, and the break shows up as an empty graph rather than an
// error.
//
// A Vec with no observations reports no metric family, so presence is checked
// by attempting a conflicting registration: if the name is taken, Prometheus
// refuses.
func TestEveryDocumentedMetricExists(t *testing.T) {
	want := []string{
		"ingest_records_total", "ingest_bytes_total", "ingest_fragments_total",
		"ingest_frame_errors_total", "ingest_connections", "ingest_out_queue_depth",
		"ingest_udp_kernel_drops", "ingest_file_truncations_total",
		"ingest_checkpoint_writes_total",
	}
	for _, name := range want {
		reg := prometheus.NewRegistry()
		ingest.NewMetrics(reg)
		err := reg.Register(prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"}))
		if err == nil {
			t.Errorf("metric %q is not registered; PRD section 13 lists it", name)
		}
	}
}

// TestEveryVaultMetricExists does the same for the vault's set.
func TestEveryVaultMetricExists(t *testing.T) {
	want := []string{
		"vault_put_total", "vault_put_latency_seconds", "vault_fsync_seconds",
		"vault_group_size_records", "vault_active_segment_bytes",
		"vault_segments_sealed_total", "vault_seal_seconds",
		"vault_verify_failures_total", "vault_failed",
		"vault_compaction_seconds", "vault_compaction_ratio",
		"vault_compaction_bytes_in_total", "vault_compaction_bytes_out_total",
		"vault_compaction_failures_total",
	}
	for _, name := range want {
		reg := prometheus.NewRegistry()
		vault.NewMetrics(reg)
		err := reg.Register(prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"}))
		if err == nil {
			t.Errorf("metric %q is not registered; PRD section 13 lists it", name)
		}
	}
}

// TestVaultFailedGaugeRises: vault_failed is the only signal that the vault
// has stopped accepting writes entirely, and it is what an alert fires on.
func TestVaultFailedIsAGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := vault.NewMetrics(reg)
	m.Failed.Set(1)

	fams := gather(t, reg)
	f, ok := fams["vault_failed"]
	if !ok {
		t.Fatal("vault_failed is not exported")
	}
	if f.GetType() != dto.MetricType_GAUGE {
		// A counter would make "it failed an hour ago" and "it is failing
		// now" the same number.
		t.Errorf("vault_failed is %v, want a gauge", f.GetType())
	}
	if got := f.GetMetric()[0].GetGauge().GetValue(); got != 1 {
		t.Errorf("vault_failed is %v after being set", got)
	}
}
