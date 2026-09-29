// Package telemetry holds inexpensive data-plane counters.
package telemetry

import (
	"sync"
	"sync/atomic"
	"time"
)

type Source struct {
	ID      string  `json:"id"`
	EPS     float64 `json:"eps"`
	Records uint64  `json:"records"`
}
type Metrics struct {
	events      atomic.Uint64
	quarantined atomic.Uint64
	peak        atomic.Uint64
	started     time.Time
	mu          sync.Mutex
	sources     map[string]uint64
}

func New() *Metrics { return &Metrics{started: time.Now(), sources: map[string]uint64{}} }
func (m *Metrics) Event(source string) {
	n := m.events.Add(1)
	m.bump(n)
	m.mu.Lock()
	m.sources[source]++
	m.mu.Unlock()
}
func (m *Metrics) Quarantine(source string) {
	n := m.quarantined.Add(1)
	m.bump(n)
	m.mu.Lock()
	m.sources[source]++
	m.mu.Unlock()
}
func (m *Metrics) bump(n uint64) {
	for {
		p := m.peak.Load()
		if n <= p || m.peak.CompareAndSwap(p, n) {
			return
		}
	}
}
func (m *Metrics) Snapshot() (float64, float64, uint64, uint64, []Source) {
	seconds := time.Since(m.started).Seconds()
	if seconds < 1 {
		seconds = 1
	}
	events := m.events.Load()
	quarantined := m.quarantined.Load()
	m.mu.Lock()
	defer m.mu.Unlock()
	sources := make([]Source, 0, len(m.sources))
	for id, n := range m.sources {
		sources = append(sources, Source{ID: id, EPS: float64(n) / seconds, Records: n})
	}
	return float64(events+quarantined) / seconds, float64(m.peak.Load()), events, quarantined, sources
}
