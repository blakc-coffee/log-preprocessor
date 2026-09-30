// Package replay reprocesses vaulted records under the active parser set.
package replay

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/app"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type Job struct {
	JobID      string     `json:"job_id"`
	Scope      string     `json:"scope"`
	State      string     `json:"state"`
	Processed  int        `json:"processed"`
	Succeeded  int        `json:"succeeded"`
	Failed     int        `json:"failed"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      *string    `json:"error"`
}
type Manager struct {
	vault types.Vault
	app   *app.App
	mu    sync.RWMutex
	jobs  map[string]Job
	next  atomic.Uint64
}

func New(vault types.Vault, pipeline *app.App) *Manager {
	return &Manager{vault: vault, app: pipeline, jobs: map[string]Job{}}
}
func (m *Manager) Start(ctx context.Context, scope, source string) Job {
	id := fmt.Sprintf("replay-%06d", m.next.Add(1))
	job := Job{JobID: id, Scope: scope, State: "queued"}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	go m.run(context.WithoutCancel(ctx), id, source)
	return job
}
func (m *Manager) Get(id string) (Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	return job, ok
}
func (m *Manager) run(ctx context.Context, id, source string) {
	now := time.Now().UTC()
	m.update(id, func(j *Job) { j.State = "running"; j.StartedAt = &now })
	err := m.vault.Scan(ctx, 0, func(record types.RawRecord, receipt types.Receipt) error {
		if source != "" && record.SourceID != source {
			return nil
		}
		if job, _ := m.Get(id); job.Scope == "quarantine" {
			quarantined, ok := m.app.Quarantine.Get(receipt.ID)
			if !ok || quarantined.Status != "open" {
				return nil
			}
		}
		event := types.RawEvent{RawRecord: record, Receipt: receipt}
		m.update(id, func(j *Job) { j.Processed++ })
		if err := m.app.Process(ctx, event); err != nil {
			m.update(id, func(j *Job) { j.Failed++ })
			return nil
		}
		// A record no parser claims stays quarantined: processed, but neither
		// succeeded nor failed. Failed means the pipeline itself errored.
		if _, ok := m.app.Events.CurrentByRecord(receipt.ID); ok {
			m.update(id, func(j *Job) { j.Succeeded++ })
		}
		return nil
	})
	finished := time.Now().UTC()
	m.update(id, func(j *Job) {
		j.State = "done"
		j.FinishedAt = &finished
		if err != nil {
			s := err.Error()
			j.Error = &s
			j.State = "failed"
		}
	})
}
func (m *Manager) update(id string, fn func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	fn(&job)
	m.jobs[id] = job
}
