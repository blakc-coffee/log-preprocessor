// Package quarantine tracks records that did not produce a normalized event.
package quarantine

import (
	"sort"
	"sync"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type Store struct {
	mu      sync.RWMutex
	records map[types.RecordID]types.QuarantineRecord
}

type Summary struct {
	SourceID string         `json:"source_id"`
	Open     int            `json:"open"`
	Resolved int            `json:"resolved"`
	Ignored  int            `json:"ignored"`
	ByStage  map[string]int `json:"by_stage"`
}

func New() *Store { return &Store{records: map[types.RecordID]types.QuarantineRecord{}} }
func (s *Store) Put(record types.QuarantineRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.Status == "" {
		record.Status = "open"
	}
	_, exists := s.records[record.RecordID]
	s.records[record.RecordID] = record
	return !exists
}
func (s *Store) Resolve(id types.RecordID, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.records[id]; ok {
		record.Status = "resolved"
		record.ResolvedBy = by
		s.records[id] = record
	}
}
func (s *Store) Get(id types.RecordID) (types.QuarantineRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[id]
	return record, ok
}
func (s *Store) List(source, status string, limit int) []types.QuarantineRecord {
	return s.ListStage(source, status, "", limit)
}

func (s *Store) ListStage(source, status, stage string, limit int) []types.QuarantineRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]int, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]types.QuarantineRecord, 0, limit)
	for _, n := range ids {
		record := s.records[types.RecordID(n)]
		if source != "" && record.SourceID != source || status != "" && record.Status != status || stage != "" && record.FailureStage != stage {
			continue
		}
		out = append(out, record)
		if len(out) == limit {
			break
		}
	}
	return out
}
func (s *Store) OpenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, record := range s.records {
		if record.Status == "open" {
			n++
		}
	}
	return n
}
func (s *Store) Total() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.records) }

func (s *Store) Summary(source string) []Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bySource := map[string]*Summary{}
	for _, record := range s.records {
		if source != "" && record.SourceID != source {
			continue
		}
		summary := bySource[record.SourceID]
		if summary == nil {
			summary = &Summary{SourceID: record.SourceID, ByStage: map[string]int{}}
			bySource[record.SourceID] = summary
		}
		switch record.Status {
		case "open":
			summary.Open++
		case "resolved":
			summary.Resolved++
		case "ignored":
			summary.Ignored++
		}
		summary.ByStage[record.FailureStage]++
	}
	ids := make([]string, 0, len(bySource))
	for id := range bySource {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Summary, 0, len(ids))
	for _, id := range ids {
		out = append(out, *bySource[id])
	}
	return out
}
