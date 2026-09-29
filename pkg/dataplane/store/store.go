// Package store keeps normalized event versions and their current pointers.
package store

import (
	"errors"
	"sort"
	"sync"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

var ErrNotFound = errors.New("store: event not found")

type Store struct {
	mu       sync.RWMutex
	byID     map[string]types.NormalizedEvent
	byRecord map[types.RecordID][]string
}

func New() *Store {
	return &Store{byID: map[string]types.NormalizedEvent{}, byRecord: map[types.RecordID][]string{}}
}

func (s *Store) Put(event types.NormalizedEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[event.EventID]; exists {
		return false
	}
	for _, id := range s.byRecord[event.RecordID] {
		old := s.byID[id]
		old.Current = false
		s.byID[id] = old
	}
	event.Current = true
	s.byID[event.EventID] = event
	s.byRecord[event.RecordID] = append(s.byRecord[event.RecordID], event.EventID)
	return true
}

func (s *Store) Get(id string) (types.NormalizedEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.byID[id]
	if !ok {
		return types.NormalizedEvent{}, ErrNotFound
	}
	return event, nil
}

func (s *Store) List(source, parser string, currentOnly bool, from, to *time.Time, after string, limit int) ([]types.NormalizedEvent, *string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.byID[ids[i]], s.byID[ids[j]]
		if a.RecordID != b.RecordID {
			return a.RecordID > b.RecordID
		}
		return ids[i] > ids[j]
	})
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]types.NormalizedEvent, 0, limit)
	started := after == ""
	for _, id := range ids {
		if !started {
			if id == after {
				started = true
			}
			continue
		}
		event := s.byID[id]
		if source != "" && event.SourceID != source || parser != "" && event.ParserID != parser || currentOnly && !event.Current {
			continue
		}
		if from != nil && event.ReceivedAt.Before(*from) || to != nil && event.ReceivedAt.After(*to) {
			continue
		}
		if len(out) == limit {
			cursor := out[len(out)-1].EventID
			return out, &cursor
		}
		out = append(out, event)
	}
	return out, nil
}

func (s *Store) CurrentByRecord(id types.RecordID) (types.NormalizedEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, eid := range s.byRecord[id] {
		if event := s.byID[eid]; event.Current {
			return event, true
		}
	}
	return types.NormalizedEvent{}, false
}
func (s *Store) Count() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.byID) }

func (s *Store) MaxRecordID() types.RecordID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var max types.RecordID
	for recordID := range s.byRecord {
		if recordID > max {
			max = recordID
		}
	}
	return max
}

func (s *Store) Reenrich(ip string, from, to time.Time, resolve func(string, time.Time) []types.Entity) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := 0
	for id, event := range s.byID {
		if !event.Current || event.EventTime == nil || event.EventTime.Before(from) || !event.EventTime.Before(to) {
			continue
		}
		if endpointIP(event.OCSF, "src_endpoint") != ip && endpointIP(event.OCSF, "dst_endpoint") != ip {
			continue
		}
		event.Entities = enrichEntities(event, resolve)
		s.byID[id] = event
		changed++
	}
	return changed
}

func enrichEntities(event types.NormalizedEvent, resolve func(string, time.Time) []types.Entity) []types.Entity {
	var out []types.Entity
	for _, role := range []string{"src", "dst"} {
		ip := endpointIP(event.OCSF, role+"_endpoint")
		for _, entity := range resolve(ip, *event.EventTime) {
			entity.Role = role
			out = append(out, entity)
		}
	}
	return out
}
func endpointIP(ocsf map[string]any, key string) string {
	endpoint, _ := ocsf[key].(map[string]any)
	value, _ := endpoint["ip"].(string)
	return value
}
