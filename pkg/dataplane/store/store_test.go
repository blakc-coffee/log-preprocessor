package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	types "github.com/dark-14100/sluice/pkg/types"
)

func ev(rec uint64, parser string, ip string, at time.Time) types.NormalizedEvent {
	return types.NormalizedEvent{
		EventID: fmt.Sprintf("%d.%s@1.0.0", rec, parser), RecordID: types.RecordID(rec), SourceID: "s", ParserID: parser,
		ReceivedAt: at, EventTime: &at, Entities: []types.Entity{},
		OCSF: map[string]any{"src_endpoint": map[string]any{"ip": ip}, "dst_endpoint": map[string]any{"ip": "203.0.113.1"}},
	}
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if !s.Put(ev(i, "a", "10.0.0.1", at.Add(time.Duration(i)*time.Second))) {
			t.Fatalf("put %d", i)
		}
	}
	if s.Put(ev(3, "a", "10.0.0.1", at)) {
		t.Fatal("the same event version must not be stored twice")
	}
	// a new parser version for record 3 becomes current; the old one stays, not current
	s.Put(ev(3, "b", "10.0.0.1", at))
	if old, _ := s.Get("3.a@1.0.0"); old.Current {
		t.Fatal("superseded version must not be current")
	}
	if cur, ok := s.CurrentByRecord(3); !ok || cur.ParserID != "b" {
		t.Fatalf("current for record 3 = %+v", cur)
	}
	// pages: newest record first, cursor continues exactly where the page ended
	p1, cur := s.List("", "", false, nil, nil, "", 3)
	if len(p1) != 3 || cur == nil || p1[0].RecordID != 5 {
		t.Fatalf("page 1: %d events, cursor %v", len(p1), cur)
	}
	p2, cur2 := s.List("", "", false, nil, nil, *cur, 3)
	if len(p2) != 3 || cur2 != nil || p2[0].RecordID == p1[2].RecordID && p2[0].EventID == p1[2].EventID {
		t.Fatalf("page 2: %d events, cursor %v", len(p2), cur2)
	}
	if cur, _ := s.List("", "", true, nil, nil, "", 100); len(cur) != 5 {
		t.Fatalf("current-only: %d events, want 5", len(cur))
	}
	// late identity change rewrites entities of the affected events only
	n := s.Reenrich("10.0.0.1", at, at.Add(time.Hour), func(ip string, _ time.Time) []types.Entity {
		return []types.Entity{{Type: "user", ID: "carol"}}
	})
	if n != 5 {
		t.Fatalf("reenriched %d, want 5 current events", n)
	}
	if got, _ := s.Get("5.a@1.0.0"); len(got.Entities) != 2 || got.Entities[0].Role != "src" {
		t.Fatalf("entities after reenrich: %+v", got.Entities)
	}
	// durable across reopen, and the count and max survive
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 6 || s.MaxRecordID() != 5 {
		t.Fatalf("after reopen: count %d max %d", s.Count(), s.MaxRecordID())
	}
	if _, err := s.Get("nope"); err != ErrNotFound {
		t.Fatalf("missing event: %v", err)
	}
}
