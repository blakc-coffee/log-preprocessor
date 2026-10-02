package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func call(t *testing.T, s *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func ids(t *testing.T, s *Server) map[string]string {
	t.Helper()
	_, out := call(t, s, http.MethodGet, "/admin/proposals", "")
	got := map[string]string{}
	for _, p := range out["proposals"].([]any) {
		m := p.(map[string]any)
		got[m["id"].(string)] = m["status"].(string)
	}
	return got
}

// The bug: proposals lived in memory, so a restart emptied the review queue and reissued
// proposal ids, which the approval audit trail refers to.
func TestProposalsAndIdsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-state.json")
	first := New(nil, nil, nil, nil, nil)
	if err := first.Persist(path); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"a", "b"} {
		if code, _ := call(t, first, http.MethodPost, "/admin/proposals", `{"kind":"new","parser_id":"p_`+src+`","source_id":"`+src+`","yaml":"y"}`); code != 201 {
			t.Fatalf("create: %d", code)
		}
	}
	if code, _ := call(t, first, http.MethodPost, "/admin/proposals/proposal-000002/reject", `{"by":"me","comment":"no"}`); code != 200 {
		t.Fatalf("reject: %d", code)
	}
	if code, _ := call(t, first, http.MethodPost, "/admin/drift", `{"source_id":"a","parser_id":"p_a","score":0.9}`); code != 201 && code != 200 {
		t.Fatalf("alert: %d", code)
	}

	second := New(nil, nil, nil, nil, nil) // a restart
	if err := second.Persist(path); err != nil {
		t.Fatal(err)
	}
	got := ids(t, second)
	if got["proposal-000001"] != "pending" || got["proposal-000002"] != "rejected" || len(got) != 2 {
		t.Fatalf("proposals after restart: %v", got)
	}
	code, created := call(t, second, http.MethodPost, "/admin/proposals", `{"kind":"new","parser_id":"p_c","source_id":"c","yaml":"y"}`)
	if code != 201 || created["id"] == "proposal-000001" || created["id"] == "proposal-000002" {
		t.Fatalf("an id was reissued after the restart: %v", created["id"])
	}
	if n := len(second.alerts); n != 1 {
		t.Fatalf("drift alerts after restart: %d", n)
	}
}

func TestNoStateFileIsFineAndCorruptOneIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := New(nil, nil, nil, nil, nil).Persist(filepath.Join(dir, "none.json")); err != nil {
		t.Fatalf("a missing file is a first run, not an error: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o600)
	if err := New(nil, nil, nil, nil, nil).Persist(bad); err == nil {
		t.Fatal("a corrupt state file must be reported, not silently discarded")
	}
}
