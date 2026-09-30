package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dark-14100/sluice/pkg/control/adminclient"
	"github.com/dark-14100/sluice/pkg/control/internal/apitest"
	"github.com/dark-14100/sluice/pkg/control/mock"
	"github.com/dark-14100/sluice/pkg/control/registry"
	types "github.com/dark-14100/sluice/pkg/types"
)

type env struct {
	t   *testing.T
	m   *mock.Mock
	s   *Server
	reg *registry.Registry
}

var testUI = fstest.MapFS{
	"index.html":           {Data: []byte("<!doctype html><title>ULPF</title>")},
	"assets/app-abc123.js": {Data: []byte("console.log('ulpf')")},
}

func newEnv(t *testing.T) *env {
	t.Helper()
	m := mock.New(mock.Options{Seed: 42})
	reg, err := registry.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	s, err := New(Config{Admin: adminclient.NewInProcess(m.Handler()), Registry: reg, UI: testUI})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, m: m, s: s, reg: reg}
}

func (e *env) do(method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	rec := httptest.NewRecorder()
	e.s.ServeHTTP(rec, httptest.NewRequest(method, path, rd))
	return rec
}

func (e *env) expect(rec *httptest.ResponseRecorder, status int) []byte {
	e.t.Helper()
	if rec.Code != status {
		e.t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	return rec.Body.Bytes()
}

// Proxied routes return exactly what the admin API returns, so their bodies
// must satisfy the admin contract.
func TestProxiedRoutesMatchTheContract(t *testing.T) {
	e := newEnv(t)
	k := apitest.Load(t)
	var list struct {
		Events []types.NormalizedEvent `json:"events"`
	}
	b := e.expect(e.do("GET", "/api/events?limit=5", nil), 200)
	k.Response(t, "GET", "/admin/events", 200, b)
	_ = json.Unmarshal(b, &list)
	id := list.Events[0].EventID
	routes := map[string]string{
		"/api/events/" + id:          "/admin/events/{event_id}",
		"/api/events/" + id + "/raw": "/admin/events/{event_id}/raw",
		"/api/lineage/" + id:         "/admin/lineage/{event_id}",
		"/api/quarantine":            "/admin/quarantine",
		"/api/samples?source_id=palo_alto&status=quarantined": "/admin/samples",
		"/api/drift":                         "/admin/drift",
		"/api/proposals":                     "/admin/proposals",
		"/api/parsers":                       "/admin/parsers",
		"/api/identity/timeline?ip=10.1.4.7": "/admin/identity/timeline",
		"/api/identity/resolve?ip=10.1.4.7&at=2026-09-28T03:00:00Z": "/admin/identity/resolve",
		"/api/identity/graph?user=alice":                            "/admin/identity/graph",
		"/api/vault/segments":                                       "/admin/vault/segments",
		"/api/vault/verify?deep=true":                               "/admin/vault/verify",
		"/api/telemetry":                                            "/admin/telemetry",
	}
	for path, tpl := range routes {
		k.Response(t, "GET", tpl, 200, e.expect(e.do("GET", path, nil), 200))
	}
	// Upstream errors keep their status and the contract's error shape.
	k.Response(t, "GET", "/admin/events/{event_id}", 404, e.expect(e.do("GET", "/api/events/1.nope@1.0.0", nil), 404))
}

func pendingProposal(t *testing.T, e *env, parser string) types.Proposal {
	t.Helper()
	var ps struct {
		Proposals []types.Proposal `json:"proposals"`
	}
	_ = json.Unmarshal(e.expect(e.do("GET", "/api/proposals?status=pending", nil), 200), &ps)
	for _, p := range ps.Proposals {
		if p.ParserID == parser {
			return p
		}
	}
	t.Fatalf("no pending %s proposal", parser)
	return types.Proposal{}
}

func TestApproveWritesTheRegistryAroundTheAdminCall(t *testing.T) {
	e := newEnv(t)
	e.m.Advance() // drift: the fortinet patch appears
	p := pendingProposal(t, e, "fortinet")

	var view struct {
		Proposal   types.Proposal `json:"proposal"`
		ActiveYAML string         `json:"active_yaml"`
	}
	_ = json.Unmarshal(e.expect(e.do("GET", "/api/proposals/"+p.ID, nil), 200), &view)
	if !strings.Contains(view.ActiveYAML, "{from: srcip,") {
		t.Fatal("proposal view should carry the YAML of the base version for the diff")
	}
	var dr types.DryRunResult
	_ = json.Unmarshal(e.expect(e.do("POST", "/api/proposals/"+p.ID+"/dryrun", map[string]any{}), 200), &dr)
	if dr.MatchRate < 0.95 {
		t.Fatalf("dry-run match rate %v", dr.MatchRate)
	}

	e.expect(e.do("POST", "/api/proposals/"+p.ID+"/approve", map[string]any{"comment": "x"}), 400) // no recorded name

	var act activation
	_ = json.Unmarshal(e.expect(e.do("POST", "/api/proposals/"+p.ID+"/approve",
		map[string]any{"approved_by": "nisha", "comment": "firmware 7.4 layout"}), 200), &act)
	if act.Version != "1.0.1" || act.ReplayJobID == nil {
		t.Fatalf("activation %+v", act)
	}
	rows, _ := e.reg.List(context.Background(), "fortinet", 0)
	if len(rows) != 1 || rows[0].Result != registry.ResultOK || rows[0].FromVersion != "1.0.0" || rows[0].ToVersion != "1.0.1" ||
		rows[0].ReplayJobID != *act.ReplayJobID || rows[0].ApprovedBy != "nisha" {
		t.Fatalf("registry row %+v", rows)
	}

	// The same proposal again is stale: its base is no longer active.
	b := e.expect(e.do("POST", "/api/proposals/"+p.ID+"/approve", map[string]any{"approved_by": "nisha", "comment": ""}), 409)
	if !strings.Contains(string(b), CodeStale) {
		t.Fatalf("want %s, got %s", CodeStale, b)
	}
	rows, _ = e.reg.List(context.Background(), "fortinet", 0)
	if rows[0].Result != registry.ResultStale {
		t.Fatalf("stale attempt recorded as %q", rows[0].Result)
	}

	e.m.TickN(10)
	var job struct {
		State     string `json:"state"`
		Succeeded int    `json:"succeeded"`
	}
	_ = json.Unmarshal(e.expect(e.do("GET", "/api/replay/"+*act.ReplayJobID, nil), 200), &job)
	if job.State != "done" || job.Succeeded == 0 {
		t.Fatalf("replay %+v", job)
	}

	var vs struct {
		Versions []struct {
			Version string         `json:"version"`
			Active  bool           `json:"active"`
			History []registry.Row `json:"history"`
		} `json:"versions"`
	}
	_ = json.Unmarshal(e.expect(e.do("GET", "/api/parsers/fortinet/versions", nil), 200), &vs)
	if len(vs.Versions) != 2 || !vs.Versions[0].Active || vs.Versions[0].Version != "1.0.1" || len(vs.Versions[0].History) != 1 {
		t.Fatalf("versions view %+v", vs)
	}
	e.expect(e.do("POST", "/api/parsers/fortinet/rollback", map[string]any{"to_version": "1.0.0", "by": "nisha", "comment": "undo"}), 200)
	all, _ := e.reg.List(context.Background(), "fortinet", 0)
	if all[0].Action != registry.ActionRollback || all[0].Result != registry.ResultOK {
		t.Fatalf("rollback row %+v", all[0])
	}
}

func TestRejectIsRecorded(t *testing.T) {
	e := newEnv(t)
	p := pendingProposal(t, e, "palo_alto_traffic")
	e.expect(e.do("POST", "/api/proposals/"+p.ID+"/reject", map[string]any{"by": "nisha", "comment": "wrong columns"}), 200)
	e.expect(e.do("POST", "/api/proposals/"+p.ID+"/reject", map[string]any{"by": "nisha", "comment": "again"}), 409)
	rows, _ := e.reg.List(context.Background(), "palo_alto_traffic", 0)
	if len(rows) != 2 || rows[1].Result != registry.ResultOK || rows[0].Result != registry.ResultError {
		t.Fatalf("reject rows %+v", rows)
	}
}

func TestAdminUnreachableAndSlow(t *testing.T) {
	dead, _ := adminclient.New("http://127.0.0.1:1") // nothing listens on port 1
	s, _ := New(Config{Admin: dead, UI: testUI, Timeout: 500 * time.Millisecond})
	defer s.Close()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/api/telemetry", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), CodeAdminUnreachable) {
		t.Fatalf("unreachable admin: %d %s", rec.Code, rec.Body)
	}
	// The SPA is still served.
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("SPA not served while the admin is down: %d", rec.Code)
	}

	release := make(chan struct{})
	slowAdmin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	slow, _ := New(Config{Admin: adminclient.NewInProcess(slowAdmin), UI: testUI, Timeout: 100 * time.Millisecond})
	defer slow.Close()
	start := time.Now()
	rec = httptest.NewRecorder()
	slow.ServeHTTP(rec, httptest.NewRequest("GET", "/api/telemetry", nil))
	close(release)
	if rec.Code != http.StatusGatewayTimeout || !strings.Contains(rec.Body.String(), CodeAdminTimeout) || time.Since(start) > 2*time.Second {
		t.Fatalf("slow admin: %d %s after %s", rec.Code, rec.Body, time.Since(start))
	}
}

func TestSPAServingAndHeaders(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/events/7.cisco_asa@1.0.0", "/review"} {
		rec := e.do("GET", path, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>ULPF</title>") {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: index.html must not be cached", path)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
			t.Fatalf("%s: CSP missing", path)
		}
		for _, h := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"} {
			if rec.Header().Get(h) == "" {
				t.Fatalf("%s: %s missing", path, h)
			}
		}
	}
	rec := e.do("GET", "/assets/app-abc123.js", nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("hashed asset: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec := e.do("GET", "/assets/missing.js", nil); rec.Code != 404 {
		t.Fatalf("a missing asset must 404, got %d", rec.Code)
	}
	// /api is never swallowed by the SPA fallback.
	rec = e.do("GET", "/api/nope", nil)
	if rec.Code != 404 || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("/api/nope: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestGzip(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("GET", "/api/telemetry", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	e.s.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("JSON response not gzipped")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !json.Valid(b) {
		t.Fatal("gzipped body is not valid JSON")
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	if b := e.expect(e.do("GET", "/healthz", nil), 200); !strings.Contains(string(b), `"admin":"reachable"`) {
		t.Fatalf("healthz %s", b)
	}
	dead, _ := adminclient.New("http://127.0.0.1:1")
	s, _ := New(Config{Admin: dead, UI: testUI})
	defer s.Close()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"admin":"unreachable"`) {
		t.Fatalf("healthz with the admin down: %d %s", rec.Code, rec.Body)
	}
}
