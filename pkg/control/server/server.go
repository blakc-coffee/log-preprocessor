// Package server is the control plane's HTTP surface on :8000: the embedded
// UI, the control API under /api/, and /healthz.
//
// The control API is mostly a typed pass-through to the data plane's admin
// API. It adds three things (Frontend PRD 2): the approval registry, stable
// error codes the UI can render, and combined views such as a proposal with
// the YAML of the version it patches.
//
// Authentication is optional (Config.Users). Without it, bind to loopback; the
// UI's About panel and the README say so.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/control/adminclient"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/registry"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/ui"
)

// Config wires the server. Admin is required; everything else has a default.
type Config struct {
	// Admin reaches the data plane's admin API (or the mock).
	Admin *adminclient.Client
	// Registry records approvals. Nil opens an in-memory registry, which is
	// only suitable for --mock and tests.
	Registry *registry.Registry
	// UI is the built frontend. Nil means the embedded build.
	UI fs.FS
	// Timeout bounds ordinary admin calls; LongTimeout bounds dry-run, approve
	// and deep verification. Defaults 5s and 30s.
	Timeout, LongTimeout time.Duration
	Logger               *slog.Logger
	// Users turns on HTTP Basic sign-in for everything except /healthz. Nil
	// means no authentication: only safe on loopback.
	Users Users
	// Metrics, when set, is served at GET /metrics (behind sign-in when on).
	Metrics http.Handler
}

// Server is an http.Handler. Close releases a registry the server opened.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	handler http.Handler
	ownsReg bool
	log     *slog.Logger
}

// New builds the handler. The returned value is an http.Handler (the
// integration surface cmd/ulpf uses) and also has Close.
func New(cfg Config) (*Server, error) {
	if cfg.Admin == nil {
		return nil, errors.New("server: Config.Admin is required")
	}
	s := &Server{cfg: cfg}
	if s.cfg.Registry == nil {
		reg, err := registry.Open(":memory:")
		if err != nil {
			return nil, err
		}
		s.cfg.Registry, s.ownsReg = reg, true
	}
	if s.cfg.UI == nil {
		s.cfg.UI = ui.Dist()
	}
	if s.cfg.Timeout == 0 {
		s.cfg.Timeout = 5 * time.Second
	}
	if s.cfg.LongTimeout == 0 {
		s.cfg.LongTimeout = 30 * time.Second
	}
	s.log = cfg.Logger
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.routes()
	s.handler = securityHeaders(gzipMiddleware(s.mux))
	if cfg.Users != nil {
		s.handler = authMiddleware(cfg.Users, s.handler)
	}
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Close closes the registry if the server opened it.
func (s *Server) Close() error {
	if s.ownsReg {
		return s.cfg.Registry.Close()
	}
	return nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	s.mux = m

	pass := func(pattern, admin string) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { s.proxy(w, r, admin) })
	}
	pass("GET /api/events", "/admin/events")
	pass("GET /api/events/{id}", "/admin/events/{id}")
	pass("GET /api/events/{id}/raw", "/admin/events/{id}/raw")
	pass("GET /api/lineage/{id}", "/admin/lineage/{id}")
	pass("GET /api/quarantine", "/admin/quarantine")
	pass("GET /api/samples", "/admin/samples")
	pass("GET /api/drift", "/admin/drift")
	pass("GET /api/proposals", "/admin/proposals")
	pass("GET /api/replay/{id}", "/admin/replay/{id}")
	pass("GET /api/parsers", "/admin/parsers")
	pass("GET /api/identity/timeline", "/admin/identity/timeline")
	pass("GET /api/identity/resolve", "/admin/identity/resolve")
	pass("GET /api/identity/graph", "/admin/identity/graph")
	pass("GET /api/vault/segments", "/admin/vault/segments")
	pass("GET /api/vault/verify", "/admin/vault/verify")
	pass("GET /api/telemetry", "/admin/telemetry")

	m.HandleFunc("GET /api/proposals/{id}", s.getProposal)
	m.HandleFunc("POST /api/proposals/{id}/dryrun", s.dryRunProposal)
	m.HandleFunc("POST /api/proposals/{id}/approve", s.approve)
	m.HandleFunc("POST /api/proposals/{id}/reject", s.reject)
	m.HandleFunc("GET /api/parsers/{id}/versions", s.parserVersions)
	m.HandleFunc("GET /api/parsers/{id}/versions/{v}", s.parserYAML)
	m.HandleFunc("POST /api/parsers/{id}/rollback", s.rollback)
	m.HandleFunc("POST /api/parsers/{id}/verify", s.verifyParser)
	m.HandleFunc("GET /api/history", s.history)
	m.HandleFunc("GET /healthz", s.healthz)
	if s.cfg.Metrics != nil {
		m.Handle("GET /metrics", s.cfg.Metrics)
	}
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no control API route "+r.Method+" "+r.URL.Path)
	})
	m.Handle("/", ui.Handler(s.cfg.UI))
}

// ---- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// Error codes the UI relies on. Upstream admin errors keep their own codes.
const (
	CodeAdminUnreachable = "admin_unreachable"
	CodeAdminTimeout     = "admin_timeout"
	CodeBadUpstream      = "bad_upstream"
	CodeStale            = "stale_base_version"
	CodeBadRequest       = "bad_request"
)

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// adminFailure maps a transport failure to the stable codes.
func adminFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminclient.ErrTimeout):
		writeErr(w, http.StatusGatewayTimeout, CodeAdminTimeout, err.Error())
	case errors.Is(err, adminclient.ErrUnreachable):
		writeErr(w, http.StatusBadGateway, CodeAdminUnreachable, "the data plane admin API is unreachable")
	default:
		writeErr(w, http.StatusBadGateway, CodeBadUpstream, err.Error())
	}
}

// relay writes an admin response to the client. A 2xx body that is not
// valid JSON is a contract violation, reported as bad_upstream rather than
// forwarded.
func relay(w http.ResponseWriter, resp *adminclient.Response) {
	ct := resp.Header.Get("Content-Type")
	if !json.Valid(resp.Body) {
		if resp.OK() {
			writeErr(w, http.StatusBadGateway, CodeBadUpstream, "admin API returned a non-JSON body")
			return
		}
		writeErr(w, resp.Status, "upstream_error", fmt.Sprintf("admin API returned %d", resp.Status))
		return
	}
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func expand(tpl string, r *http.Request) string {
	out := []byte{}
	for i := 0; i < len(tpl); i++ {
		if tpl[i] == '{' {
			j := i + 1
			for j < len(tpl) && tpl[j] != '}' {
				j++
			}
			out = append(out, escapePath(r.PathValue(tpl[i+1:j]))...)
			i = j
			continue
		}
		out = append(out, tpl[i])
	}
	if q := r.URL.RawQuery; q != "" {
		out = append(out, '?')
		out = append(out, q...)
	}
	return string(out)
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request, adminTpl string) {
	timeout := s.cfg.Timeout
	if adminTpl == "/admin/vault/verify" {
		timeout = s.cfg.LongTimeout
	}
	resp, err := s.cfg.Admin.Do(r.Context(), timeout, r.Method, expand(adminTpl, r), nil, "")
	if err != nil {
		adminFailure(w, err)
		return
	}
	relay(w, resp)
}

// call makes an admin request and decodes a 2xx JSON body into out. On any
// failure it writes the error response and returns false.
func (s *Server) call(w http.ResponseWriter, ctx context.Context, timeout time.Duration, method, path string, body any, out any) (*adminclient.Response, bool) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			writeErr(w, 500, "internal", err.Error())
			return nil, false
		}
	}
	resp, err := s.cfg.Admin.Do(ctx, timeout, method, path, b, "")
	if err != nil {
		adminFailure(w, err)
		return nil, false
	}
	if !resp.OK() {
		return resp, false
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			writeErr(w, http.StatusBadGateway, CodeBadUpstream, "admin API response does not match the contract: "+err.Error())
			return nil, false
		}
	}
	return resp, true
}

// decodeBody reads a small JSON request body, refusing unknown fields.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, CodeBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}
