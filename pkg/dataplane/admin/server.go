// Package admin serves the loopback-only data-plane administration API.
package admin

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/app"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/identity"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/registry"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/replay"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type Server struct {
	vault     types.Vault
	app       *app.App
	registry  *registry.Registry
	replay    *replay.Manager
	identity  *identity.Resolver
	mu        sync.RWMutex
	alerts    []types.DriftAlert
	proposals map[string]types.Proposal
	next      uint64
}

func New(vault types.Vault, pipeline *app.App, reg *registry.Registry, replays *replay.Manager, resolver *identity.Resolver) *Server {
	return &Server{vault: vault, app: pipeline, registry: reg, replay: replays, identity: resolver, proposals: map[string]types.Proposal{}}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/healthz":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	case r.Method == "GET" && p == "/admin/events":
		s.events(w, r)
	case r.Method == "GET" && strings.HasPrefix(p, "/admin/events/") && strings.HasSuffix(p, "/raw"):
		s.raw(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/admin/events/"), "/raw"))
	case r.Method == "GET" && strings.HasPrefix(p, "/admin/events/"):
		s.event(w, strings.TrimPrefix(p, "/admin/events/"))
	case r.Method == "GET" && strings.HasPrefix(p, "/admin/lineage/"):
		s.lineage(w, strings.TrimPrefix(p, "/admin/lineage/"))
	case r.Method == "GET" && p == "/admin/quarantine":
		s.quarantine(w, r)
	case r.Method == "GET" && p == "/admin/samples":
		s.samples(w, r)
	case p == "/admin/drift":
		s.drift(w, r)
	case p == "/admin/proposals":
		s.proposalList(w, r)
	case strings.HasPrefix(p, "/admin/proposals/"):
		s.proposalOne(w, r)
	case r.Method == "GET" && p == "/admin/parsers":
		write(w, 200, map[string]any{"parsers": s.registry.List()})
	case r.Method == "POST" && p == "/admin/parsers/dryrun":
		s.dryRun(w, r)
	case r.Method == "POST" && p == "/admin/parsers/approve":
		s.approve(w, r)
	case strings.HasPrefix(p, "/admin/parsers/"):
		s.parserVersion(w, r)
	case r.Method == "POST" && p == "/admin/replay":
		s.startReplay(w, r)
	case r.Method == "GET" && strings.HasPrefix(p, "/admin/replay/"):
		s.getReplay(w, strings.TrimPrefix(p, "/admin/replay/"))
	case r.Method == "GET" && p == "/admin/identity/resolve":
		s.resolve(w, r)
	case r.Method == "GET" && p == "/admin/identity/timeline":
		s.timeline(w, r)
	case r.Method == "GET" && p == "/admin/identity/graph":
		s.graph(w, r)
	case r.Method == "GET" && p == "/admin/vault/segments":
		s.segments(w, r)
	case r.Method == "GET" && p == "/admin/vault/verify":
		s.verify(w, r)
	case r.Method == "GET" && p == "/admin/telemetry":
		s.telemetry(w, r)
	default:
		fail(w, 404, "not_found", "resource not found")
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, cursor := s.app.Events.List(r.URL.Query().Get("source_id"), "", false, nil, nil, r.URL.Query().Get("cursor"), limit)
	write(w, 200, map[string]any{"events": events, "next_cursor": cursor, "max_seq": s.app.Events.MaxRecordID()})
}
func (s *Server) event(w http.ResponseWriter, id string) {
	event, err := s.app.Events.Get(id)
	if err != nil {
		fail(w, 404, "not_found", "event not found")
		return
	}
	write(w, 200, event)
}
func (s *Server) raw(w http.ResponseWriter, r *http.Request, id string) {
	event, err := s.app.Events.Get(id)
	if err != nil {
		fail(w, 404, "not_found", "event not found")
		return
	}
	record, receipt, err := s.vault.Get(r.Context(), event.RecordID)
	if err != nil {
		fail(w, 404, "not_found", "record not found")
		return
	}
	sum := hex.EncodeToString(receipt.RawSHA256[:])
	w.Header().Set("X-Raw-SHA256", sum)
	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(record.Raw)
		return
	}
	write(w, 200, map[string]any{"record_id": receipt.ID, "segment": receipt.Segment, "received_at": record.ReceivedAt, "origin": record.Origin, "terminator": record.Term, "fragment": record.Frag, "raw_base64": base64.StdEncoding.EncodeToString(record.Raw), "raw_sha256": sum, "sha_match": event.RawSHA256 == sum})
}
func (s *Server) lineage(w http.ResponseWriter, id string) {
	event, err := s.app.Events.Get(id)
	if err != nil {
		fail(w, 404, "not_found", "event not found")
		return
	}
	head, through, _ := s.vault.Head(context.Background())
	result := map[string]any{"event_id": event.EventID, "record_id": event.RecordID, "raw_sha256": event.RawSHA256, "sealed": false, "proof": nil, "coverage": event.Coverage, "render_back": map[string]any{"applicable": event.Coverage.Applicable, "ok": event.Coverage.RenderBackOK}, "chain": map[string]any{"head": hex.EncodeToString(head[:]), "sealed_through": through}}
	proof, err := s.vault.Proof(context.Background(), event.RecordID)
	if err == nil {
		result["sealed"] = true
		result["proof"] = proof
	} else if !errors.Is(err, types.ErrNotSealed) {
		fail(w, 500, "vault_error", err.Error())
		return
	}
	write(w, 200, result)
}

func (s *Server) quarantine(w http.ResponseWriter, r *http.Request) {
	records := s.app.Quarantine.ListStage(r.URL.Query().Get("source_id"), r.URL.Query().Get("status"), r.URL.Query().Get("stage"), parseLimit(r, 100))
	summary := s.app.Quarantine.Summary(r.URL.Query().Get("source_id"))
	write(w, 200, map[string]any{"records": records, "summary": summary, "next_cursor": nil})
}
func (s *Server) samples(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source_id")
	if source == "" {
		fail(w, 400, "bad_request", "source_id is required")
		return
	}
	status := r.URL.Query().Get("status")
	limit := parseLimit(r, 100)
	samples := []map[string]any{}
	_ = s.vault.Scan(r.Context(), 0, func(record types.RawRecord, receipt types.Receipt) error {
		if len(samples) >= limit || record.SourceID != source {
			return nil
		}
		event, parsed := s.app.Events.CurrentByRecord(receipt.ID)
		_, quarantined := s.app.Quarantine.Get(receipt.ID)
		if status == "parsed" && !parsed || status == "quarantined" && !quarantined {
			return nil
		}
		parserID := ""
		state := "quarantined"
		if parsed {
			parserID = event.ParserID
			state = "parsed"
		}
		samples = append(samples, map[string]any{"record_id": receipt.ID, "source_id": source, "raw_base64": base64.StdEncoding.EncodeToString(record.Raw), "received_at": record.ReceivedAt, "status": state, "parser_id": parserID})
		return nil
	})
	write(w, 200, map[string]any{"samples": samples})
}

func (s *Server) dryRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML            string           `json:"yaml"`
		SourceID        string           `json:"source_id"`
		SampleRecordIDs []types.RecordID `json:"sample_record_ids"`
		SampleLimit     int              `json:"sample_limit"`
	}
	if !decode(w, r, &req) {
		return
	}
	parser, err := parsers.New().Load([]byte(req.YAML))
	if err != nil {
		fail(w, 400, "invalid_parser", err.Error())
		return
	}
	wanted := map[types.RecordID]bool{}
	for _, id := range req.SampleRecordIDs {
		wanted[id] = true
	}
	limit := req.SampleLimit
	if limit <= 0 {
		limit = 200
	}
	result := types.DryRunResult{FieldStats: map[string]types.FieldStat{}, Failures: []types.DryRunFailure{}, Warnings: []string{}}
	coverage := 0.0
	renderN, renderOK := 0, 0
	_ = s.vault.Scan(r.Context(), 0, func(record types.RawRecord, receipt types.Receipt) error {
		if result.Samples >= limit {
			return nil
		}
		if len(wanted) > 0 && !wanted[receipt.ID] || len(wanted) == 0 && req.SourceID != "" && record.SourceID != req.SourceID {
			return nil
		}
		result.Samples++
		parsed, err := parser.Parse(record.Raw, record.ReceivedAt)
		if err != nil || parsed == nil {
			result.Failed++
			message := "no extractor matched"
			if err != nil {
				message = err.Error()
			}
			result.Failures = append(result.Failures, types.DryRunFailure{RecordID: receipt.ID, Error: message})
			return nil
		}
		result.Parsed++
		den := parsed.Coverage.MappedBytes + parsed.Coverage.UnmappedBytes
		if den > 0 {
			coverage += float64(parsed.Coverage.MappedBytes) / float64(den)
		}
		if parsed.RenderBackOK != nil {
			renderN++
			if *parsed.RenderBackOK {
				renderOK++
			}
		}
		return nil
	})
	if result.Samples > 0 {
		result.MatchRate = float64(result.Parsed) / float64(result.Samples)
	}
	if result.Parsed > 0 {
		result.MeanCoverage = coverage / float64(result.Parsed)
	}
	if renderN > 0 {
		rate := float64(renderOK) / float64(renderN)
		result.RenderBackOKRate = &rate
	}
	write(w, 200, result)
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML       string `json:"yaml"`
		ProposalID string `json:"proposal_id,omitempty"`
		ApprovedBy string `json:"approved_by"`
		Comment    string `json:"comment"`
		Replay     bool   `json:"replay"`
	}
	if !decode(w, r, &req) {
		return
	}
	parser, err := s.registry.Approve([]byte(req.YAML))
	if errors.Is(err, registry.ErrConflict) {
		s.setProposalStatus(req.ProposalID, "stale")
		fail(w, 409, "stale", "base version is not active")
		return
	}
	if err != nil {
		fail(w, 400, "invalid_parser", err.Error())
		return
	}
	s.setProposalStatus(req.ProposalID, "approved")
	var jobID *string
	if req.Replay {
		job := s.replay.Start(r.Context(), "quarantine", "")
		jobID = &job.JobID
	}
	write(w, 200, map[string]any{"parser_id": parser.ID(), "version": parser.Version(), "replay_job_id": jobID})
}

func (s *Server) setProposalStatus(id, status string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if proposal, ok := s.proposals[id]; ok {
		proposal.Status = status
		s.proposals[id] = proposal
	}
}
func (s *Server) parserVersion(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/parsers/"), "/")
	if len(parts) == 2 && parts[1] == "rollback" && r.Method == "POST" {
		var req struct {
			ToVersion string `json:"to_version"`
			By        string `json:"by"`
			Comment   string `json:"comment"`
			Replay    bool   `json:"replay"`
		}
		if !decode(w, r, &req) {
			return
		}
		p, err := s.registry.Rollback(parts[0], req.ToVersion)
		if err != nil {
			fail(w, 404, "not_found", err.Error())
			return
		}
		var jobID *string
		if req.Replay {
			job := s.replay.Start(r.Context(), "quarantine", "")
			jobID = &job.JobID
		}
		write(w, 200, map[string]any{"parser_id": p.ID(), "version": p.Version(), "replay_job_id": jobID})
		return
	}
	if len(parts) == 3 && parts[1] == "versions" && r.Method == "GET" {
		_, src, err := s.registry.Get(parts[0], parts[2])
		if err != nil {
			fail(w, 404, "not_found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.WriteHeader(200)
		_, _ = w.Write(src)
		return
	}
	fail(w, 404, "not_found", "parser route not found")
}

func (s *Server) startReplay(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope    string `json:"scope"`
		SourceID string `json:"source_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Scope != "quarantine" && req.Scope != "source" && req.Scope != "range" {
		fail(w, 400, "bad_request", "invalid scope")
		return
	}
	write(w, 202, s.replay.Start(r.Context(), req.Scope, req.SourceID))
}
func (s *Server) getReplay(w http.ResponseWriter, id string) {
	job, ok := s.replay.Get(id)
	if !ok {
		fail(w, 404, "not_found", "replay not found")
		return
	}
	write(w, 200, job)
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	at, err := time.Parse(time.RFC3339, r.URL.Query().Get("at"))
	if err != nil {
		fail(w, 400, "bad_request", "invalid at")
		return
	}
	ip := r.URL.Query().Get("ip")
	write(w, 200, map[string]any{"ip": ip, "at": at, "entities": s.identity.ResolveAt(ip, at)})
}
func (s *Server) timeline(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	from, _ := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
	to, _ := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
	bindings := []map[string]any{}
	for _, b := range s.identity.Timeline(ip, from, to) {
		bindings = append(bindings, map[string]any{"kind": b.Kind, "user": b.User, "host": b.Host, "mac": b.MAC, "valid_from": b.ValidFrom, "valid_to": b.ValidTo, "confidence": b.Confidence, "evidence": b.Evidence})
	}
	write(w, 200, map[string]any{"ip": ip, "bindings": bindings})
}
func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	typ, id := "", ""
	for _, key := range []string{"ip", "user", "host"} {
		if value := r.URL.Query().Get(key); value != "" {
			if typ != "" {
				fail(w, 400, "bad_request", "provide one graph key")
				return
			}
			typ, id = key, value
		}
	}
	if typ == "" {
		fail(w, 400, "bad_request", "provide one graph key")
		return
	}
	graph := s.identity.Neighbours(typ, id, time.Time{}, time.Time{})
	nodes := []map[string]any{}
	edges := []map[string]any{}
	for _, n := range graph.Nodes {
		nodes = append(nodes, map[string]any{"type": n.Type, "id": n.ID})
	}
	for _, e := range graph.Edges {
		edges = append(edges, map[string]any{"type": e.Type, "a": e.A, "b": e.B, "valid_from": e.ValidFrom, "valid_to": e.ValidTo})
	}
	write(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}
func (s *Server) segments(w http.ResponseWriter, r *http.Request) {
	seals, err := s.vault.Seals(r.Context())
	if err != nil {
		fail(w, 500, "vault_error", err.Error())
		return
	}
	_, through, _ := s.vault.Head(r.Context())
	active := map[string]any{"segment": uint64(len(seals) + 1), "first_seq": through + 1, "records": 0}
	write(w, 200, map[string]any{"segments": seals, "active": active})
}
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	deep, _ := strconv.ParseBool(r.URL.Query().Get("deep"))
	report, err := s.vault.VerifyChain(r.Context(), deep)
	if err != nil {
		fail(w, 500, "vault_error", err.Error())
		return
	}
	write(w, 200, report)
}
func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	eps, peak, events, quarantined, sources := s.app.Metrics.Snapshot()
	chain, _ := s.vault.VerifyChain(r.Context(), false)
	write(w, 200, map[string]any{"eps_1m": eps, "eps_peak": peak, "events_total": events, "quarantined_total": quarantined, "quarantine_open": s.app.Quarantine.OpenCount(), "sources": sources, "sinks": []any{}, "vault": map[string]any{"records": chain.Records, "segments": chain.Segments, "chain_head": hex.EncodeToString(chain.Head[:]), "sealed_through": chain.Records, "bytes_raw": 0, "bytes_compressed": 0, "ratio": 0, "failed": !chain.OK}, "lossless": map[string]any{"last_verify_at": time.Now().UTC(), "last_verify_ok": chain.OK}})
}

func (s *Server) drift(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == "GET" {
		write(w, 200, map[string]any{"alerts": s.alerts})
		return
	}
	var alert types.DriftAlert
	if !decode(w, r, &alert) {
		return
	}
	for _, existing := range s.alerts {
		if existing.SourceID == alert.SourceID && existing.ParserID == alert.ParserID {
			write(w, 200, existing)
			return
		}
	}
	s.next++
	alert.ID = fmt.Sprintf("drift-%06d", s.next)
	alert.Status = "open"
	s.alerts = append(s.alerts, alert)
	write(w, 201, alert)
}
func (s *Server) proposalList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == "GET" {
		out := []types.Proposal{}
		for _, p := range s.proposals {
			if status := r.URL.Query().Get("status"); status == "" || p.Status == status {
				out = append(out, p)
			}
		}
		write(w, 200, map[string]any{"proposals": out})
		return
	}
	var p types.Proposal
	if !decode(w, r, &p) {
		return
	}
	s.next++
	p.ID = fmt.Sprintf("proposal-%06d", s.next)
	p.Status = "pending"
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.proposals[p.ID] = p
	write(w, 201, p)
}
func (s *Server) proposalOne(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/proposals/")
	reject := strings.HasSuffix(path, "/reject")
	id := strings.TrimSuffix(path, "/reject")
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.proposals[id]
	if !ok {
		fail(w, 404, "not_found", "proposal not found")
		return
	}
	if reject && r.Method == "POST" {
		var req struct {
			By      string `json:"by"`
			Comment string `json:"comment"`
		}
		if !decode(w, r, &req) {
			return
		}
		if p.Status != "pending" {
			fail(w, 409, "conflict", "proposal is not pending")
			return
		}
		p.Status = "rejected"
		s.proposals[id] = p
	}
	write(w, 200, p)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, 400, "bad_request", err.Error())
		return false
	}
	return true
}
func write(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func parseLimit(r *http.Request, fallback int) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		return fallback
	}
	if n > 500 {
		return 500
	}
	return n
}
