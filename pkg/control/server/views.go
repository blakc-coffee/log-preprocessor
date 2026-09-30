package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/control/adminclient"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/registry"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func escapePath(s string) string { return url.PathEscape(s) }

type parserInfo struct {
	ID            string   `json:"id"`
	ActiveVersion string   `json:"active_version"`
	Versions      []string `json:"versions"`
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	Signature     string   `json:"signature"`
}

// parser looks one parser up in GET /admin/parsers. found is false when the
// id is not active in the data plane (a brand-new proposal's parser).
func (s *Server) parser(w http.ResponseWriter, r *http.Request, id string) (p parserInfo, found, ok bool) {
	var list struct {
		Parsers []parserInfo `json:"parsers"`
	}
	resp, ok := s.call(w, r.Context(), s.cfg.Timeout, "GET", "/admin/parsers", nil, &list)
	if !ok {
		if resp != nil {
			relay(w, resp)
		}
		return p, false, false
	}
	for _, x := range list.Parsers {
		if x.ID == id {
			return x, true, true
		}
	}
	return p, false, true
}

func (s *Server) loadProposal(w http.ResponseWriter, r *http.Request) (*types.Proposal, bool) {
	var p types.Proposal
	resp, ok := s.call(w, r.Context(), s.cfg.Timeout, "GET", "/admin/proposals/"+escapePath(r.PathValue("id")), nil, &p)
	if !ok {
		if resp != nil {
			relay(w, resp)
		}
		return nil, false
	}
	return &p, true
}

// getProposal returns {proposal, active_yaml}. active_yaml is the YAML of
// the version a patch was made against (its base_version), so the UI can diff
// the two; it is "" for a new parser.
func (s *Server) getProposal(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProposal(w, r)
	if !ok {
		return
	}
	active := ""
	if p.BaseVersion != "" {
		resp, err := s.cfg.Admin.Do(r.Context(), s.cfg.Timeout, "GET",
			"/admin/parsers/"+escapePath(p.ParserID)+"/versions/"+escapePath(p.BaseVersion), nil, "text/yaml")
		if err != nil {
			adminFailure(w, err)
			return
		}
		if resp.OK() {
			active = string(resp.Body)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p, "active_yaml": active})
}

// dryRunProposal re-runs the admin dry-run for the proposal, with edited
// YAML when the body carries it, against the proposal's own samples.
func (s *Server) dryRunProposal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	if !decodeBody(w, r, 8<<20, &body) {
		return
	}
	p, ok := s.loadProposal(w, r)
	if !ok {
		return
	}
	req := map[string]any{"yaml": p.YAML, "source_id": p.SourceID}
	if body.YAML != "" {
		req["yaml"] = body.YAML
	}
	if len(p.SampleRecordIDs) > 0 {
		req["sample_record_ids"] = p.SampleRecordIDs
	}
	b, _ := json.Marshal(req)
	resp, err := s.cfg.Admin.Do(r.Context(), s.cfg.LongTimeout, "POST", "/admin/parsers/dryrun", b, "")
	if err != nil {
		adminFailure(w, err)
		return
	}
	relay(w, resp)
}

type activation struct {
	ParserID    string  `json:"parser_id"`
	Version     string  `json:"version"`
	ReplayJobID *string `json:"replay_job_id"`
}

// approve records the attempt, asks the data plane to activate the parser and
// replay the quarantine, then records the outcome. The registry row is written
// first so a crash mid-call leaves a pending row behind.
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ApprovedBy string `json:"approved_by"`
		Comment    string `json:"comment"`
		YAML       string `json:"yaml"`
	}
	if !decodeBody(w, r, 8<<20, &body) {
		return
	}
	body.ApprovedBy = s.actor(r, body.ApprovedBy)
	if body.ApprovedBy == "" {
		writeErr(w, http.StatusBadRequest, CodeBadRequest, "approved_by is required: enter the name to record")
		return
	}
	p, ok := s.loadProposal(w, r)
	if !ok {
		return
	}
	yaml := p.YAML
	if body.YAML != "" {
		yaml = body.YAML
	}
	current, _, ok := s.parser(w, r, p.ParserID)
	if !ok {
		return
	}
	ctx := r.Context()
	rowID, err := s.cfg.Registry.Begin(ctx, registry.Row{ProposalID: p.ID, ParserID: p.ParserID, FromVersion: current.ActiveVersion,
		Action: registry.ActionApprove, YAMLSHA256: registry.YAMLSHA256(yaml), ApprovedBy: body.ApprovedBy, Comment: body.Comment})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registry_error", err.Error())
		return
	}
	var res activation
	resp, ok := s.call(w, ctx, s.cfg.LongTimeout, "POST", "/admin/parsers/approve",
		map[string]any{"yaml": yaml, "proposal_id": p.ID, "approved_by": body.ApprovedBy, "comment": body.Comment, "replay": true}, &res)
	switch {
	case ok:
		job := ""
		if res.ReplayJobID != nil {
			job = *res.ReplayJobID
		}
		s.finish(ctx, rowID, registry.ResultOK, res.Version, job, "")
		writeJSON(w, http.StatusOK, res)
	case resp != nil && resp.Status == http.StatusConflict:
		s.finish(ctx, rowID, registry.ResultStale, "", "", string(resp.Body))
		writeErr(w, http.StatusConflict, CodeStale, "the parser changed since this proposal was made (base "+p.BaseVersion+
			", active "+current.ActiveVersion+"); regenerate the proposal")
	case resp != nil:
		s.finish(ctx, rowID, registry.ResultError, "", "", string(resp.Body))
		relay(w, resp)
	default:
		// Transport failure: the response is already written. The row stays
		// informative about what happened.
		s.finish(ctx, rowID, registry.ResultError, "", "", "admin call failed before a response")
	}
}

// finish completes a registry row. It detaches from the request context: if
// the browser went away mid-approve, the audit row must still be completed.
func (s *Server) finish(ctx context.Context, id int64, result, to, job, msg string) {
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.cfg.Registry.Finish(c, id, result, to, job, msg); err != nil {
		s.log.Error("registry finish failed; the row stays pending", "id", id, "err", err)
	}
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		By      string `json:"by"`
		Comment string `json:"comment"`
	}
	if !decodeBody(w, r, 1<<20, &body) {
		return
	}
	body.By = s.actor(r, body.By)
	if body.By == "" {
		writeErr(w, http.StatusBadRequest, CodeBadRequest, "by is required: enter the name to record")
		return
	}
	p, ok := s.loadProposal(w, r)
	if !ok {
		return
	}
	rowID, err := s.cfg.Registry.Begin(r.Context(), registry.Row{ProposalID: p.ID, ParserID: p.ParserID, FromVersion: p.BaseVersion,
		Action: registry.ActionReject, YAMLSHA256: registry.YAMLSHA256(p.YAML), ApprovedBy: body.By, Comment: body.Comment})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registry_error", err.Error())
		return
	}
	resp, ok := s.call(w, r.Context(), s.cfg.Timeout, "POST", "/admin/proposals/"+escapePath(p.ID)+"/reject", body, nil)
	s.record(r, rowID, resp, ok, "")
	if resp != nil {
		relay(w, resp)
	}
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToVersion string `json:"to_version"`
		By        string `json:"by"`
		Comment   string `json:"comment"`
		Replay    bool   `json:"replay"`
	}
	if !decodeBody(w, r, 1<<20, &body) {
		return
	}
	body.By = s.actor(r, body.By)
	if body.By == "" || body.ToVersion == "" {
		writeErr(w, http.StatusBadRequest, CodeBadRequest, "to_version and by are required")
		return
	}
	id := r.PathValue("id")
	current, found, ok := s.parser(w, r, id)
	if !ok {
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "parser "+id+" is not known to the data plane")
		return
	}
	rowID, err := s.cfg.Registry.Begin(r.Context(), registry.Row{ParserID: id, FromVersion: current.ActiveVersion, ToVersion: body.ToVersion,
		Action: registry.ActionRollback, ApprovedBy: body.By, Comment: body.Comment})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registry_error", err.Error())
		return
	}
	var res activation
	resp, ok := s.call(w, r.Context(), s.cfg.LongTimeout, "POST", "/admin/parsers/"+escapePath(id)+"/rollback", body, &res)
	job := ""
	if ok && res.ReplayJobID != nil {
		job = *res.ReplayJobID
	}
	s.record(r, rowID, resp, ok, job)
	if resp != nil {
		relay(w, resp)
	}
}

// record finishes a registry row from an admin response.
func (s *Server) record(r *http.Request, rowID int64, resp *adminclient.Response, ok bool, job string) {
	result, msg := registry.ResultOK, ""
	switch {
	case ok:
	case resp != nil:
		result, msg = registry.ResultError, fmt.Sprintf("admin returned %d: %s", resp.Status, resp.Body)
	default:
		result, msg = registry.ResultError, "admin call failed before a response"
	}
	s.finish(r.Context(), rowID, result, "", job, msg)
}

// parserVersions merges the data plane's version list with the registry's
// history for that parser.
func (s *Server) parserVersions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, found, ok := s.parser(w, r, id)
	if !ok {
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "parser "+id+" is not known to the data plane")
		return
	}
	hist, err := s.cfg.Registry.List(r.Context(), id, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registry_error", err.Error())
		return
	}
	type version struct {
		Version string         `json:"version"`
		Active  bool           `json:"active"`
		History []registry.Row `json:"history"`
	}
	vs := []version{}
	for i := len(p.Versions) - 1; i >= 0; i-- {
		v := version{Version: p.Versions[i], Active: p.Versions[i] == p.ActiveVersion, History: []registry.Row{}}
		for _, h := range hist {
			if h.ToVersion == v.Version {
				v.History = append(v.History, h)
			}
		}
		vs = append(vs, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"parser": p, "versions": vs, "history": hist})
}

func (s *Server) parserYAML(w http.ResponseWriter, r *http.Request) {
	resp, err := s.cfg.Admin.Do(r.Context(), s.cfg.Timeout, "GET",
		"/admin/parsers/"+escapePath(r.PathValue("id"))+"/versions/"+escapePath(r.PathValue("v")), nil, "text/yaml")
	if err != nil {
		adminFailure(w, err)
		return
	}
	if !resp.OK() {
		relay(w, resp)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(resp.Body)
}

// verifyParser dry-runs the active version of a parser against recent
// samples of the source with the same id. It changes nothing.
func (s *Server) verifyParser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, found, ok := s.parser(w, r, id)
	if !ok {
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "parser "+id+" is not known to the data plane")
		return
	}
	yresp, err := s.cfg.Admin.Do(r.Context(), s.cfg.Timeout, "GET", "/admin/parsers/"+escapePath(id)+"/versions/"+escapePath(p.ActiveVersion), nil, "text/yaml")
	if err != nil {
		adminFailure(w, err)
		return
	}
	if !yresp.OK() {
		relay(w, yresp)
		return
	}
	b, _ := json.Marshal(map[string]any{"yaml": string(yresp.Body), "source_id": id, "sample_limit": 200})
	resp, err := s.cfg.Admin.Do(r.Context(), s.cfg.LongTimeout, "POST", "/admin/parsers/dryrun", b, "")
	if err != nil {
		adminFailure(w, err)
		return
	}
	relay(w, resp)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.cfg.Registry.List(r.Context(), r.URL.Query().Get("parser_id"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registry_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": rows})
}

// healthz is 200 whenever the control plane is up, and reports whether the
// admin API answered, so a container health check does not restart the UI
// because the data plane is down.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	admin := "reachable"
	resp, err := s.cfg.Admin.Do(r.Context(), 2*s.cfg.Timeout/5, "GET", "/healthz", nil, "text/plain")
	switch {
	case err != nil:
		admin = "unreachable"
	case !resp.OK():
		admin = "unhealthy"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "admin": admin})
}
