package mock

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

var bg = context.Background()

// Handler serves the admin API (every route in contracts/admin.openapi.yaml)
// plus three mock-only routes:
//
//	POST /mock/advance   move the scenario one step, returns {"scenario": ...}
//	POST /mock/reset     rebuild from the seed
//	POST /mock/tick?n=N  advance the virtual clock N seconds (default 1)
//	GET  /mock/state     {"scenario", "now"}
func (m *Mock) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, f func(http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			m.mu.Lock()
			defer m.mu.Unlock()
			f(w, r)
		})
	}
	h("GET /admin/events", m.listEvents)
	h("GET /admin/events/{event_id}", m.getEvent)
	h("GET /admin/events/{event_id}/raw", m.getRaw)
	h("GET /admin/lineage/{event_id}", m.getLineage)
	h("GET /admin/quarantine", m.listQuarantine)
	h("GET /admin/samples", m.listSamples)
	h("GET /admin/drift", m.listDrift)
	h("POST /admin/drift", m.postDrift)
	h("GET /admin/proposals", m.listProposals)
	h("POST /admin/proposals", m.postProposal)
	h("GET /admin/proposals/{id}", m.getProposal)
	h("POST /admin/proposals/{id}/reject", m.rejectProposal)
	h("GET /admin/parsers", m.listParsers)
	h("POST /admin/parsers/dryrun", m.postDryRun)
	h("POST /admin/parsers/approve", m.postApprove)
	h("POST /admin/parsers/{id}/rollback", m.postRollback)
	h("GET /admin/parsers/{id}/versions/{v}", m.getParserVersion)
	h("POST /admin/replay", m.postReplay)
	h("GET /admin/replay/{job_id}", m.getReplay)
	h("GET /admin/identity/resolve", m.identityResolve)
	h("GET /admin/identity/timeline", m.identityTimeline)
	h("GET /admin/identity/graph", m.identityGraph)
	h("GET /admin/vault/segments", m.vaultSegments)
	h("GET /admin/vault/verify", m.vaultVerify)
	h("GET /admin/telemetry", m.telemetry)
	h("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})

	mux.HandleFunc("POST /mock/advance", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"scenario": m.Advance()})
	})
	mux.HandleFunc("POST /mock/reset", func(w http.ResponseWriter, _ *http.Request) {
		m.Reset()
		writeJSON(w, 200, map[string]string{"scenario": m.Scenario()})
	})
	mux.HandleFunc("POST /mock/tick", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		m.TickN(min(max(n, 1), 3600))
		writeJSON(w, 200, map[string]string{"scenario": m.Scenario()})
	})
	h("GET /mock/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"scenario": m.scenario, "now": m.now})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "bad_request", "invalid body: "+err.Error())
		return false
	}
	return true
}

// ---- events -------------------------------------------------------------

func entityID(ev *types.NormalizedEvent, typ string) []string {
	var ids []string
	for _, e := range ev.Entities {
		if e.Type == typ {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

func ocsfInt(o map[string]any, key string) (int, bool) {
	switch v := o[key].(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	}
	return 0, false
}

func endpointIP(o map[string]any, side string) string {
	if ep, ok := o[side].(map[string]any); ok {
		if ip, ok := ep["ip"].(string); ok {
			return ip
		}
	}
	return ""
}

type eventFilter struct {
	q                      map[string]string
	severity, action       int
	hasSeverity, hasAction bool
	from, to               time.Time
}

func newFilter(r *http.Request) (eventFilter, error) {
	f := eventFilter{q: map[string]string{}}
	for _, k := range []string{"ip", "src_ip", "dst_ip", "vendor", "user", "host", "source_id", "flag"} {
		if v := r.URL.Query().Get(k); v != "" {
			f.q[k] = v
		}
	}
	for _, k := range []string{"ip", "src_ip", "dst_ip"} {
		if v, ok := f.q[k]; ok {
			if _, err := netip.ParseAddr(v); err != nil {
				return f, fmt.Errorf("%s: not an IP address", k)
			}
		}
	}
	var err error
	if v := r.URL.Query().Get("severity"); v != "" {
		if f.severity, err = strconv.Atoi(v); err != nil {
			return f, errors.New("severity: want an integer")
		}
		f.hasSeverity = true
	}
	if v := r.URL.Query().Get("action"); v != "" {
		if f.action, err = strconv.Atoi(v); err != nil {
			return f, errors.New("action: want an integer")
		}
		f.hasAction = true
	}
	for k, dst := range map[string]*time.Time{"from": &f.from, "to": &f.to} {
		if v := r.URL.Query().Get(k); v != "" {
			if *dst, err = time.Parse(time.RFC3339Nano, v); err != nil {
				return f, fmt.Errorf("%s: want RFC 3339", k)
			}
		}
	}
	return f, nil
}

func (f eventFilter) match(ev *types.NormalizedEvent) bool {
	src, dst := endpointIP(ev.OCSF, "src_endpoint"), endpointIP(ev.OCSF, "dst_endpoint")
	if v, ok := f.q["ip"]; ok && src != v && dst != v {
		return false
	}
	if v, ok := f.q["src_ip"]; ok && src != v {
		return false
	}
	if v, ok := f.q["dst_ip"]; ok && dst != v {
		return false
	}
	if v, ok := f.q["vendor"]; ok && ev.Vendor != v {
		return false
	}
	if v, ok := f.q["source_id"]; ok && ev.SourceID != v {
		return false
	}
	if v, ok := f.q["user"]; ok && !slices.Contains(entityID(ev, "user"), v) {
		return false
	}
	if v, ok := f.q["host"]; ok && !slices.Contains(entityID(ev, "host"), v) {
		return false
	}
	if v, ok := f.q["flag"]; ok && !slices.Contains(ev.IntegrityFlags, v) {
		return false
	}
	if f.hasSeverity {
		if s, _ := ocsfInt(ev.OCSF, "severity_id"); s != f.severity {
			return false
		}
	}
	if f.hasAction {
		if a, _ := ocsfInt(ev.OCSF, "action_id"); a != f.action {
			return false
		}
	}
	t := ev.ReceivedAt
	if ev.EventTime != nil {
		t = *ev.EventTime
	}
	if !f.from.IsZero() && t.Before(f.from) {
		return false
	}
	if !f.to.IsZero() && !t.Before(f.to) {
		return false
	}
	return ev.Current
}

func limitParam(r *http.Request, def int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 500 {
		return 0, errors.New("limit: want 1-500")
	}
	return n, nil
}

func (m *Mock) listEvents(w http.ResponseWriter, r *http.Request) {
	f, err := newFilter(r)
	limit, lerr := limitParam(r, 100)
	if err == nil {
		err = lerr
	}
	if err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	out := []types.NormalizedEvent{}
	var next *string
	maxSeq := m.nextSeq - 1
	if s := r.URL.Query().Get("since_seq"); s != "" {
		since, err := strconv.Atoi(s)
		if err != nil || since < 0 {
			writeErr(w, 400, "bad_request", "since_seq: want a non-negative integer")
			return
		}
		i := sort.Search(len(m.events), func(i int) bool { return m.events[i].seq > since })
		for ; i < len(m.events) && len(out) < limit; i++ {
			if f.match(&m.events[i].ev) {
				out = append(out, m.events[i].ev)
			}
		}
		writeJSON(w, 200, map[string]any{"events": out, "next_cursor": nil, "max_seq": maxSeq})
		return
	}
	start := len(m.events) - 1
	if c := r.URL.Query().Get("cursor"); c != "" {
		seq, err := strconv.Atoi(c)
		if err != nil {
			writeErr(w, 400, "bad_request", "cursor: malformed")
			return
		}
		start = sort.Search(len(m.events), func(i int) bool { return m.events[i].seq >= seq }) - 1
	}
	i := start
	for ; i >= 0 && len(out) < limit; i-- {
		if f.match(&m.events[i].ev) {
			out = append(out, m.events[i].ev)
		}
	}
	if len(out) == limit && i >= 0 {
		c := strconv.Itoa(m.events[i+1].seq)
		next = &c
	}
	writeJSON(w, 200, map[string]any{"events": out, "next_cursor": next, "max_seq": maxSeq})
}

func (m *Mock) event(w http.ResponseWriter, r *http.Request) *evRow {
	id := r.PathValue("event_id")
	row := m.byID[id]
	if row == nil {
		writeErr(w, 404, "not_found", "event "+id+" does not exist")
	}
	return row
}

func (m *Mock) getEvent(w http.ResponseWriter, r *http.Request) {
	if row := m.event(w, r); row != nil {
		writeJSON(w, 200, row.ev)
	}
}

var fragment = map[types.Fragment]int{types.FragNone: 0, types.FragMore: 1, types.FragCont: 2, types.FragMore | types.FragCont: 3}

func (m *Mock) getRaw(w http.ResponseWriter, r *http.Request) {
	row := m.event(w, r)
	if row == nil {
		return
	}
	rec, rc, err := m.v.Get(bg, row.ev.RecordID)
	if err != nil {
		writeErr(w, 500, "vault_error", err.Error())
		return
	}
	sum := fmt.Sprintf("%x", rc.RawSHA256)
	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Raw-SHA256", sum)
		_, _ = w.Write(rec.Raw)
		return
	}
	writeJSON(w, 200, map[string]any{
		"record_id": rc.ID, "segment": rc.Segment, "raw_base64": base64.StdEncoding.EncodeToString(rec.Raw), "raw_sha256": sum,
		"sha_match": sum == row.ev.RawSHA256, "origin": rec.Origin, "terminator": termWire(rec.Term), "fragment": fragment[rec.Frag],
		"received_at": rec.ReceivedAt,
	})
}

// termWire is the schema's spelling, which differs from Terminator.String
// only for TermNone ("none").
func termWire(t types.Terminator) string {
	switch t {
	case types.TermLF:
		return "LF"
	case types.TermCRLF:
		return "CRLF"
	case types.TermNUL:
		return "NUL"
	}
	return "none"
}

func (m *Mock) getLineage(w http.ResponseWriter, r *http.Request) {
	row := m.event(w, r)
	if row == nil {
		return
	}
	head, through, _ := m.v.Head(bg)
	var proof any
	p, err := m.v.Proof(bg, row.ev.RecordID)
	switch {
	case err == nil:
		proof = p
	case errors.Is(err, types.ErrNotSealed):
	default:
		writeErr(w, 500, "vault_error", err.Error())
		return
	}
	cov := row.ev.Coverage
	writeJSON(w, 200, map[string]any{
		"event_id": row.ev.EventID, "record_id": row.ev.RecordID, "raw_sha256": row.ev.RawSHA256, "sealed": proof != nil, "proof": proof,
		"chain": map[string]any{"head": fmt.Sprintf("%x", head), "sealed_through": through}, "coverage": cov,
		"render_back": map[string]any{"applicable": cov.Applicable, "ok": cov.RenderBackOK},
	})
}

// ---- quarantine and samples ------------------------------------------------

func (m *Mock) listQuarantine(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	limit, err := limitParam(r, 100)
	if err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	after := types.RecordID(1<<63 - 1)
	if c := qp.Get("cursor"); c != "" {
		n, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			writeErr(w, 400, "bad_request", "cursor: malformed")
			return
		}
		after = types.RecordID(n)
	}
	out := []types.QuarantineRecord{}
	var next *string
	type sum struct {
		SourceID string         `json:"source_id"`
		Open     int            `json:"open"`
		Resolved int            `json:"resolved"`
		Ignored  int            `json:"ignored"`
		ByStage  map[string]int `json:"by_stage"`
	}
	sums := map[string]*sum{}
	for i := len(m.quar) - 1; i >= 0; i-- {
		q := m.quar[i]
		if s := qp.Get("source_id"); s != "" && q.SourceID != s {
			continue
		}
		s := sums[q.SourceID]
		if s == nil {
			s = &sum{SourceID: q.SourceID, ByStage: map[string]int{}}
			sums[q.SourceID] = s
		}
		switch q.Status {
		case "open":
			s.Open++
			s.ByStage[q.FailureStage]++
		case "resolved":
			s.Resolved++
		default:
			s.Ignored++
		}
		if st := qp.Get("status"); st != "" && q.Status != st {
			continue
		}
		if st := qp.Get("stage"); st != "" && q.FailureStage != st {
			continue
		}
		if q.RecordID >= after {
			continue
		}
		if len(out) == limit {
			if next == nil {
				c := strconv.FormatUint(uint64(out[len(out)-1].RecordID), 10)
				next = &c
			}
			continue
		}
		out = append(out, *q)
	}
	summary := []sum{}
	for _, s := range sums {
		summary = append(summary, *s)
	}
	sort.Slice(summary, func(i, j int) bool { return summary[i].SourceID < summary[j].SourceID })
	writeJSON(w, 200, map[string]any{"records": out, "next_cursor": next, "summary": summary})
}

func (m *Mock) listSamples(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	source := qp.Get("source_id")
	if source == "" {
		writeErr(w, 400, "bad_request", "source_id is required")
		return
	}
	limit := 100
	if v := qp.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, 400, "bad_request", "limit: want 1-500")
			return
		}
		limit = n
	}
	status := qp.Get("status")
	type sample struct {
		RecordID   types.RecordID `json:"record_id"`
		SourceID   string         `json:"source_id"`
		RawBase64  string         `json:"raw_base64"`
		ReceivedAt time.Time      `json:"received_at"`
		Status     string         `json:"status"`
		ParserID   string         `json:"parser_id"`
	}
	out := []sample{}
	add := func(id types.RecordID, st, parserID string) {
		if rec, _, err := m.v.Get(bg, id); err == nil {
			out = append(out, sample{id, source, base64.StdEncoding.EncodeToString(rec.Raw), rec.ReceivedAt, st, parserID})
		}
	}
	if status != "parsed" {
		for i := len(m.quar) - 1; i >= 0 && len(out) < limit; i-- {
			if q := m.quar[i]; q.SourceID == source && q.Status == "open" {
				add(q.RecordID, "quarantined", "")
			}
		}
	}
	if status != "quarantined" {
		for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
			if ev := m.events[i].ev; ev.SourceID == source && ev.Current {
				add(ev.RecordID, "parsed", ev.ParserID)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"samples": out})
}

// ---- intelligence -------------------------------------------------------

func (m *Mock) listDrift(w http.ResponseWriter, _ *http.Request) {
	out := []types.DriftAlert{}
	for i := len(m.drift) - 1; i >= 0; i-- {
		out = append(out, *m.drift[i])
	}
	writeJSON(w, 200, map[string]any{"alerts": out})
}

func (m *Mock) postDrift(w http.ResponseWriter, r *http.Request) {
	var a types.DriftAlert
	if !decode(w, r, 1<<20, &a) {
		return
	}
	for _, old := range m.drift {
		if old.SourceID == a.SourceID && old.ParserID == a.ParserID && old.FirstSeen.Truncate(time.Hour).Equal(a.FirstSeen.Truncate(time.Hour)) {
			writeJSON(w, 200, old)
			return
		}
	}
	a.ID, a.Status = m.newID("drift"), "open"
	m.drift = append(m.drift, &a)
	writeJSON(w, 201, a)
}

func (m *Mock) listProposals(w http.ResponseWriter, r *http.Request) {
	st := r.URL.Query().Get("status")
	out := []types.Proposal{}
	for i := len(m.proposals) - 1; i >= 0; i-- {
		if p := m.proposals[i]; st == "" || p.Status == st {
			out = append(out, *p)
		}
	}
	writeJSON(w, 200, map[string]any{"proposals": out})
}

func (m *Mock) postProposal(w http.ResponseWriter, r *http.Request) {
	var p types.Proposal
	if !decode(w, r, 8<<20, &p) {
		return
	}
	p.ID, p.Status = m.newID("prop"), "pending"
	if p.CreatedAt.IsZero() {
		p.CreatedAt = m.now
	}
	m.proposals = append(m.proposals, &p)
	writeJSON(w, 201, p)
}

func (m *Mock) proposal(w http.ResponseWriter, r *http.Request) *types.Proposal {
	id := r.PathValue("id")
	for _, p := range m.proposals {
		if p.ID == id {
			return p
		}
	}
	writeErr(w, 404, "not_found", "proposal "+id+" does not exist")
	return nil
}

func (m *Mock) getProposal(w http.ResponseWriter, r *http.Request) {
	if p := m.proposal(w, r); p != nil {
		writeJSON(w, 200, p)
	}
}

func (m *Mock) rejectProposal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		By      string `json:"by"`
		Comment string `json:"comment"`
	}
	if !decode(w, r, 1<<20, &body) {
		return
	}
	p := m.proposal(w, r)
	if p == nil {
		return
	}
	if body.By == "" {
		writeErr(w, 400, "bad_request", "by is required")
		return
	}
	if p.Status != "pending" {
		writeErr(w, 409, "conflict", "proposal "+p.ID+" is "+p.Status+", not pending")
		return
	}
	p.Status = "rejected"
	writeJSON(w, 200, p)
}

// ---- parsers --------------------------------------------------------------

func (m *Mock) listParsers(w http.ResponseWriter, _ *http.Request) {
	type item struct {
		ID            string   `json:"id"`
		ActiveVersion string   `json:"active_version"`
		Versions      []string `json:"versions"`
		Vendor        string   `json:"vendor"`
		Product       string   `json:"product"`
		Signature     string   `json:"signature"`
	}
	out := []item{}
	for _, id := range m.order {
		p := m.parsers[id]
		out = append(out, item{p.id, p.active, append([]string{}, p.versions...), p.vendor, p.product, p.signature})
	}
	writeJSON(w, 200, map[string]any{"parsers": out})
}

func (m *Mock) postDryRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML            string           `json:"yaml"`
		SourceID        string           `json:"source_id"`
		SampleRecordIDs []types.RecordID `json:"sample_record_ids"`
		SampleLimit     int              `json:"sample_limit"`
	}
	if !decode(w, r, 8<<20, &body) {
		return
	}
	limit := body.SampleLimit
	if len(body.SampleRecordIDs) > 0 {
		limit = len(body.SampleRecordIDs)
	}
	res, err := m.dryRun(body.YAML, body.SourceID, limit)
	if err != nil {
		writeErr(w, 400, "invalid_parser", err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (m *Mock) postApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML       string `json:"yaml"`
		ProposalID string `json:"proposal_id"`
		ApprovedBy string `json:"approved_by"`
		Comment    string `json:"comment"`
		Replay     bool   `json:"replay"`
	}
	if !decode(w, r, 8<<20, &body) {
		return
	}
	if body.ApprovedBy == "" {
		writeErr(w, 400, "bad_request", "approved_by is required")
		return
	}
	res, err := m.approve(body.YAML, body.ProposalID, body.ApprovedBy, body.Comment, body.Replay)
	var bad errBadYAML
	switch {
	case errors.As(err, &bad):
		writeErr(w, 400, "invalid_parser", err.Error())
	case errors.Is(err, errStale):
		writeErr(w, 409, "stale_base_version", "the proposal's base_version is no longer the active version; regenerate it")
	case err != nil:
		writeErr(w, 500, "internal", err.Error())
	default:
		writeJSON(w, 200, res)
	}
}

func (m *Mock) postRollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToVersion string `json:"to_version"`
		By        string `json:"by"`
		Comment   string `json:"comment"`
		Replay    bool   `json:"replay"`
	}
	if !decode(w, r, 1<<20, &body) {
		return
	}
	p := m.parsers[r.PathValue("id")]
	if p == nil || !slices.Contains(p.versions, body.ToVersion) {
		writeErr(w, 404, "not_found", "no such parser version")
		return
	}
	p.active = body.ToVersion
	res := activation{ParserID: p.id, Version: body.ToVersion}
	if body.Replay {
		var ids []types.RecordID
		for _, ev := range m.events {
			if ev.ev.ParserID == p.id && ev.ev.Current {
				ids = append(ids, ev.ev.RecordID)
			}
		}
		j := m.startJob("source", p.id, nil)
		j.Processed, j.Succeeded = len(ids), len(ids) // re-normalization is a no-op in the mock
		res.ReplayJobID = &j.JobID
	}
	writeJSON(w, 200, res)
}

func (m *Mock) getParserVersion(w http.ResponseWriter, r *http.Request) {
	p := m.parsers[r.PathValue("id")]
	if p == nil || p.yaml[r.PathValue("v")] == "" {
		writeErr(w, 404, "not_found", "no such parser version")
		return
	}
	w.Header().Set("Content-Type", "text/yaml")
	_, _ = io.WriteString(w, p.yaml[r.PathValue("v")])
}

// ---- replay -----------------------------------------------------------------

func (m *Mock) postReplay(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope      string         `json:"scope"`
		SourceID   string         `json:"source_id"`
		FromRecord types.RecordID `json:"from_record"`
		ToRecord   types.RecordID `json:"to_record"`
		ParserID   string         `json:"parser_id"`
	}
	if !decode(w, r, 1<<20, &body) {
		return
	}
	if body.Scope != "quarantine" && body.Scope != "source" && body.Scope != "range" {
		writeErr(w, 400, "bad_request", "scope: want quarantine, source or range")
		return
	}
	var ids []types.RecordID
	for _, q := range m.quar {
		if q.Status == "open" && (body.SourceID == "" || q.SourceID == body.SourceID) {
			ids = append(ids, q.RecordID)
		}
	}
	j := m.startJob(body.Scope, body.SourceID, ids)
	writeJSON(w, 202, j.replayJob)
}

func (m *Mock) getReplay(w http.ResponseWriter, r *http.Request) {
	j := m.jobs[r.PathValue("job_id")]
	if j == nil {
		writeErr(w, 404, "not_found", "replay job "+r.PathValue("job_id")+" does not exist")
		return
	}
	writeJSON(w, 200, j.replayJob)
}

// ---- identity ---------------------------------------------------------------

func ipParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := r.URL.Query().Get("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		writeErr(w, 400, "bad_request", "ip: not an IP address")
		return "", false
	}
	return ip, true
}

func (m *Mock) identityResolve(w http.ResponseWriter, r *http.Request) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("at"))
	if err != nil {
		writeErr(w, 400, "bad_request", "at: want RFC 3339")
		return
	}
	ents := m.resolve(ip, at, "observer")
	if ents == nil {
		ents = []types.Entity{}
	}
	writeJSON(w, 200, map[string]any{"ip": ip, "at": at.UTC(), "entities": ents})
}

func (m *Mock) identityTimeline(w http.ResponseWriter, r *http.Request) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	var from, to time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		from, _ = time.Parse(time.RFC3339Nano, v)
	}
	if v := r.URL.Query().Get("to"); v != "" {
		to, _ = time.Parse(time.RFC3339Nano, v)
	}
	type binding struct {
		Kind       string              `json:"kind"`
		User       string              `json:"user"`
		Host       string              `json:"host"`
		MAC        string              `json:"mac"`
		ValidFrom  time.Time           `json:"valid_from"`
		ValidTo    *time.Time          `json:"valid_to"`
		Confidence float64             `json:"confidence"`
		Evidence   []types.EvidenceRef `json:"evidence"`
	}
	out := []binding{}
	for _, c := range m.claims {
		if c.ip != ip || (!to.IsZero() && !c.from.Before(to)) || (!from.IsZero() && c.to != nil && !c.to.After(from)) {
			continue
		}
		b := binding{Kind: c.kind, MAC: c.mac, ValidFrom: c.from, ValidTo: c.to, Confidence: 1,
			Evidence: []types.EvidenceRef{{RecordID: c.evidenceRecord, Kind: c.kind}}}
		if c.kind == "radius" {
			b.User = c.user
		} else {
			b.Host = c.host
		}
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ValidFrom.Before(out[j].ValidFrom) })
	writeJSON(w, 200, map[string]any{"ip": ip, "bindings": out})
}

func (m *Mock) identityGraph(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	set := 0
	for _, k := range []string{"ip", "user", "host"} {
		if qp.Get(k) != "" {
			set++
		}
	}
	if set != 1 {
		writeErr(w, 400, "bad_request", "exactly one of ip, user, host")
		return
	}
	type node struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	type edge struct {
		Type      string     `json:"type"`
		A         string     `json:"a"`
		B         string     `json:"b"`
		ValidFrom time.Time  `json:"valid_from"`
		ValidTo   *time.Time `json:"valid_to"`
	}
	nodes, edges, seen := []node{}, []edge{}, map[node]bool{}
	addNode := func(n node) {
		if !seen[n] {
			seen[n] = true
			nodes = append(nodes, n)
		}
	}
	for _, c := range m.claims {
		if !(qp.Get("ip") == c.ip || (qp.Get("user") != "" && qp.Get("user") == c.user) || (qp.Get("host") != "" && qp.Get("host") == c.host)) {
			continue
		}
		addNode(node{"ip", c.ip})
		if c.kind == "radius" {
			addNode(node{"user", c.user})
			edges = append(edges, edge{"ip-user", c.ip, c.user, c.from, c.to})
		} else {
			addNode(node{"host", c.host})
			addNode(node{"mac", c.mac})
			edges = append(edges, edge{"ip-host", c.ip, c.host, c.from, c.to}, edge{"host-mac", c.host, c.mac, c.from, c.to})
		}
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}

// ---- vault and telemetry ----------------------------------------------------

func (m *Mock) vaultSegments(w http.ResponseWriter, _ *http.Request) {
	seals, err := m.v.Seals(bg)
	if err != nil {
		writeErr(w, 500, "vault_error", err.Error())
		return
	}
	if seals == nil {
		seals = []types.SegmentSeal{}
	}
	var sealed uint64
	if len(seals) > 0 {
		sealed = seals[len(seals)-1].LastSeq
	}
	writeJSON(w, 200, map[string]any{"segments": seals, "active": map[string]any{
		"segment": len(seals) + 1, "first_seq": sealed + 1, "records": uint64(m.records) - sealed}})
}

func (m *Mock) vaultVerify(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, m.verify(r.URL.Query().Get("deep") == "true"))
}

func (m *Mock) telemetry(w http.ResponseWriter, _ *http.Request) {
	head, through, _ := m.v.Head(bg)
	seals, _ := m.v.Seals(bg)
	var open, total int
	perSource := map[string]int{}
	for _, q := range m.quar {
		total++
		if q.Status == "open" {
			open++
		}
	}
	for _, row := range m.events {
		perSource[row.ev.SourceID]++
	}
	sources := []map[string]any{}
	ids := make([]string, 0, len(perSource))
	for id := range perSource {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sources = append(sources, map[string]any{"id": id, "eps": 0, "records": perSource[id]})
	}
	// memvault does not compress; the mock reports the ratio the golden
	// telemetry carries, so the tile has a value. It is not a measurement.
	const ratio = 2.25
	writeJSON(w, 200, map[string]any{
		"eps_1m": m.eps(), "eps_peak": m.peak, "events_total": len(m.events), "quarantined_total": total, "quarantine_open": open,
		"vault": map[string]any{"records": m.records, "segments": len(seals) + 1, "bytes_raw": m.bytesRaw,
			"bytes_compressed": int(float64(m.bytesRaw) / ratio), "ratio": ratio, "chain_head": fmt.Sprintf("%x", head),
			"sealed_through": through, "failed": false},
		"lossless": map[string]any{"last_verify_ok": m.lastVerifyOK, "last_verify_at": m.lastVerify},
		"sources":  sources, "sinks": []map[string]any{{"name": "parquet", "lag": 0, "errors": 0}},
	})
}
