package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blakc-coffee/sluice/contracts/conformance"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// HTTP is an API backed by a running data plane. Every request body it sends and every response it receives is
// checked against admin.openapi.yaml; a mismatch is returned as an error that begins "contract:".
type HTTP struct {
	Base   string // http://127.0.0.1:9000
	Client *http.Client
}

// NewHTTP returns a client for base with a sensible timeout.
func NewHTTP(base string) *HTTP {
	return &HTTP{Base: strings.TrimRight(base, "/"), Client: &http.Client{Timeout: 30 * time.Second}}
}

func (h *HTTP) do(method, path string, query url.Values, in any, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
		if err := conformance.ValidateRequest(method, path, body); err != nil {
			return fmt.Errorf("contract: the request this check sends is itself invalid (a bug in the check): %w", err)
		}
	}
	u := h.Base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if err := conformance.ValidateResponse(method, path, resp.StatusCode, resp.Header.Get("Content-Type"), b); err != nil {
		return fmt.Errorf("contract: %w", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func (h *HTTP) Telemetry() (t Telemetry, err error) {
	return t, h.do("GET", "/admin/telemetry", nil, nil, &t)
}

func (h *HTTP) Events() ([]types.NormalizedEvent, error) {
	var all []types.NormalizedEvent
	cursor := ""
	for {
		q := url.Values{"limit": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Events     []types.NormalizedEvent `json:"events"`
			NextCursor *string                 `json:"next_cursor"`
		}
		if err := h.do("GET", "/admin/events", q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Events...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = *page.NextCursor
	}
}

func (h *HTTP) Raw(id string) (r RawResponse, err error) {
	return r, h.do("GET", "/admin/events/"+url.PathEscape(id)+"/raw", nil, nil, &r)
}

// Quarantined returns up to 500 records per source: /admin/samples has a limit and no cursor.
func (h *HTTP) Quarantined() ([]Sample, error) {
	var q struct {
		Summary []struct {
			SourceID string `json:"source_id"`
		} `json:"summary"`
	}
	if err := h.do("GET", "/admin/quarantine", url.Values{"limit": {"1"}}, nil, &q); err != nil {
		return nil, err
	}
	var out []Sample
	for _, s := range q.Summary {
		var resp struct {
			Samples []struct {
				RecordID types.RecordID `json:"record_id"`
				SourceID string         `json:"source_id"`
				Raw      string         `json:"raw_base64"`
				Status   string         `json:"status"`
				ParserID string         `json:"parser_id"`
			} `json:"samples"`
		}
		if err := h.do("GET", "/admin/samples", url.Values{"source_id": {s.SourceID}, "status": {"quarantined"}, "limit": {"500"}}, nil, &resp); err != nil {
			return nil, err
		}
		for _, x := range resp.Samples {
			b, err := base64.StdEncoding.DecodeString(x.Raw)
			if err != nil {
				return nil, err
			}
			out = append(out, Sample{RecordID: x.RecordID, SourceID: x.SourceID, Raw: b, Status: x.Status, ParserID: x.ParserID})
		}
	}
	return out, nil
}

func (h *HTTP) Lineage(id string) (l Lineage, err error) {
	return l, h.do("GET", "/admin/lineage/"+url.PathEscape(id), nil, nil, &l)
}

func (h *HTTP) VerifyChain(deep bool) (r types.ChainReport, err error) {
	return r, h.do("GET", "/admin/vault/verify", url.Values{"deep": {fmt.Sprint(deep)}}, nil, &r)
}

func (h *HTTP) Timeline(ip string) ([]Binding, error) {
	var t struct {
		Bindings []Binding `json:"bindings"`
	}
	return t.Bindings, h.do("GET", "/admin/identity/timeline", url.Values{"ip": {ip}}, nil, &t)
}

func (h *HTTP) Parsers() ([]ParserInfo, error) {
	var p struct {
		Parsers []ParserInfo `json:"parsers"`
	}
	return p.Parsers, h.do("GET", "/admin/parsers", nil, nil, &p)
}

func (h *HTTP) DryRun(y, source string) (r types.DryRunResult, err error) {
	return r, h.do("POST", "/admin/parsers/dryrun", nil, map[string]any{"yaml": y, "source_id": source}, &r)
}

func (h *HTTP) Approve(y, by string, replay bool) (a Activation, err error) {
	return a, h.do("POST", "/admin/parsers/approve", nil, map[string]any{"yaml": y, "approved_by": by, "comment": "integration check", "replay": replay}, &a)
}

func (h *HTTP) StartReplay(scope, source string) (j ReplayJob, err error) {
	return j, h.do("POST", "/admin/replay", nil, map[string]any{"scope": scope, "source_id": source}, &j)
}

func (h *HTTP) Replay(id string) (j ReplayJob, err error) {
	return j, h.do("GET", "/admin/replay/"+url.PathEscape(id), nil, nil, &j)
}

func (h *HTTP) DriftAlerts() ([]types.DriftAlert, error) {
	var r struct {
		Alerts []types.DriftAlert `json:"alerts"`
	}
	return r.Alerts, h.do("GET", "/admin/drift", nil, nil, &r)
}

func (h *HTTP) Proposals() ([]types.Proposal, error) {
	var r struct {
		Proposals []types.Proposal `json:"proposals"`
	}
	return r.Proposals, h.do("GET", "/admin/proposals", nil, nil, &r)
}
