package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// serve exposes a plane as a synthetic admin API: just enough endpoints, encoded per admin.openapi.yaml. It is
// not a mock of anything the frontend uses; it exists so the HTTP client, request/response validation and the
// steps run end to end before the real data plane does. `corrupt` lets a test make one response invalid.
func serve(t *testing.T, p *plane, corrupt func(path string, body map[string]any)) *httptest.Server {
	send := func(w http.ResponseWriter, path string, v any) {
		b, _ := json.Marshal(v)
		var m map[string]any
		if json.Unmarshal(b, &m) == nil && corrupt != nil {
			corrupt(path, m)
			b, _ = json.Marshal(m)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
	cov := map[string]any{"applicable": false, "render_back_ok": nil, "mapped_bytes": 0, "unmapped_bytes": 0, "constant_bytes": 0, "uncovered_bytes": 0, "mapped_fields": 0, "unmapped_fields": 0}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query()
		switch {
		case path == "/admin/telemetry":
			send(w, path, map[string]any{"eps_1m": 0, "eps_peak": 0, "events_total": p.tel.EventsTotal, "quarantined_total": p.tel.QuarantinedTotal, "quarantine_open": p.tel.QuarantineOpen,
				"vault":    map[string]any{"records": p.tel.Vault.Records, "segments": p.tel.Vault.Segments, "bytes_raw": 0, "bytes_compressed": 0, "ratio": 1, "chain_head": strings.Repeat("0", 64), "sealed_through": 0, "failed": false},
				"lossless": map[string]any{"last_verify_ok": nil, "last_verify_at": nil}, "sources": []any{}, "sinks": []any{}})
		case path == "/admin/events":
			from, _ := strconv.Atoi(q.Get("cursor"))
			end := from + 200 // a page size below the client's limit, to exercise cursors
			var next any
			if end < len(p.events) {
				next = strconv.Itoa(end)
			} else {
				end = len(p.events)
			}
			send(w, path, map[string]any{"events": p.events[from:end], "next_cursor": next, "max_seq": len(p.events)})
		case strings.HasSuffix(path, "/raw"):
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/admin/events/"), "/raw")
			raw, ok := p.raw[id]
			if !ok {
				w.WriteHeader(404)
				send(w, path, map[string]any{"error": map[string]any{"code": "not_found", "message": id}})
				return
			}
			send(w, path, map[string]any{"record_id": raw.RecordID, "segment": raw.Segment, "raw_base64": raw.RawBase64, "raw_sha256": raw.RawSHA256, "sha_match": raw.ShaMatch,
				"origin": raw.Origin, "terminator": raw.Terminator, "fragment": raw.Fragment, "received_at": raw.ReceivedAt.UTC()})
		case strings.HasPrefix(path, "/admin/lineage/"):
			l := p.lineage[strings.TrimPrefix(path, "/admin/lineage/")]
			send(w, path, map[string]any{"event_id": l.EventID, "record_id": l.RecordID, "raw_sha256": l.RawSHA256, "sealed": l.Sealed, "proof": l.Proof,
				"chain": map[string]any{"head": strings.Repeat("0", 64), "sealed_through": 0}, "coverage": cov, "render_back": map[string]any{"applicable": false, "ok": nil}})
		case path == "/admin/vault/verify":
			send(w, path, p.chain)
		case path == "/admin/quarantine":
			srcs := map[string]int{}
			for _, s := range p.quar {
				srcs[s.SourceID]++
			}
			var sum []any
			for s, n := range srcs {
				sum = append(sum, map[string]any{"source_id": s, "open": n, "resolved": 0, "ignored": 0, "by_stage": map[string]any{}})
			}
			send(w, path, map[string]any{"records": []any{}, "next_cursor": nil, "summary": sum})
		case path == "/admin/samples":
			var out []any
			for _, s := range p.quar {
				if s.SourceID == q.Get("source_id") {
					out = append(out, map[string]any{"record_id": s.RecordID, "source_id": s.SourceID, "raw_base64": base64.StdEncoding.EncodeToString(s.Raw), "received_at": "2026-09-28T03:30:00Z", "status": "quarantined", "parser_id": ""})
				}
			}
			send(w, path, map[string]any{"samples": out})
		case path == "/admin/identity/timeline":
			var bs []any
			for _, b := range p.timeline {
				var to any
				if b.ValidTo != nil {
					to = b.ValidTo.UTC()
				}
				bs = append(bs, map[string]any{"kind": b.Kind, "user": b.User, "host": "", "mac": "", "valid_from": b.ValidFrom.UTC(), "valid_to": to, "confidence": 1, "evidence": []any{}})
			}
			send(w, path, map[string]any{"ip": q.Get("ip"), "bindings": bs})
		default:
			w.WriteHeader(404)
			send(w, path, map[string]any{"error": map[string]any{"code": "not_found", "message": path}})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStepsOverHTTPAgainstASyntheticAdminAPI(t *testing.T) {
	p := newPlane(t)
	api := NewHTTP(serve(t, p, nil).URL)
	r := Step1(api, p.man, Step1Options{})
	requirePass(t, r)
	requirePass(t, Step5(api, p.man))
	t.Log("\n" + r.String())
}

// The client must notice a response the contract does not describe, and say so as a contract violation.
func TestHTTPClientReportsContractViolations(t *testing.T) {
	p := newPlane(t)
	for _, c := range []struct {
		name string
		fn   func(path string, body map[string]any)
		call func(a *HTTP) error
	}{
		{"an event missing a required field", func(path string, b map[string]any) {
			if path == "/admin/events" {
				delete(b["events"].([]any)[0].(map[string]any), "raw_sha256")
			}
		}, func(a *HTTP) error { _, err := a.Events(); return err }},
		{"a raw response with an unknown field", func(path string, b map[string]any) {
			if strings.HasSuffix(path, "/raw") {
				b["surprise"] = 1
			}
		}, func(a *HTTP) error { _, err := a.Raw(p.events[0].EventID); return err }},
		{"telemetry with a wrong type", func(path string, b map[string]any) {
			if path == "/admin/telemetry" {
				b["eps_1m"] = "fast"
			}
		}, func(a *HTTP) error { _, err := a.Telemetry(); return err }},
		{"a lineage whose proof hash is upper case", func(path string, b map[string]any) {
			if pr, ok := b["proof"].(map[string]any); ok {
				pr["root"] = strings.ToUpper(pr["root"].(string))
			}
		}, func(a *HTTP) error {
			for _, e := range p.events {
				if p.lineage[e.EventID].Sealed {
					_, err := a.Lineage(e.EventID)
					return err
				}
			}
			return nil
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := NewHTTP(serve(t, p, c.fn).URL)
			if err := c.call(api); err == nil || !strings.HasPrefix(err.Error(), "contract:") {
				t.Fatalf("want a contract violation, got %v", err)
			}
		})
	}
	t.Run("an undocumented endpoint answers 404 and the client says so", func(t *testing.T) {
		api := NewHTTP(serve(t, p, nil).URL)
		if _, err := api.Parsers(); err == nil {
			t.Fatal("a 404 from an endpoint this server does not implement must be an error")
		}
	})
	t.Run("an unreachable data plane is an error, not a pass", func(t *testing.T) {
		api := NewHTTP("http://127.0.0.1:1")
		api.Client.Timeout = 300 * time.Millisecond
		if r := Step1(api, p.man, Step1Options{}); r.Passed() {
			t.Fatal("a step against nothing must not pass")
		}
	})
}
