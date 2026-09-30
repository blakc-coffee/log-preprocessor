package mock

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/control/internal/apitest"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/merkle"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

type client struct {
	t *testing.T
	h http.Handler
	k *apitest.Contract
}

func newClient(t *testing.T, m *Mock) *client {
	return &client{t: t, h: m.Handler(), k: apitest.Load(t)}
}

// do calls the handler and validates the response against the OpenAPI
// operation named by template.
func (c *client) do(method, template, path string, body any, wantStatus int) []byte {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	if template != "" {
		c.k.Response(c.t, method, template, rec.Code, rec.Body.Bytes())
	}
	return rec.Body.Bytes()
}

func decodeInto[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestEveryRouteMatchesTheContract(t *testing.T) {
	m := New(Options{Seed: 7})
	m.TickN(30)
	c := newClient(t, m)

	list := decodeInto[struct {
		Events     []types.NormalizedEvent `json:"events"`
		NextCursor *string                 `json:"next_cursor"`
		MaxSeq     int                     `json:"max_seq"`
	}](t, c.do("GET", "/admin/events", "/admin/events?limit=50", nil, 200))
	if len(list.Events) != 50 || list.NextCursor == nil {
		t.Fatalf("want a full first page with a cursor, got %d events", len(list.Events))
	}
	page2 := decodeInto[struct {
		Events []types.NormalizedEvent `json:"events"`
	}](t, c.do("GET", "/admin/events", "/admin/events?limit=50&cursor="+*list.NextCursor, nil, 200))
	if page2.Events[0].EventID == list.Events[49].EventID {
		t.Fatal("cursor page repeats the last event of the previous page")
	}
	c.do("GET", "/admin/events", "/admin/events?ip=10.1.4.7&limit=5", nil, 200)
	c.do("GET", "/admin/events", "/admin/events?ip=nope", nil, 400)
	c.do("GET", "/admin/events", fmt.Sprintf("/admin/events?since_seq=%d", list.MaxSeq-3), nil, 200)

	id := list.Events[0].EventID
	c.do("GET", "/admin/events/{event_id}", "/admin/events/"+id, nil, 200)
	c.do("GET", "/admin/events/{event_id}", "/admin/events/999999.x@1.0.0", nil, 404)
	c.do("GET", "/admin/events/{event_id}/raw", "/admin/events/"+id+"/raw", nil, 200)
	c.do("GET", "/admin/lineage/{event_id}", "/admin/lineage/"+id, nil, 200)
	c.do("GET", "/admin/lineage/{event_id}", "/admin/lineage/"+list.Events[49].EventID, nil, 200)
	c.do("GET", "/admin/quarantine", "/admin/quarantine?limit=10", nil, 200)
	c.do("GET", "/admin/samples", "/admin/samples?source_id=palo_alto&status=quarantined&limit=3", nil, 200)
	c.do("GET", "/admin/drift", "/admin/drift", nil, 200)
	c.do("GET", "/admin/proposals", "/admin/proposals", nil, 200)
	c.do("GET", "/admin/parsers", "/admin/parsers", nil, 200)
	c.do("GET", "/admin/identity/resolve", "/admin/identity/resolve?ip=10.1.4.7&at=2026-09-28T02:45:00Z", nil, 200)
	c.do("GET", "/admin/identity/timeline", "/admin/identity/timeline?ip=10.1.4.7", nil, 200)
	c.do("GET", "/admin/identity/graph", "/admin/identity/graph?ip=10.1.4.7", nil, 200)
	c.do("GET", "/admin/vault/segments", "/admin/vault/segments", nil, 200)
	c.do("GET", "/admin/vault/verify", "/admin/vault/verify?deep=true", nil, 200)
	c.do("GET", "/admin/telemetry", "/admin/telemetry", nil, 200)
	c.do("POST", "/admin/parsers/dryrun", "/admin/parsers/dryrun", map[string]any{"yaml": "nope"}, 400)
}

// The browser verifier rebuilds the Merkle leaf from the raw bytes and the
// record metadata, then folds the proof. Doing the same here proves the mock
// hands the UI proofs that are real, not decorative.
func TestLineageProofVerifiesFromRawBytes(t *testing.T) {
	m := New(Options{Seed: 3})
	c := newClient(t, m)
	list := decodeInto[struct {
		Events []types.NormalizedEvent `json:"events"`
	}](t, c.do("GET", "", "/admin/events?limit=500", nil, 200))
	ev := list.Events[len(list.Events)-1] // old enough to be sealed
	raw := decodeInto[struct {
		RawBase64  string       `json:"raw_base64"`
		RawSHA256  string       `json:"raw_sha256"`
		Origin     types.Origin `json:"origin"`
		Terminator string       `json:"terminator"`
		ReceivedAt string       `json:"received_at"`
	}](t, c.do("GET", "", "/admin/events/"+ev.EventID+"/raw", nil, 200))
	lin := decodeInto[struct {
		Sealed bool                  `json:"sealed"`
		Proof  *types.InclusionProof `json:"proof"`
	}](t, c.do("GET", "", "/admin/lineage/"+ev.EventID, nil, 200))
	if !lin.Sealed || lin.Proof == nil {
		t.Fatal("an event from the backlog should be sealed")
	}
	b, _ := base64.StdEncoding.DecodeString(raw.RawBase64)
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != ev.RawSHA256 {
		t.Fatal("raw bytes do not hash to the event's raw_sha256")
	}
	// Rebuild the record body exactly as the vault encodes it.
	var body []byte
	term := map[string]byte{"none": 0, "LF": 1, "CRLF": 2, "NUL": 3}[raw.Terminator]
	body = append(body, 1, term)
	body = be64(body, uint64(ev.RecordID))
	body = be64(body, uint64(ev.ReceivedAt.UnixNano()))
	body = append(body, byte(len(ev.SourceID)>>8), byte(len(ev.SourceID)))
	body = append(body, ev.SourceID...)
	body = append(body, byte(raw.Origin.Kind))
	body = append(body, byte(len(raw.Origin.Addr)>>8), byte(len(raw.Origin.Addr)))
	body = append(body, raw.Origin.Addr...)
	body = be64(body, raw.Origin.Offset)
	body = append(body, byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	body = append(body, b...)
	leaf := merkle.LeafHash(body)
	if leaf != lin.Proof.LeafHash {
		t.Fatalf("leaf rebuilt from raw bytes does not match the proof")
	}
	if !merkle.VerifyInclusion(leaf, lin.Proof.LeafIndex, lin.Proof.TreeSize, lin.Proof.Path, lin.Proof.Root) {
		t.Fatal("inclusion proof does not verify")
	}
	if !merkle.VerifyChainLink(*lin.Proof) {
		t.Fatal("chain link does not verify")
	}
}

func be64(b []byte, v uint64) []byte {
	for i := 7; i >= 0; i-- {
		b = append(b, byte(v>>(8*i)))
	}
	return b
}

// The demo path: drift appears, the patch is approved, replay drains the
// quarantine and the recovered events are in the event list.
func TestScenarioDriftApproveReplay(t *testing.T) {
	m := New(Options{Seed: 11})
	c := newClient(t, m)
	if m.Advance() != ScenarioDrift {
		t.Fatal("steady should advance to drift")
	}
	props := decodeInto[struct {
		Proposals []types.Proposal `json:"proposals"`
	}](t, c.do("GET", "/admin/proposals", "/admin/proposals?status=pending", nil, 200))
	var patch *types.Proposal
	for i := range props.Proposals {
		if props.Proposals[i].ParserID == "fortinet" {
			patch = &props.Proposals[i]
		}
	}
	if patch == nil || patch.Kind != "patch" || patch.BaseVersion != "1.0.0" {
		t.Fatalf("want a fortinet patch proposal on 1.0.0, got %+v", patch)
	}
	if !strings.Contains(patch.YAML, "{from: src,") || strings.Contains(patch.YAML, "{from: srcip,") {
		t.Fatal("patch YAML should remap srcip to src")
	}
	openBefore := len(m.openQuarantine("fortinet"))
	res := decodeInto[activation](t, c.do("POST", "/admin/parsers/approve", "/admin/parsers/approve",
		map[string]any{"yaml": patch.YAML, "proposal_id": patch.ID, "approved_by": "test", "comment": "", "replay": true}, 200))
	if res.Version != "1.0.1" || res.ReplayJobID == nil {
		t.Fatalf("approve: %+v", res)
	}
	// Approving the same proposal again is stale: the base moved to 1.0.1.
	c.do("POST", "/admin/parsers/approve", "/admin/parsers/approve",
		map[string]any{"yaml": patch.YAML, "proposal_id": patch.ID, "approved_by": "test", "comment": "", "replay": true}, 409)
	m.TickN(20)
	job := decodeInto[replayJob](t, c.do("GET", "/admin/replay/{job_id}", "/admin/replay/"+*res.ReplayJobID, nil, 200))
	if job.State != "done" || job.Succeeded != openBefore || job.Failed != 0 {
		t.Fatalf("replay job %+v, want done with %d succeeded", job, openBefore)
	}
	if n := len(m.openQuarantine("fortinet")); n != 0 {
		t.Fatalf("%d fortinet records still quarantined after replay", n)
	}
	recovered := decodeInto[struct {
		Events []types.NormalizedEvent `json:"events"`
	}](t, c.do("GET", "", "/admin/events?source_id=fortinet&limit=500", nil, 200))
	found := false
	for _, e := range recovered.Events {
		found = found || e.ParserVersion == "1.0.1"
	}
	if !found {
		t.Fatal("no events normalized by fortinet 1.0.1")
	}
	if m.Scenario() != ScenarioSteady {
		t.Fatalf("scenario %s after the replay finished, want steady", m.Scenario())
	}
}

// The resolver never answers across the gap between alice's release and
// bob's lease on 10.1.4.7.
func TestIdentityReassignment(t *testing.T) {
	m := New(Options{Seed: 5})
	base := Start.Add(-time.Hour)
	cases := map[time.Duration]string{15 * time.Minute: "alice", 33 * time.Minute: "", 50 * time.Minute: "bob"}
	for off, want := range cases {
		got := ""
		for _, e := range m.resolve("10.1.4.7", base.Add(off), "src") {
			if e.Type == "user" {
				got = e.ID
			}
		}
		if got != want {
			t.Errorf("at +%s: user %q, want %q", off, got, want)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, b := New(Options{Seed: 9}), New(Options{Seed: 9})
	a.TickN(10)
	b.TickN(10)
	ha, _, _ := a.v.Head(bg)
	hb, _, _ := b.v.Head(bg)
	if ha != hb || len(a.events) != len(b.events) {
		t.Fatal("same seed produced different vaults")
	}
}
