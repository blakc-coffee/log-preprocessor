package integration

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func requirePass(t *testing.T, r Report) {
	t.Helper()
	if !r.Passed() {
		t.Fatalf("a perfect data plane must pass:\n%s", r)
	}
}

// requireFails: the report must fail, and the named gate must be among the failures. Failing some other gate
// does not count: each defect has to be noticed by the check written for it.
func requireFails(t *testing.T, r Report, gate string) {
	t.Helper()
	for _, g := range r.Failed() {
		if strings.Contains(g.Name, gate) {
			return
		}
	}
	t.Fatalf("expected the gate %q to fail; report:\n%s", gate, r)
}

func find(p *plane, pred func(types.NormalizedEvent) bool) int {
	for i, e := range p.events {
		if pred(e) {
			return i
		}
	}
	return -1
}

func TestStep1PassesOnAPerfectPlane(t *testing.T) {
	p := newPlane(t)
	r := Step1(p, p.man, Step1Options{})
	requirePass(t, r)
	if len(p.events) < 400 || p.tel.Vault.Segments < 2 {
		t.Fatalf("the synthetic plane is too small to mean anything: %d events, %d sealed segments", len(p.events), p.tel.Vault.Segments)
	}
	t.Log("\n" + r.String())
}

func TestStep1CatchesEachDefect(t *testing.T) {
	sealed := func(p *plane, want bool) types.NormalizedEvent {
		i := find(p, func(e types.NormalizedEvent) bool { return p.lineage[e.EventID].Sealed == want })
		if i < 0 {
			t.Fatalf("no event with sealed=%v", want)
		}
		return p.events[i]
	}
	for _, c := range []struct {
		name, gate string
		break_     func(p *plane)
	}{
		{"an event is missing", "produced an event", func(p *plane) { p.events = p.events[1:] }},
		{"an event has the wrong source address", "agrees with the manifest", func(p *plane) {
			p.events[3].OCSF["src_endpoint"] = map[string]any{"ip": "203.0.113.99"}
		}},
		{"an event has the wrong time", "agrees with the manifest", func(p *plane) { p.events[3].OCSF["time"] = 1.0 }},
		{"an event exists twice", "agrees with the manifest", func(p *plane) { p.events = append(p.events, p.events[5]) }},
		{"an event exists for a record that must not parse", "agrees with the manifest", func(p *plane) {
			s := p.quar[0]
			p.events = append(p.events, types.NormalizedEvent{EventID: "9999.x@1", RecordID: 9999, RawSHA256: sha(s.Raw)})
			p.raw["9999.x@1"] = RawResponse{RecordID: 9999, RawBase64: base64.StdEncoding.EncodeToString(s.Raw), RawSHA256: sha(s.Raw), ShaMatch: true}
		}},
		{"the served bytes were altered", "byte-exact", func(p *plane) {
			id := p.events[7].EventID
			r := p.raw[id]
			r.RawBase64 = base64.StdEncoding.EncodeToString([]byte("altered"))
			p.raw[id] = r
		}},
		{"sha_match is false", "byte-exact", func(p *plane) {
			id := p.events[7].EventID
			r := p.raw[id]
			r.ShaMatch = false
			p.raw[id] = r
		}},
		{"a quarantined record is gone", "in quarantine", func(p *plane) { p.quar = p.quar[1:] }},
		{"a parsed record is also quarantined", "in quarantine", func(p *plane) {
			id := p.events[0].EventID
			b, _ := base64.StdEncoding.DecodeString(p.raw[id].RawBase64)
			p.quar = append(p.quar, Sample{RecordID: 1, Raw: b})
		}},
		{"a quarantined record's bytes were altered", "in quarantine", func(p *plane) { p.quar[0].Raw = append([]byte("x"), p.quar[0].Raw...) }},
		{"telemetry does not add up", "nothing dropped", func(p *plane) { p.tel.EventsTotal-- }},
		{"an inclusion proof has one flipped bit", "lineage", func(p *plane) {
			e := sealed(p, true)
			l := p.lineage[e.EventID]
			pr := *l.Proof
			pr.Path = append([][32]byte(nil), pr.Path...)
			pr.Path[0][0] ^= 1
			l.Proof = &pr
			p.lineage[e.EventID] = l
		}},
		{"the served received_at differs from what was hashed", "lineage", func(p *plane) {
			e := sealed(p, true)
			r := p.raw[e.EventID]
			r.ReceivedAt = r.ReceivedAt.Add(time.Nanosecond)
			p.raw[e.EventID] = r
		}},
		{"the served origin differs from what was hashed", "lineage", func(p *plane) {
			e := sealed(p, true)
			r := p.raw[e.EventID]
			r.Origin.Offset++
			p.raw[e.EventID] = r
		}},
		{"the chain hash in a proof is wrong", "lineage", func(p *plane) {
			e := sealed(p, true)
			l := p.lineage[e.EventID]
			pr := *l.Proof
			pr.Chain[3] ^= 0x80
			l.Proof = &pr
			p.lineage[e.EventID] = l
		}},
		{"sealed but no proof", "lineage", func(p *plane) {
			e := sealed(p, true)
			l := p.lineage[e.EventID]
			l.Proof = nil
			p.lineage[e.EventID] = l
		}},
		{"not sealed but a proof is returned", "lineage", func(p *plane) {
			e := sealed(p, false)
			l := p.lineage[e.EventID]
			pr := *p.lineage[sealed(p, true).EventID].Proof
			l.Proof = &pr
			p.lineage[e.EventID] = l
		}},
		{"lineage names a different record", "lineage", func(p *plane) {
			e := sealed(p, true)
			l := p.lineage[e.EventID]
			l.RecordID++
			p.lineage[e.EventID] = l
		}},
		{"the vault does not verify", "vault verify", func(p *plane) { p.chain.OK = false }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPlane(t)
			c.break_(p)
			requireFails(t, Step1(p, p.man, Step1Options{MaxLineage: 100000}), c.gate)
		})
	}
}

func TestStep5(t *testing.T) {
	p := newPlane(t)
	requirePass(t, Step5(p, p.man))
	userOf := func(e *types.NormalizedEvent) string {
		if len(e.Entities) > 0 {
			return e.Entities[0].ID
		}
		return ""
	}
	for _, c := range []struct {
		name, gate string
		break_     func(p *plane)
	}{
		{"the previous tenant is returned on a reassigned address", "across IP reassignment", func(p *plane) {
			for i := range p.events {
				if o := p.events[i].OCSF["src_endpoint"]; p.events[i].SourceID == "identity_firewall" && o != nil && o.(map[string]any)["ip"] == "10.1.4.9" && len(p.events[i].Entities) > 0 {
					p.events[i].Entities[0].ID = "carol"
				}
			}
		}},
		{"a user is invented in a gap", "gaps between tenancies", func(p *plane) {
			for i := range p.events {
				if p.events[i].SourceID == "identity_firewall" && len(p.events[i].Entities) == 0 {
					p.events[i].Entities = []types.Entity{{Type: "user", ID: "ghost", Role: "src"}}
					return
				}
			}
			t.Fatal("no gap record in the sample")
		}},
		{"many users are wrong", "99%", func(p *plane) {
			n := 0
			for i := range p.events {
				if p.events[i].SourceID == "identity_firewall" && userOf(&p.events[i]) != "" && n < 6 {
					p.events[i].Entities[0].ID, n = "nobody", n+1
				}
			}
		}},
		{"the timeline overlaps", "timeline", func(p *plane) { p.timeline[0].ValidTo = nil }},
		{"a firewall event is missing", "has an event", func(p *plane) {
			for i := range p.events {
				if p.events[i].SourceID == "identity_firewall" {
					p.events = append(p.events[:i], p.events[i+1:]...)
					return
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPlane(t)
			c.break_(p)
			requireFails(t, Step5(p, p.man), c.gate)
		})
	}
}

func step2(p *plane) Report {
	return Step2(p, p.man, Step2Options{Files: []string{"palo_alto_unknown.log"}, Source: "palo_alto_unknown", ParserYAML: "id: palo_alto_auto\nversion: 1.0.0\n", Sleep: func(time.Duration) {}})
}

func TestStep2(t *testing.T) {
	p := newPlane(t)
	r := step2(p)
	requirePass(t, r)
	if p.polls < 3 {
		t.Fatal("the replay was never polled: the wait loop is untested")
	}
	for _, c := range []struct {
		name, gate string
		break_     func(p *plane)
	}{
		{"the quarantine does not drain", "quarantine drains", func(p *plane) { p.noDrain = true }},
		{"the replay fails records", "no failures", func(p *plane) { p.replayFails = true }},
		{"a second replay duplicates events", "idempotent", func(p *plane) { p.dupOnReplay = true }},
		{"the dry-run misses the thresholds", "dry-run", func(p *plane) { p.dry.MatchRate = 0.5 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPlane(t)
			c.break_(p)
			requireFails(t, step2(p), c.gate)
		})
	}
	t.Run("the precondition: the source must be quarantined first", func(t *testing.T) {
		p := newPlane(t)
		p.quar = nil
		requireFails(t, step2(p), "before")
	})
}

func alertAndProposal() ([]types.DriftAlert, []types.Proposal) {
	return []types.DriftAlert{{ID: "d1", SourceID: "fortinet", Score: 0.63, Signals: []string{"keys renamed: srcip->src, dstip->dst", "quarantine rate 0.94"}, QuarantineRate: 0.94, Status: "open"}},
		[]types.Proposal{{ID: "p1", Kind: "patch", ParserID: "fortinet", BaseVersion: "1.0.0", SourceID: "fortinet", Status: "pending", DryRun: &types.DryRunResult{MatchRate: 1}}}
}

func TestStep4(t *testing.T) {
	run := func(p *plane) Report {
		return Step4(p, p.man, Step4Options{Source: "fortinet", Settle: func() {}})
	}
	p := newPlane(t)
	p.alerts, p.proposals = alertAndProposal()
	requirePass(t, run(p))
	for _, c := range []struct {
		name, gate string
		break_     func(p *plane)
	}{
		{"no alert", "exactly one drift alert", func(p *plane) { p.alerts = nil }},
		{"two alerts", "exactly one drift alert", func(p *plane) { p.alerts = append(p.alerts, p.alerts[0]) }},
		{"a weak score", "at least 0.6", func(p *plane) { p.alerts[0].Score = 0.3 }},
		{"the renames are not named", "renamed keys", func(p *plane) { p.alerts[0].Signals = []string{"something changed"} }},
		{"no proposal", "exactly one proposal", func(p *plane) { p.proposals = nil }},
		{"a proposal for a stale version", "patch of the active version", func(p *plane) { p.proposals[0].BaseVersion = "0.9.0" }},
		{"a new parser instead of a patch", "patch of the active version", func(p *plane) { p.proposals[0].Kind = "new"; p.proposals[0].BaseVersion = "" }},
		{"a failing dry-run", "acceptance thresholds", func(p *plane) { p.proposals[0].DryRun.MatchRate = 0.4 }},
		{"no dry-run at all", "acceptance thresholds", func(p *plane) { p.proposals[0].DryRun = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPlane(t)
			p.alerts, p.proposals = alertAndProposal()
			c.break_(p)
			requireFails(t, run(p), c.gate)
		})
	}
	t.Run("a duplicate appears while waiting", func(t *testing.T) {
		p := newPlane(t)
		p.alerts, p.proposals = alertAndProposal()
		r := Step4(p, p.man, Step4Options{Source: "fortinet", Settle: func() { p.proposals = append(p.proposals, p.proposals[0]) }})
		requireFails(t, r, "waiting changes nothing")
	})
}
