package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/vault/memvault"
	types "github.com/dark-14100/sluice/pkg/types"
)

const testdata = "../../testdata/sample"

var parserOf = map[string]string{
	"cisco_asa.log": "cisco_asa", "identity_firewall.log": "cisco_asa", "fortinet.log": "fortinet", "crlf.log": "fortinet",
	"suricata.json": "suricata_eve", "dhcp.log": "isc_dhcpd", "radius.log": "freeradius", "openvpn.log": "openvpn", "multiline.log": "vpn_gateway",
}

// plane is a "perfect data plane": every record of the sample corpus goes through a real memvault, the records the
// manifest says parse become events carrying exactly the manifest's values, everything else is quarantined, and
// the lineage proofs are real. Tests copy it, break one thing, and require the right gate to notice.
type plane struct {
	man       Manifest
	events    []types.NormalizedEvent
	raw       map[string]RawResponse
	quar      []Sample
	lineage   map[string]Lineage
	tel       Telemetry
	chain     types.ChainReport
	timeline  []Binding
	parsers   []ParserInfo
	alerts    []types.DriftAlert
	proposals []types.Proposal
	dry       types.DryRunResult
	polls     int
	// behaviour knobs
	replayFails, dupOnReplay, noDrain bool
	approved                          string
}

func newPlane(t *testing.T) *plane {
	t.Helper()
	man, err := LoadManifest(testdata)
	if err != nil {
		t.Fatal(err)
	}
	p := &plane{man: man, raw: map[string]RawResponse{}, lineage: map[string]Lineage{}}
	mv := memvault.New(memvault.Options{SealEvery: 100, Now: func() time.Time { return time.Unix(1790000000, 0) }})
	base := time.Date(2026, 9, 28, 3, 30, 0, 0, time.UTC)
	var rs []types.RawRecord
	var bodies [][]byte
	files := map[string][]byte{}
	for i, m := range man.Records {
		b, ok := files[m.File]
		if !ok {
			if b, err = os.ReadFile(filepath.Join(testdata, m.File)); err != nil {
				t.Fatal(err)
			}
			files[m.File] = b
		}
		raw := b[m.ByteStart:m.ByteEnd]
		term := types.TermLF
		if strings.Contains(m.File, "crlf") {
			term = types.TermCRLF
		}
		rs = append(rs, types.RawRecord{SourceID: sourceOf(m.File), ReceivedAt: base.Add(time.Duration(i) * time.Second), Origin: types.Origin{Kind: types.OriginFile, Addr: "/var/log/" + m.File, Offset: uint64(m.ByteStart)}, Term: term, Raw: raw})
		bodies = append(bodies, raw)
	}
	ctx := context.Background()
	rc, err := mv.PutBatch(ctx, rs)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range man.Records {
		if m.Expect != "parse" {
			p.quar = append(p.quar, Sample{RecordID: rc[i].ID, SourceID: sourceOf(m.File), Raw: bodies[i], Status: "quarantined"})
			continue
		}
		pid := parserOf[m.File]
		if pid == "" {
			pid = "generic"
		}
		ev := types.NormalizedEvent{EventID: fmt.Sprintf("%d.%s@1.0.0", rc[i].ID, pid), RecordID: rc[i].ID, Segment: rc[i].Segment, RawSHA256: m.SHA256, SourceID: sourceOf(m.File),
			Vendor: "test", Product: "plane", TemplateID: pid + "/x", ParserID: pid, ParserVersion: "1.0.0", SchemaVersion: "ulpf-uef/1", ReceivedAt: rs[i].ReceivedAt, IntegrityFlags: []string{}, Unmapped: map[string]any{},
			Entities: []types.Entity{}, Current: true, OCSF: ocsfOf(m)}
		if m.File == "identity_firewall.log" && m.User != nil {
			ev.Entities = []types.Entity{{Type: "user", ID: *m.User, Role: "src", Confidence: 1, Evidence: []types.EvidenceRef{}}}
		}
		p.events = append(p.events, ev)
		p.raw[ev.EventID] = RawResponse{RecordID: rc[i].ID, Segment: rc[i].Segment, RawBase64: base64.StdEncoding.EncodeToString(bodies[i]), RawSHA256: m.SHA256, ShaMatch: true,
			Origin: rs[i].Origin, Terminator: rs[i].Term, ReceivedAt: rs[i].ReceivedAt}
		l := Lineage{EventID: ev.EventID, RecordID: rc[i].ID, RawSHA256: m.SHA256}
		if pr, err := mv.Proof(ctx, rc[i].ID); err == nil {
			l.Sealed, l.Proof = true, &pr
		} else if err != types.ErrNotSealed {
			t.Fatal(err)
		}
		p.lineage[ev.EventID] = l
	}
	seals, _ := mv.Seals(ctx)
	p.tel = Telemetry{EventsTotal: len(p.events), QuarantinedTotal: len(p.quar), QuarantineOpen: len(p.quar)}
	p.tel.Vault.Records, p.tel.Vault.Segments = uint64(len(man.Records)), len(seals)
	p.chain, _ = mv.VerifyChain(ctx, true)
	from := func(s string) time.Time { x, _ := time.Parse(time.RFC3339, s); return x.UTC() }
	c1, h1 := from("2026-09-28T09:43:25+05:30"), from("2026-09-28T10:13:25+05:30")
	p.timeline = []Binding{{Kind: "radius", User: "carol", ValidFrom: from("2026-09-28T09:01:35+05:30"), ValidTo: &c1}, {Kind: "radius", User: "heidi", ValidFrom: h1}}
	p.parsers = []ParserInfo{{ID: "fortinet", ActiveVersion: "1.0.0"}}
	p.dry = types.DryRunResult{Samples: 50, Parsed: 50, MatchRate: 1, MeanCoverage: 1}
	return p
}

func sourceOf(file string) string {
	return strings.TrimSuffix(strings.TrimSuffix(file, ".log"), ".json")
}

func ocsfOf(m Record) map[string]any {
	o := map[string]any{"class_uid": 4001.0, "category_uid": 4.0, "activity_id": 6.0, "type_uid": 400106.0, "time": 0.0, "severity_id": 1.0, "action_id": 1.0,
		"src_endpoint": map[string]any{}, "dst_endpoint": map[string]any{}, "connection_info": map[string]any{},
		"metadata": map[string]any{"version": "1.1.0", "product": map[string]any{"vendor_name": "test", "name": "plane"}}}
	set := func(k, sub string, v any) { o[k].(map[string]any)[sub] = v }
	if m.SrcIP != nil {
		set("src_endpoint", "ip", *m.SrcIP)
	}
	if m.DstIP != nil {
		set("dst_endpoint", "ip", *m.DstIP)
	}
	if m.SrcPort != nil {
		set("src_endpoint", "port", float64(*m.SrcPort))
	}
	if m.DstPort != nil {
		set("dst_endpoint", "port", float64(*m.DstPort))
	}
	if m.Proto != nil {
		set("connection_info", "protocol_name", *m.Proto)
	}
	if m.Time != nil {
		if t, err := time.Parse(time.RFC3339, *m.Time); err == nil {
			o["time"] = float64(t.UnixMilli())
		}
	}
	return o
}

// -- API -------------------------------------------------------------------------------------------------
func (p *plane) Telemetry() (Telemetry, error)            { return p.tel, nil }
func (p *plane) Events() ([]types.NormalizedEvent, error) { return p.events, nil }
func (p *plane) Raw(id string) (RawResponse, error) {
	r, ok := p.raw[id]
	if !ok {
		return r, fmt.Errorf("no such event %s", id)
	}
	return r, nil
}
func (p *plane) Quarantined() ([]Sample, error) { return p.quar, nil }
func (p *plane) Lineage(id string) (Lineage, error) {
	l, ok := p.lineage[id]
	if !ok {
		return l, fmt.Errorf("no lineage for %s", id)
	}
	return l, nil
}
func (p *plane) VerifyChain(bool) (types.ChainReport, error) { return p.chain, nil }
func (p *plane) Timeline(string) ([]Binding, error)          { return p.timeline, nil }
func (p *plane) Parsers() ([]ParserInfo, error)              { return p.parsers, nil }
func (p *plane) DryRun(string, string) (types.DryRunResult, error) {
	return p.dry, nil
}
func (p *plane) DriftAlerts() ([]types.DriftAlert, error) { return p.alerts, nil }
func (p *plane) Proposals() ([]types.Proposal, error)     { return p.proposals, nil }

// Approve activates the parser and "replays": the quarantined records of the palo source become events.
func (p *plane) Approve(y, by string, replay bool) (Activation, error) {
	id := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(y, "\n", 2)[0], "id:"))
	p.approved = id
	job := "job-1"
	return Activation{ParserID: id, Version: "1.0.1", ReplayJobID: &job}, p.replayNow(id)
}

func (p *plane) replayNow(parser string) error {
	if p.replayFails {
		return nil
	}
	var keep []Sample
	for _, s := range p.quar {
		if s.SourceID != "palo_alto_unknown" || p.noDrain {
			keep = append(keep, s)
			continue
		}
		id := fmt.Sprintf("%d.%s@1.0.1", s.RecordID, parser)
		p.events = append(p.events, types.NormalizedEvent{EventID: id, RecordID: s.RecordID, RawSHA256: sha(s.Raw), ParserID: parser, Current: true, OCSF: map[string]any{}, Entities: []types.Entity{}})
	}
	p.quar = keep
	return nil
}

func (p *plane) StartReplay(string, string) (ReplayJob, error) {
	if p.dupOnReplay { // a replay that forgets it already produced these events
		n := len(p.events)
		for _, e := range p.events[:n] {
			if e.ParserID == p.approved {
				e.EventID += "-dup"
				p.events = append(p.events, e)
			}
		}
	}
	return ReplayJob{JobID: "job-2", State: "queued"}, nil
}

func (p *plane) Replay(id string) (ReplayJob, error) {
	p.polls++
	if p.polls%3 != 0 { // exercise the polling loop
		return ReplayJob{JobID: id, State: "running"}, nil
	}
	if p.replayFails {
		return ReplayJob{JobID: id, State: "done", Processed: 10, Failed: 3}, nil
	}
	return ReplayJob{JobID: id, State: "done", Processed: len(p.quar), Succeeded: len(p.quar)}, nil
}
