// Command gen writes contracts/golden/*.json.
//
// Every golden is built from real fixture lines in testdata/sample, stored in a
// memvault, so record ids, raw hashes, Merkle proofs and the chain head are
// real output of the production merkle code rather than invented hex. Records
// are referenced consistently across files (record 8 is the Palo Alto line in
// the quarantine list, the proposal and its dry run).
//
// Deterministic: fixed fixtures, fixed clock, no time.Now, no map iteration
// into output (encoding/json sorts map keys). `make contract-golden` runs it;
// `make contract-test` fails if the checked-in files differ.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/memvault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// ocsfVersion is contracts/ocsf/VERSION.
const ocsfVersion = "1.1.0"

type fixture struct {
	file, match, source string
	kind                types.OriginKind
	addr                string
	layout              string // time layout of the line's own timestamp, "" = unused
	ts                  string
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

// line returns the first line of testdata/sample/file containing match.
func line(dir, file, match string) string { return nthLine(dir, file, match, 1) }

// nthLine returns the n-th (1-based) line containing match.
func nthLine(dir, file, match string, n int) string {
	b, err := os.ReadFile(filepath.Join(dir, file))
	die(err)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, match) {
			if n--; n == 0 {
				return strings.TrimRight(l, "\r")
			}
		}
	}
	die(fmt.Errorf("%s: no line containing %q", file, match))
	return ""
}

func hexsum(b []byte) string    { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func at(s string) time.Time     { t, err := time.Parse(time.RFC3339, s); die(err); return t.UTC() }
func tp(t time.Time) *time.Time { return &t }
func bp(b bool) *bool           { return &b }

func main() {
	fixtures := flag.String("fixtures", "testdata/sample", "sample corpus")
	out := flag.String("out", "contracts/golden", "output directory")
	flag.Parse()
	ctx := context.Background()

	// --- the records, in vault order (RecordID = position) -------------------
	type rec struct {
		src, raw string
		origin   types.Origin
		at       time.Time
	}
	udp := func(a string) types.Origin { return types.Origin{Kind: types.OriginUDP, Addr: a} }
	file := func(p string, off uint64) types.Origin {
		return types.Origin{Kind: types.OriginFile, Addr: p, Offset: off}
	}
	recs := []rec{
		{"cisco_asa", line(*fixtures, "cisco_asa.log", "%ASA-6-302013"), udp("192.0.2.10:514"), at("2026-09-28T03:30:07.120Z")},
		{"cisco_asa", line(*fixtures, "cisco_asa.log", "%ASA-4-106023"), udp("192.0.2.10:514"), at("2026-09-28T03:30:07.480Z")},
		{"fortinet", line(*fixtures, "fortinet.log", "type=\"traffic\""), file("/var/log/fortinet.log", 0), at("2026-09-28T03:30:02.900Z")},
		{"suricata", line(*fixtures, "suricata.json", "\"event_type\":\"alert\""), file("/var/log/suricata/eve.json", 0), at("2026-09-28T03:30:00.700Z")},
		{"dhcp", line(*fixtures, "dhcp.log", "DHCPACK on 10.1.4.9 to aa:bb:cc:8a:06:2d"), udp("192.0.2.30:514"), at("2026-09-28T03:31:14.050Z")},
		{"radius", line(*fixtures, "radius.log", "Start User-Name=\"carol\" Framed-IP-Address=10.1.4.9 "), udp("192.0.2.31:514"), at("2026-09-28T03:31:35.020Z")},
		{"cisco_asa", line(*fixtures, "identity_firewall.log", "302013: Built outbound TCP connection 5001"), udp("192.0.2.10:514"), at("2026-09-28T03:41:29.310Z")},
		{"palo_alto", line(*fixtures, "palo_alto_unknown.log", ",TRAFFIC,"), udp("192.0.2.40:514"), at("2026-09-28T03:30:02.610Z")},
		{"fortinet", line(*fixtures, "fortinet_drift.log", "eventtime="), file("/var/log/fortinet.log", 515), at("2026-09-28T03:30:02.950Z")},
		{"fortinet", nthLine(*fixtures, "fortinet.log", "type=\"traffic\"", 2), file("/var/log/fortinet.log", 1030), at("2026-09-28T03:30:04.100Z")},
	}

	mv := memvault.New(memvault.Options{SealEvery: 8, Now: func() time.Time { return at("2026-09-28T04:00:00Z") }})
	var rs []types.RawRecord
	for _, r := range recs {
		rs = append(rs, types.RawRecord{SourceID: r.src, ReceivedAt: r.at, Origin: r.origin, Term: types.TermLF, Raw: []byte(r.raw)})
	}
	receipts, err := mv.PutBatch(ctx, rs)
	die(err)
	sha := func(id int) string { return hex.EncodeToString(receipts[id-1].RawSHA256[:]) }
	seg := func(id int) uint64 { return receipts[id-1].Segment }

	rawBytes := 0
	for _, r := range recs {
		rawBytes += len(r.raw)
	}
	w := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		die(err)
		die(os.WriteFile(filepath.Join(*out, name+".json"), append(b, '\n'), 0o644))
	}

	// --- events --------------------------------------------------------------
	// unmapped and coverage come from the DSL example that specifies each
	// parser; the OCSF map is written out here and checked against the DSL's
	// `to:` paths by TestOCSFPathsMatchDSL.
	ev := func(id int, parser, extractor string, evTime time.Time, conf float64, ocsf map[string]any) types.NormalizedEvent {
		r, pd := recs[id-1], loadParser(parser)
		a := pd.extractor(extractor).account(r.raw)
		return types.NormalizedEvent{
			EventID: fmt.Sprintf("%d.%s@%s", id, pd.ID, pd.Version), RecordID: types.RecordID(id), Segment: seg(id),
			RawSHA256: sha(id), SourceID: r.src, Vendor: pd.Vendor, Product: pd.Product,
			ParserID: pd.ID, ParserVersion: pd.Version, TemplateID: pd.ID + "/" + extractor,
			SchemaVersion: "ulpf-uef/1", ReceivedAt: r.at, EventTime: tp(evTime), ParseConfidence: conf,
			IntegrityFlags: []string{}, OCSF: ocsf, Unmapped: a.unmapped, Entities: []types.Entity{},
			Coverage: a.cov, Current: true,
		}
	}
	meta := func(parser string) map[string]any {
		pd := loadParser(parser)
		return map[string]any{"version": ocsfVersion, "product": map[string]any{"vendor_name": pd.Vendor, "name": pd.Product}}
	}
	ms := func(t time.Time) int64 { return t.UnixMilli() }
	net := func(class map[string]any) map[string]any {
		class["class_uid"], class["category_uid"] = 4001, 4
		return class
	}
	ep := func(ip string, port int) map[string]any { return map[string]any{"ip": ip, "port": port} }
	conn := func(proto string, num int) map[string]any {
		return map[string]any{"protocol_name": proto, "protocol_num": num}
	}

	t1 := at("2026-09-28T03:30:07Z")
	e1 := ev(1, "cisco_asa", "asa_302013", t1, 1.0, net(map[string]any{
		"activity_id": 1, "type_uid": 400101, "time": ms(t1), "severity_id": 1, "action_id": 1, "disposition_id": 1,
		"src_endpoint": ep("192.0.2.179", 22), "dst_endpoint": ep("10.1.11.225", 56376),
		"connection_info": conn("tcp", 6), "metadata": meta("cisco_asa"),
	}))
	w("event_asa_built", e1)

	t2 := at("2026-09-28T03:30:07Z")
	e2 := ev(2, "cisco_asa", "asa_106023", t2, 1.0, net(map[string]any{
		"activity_id": 5, "type_uid": 400105, "time": ms(t2), "severity_id": 3, "action_id": 2, "disposition_id": 2,
		"src_endpoint": ep("198.51.100.5", 59563), "dst_endpoint": ep("10.1.4.54", 3306),
		"connection_info": conn("udp", 17), "metadata": meta("cisco_asa"),
	}))
	w("event_asa_deny", e2)

	t3 := at("2026-09-28T03:30:02Z")
	e3 := ev(3, "fortinet", "fgt_traffic", t3, 1.0, net(map[string]any{
		"activity_id": 6, "type_uid": 400106, "time": ms(t3), "severity_id": 2, "action_id": 1, "disposition_id": 1,
		"src_endpoint": ep("10.1.4.25", 53513), "dst_endpoint": ep("203.0.113.125", 143),
		"connection_info": conn("tcp", 6), "traffic": map[string]any{"bytes_out": 734601, "bytes_in": 677693, "packets_out": 331, "packets_in": 397},
		"metadata": meta("fortinet"), "duration": 554000,
	}))
	w("event_fortinet", e3)

	t4 := at("2026-09-28T03:30:00.693Z")
	e4 := ev(4, "suricata_eve", "eve_alert", t4, 0.95, net(map[string]any{
		"activity_id": 6, "type_uid": 400106, "time": ms(t4), "severity_id": 3, "action_id": 1, "disposition_id": 15,
		"src_endpoint": ep("198.51.100.236", 55929), "dst_endpoint": ep("10.1.4.50", 5432),
		"connection_info": conn("tcp", 6), "metadata": meta("suricata_eve"),
		"message": "ET SCAN Potential SSH Scan",
	}))
	w("event_suricata_alert", e4)

	// Record 7: outbound ASA connection from 10.1.4.9, resolved to carol via
	// the radius (6) and dhcp (5) records.
	t7 := at("2026-09-28T03:41:29Z")
	e7 := ev(7, "cisco_asa", "asa_302013", t7, 1.0, net(map[string]any{
		"activity_id": 1, "type_uid": 400101, "time": ms(t7), "severity_id": 1, "action_id": 1, "disposition_id": 1,
		"src_endpoint": ep("10.1.4.9", 60003), "dst_endpoint": ep("198.51.100.232", 53),
		"connection_info": conn("tcp", 6), "metadata": meta("cisco_asa"),
	}))
	from := at("2026-09-28T03:31:35Z")
	to := at("2026-09-28T04:12:14Z")
	dhcpFrom := at("2026-09-28T03:31:14Z")
	dhcpTo := at("2026-09-28T04:13:25Z")
	e7.Entities = []types.Entity{
		{Type: "ip", ID: "10.1.4.9", Role: "src", Confidence: 1, Evidence: []types.EvidenceRef{}},
		{Type: "user", ID: "carol", Role: "src", ValidFrom: tp(from), ValidTo: tp(to), Confidence: 1, Evidence: []types.EvidenceRef{{RecordID: 6, Kind: "radius"}}},
		{Type: "host", ID: "laptop-carol", Role: "src", ValidFrom: tp(dhcpFrom), ValidTo: tp(dhcpTo), Confidence: 1, Evidence: []types.EvidenceRef{{RecordID: 5, Kind: "dhcp"}}},
		{Type: "mac", ID: "aa:bb:cc:8a:06:2d", Role: "src", ValidFrom: tp(dhcpFrom), ValidTo: tp(dhcpTo), Confidence: 1, Evidence: []types.EvidenceRef{{RecordID: 5, Kind: "dhcp"}}},
	}
	w("event_with_entities", e7)

	// Record 5: an identity-source event carrying its IdentityFact.
	t5 := at("2026-09-28T03:31:14Z")
	e5 := ev(5, "isc_dhcpd", "dhcp_lease", t5, 1.0, map[string]any{
		"class_uid": 4004, "category_uid": 4, "activity_id": 5, "type_uid": 400405, "time": ms(t5), "severity_id": 1,
		"src_endpoint": map[string]any{"ip": "10.1.4.9", "mac": "aa:bb:cc:8a:06:2d", "hostname": "laptop-carol"},
		"metadata":     meta("isc_dhcpd"),
	})
	e5.Identity = &types.IdentityFact{Kind: "dhcp", Action: "bind", IP: "10.1.4.9", MAC: "aa:bb:cc:8a:06:2d", Host: "laptop-carol", At: t5, RecordID: 5, SourceID: "dhcp"}
	w("identity_dhcp_bind", e5)

	// --- quarantine, drift, proposal, dry run ---------------------------------
	q8 := types.QuarantineRecord{RecordID: 8, SourceID: "palo_alto", FailureStage: "detect", Error: "no parser matched", ReceivedAt: recs[7].at, Status: "open"}
	q9 := types.QuarantineRecord{RecordID: 9, SourceID: "fortinet", FailureStage: "extract", Error: "extractor fgt_traffic: pattern did not match (missing key srcip)", ReceivedAt: recs[8].at, Status: "open"}
	w("quarantine_list", map[string]any{
		"records":     []types.QuarantineRecord{q8, q9},
		"next_cursor": nil,
		"summary": []map[string]any{
			{"source_id": "fortinet", "open": 1, "resolved": 0, "ignored": 0, "by_stage": map[string]int{"extract": 1}},
			{"source_id": "palo_alto", "open": 1, "resolved": 0, "ignored": 0, "by_stage": map[string]int{"detect": 1}},
		},
	})

	first := at("2026-09-28T03:30:03Z")
	w("drift_alert", types.DriftAlert{ID: "drift-01", SourceID: "fortinet", ParserID: "fortinet", Score: 0.71,
		Signals:        []string{"keys renamed: srcip->src, dstip->dst, srcport->sport, dstport->dport", "keys removed: date, time", "key added: eventtime", "quarantine rate 0.94"},
		QuarantineRate: 0.94, FirstSeen: first, Status: "open"})

	dry := types.DryRunResult{Samples: 50, Parsed: 49, Failed: 1, MatchRate: 0.98, MeanCoverage: 0.97, RenderBackOKRate: nil,
		FieldStats: map[string]types.FieldStat{
			"col_7":  {Present: 50, Distinct: 8, Sample: []string{"10.1.4.60", "10.1.4.8", "10.1.4.52"}},
			"col_29": {Present: 50, Distinct: 2, Sample: []string{"tcp", "udp"}},
		},
		Failures: []types.DryRunFailure{{RecordID: 8, Error: "csv: 41 columns, expected at least 47"}},
		Warnings: []string{"field col_12 abstained (confidence 0.41), left in unmapped"}}
	w("dryrun_result", dry)

	w("proposal_palo_alto", types.Proposal{
		ID: "prop-01", Kind: "new", ParserID: "palo_alto_traffic", BaseVersion: "", SourceID: "palo_alto",
		YAML:        "id: palo_alto_traffic\nversion: 1.0.0\nvendor: palo_alto\nproduct: pan-os\nextractors:\n  - id: pan_traffic\n    kind: csv\n    sep: \",\"\n    min_columns: 47\n    columns: [_, ts, _, _, action_word, _, _, src_ip, dst_ip]\n    map:\n      - {from: src_ip, to: src_endpoint.ip, type: ip}\n",
		ClusterSize: 50, Templates: []string{",<*>,<*>,TRAFFIC,<*>,<*>,<*>,<*>,<*>,<*>"}, SampleRecordIDs: []types.RecordID{8},
		TypedFields: []types.TypedField{
			{Field: "col_7", OCSFPath: "src_endpoint.ip", Type: "ipv4", Confidence: 0.91, Evidence: "100% of values parse as IPv4; internal ranges; first IP column; paired with ephemeral ports"},
			{Field: "col_8", OCSFPath: "dst_endpoint.ip", Type: "ipv4", Confidence: 0.88, Evidence: "100% IPv4; public ranges; paired with well-known ports", Alternatives: []string{"src_endpoint.ip"}},
		},
		DryRun: &dry, Status: "pending", CreatedAt: at("2026-09-28T03:31:00Z"),
	})

	// --- lineage --------------------------------------------------------------
	head, through, err := mv.Head(ctx)
	die(err)
	proof, err := mv.Proof(ctx, 1)
	die(err)
	chain := map[string]any{"head": hex.EncodeToString(head[:]), "sealed_through": uint64(through)}
	w("lineage_sealed", map[string]any{
		"event_id": e1.EventID, "record_id": 1, "raw_sha256": sha(1), "sealed": true,
		"proof": vault.NewProofJSON(proof), "chain": chain, "coverage": e1.Coverage,
		"render_back": map[string]any{"applicable": true, "ok": true},
	})
	w("lineage_pending", map[string]any{
		"event_id": "10.fortinet@1.0.0", "record_id": 10, "raw_sha256": sha(10), "sealed": false,
		"proof": nil, "chain": chain, "coverage": loadParser("fortinet").extractor("fgt_traffic").account(recs[9].raw).cov,
		"render_back": map[string]any{"applicable": true, "ok": true},
	})

	// --- raw, telemetry, replay, parsers, error --------------------------------
	w("raw_response", map[string]any{
		"record_id": 1, "segment": seg(1), "raw_base64": b64(recs[0].raw), "raw_sha256": sha(1), "sha_match": true,
		"origin": recs[0].origin, "terminator": types.TermLF, "fragment": types.FragNone, "received_at": recs[0].at,
	})
	w("telemetry", map[string]any{
		"eps_1m": 812.4, "eps_peak": 2210.0, "events_total": 8, "quarantined_total": 2, "quarantine_open": 2,
		"vault": map[string]any{"records": len(recs), "segments": 1, "bytes_raw": rawBytes, "bytes_compressed": rawBytes * 4 / 9, "ratio": 2.25,
			"chain_head": chain["head"], "sealed_through": chain["sealed_through"], "failed": false},
		"lossless": map[string]any{"last_verify_ok": true, "last_verify_at": at("2026-09-28T04:00:00Z")},
		"sources":  []map[string]any{{"id": "cisco_asa", "eps": 310.2, "records": 3}, {"id": "fortinet", "eps": 180.0, "records": 2}},
		"sinks":    []map[string]any{{"name": "parquet", "lag": 0, "errors": 0}},
	})
	w("replay_job", map[string]any{
		"job_id": "replay-01", "state": "done", "scope": "quarantine", "processed": 50, "succeeded": 50, "failed": 0,
		"started_at": at("2026-09-28T03:35:00Z"), "finished_at": at("2026-09-28T03:35:02Z"), "error": nil,
	})
	w("parsers_list", map[string]any{"parsers": []map[string]any{
		{"id": "cisco_asa", "active_version": "1.0.0", "versions": []string{"1.0.0"}, "vendor": "cisco", "product": "asa", "signature": "^(?:<\\d+>)?(?:[A-Z][a-z]{2} +\\d+ \\d{4} [\\d:]+ )?\\S* ?: ?%ASA-\\d-\\d{6}:"},
		{"id": "fortinet", "active_version": "1.0.0", "versions": []string{"1.0.0"}, "vendor": "fortinet", "product": "fortigate", "signature": "type=\"?traffic"},
	}})
	w("error", map[string]any{"error": map[string]any{"code": "not_found", "message": "event 999.cisco_asa@1.0.0 does not exist"}})
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
