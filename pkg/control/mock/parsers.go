package mock

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blakc-coffee/sluice/contracts"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// radiusYAML is the one built-in the contract's DSL examples do not cover.
const radiusYAML = `id: radius_acct
version: 1.0.0
vendor: freeradius
product: radiusd
timezone: "+05:30"
match:
  signature: 'radiusd\[\d+\]: Acct-Status-Type='
ocsf_defaults: {class_uid: 3002, category_uid: 3}
extractors:
  - id: acct
    kind: kv
    skip_prefix: '^[A-Z][a-z]{2} +\d+ [\d:]+ \S+ radiusd\[\d+\]: '
    pair_sep: " "
    kv_sep: "="
    quote: '"'
    render: auto
    map:
      - {from: Acct-Status-Type, to: activity_id, type: enum, enum: {Start: 1, Stop: 2}, default: 99}
      - {from: Framed-IP-Address, to: src_endpoint.ip, type: ip}
      - {from: Calling-Station-Id, to: src_endpoint.mac, type: mac}
      - {from: User-Name, to: user.name, type: string}
identity:
  kind: radius
  when: {field: Acct-Status-Type, in: [Start, Stop]}
  action: {Start: bind, Stop: release}
  ip: Framed-IP-Address
  user: User-Name
  at: time
`

func example(name string) string {
	b, err := contracts.DSLExamples.ReadFile("dsl/examples/" + name + ".yaml")
	if err != nil {
		panic("mock: contract DSL example missing: " + name)
	}
	return string(b)
}

func (m *Mock) initParsers() {
	m.parsers, m.order = map[string]*parser{}, nil
	add := func(id, vendor, product, sig, yaml string) {
		m.parsers[id] = &parser{id: id, vendor: vendor, product: product, signature: sig, versions: []string{"1.0.0"}, active: "1.0.0",
			yaml: map[string]string{"1.0.0": yaml}}
		m.order = append(m.order, id)
	}
	add("cisco_asa", "cisco", "asa", `^(?:<\d+>)?(?:[A-Z][a-z]{2} +\d+ \d{4} [\d:]+ )?\S* ?: ?%ASA-\d-\d{6}:`, example("cisco_asa"))
	add("fortinet", "fortinet", "fortigate", `\btype="?traffic"?(?: |$)`, example("fortinet"))
	add("suricata_eve", "oisf", "suricata", `^\{.*"event_type":`, example("suricata_eve"))
	add("isc_dhcpd", "isc", "dhcpd", `dhcpd\[\d+\]: DHCP(?:ACK|RELEASE)`, example("isc_dhcpd"))
	add("radius_acct", "freeradius", "radiusd", `radiusd\[\d+\]: Acct-Status-Type=`, radiusYAML)
}

func (m *Mock) openQuarantine(source string) []types.RecordID {
	var ids []types.RecordID
	for _, q := range m.quar {
		if q.SourceID == source && q.Status == "open" {
			ids = append(ids, q.RecordID)
		}
	}
	return ids
}

func firstN(ids []types.RecordID, n int) []types.RecordID {
	if len(ids) > n {
		ids = ids[:n]
	}
	return append([]types.RecordID{}, ids...)
}

// proposePaloAlto posts the new-parser proposal the sidecar makes for the
// headerless PAN-OS rows in the backlog.
func (m *Mock) proposePaloAlto() {
	ids := m.openQuarantine("palo_alto")
	if len(ids) == 0 {
		return
	}
	n := min(len(ids), 200)
	cov := 0.94
	p := &types.Proposal{
		ID: m.newID("prop"), Kind: "new", ParserID: "palo_alto_traffic", SourceID: "palo_alto", YAML: example("palo_alto_traffic"),
		ClusterSize: len(ids), Templates: []string{",<*>,<*>,TRAFFIC,<*>,<*>,<*>,<*>,<*>,<*>,<*>,<*>,<*>"},
		SampleRecordIDs: firstN(ids, 50),
		TypedFields: []types.TypedField{
			{Field: "col_1", OCSFPath: "time", Type: "timestamp", Confidence: 0.97, Evidence: "100% match layout 2006/01/02 15:04:05; monotonic"},
			{Field: "col_7", OCSFPath: "src_endpoint.ip", Type: "ipv4", Confidence: 0.91, Evidence: "100% of values parse as IPv4; internal ranges; first IP column; paired with ephemeral ports"},
			{Field: "col_8", OCSFPath: "dst_endpoint.ip", Type: "ipv4", Confidence: 0.88, Evidence: "100% IPv4; public ranges; paired with well-known ports", Alternatives: []string{"src_endpoint.ip"}},
			{Field: "col_12", OCSFPath: "", Type: "username", Confidence: 0.41, Evidence: `word-like, domain prefix "corp\"; no name hint`, Alternatives: []string{"actor.user.name"}},
			{Field: "col_24", OCSFPath: "src_endpoint.port", Type: "port", Confidence: 0.84, Evidence: "100% in 0-65535; 97% ephemeral"},
			{Field: "col_25", OCSFPath: "dst_endpoint.port", Type: "port", Confidence: 0.9, Evidence: "100% in 0-65535; 88% well-known"},
			{Field: "col_29", OCSFPath: "connection_info.protocol_name", Type: "protocol", Confidence: 0.98, Evidence: "values {tcp, udp}; cardinality 2"},
			{Field: "col_30", OCSFPath: "action_id", Type: "action", Confidence: 0.83, Evidence: "values {allow, drop}; action lexicon", Alternatives: []string{"disposition_id"}},
			{Field: "col_31", OCSFPath: "traffic.bytes_out", Type: "bytes", Confidence: 0.72, Evidence: "non-negative integers, heavy tail; order ambiguous with col_32", Alternatives: []string{"traffic.bytes_in"}},
			{Field: "col_32", OCSFPath: "traffic.bytes_in", Type: "bytes", Confidence: 0.72, Evidence: "non-negative integers, heavy tail; order ambiguous with col_31", Alternatives: []string{"traffic.bytes_out"}},
		},
		DryRun: &types.DryRunResult{Samples: n, Parsed: n, MatchRate: 1, MeanCoverage: cov,
			FieldStats: map[string]types.FieldStat{
				"col_7":  {Present: n, Distinct: 8, Sample: []string{"10.1.4.7", "10.1.4.25", "10.1.4.9"}},
				"col_29": {Present: n, Distinct: 2, Sample: []string{"tcp", "udp"}},
				"col_30": {Present: n, Distinct: 2, Sample: []string{"allow", "drop"}},
			},
			Failures: []types.DryRunFailure{}, Warnings: []string{"field col_12 abstained (confidence 0.41), left in unmapped"}},
		Status: "pending", CreatedAt: m.now,
	}
	m.proposals = append(m.proposals, p)
}

var driftReplacer = strings.NewReplacer(
	"{from: [date, time], to: time, type: time, layout: \"2006-01-02 15:04:05\"}", "{from: eventtime, to: time, type: time, layout: epoch_ns}",
	"{from: srcip,", "{from: src,", "{from: srcport,", "{from: sport,",
	"{from: dstip,", "{from: dst,", "{from: dstport,", "{from: dport,",
	"enum: {accept: 1, close: 1, deny: 2,", "enum: {passed: 1, blocked: 2, accept: 1, close: 1, deny: 2,",
	"version: 1.0.0", "version: 1.0.1",
)

var testsBlock = regexp.MustCompile(`(?s)\n    tests:\n.*$`)

// startDrift flips Fortinet to its drifted layout, lets the quarantine fill,
// and posts the alert and patch proposal the sidecar would post.
func (m *Mock) startDrift() {
	m.scenario = ScenarioDrift
	if m.fortinetDrifted {
		return
	}
	m.fortinetDrifted = true
	for i := range 40 {
		m.sess++
		d := genFortinet(m.r, m.now.Add(time.Duration(i)*150*time.Millisecond), m.sess, true)
		m.ingest(&d)
	}
	m.now = m.now.Add(6 * time.Second)
	ids := m.openQuarantine("fortinet")
	alert := &types.DriftAlert{ID: m.newID("drift"), SourceID: "fortinet", ParserID: "fortinet", Score: 0.71,
		Signals: []string{"keys renamed: srcip->src, dstip->dst, srcport->sport, dstport->dport", "keys removed: date, time",
			"key added: eventtime (epoch ns)", "new keys: srcmac, dstcountry, utmaction, craction", "quarantine rate 0.94"},
		QuarantineRate: 0.94, FirstSeen: m.now.Add(-6 * time.Second), Status: "proposed"}
	m.drift = append(m.drift, alert)
	yaml := testsBlock.ReplaceAllString(driftReplacer.Replace(m.parsers["fortinet"].yaml["1.0.0"]), "\n")
	one := 1.0
	m.proposals = append(m.proposals, &types.Proposal{
		ID: m.newID("prop"), Kind: "patch", ParserID: "fortinet", BaseVersion: m.parsers["fortinet"].active, SourceID: "fortinet",
		YAML: yaml, DriftAlertID: alert.ID, ClusterSize: len(ids),
		Templates:       []string{"eventtime=<*> tz=+0530 devname=FG-01 <*> type=traffic <*> src=<*> sport=<*> <*> dst=<*> dport=<*> <*> action=<*> <*>"},
		SampleRecordIDs: firstN(ids, 50),
		TypedFields: []types.TypedField{
			{Field: "eventtime", OCSFPath: "time", Type: "timestamp", Confidence: 0.99, Evidence: "19-digit integers in epoch-ns range; replaces date+time"},
			{Field: "src", OCSFPath: "src_endpoint.ip", Type: "ipv4", Confidence: 0.97, Evidence: "100% IPv4; 94% internal; renamed from srcip (value shapes match)"},
			{Field: "sport", OCSFPath: "src_endpoint.port", Type: "port", Confidence: 0.93, Evidence: "100% in 0-65535; ephemeral; renamed from srcport"},
			{Field: "dst", OCSFPath: "dst_endpoint.ip", Type: "ipv4", Confidence: 0.95, Evidence: "100% IPv4; public ranges; renamed from dstip"},
			{Field: "dport", OCSFPath: "dst_endpoint.port", Type: "port", Confidence: 0.94, Evidence: "100% in 0-65535; well-known; renamed from dstport"},
			{Field: "action", OCSFPath: "action_id", Type: "action", Confidence: 0.86, Evidence: "values {passed, blocked}; action lexicon; quoting changed"},
			{Field: "srcmac", OCSFPath: "src_endpoint.mac", Type: "mac", Confidence: 0.72, Evidence: "100% MAC; new key, no predecessor"},
			{Field: "dstcountry", OCSFPath: "", Type: "string", Confidence: 0.41, Evidence: "country names; no OCSF path in the 4001 subset", Alternatives: []string{"dst_endpoint.location.country"}},
		},
		DryRun: &types.DryRunResult{Samples: len(ids), Parsed: len(ids), MatchRate: 1, MeanCoverage: 0.96, RenderBackOKRate: &one,
			FieldStats: map[string]types.FieldStat{
				"src":    {Present: len(ids), Distinct: 8, Sample: []string{"10.1.4.7", "10.3.0.75", "10.1.4.25"}},
				"action": {Present: len(ids), Distinct: 2, Sample: []string{"passed", "blocked"}},
			},
			Failures: []types.DryRunFailure{}, Warnings: []string{"field dstcountry abstained (confidence 0.41), left in unmapped", "field srcmac mapped with confidence 0.72, below 0.8: confirm"}},
		Status: "pending", CreatedAt: m.now,
	})
}

var (
	yamlID      = regexp.MustCompile(`(?m)^id:\s*([a-z0-9_]+)\s*$`)
	yamlVersion = regexp.MustCompile(`(?m)^version:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$`)
)

// errBadYAML is a loader failure: the mock checks only what a real loader
// would reject first (an id and an extractors block).
type errBadYAML struct{ msg string }

func (e errBadYAML) Error() string { return e.msg }

func parseHeader(yaml string) (id, version string, err error) {
	mid := yamlID.FindStringSubmatch(yaml)
	if mid == nil {
		return "", "", errBadYAML{"parser: missing or invalid `id` (want [a-z0-9_]+)"}
	}
	if !strings.Contains(yaml, "\nextractors:") {
		return "", "", errBadYAML{fmt.Sprintf("parser %s: no `extractors` block", mid[1])}
	}
	if mv := yamlVersion.FindStringSubmatch(yaml); mv != nil {
		version = mv[1]
	}
	return mid[1], version, nil
}

// dryRun validates yaml against quarantined samples of its source. It has no
// side effects.
func (m *Mock) dryRun(yaml, source string, limit int) (*types.DryRunResult, error) {
	id, _, err := parseHeader(yaml)
	if err != nil {
		return nil, err
	}
	var base *types.DryRunResult
	for _, p := range m.proposals {
		if p.ParserID == id && p.DryRun != nil {
			base = p.DryRun
		}
	}
	if source == "" {
		source = id
		for _, p := range m.proposals {
			if p.ParserID == id {
				source = p.SourceID
			}
		}
	}
	if limit <= 0 {
		limit = 200
	}
	var samples []types.RecordID
	for _, q := range m.quar {
		if q.SourceID == source && len(samples) < limit {
			samples = append(samples, q.RecordID)
		}
	}
	for i := len(m.events) - 1; i >= 0 && len(samples) < limit; i-- {
		if m.events[i].ev.SourceID == source {
			samples = append(samples, m.events[i].ev.RecordID)
		}
	}
	n := len(samples)
	res := &types.DryRunResult{Samples: n, Parsed: n, MatchRate: 1, MeanCoverage: 0.95, FieldStats: map[string]types.FieldStat{},
		Failures: []types.DryRunFailure{}, Warnings: []string{}}
	if base != nil {
		res.MeanCoverage, res.RenderBackOKRate, res.FieldStats = base.MeanCoverage, base.RenderBackOKRate, base.FieldStats
		res.Warnings = append(res.Warnings, base.Warnings...)
	}
	if n == 0 {
		res.MatchRate, res.MeanCoverage = 0, 0
		res.Warnings = append(res.Warnings, "no samples stored for source "+source)
	}
	for _, path := range []string{"src_endpoint.ip", "dst_endpoint.ip", "time"} {
		if !strings.Contains(yaml, "to: "+path) && !strings.Contains(yaml, "to: "+path+",") {
			// Losing a core field costs every sample its match.
			res.Parsed, res.Failed, res.MatchRate = 0, n, 0
			res.Warnings = append(res.Warnings, "no mapping writes "+path+", required for class 4001")
			for _, r := range firstN(samples, 20) {
				res.Failures = append(res.Failures, types.DryRunFailure{RecordID: r, Error: "missing_required:" + path})
			}
			break
		}
	}
	return res, nil
}

var errStale = errors.New("stale")

type activation struct {
	ParserID    string  `json:"parser_id"`
	Version     string  `json:"version"`
	ReplayJobID *string `json:"replay_job_id"`
}

func bumpPatch(v string) string {
	parts := strings.Split(v, ".")
	n, _ := strconv.Atoi(parts[2])
	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], n+1)
}

// approve activates a parser version and optionally starts the quarantine
// replay for its source, the data plane's POST /admin/parsers/approve.
func (m *Mock) approve(yaml, proposalID, by, comment string, replay bool) (*activation, error) {
	id, _, err := parseHeader(yaml)
	if err != nil {
		return nil, err
	}
	var prop *types.Proposal
	for _, p := range m.proposals {
		if p.ID == proposalID {
			prop = p
		}
	}
	p := m.parsers[id]
	if prop != nil && prop.Kind == "patch" && p != nil && prop.BaseVersion != p.active {
		prop.Status = "stale"
		return nil, errStale
	}
	version := "1.0.0"
	if p == nil {
		vendor, product := "", ""
		if prop != nil {
			vendor, product = prop.SourceID, prop.SourceID
		}
		if id == "palo_alto_traffic" {
			vendor, product = "palo_alto", "pan-os"
		}
		p = &parser{id: id, vendor: vendor, product: product, signature: `^,\d{4}/\d\d/\d\d \d\d:\d\d:\d\d,\d+,TRAFFIC,`, yaml: map[string]string{}}
		m.parsers[id] = p
		m.order = append(m.order, id)
	} else {
		version = bumpPatch(p.active)
	}
	p.versions = append(p.versions, version)
	p.yaml[version] = yamlVersion.ReplaceAllString(yaml, "version: "+version)
	p.active = version
	source := id
	if prop != nil {
		prop.Status = "approved"
		source = prop.SourceID
		for _, a := range m.drift {
			if a.ID == prop.DriftAlertID {
				a.Status = "resolved"
			}
		}
	}
	res := &activation{ParserID: id, Version: version}
	if replay {
		j := m.startJob("quarantine", source, m.openQuarantine(source))
		res.ReplayJobID = &j.JobID
	}
	m.scenario = ScenarioApproved
	return res, nil
}

func (m *Mock) startJob(scope, source string, ids []types.RecordID) *job {
	j := &job{replayJob: replayJob{JobID: m.newID("replay"), State: "queued", Scope: scope}, source: source, pending: ids}
	m.jobs[j.JobID] = j
	m.jobOrder = append(m.jobOrder, j.JobID)
	return j
}

// runJobs gives every unfinished job one tick of work.
func (m *Mock) runJobs() {
	for _, id := range m.jobOrder {
		if j := m.jobs[id]; j.State == "queued" || j.State == "running" {
			m.stepJob(j, 12)
		}
	}
}

func (m *Mock) stepJob(j *job, n int) {
	if j.State == "queued" {
		t := m.now
		j.State, j.StartedAt = "running", &t
	}
	for ; n > 0 && len(j.pending) > 0; n-- {
		rid := j.pending[0]
		j.pending = j.pending[1:]
		j.Processed++
		d, q := m.drafts[rid], m.quarByRec[rid]
		parserID := ""
		if d != nil && d.laterParser != "" && m.hasApprovedFor(d.laterParser, d.sourceID) {
			parserID = d.laterParser
		}
		if parserID == "" || q == nil {
			j.Failed++
			continue
		}
		rec, rc, err := m.v.Get(bg, rid)
		if err != nil {
			j.Failed++
			continue
		}
		ev := m.materialize(rc, rec, d, parserID)
		m.addEvent(ev)
		q.Status, q.ResolvedBy = "resolved", parserID+"@"+ev.ParserVersion
		j.Succeeded++
	}
	if len(j.pending) == 0 {
		t := m.now
		j.State, j.FinishedAt = "done", &t
	}
}

func (m *Mock) allJobsDone() bool {
	for _, j := range m.jobs {
		if j.State == "queued" || j.State == "running" {
			return false
		}
	}
	return true
}
