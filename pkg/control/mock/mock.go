// Package mock is an in-process stand-in for the data plane's admin API
// (contracts/admin.openapi.yaml), so the control plane and the UI can be built
// and demoed without cmd/dataplane.
//
// It is not a fake that returns canned JSON. Raw lines go into a real
// memvault, so hashes, inclusion proofs and chain heads are the ones the real
// vault would produce and the browser verifier checks them for real. Events,
// quarantine, proposals and replay are driven by a small scenario state
// machine:
//
//	steady   -> events flow; Palo Alto rows have no parser and are quarantined
//	drift    -> Fortinet switches to its post-upgrade layout; a drift alert and
//	            a patch proposal appear, quarantine grows
//	approved -> a proposal was approved; its replay job drains the quarantine
//
// The clock is virtual and advances only through Tick, so tests are
// deterministic. cmd/control ticks it once a second.
package mock

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/memvault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// Scenario names, in the order Advance walks them.
const (
	ScenarioSteady   = "steady"
	ScenarioDrift    = "drift"
	ScenarioApproved = "approved"
)

// Options configure a Mock.
type Options struct {
	// Seed makes every generated line and event reproducible. Zero means 1.
	Seed uint64
	// Backlog is how many minutes of history exist before the first Tick.
	// Zero means 60; negative means none.
	Backlog int
	// SealEvery is passed to memvault. Zero means 64, so most records have a
	// proof within a few seconds.
	SealEvery int
	// MaxEvents caps the mock's event list (the oldest are dropped from the
	// list, not from the vault). Zero means 50000.
	MaxEvents int
}

// Start is the virtual time of the first live tick: 2026-09-28 09:00 IST,
// the fixture corpus's base time.
var Start = time.Date(2026, 9, 28, 3, 30, 0, 0, time.UTC)

type evRow struct {
	seq int
	ev  types.NormalizedEvent
}

type parser struct {
	id, vendor, product, signature string
	versions                       []string
	active                         string
	yaml                           map[string]string
}

// replayJob is the wire form of uef.schema.json#/$defs/replay_job.
type replayJob struct {
	JobID      string     `json:"job_id"`
	State      string     `json:"state"`
	Scope      string     `json:"scope"`
	Processed  int        `json:"processed"`
	Succeeded  int        `json:"succeeded"`
	Failed     int        `json:"failed"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      *string    `json:"error"`
}

type job struct {
	replayJob
	source  string
	pending []types.RecordID
}

// Mock is the scenario state. All methods are safe for concurrent use.
type Mock struct {
	mu   sync.Mutex
	opts Options
	r    *rand.Rand
	v    *memvault.Vault
	now  time.Time

	events    []*evRow
	byID      map[string]*evRow
	byRecord  map[types.RecordID][]*evRow
	nextSeq   int
	drafts    map[types.RecordID]*draft
	quar      []*types.QuarantineRecord
	quarByRec map[types.RecordID]*types.QuarantineRecord

	drift     []*types.DriftAlert
	proposals []*types.Proposal
	parsers   map[string]*parser
	order     []string
	jobs      map[string]*job
	jobOrder  []string
	claims    []*claim

	scenario        string
	fortinetDrifted bool

	window       []int // records ingested per tick, newest last, at most 60
	peak         float64
	records      int
	bytesRaw     int
	lastVerify   time.Time
	lastVerifyOK bool
	conn, sess   int
	ids          int
}

// New builds the mock, fills the backlog and runs one deep verification.
func New(opts Options) *Mock {
	if opts.Seed == 0 {
		opts.Seed = 1
	}
	if opts.Backlog == 0 {
		opts.Backlog = 60
	}
	if opts.SealEvery == 0 {
		opts.SealEvery = 64
	}
	if opts.MaxEvents == 0 {
		opts.MaxEvents = 50000
	}
	m := &Mock{opts: opts}
	m.reset()
	return m
}

// Reset rebuilds the mock from its seed, as if freshly constructed.
func (m *Mock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reset()
}

func (m *Mock) reset() {
	m.r = rand.New(rand.NewPCG(m.opts.Seed, 0x756c7066))
	m.v = memvault.New(memvault.Options{SealEvery: m.opts.SealEvery, Now: func() time.Time { return m.now }})
	m.events, m.byID, m.byRecord, m.nextSeq = nil, map[string]*evRow{}, map[types.RecordID][]*evRow{}, 1
	m.drafts, m.quar, m.quarByRec = map[types.RecordID]*draft{}, nil, map[types.RecordID]*types.QuarantineRecord{}
	m.drift, m.proposals, m.jobs, m.jobOrder, m.claims = nil, nil, map[string]*job{}, nil, nil
	m.scenario, m.fortinetDrifted = ScenarioSteady, false
	m.window, m.peak, m.records, m.bytesRaw = nil, 0, 0, 0
	m.conn, m.sess, m.ids = 1000, 600000, 0
	m.initParsers()

	backlog := time.Duration(max(m.opts.Backlog, 0)) * time.Minute
	m.now = Start.Add(-backlog)
	if backlog > 0 {
		m.fillBacklog(m.now, backlog)
	}
	m.now = Start
	m.proposePaloAlto()
	m.verify(true)
}

// fillBacklog writes history in time order: the identity scenario plus a
// steady mix of traffic, and a burst of unknown Palo Alto rows.
func (m *Mock) fillBacklog(from time.Time, span time.Duration) {
	var ds []draft
	for i, s := range identityPlan {
		if s.offset < span {
			ds = append(ds, identityDraft(s, from.Add(s.offset), 0xA1B20000+i))
		}
	}
	// Firewall events on 10.1.4.7 either side of the reassignment and in the
	// gap, so the timeline has something to show.
	for _, off := range []time.Duration{10 * time.Minute, 20 * time.Minute, 32 * time.Minute, 34 * time.Minute, 45 * time.Minute, 55 * time.Minute} {
		if off < span {
			at := from.Add(off)
			d := draft{sourceID: "cisco_asa", parserID: "cisco_asa", vendor: "cisco", product: "asa", at: at, proto: "tcp",
				origin: types.Origin{Kind: types.OriginUDP, Addr: "192.0.2.10:514"}, applicable: true, class: 4001}
			ds = append(ds, asaBuilt(d, "outbound", "10.1.4.7", ephemeral(m.r), pick(m.r, externalHosts), 443, m.nextConn()))
		}
	}
	for t := from; t.Before(from.Add(span)); t = t.Add(3 * time.Second) {
		ds = append(ds, m.trafficDraft(t))
	}
	for i := 0; i < 50; i++ {
		ds = append(ds, genPaloAlto(m.r, from.Add(span-10*time.Minute+time.Duration(i)*7*time.Second), paloUsers))
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].at.Before(ds[j].at) })
	for i := range ds {
		m.now = ds[i].at.Add(40 * time.Millisecond)
		m.ingest(&ds[i])
	}
}

var paloUsers = []string{"alice", "bob", "carol", "dave", "erin"}

func (m *Mock) nextConn() int { m.conn++; return m.conn }

// trafficDraft picks one line of the steady ASA / Fortinet / Suricata mix.
func (m *Mock) trafficDraft(t time.Time) draft {
	switch n := m.r.IntN(10); {
	case n < 5:
		return genASA(m.r, t, m.nextConn())
	case n < 8:
		m.sess++
		return genFortinet(m.r, t, m.sess, m.fortinetDrifted)
	default:
		return genSuricata(m.r, t)
	}
}

// ingest stores the raw line and then normalizes or quarantines it, in that
// order: nothing downstream exists before the vault has the bytes.
func (m *Mock) ingest(d *draft) {
	rec := types.RawRecord{SourceID: d.sourceID, ReceivedAt: d.at.Add(37 * time.Millisecond).UTC(), Origin: d.origin, Term: types.TermLF, Raw: d.raw}
	if d.origin.Kind == types.OriginUDP {
		rec.Term = types.TermNone
	}
	rc, err := m.v.Put(context.Background(), rec)
	if err != nil {
		panic("mock: memvault rejected a generated record: " + err.Error()) // generator bug, never input
	}
	m.records++
	m.bytesRaw += len(d.raw)
	m.drafts[rc.ID] = d
	if len(m.window) > 0 {
		m.window[len(m.window)-1]++
	}
	if d.identity != nil {
		d.identity.RecordID, d.identity.SourceID = rc.ID, d.sourceID
		m.observe(*d.identity)
	}
	parserID := d.parserID
	if parserID == "" && d.laterParser != "" && m.hasApprovedFor(d.laterParser, d.sourceID) {
		parserID = d.laterParser
	}
	if parserID == "" {
		q := &types.QuarantineRecord{RecordID: rc.ID, SourceID: d.sourceID, FailureStage: d.stage, Error: d.err, ReceivedAt: rec.ReceivedAt, Status: "open"}
		m.quar = append(m.quar, q)
		m.quarByRec[rc.ID] = q
		return
	}
	m.addEvent(m.materialize(rc, rec, d, parserID))
}

// hasApprovedFor reports whether a version of parserID that reads the
// quarantined layout of source has been activated.
func (m *Mock) hasApprovedFor(parserID, source string) bool {
	p := m.parsers[parserID]
	if p == nil {
		return false
	}
	if parserID == "fortinet" {
		return p.active != "1.0.0"
	}
	return true
}

func (m *Mock) materialize(rc types.Receipt, rec types.RawRecord, d *draft, parserID string) types.NormalizedEvent {
	version := m.parsers[parserID].active
	at := d.at.UTC()
	ev := types.NormalizedEvent{
		EventID: fmt.Sprintf("%d.%s@%s", rc.ID, parserID, version), RecordID: rc.ID, Segment: rc.Segment,
		RawSHA256: fmt.Sprintf("%x", rc.RawSHA256), SourceID: d.sourceID, Vendor: d.vendor, Product: d.product,
		ParserID: parserID, ParserVersion: version, TemplateID: parserID + "/" + d.extractor, SchemaVersion: "ulpf-uef/1",
		ReceivedAt: rec.ReceivedAt, EventTime: &at, ParseConfidence: 1, IntegrityFlags: []string{},
		OCSF: d.ocsf(), Unmapped: d.unmapped, Entities: []types.Entity{}, Coverage: d.coverage(), Current: true,
	}
	if ev.Unmapped == nil {
		ev.Unmapped = map[string]any{}
	}
	if d.identity != nil {
		f := *d.identity
		ev.Identity = &f
	}
	for _, side := range []struct{ ip, role string }{{d.srcIP, "src"}, {d.dstIP, "dst"}} {
		if side.ip == "" || !isInternal(side.ip) {
			continue
		}
		ev.Entities = append(ev.Entities, types.Entity{Type: "ip", ID: side.ip, Role: side.role, Confidence: 1, Evidence: []types.EvidenceRef{}})
		ev.Entities = append(ev.Entities, m.resolve(side.ip, at, side.role)...)
	}
	// A deterministic handful of events carry flags, so the flag filter and
	// the confidence column have something to show.
	switch rc.ID % 97 {
	case 13:
		ev.IntegrityFlags = []string{types.FlagDuplicateKey}
		ev.ParseConfidence = 0.94
	case 41:
		ev.IntegrityFlags = []string{types.FlagControlChars}
		ev.ParseConfidence = 0.6
	}
	return ev
}

func (m *Mock) addEvent(ev types.NormalizedEvent) {
	for _, old := range m.byRecord[ev.RecordID] {
		old.ev.Current = false
	}
	row := &evRow{seq: m.nextSeq, ev: ev}
	m.nextSeq++
	m.events = append(m.events, row)
	m.byID[ev.EventID] = row
	m.byRecord[ev.RecordID] = append(m.byRecord[ev.RecordID], row)
	if over := len(m.events) - m.opts.MaxEvents; over > 0 {
		for _, r := range m.events[:over] {
			delete(m.byID, r.ev.EventID)
		}
		m.events = append([]*evRow(nil), m.events[over:]...)
	}
}

// Tick advances the virtual clock by one second: new lines arrive, replay
// jobs make progress, and the EPS window moves.
func (m *Mock) Tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tick()
}

// TickN runs Tick n times.
func (m *Mock) TickN(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for range n {
		m.tick()
	}
}

func (m *Mock) tick() {
	m.window = append(m.window, 0)
	if len(m.window) > 60 {
		m.window = m.window[1:]
	}
	base := m.now
	n := 2 + m.r.IntN(5)
	for i := range n {
		d := m.trafficDraft(base.Add(time.Duration(i*1000/n) * time.Millisecond))
		m.now = d.at
		m.ingest(&d)
	}
	if m.r.IntN(8) == 0 {
		d := genPaloAlto(m.r, base.Add(900*time.Millisecond), paloUsers)
		m.ingest(&d)
	}
	m.now = base.Add(time.Second)
	m.runJobs()
	if eps := m.eps(); eps > m.peak {
		m.peak = eps
	}
	if m.scenario == ScenarioApproved && m.allJobsDone() {
		m.scenario = ScenarioSteady
	}
}

func (m *Mock) eps() float64 {
	if len(m.window) == 0 {
		return 0
	}
	sum := 0
	for _, n := range m.window {
		sum += n
	}
	return float64(sum) / float64(len(m.window))
}

// Scenario returns the current scenario name.
func (m *Mock) Scenario() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scenario
}

// Advance moves the scenario one step: steady -> drift -> approved -> steady.
// drift -> approved approves the pending Fortinet patch as "mock-scenario",
// exactly as the control plane would; the UI path is to approve it there.
func (m *Mock) Advance() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.scenario {
	case ScenarioSteady:
		m.startDrift()
	case ScenarioDrift:
		for _, p := range m.proposals {
			if p.Status == "pending" && p.ParserID == "fortinet" {
				_, _ = m.approve(p.YAML, p.ID, "mock-scenario", "advanced by /mock/advance", true)
			}
		}
		m.scenario = ScenarioApproved
	case ScenarioApproved:
		for _, j := range m.jobs {
			for len(j.pending) > 0 {
				m.stepJob(j, len(j.pending))
			}
		}
		m.scenario = ScenarioSteady
	}
	return m.scenario
}

func (m *Mock) newID(prefix string) string {
	m.ids++
	return fmt.Sprintf("%s-%02d", prefix, m.ids)
}

// verify runs VerifyChain and records the result for telemetry.
func (m *Mock) verify(deep bool) types.ChainReport {
	rep, err := m.v.VerifyChain(context.Background(), deep)
	if err != nil {
		rep = types.ChainReport{OK: false, Deep: deep, Reason: err.Error()}
	}
	m.lastVerify, m.lastVerifyOK = m.now, rep.OK
	return rep
}
