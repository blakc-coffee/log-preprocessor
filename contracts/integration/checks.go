package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dark-14100/sluice/contracts/conformance"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/merkle"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/record"
	types "github.com/dark-14100/sluice/pkg/types"
)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func first(a []string, n int) string {
	if len(a) > n {
		a = append(a[:n:n], fmt.Sprintf("... and %d more", len(a)-n))
	}
	return strings.Join(a, "; ")
}

// Step1Options selects what was ingested.
type Step1Options struct {
	Files      []string // manifest files that were ingested; empty means all
	MaxLineage int      // sealed events whose proof is verified, evenly spaced; default 100
}

// Step1 is "ingest -> vault -> parse and normalize" (docs/integration.md, step 1).
func Step1(api API, man Manifest, opt Step1Options) Report {
	r := Report{Step: "step 1: ingest, vault, parse and normalize"}
	recs := man.In(opt.Files...)
	wantParse, wantOther := map[string]int{}, map[string]int{}
	byHash := map[string]Record{}
	for _, m := range recs {
		byHash[m.SHA256] = m
		if m.Expect == "parse" {
			wantParse[m.SHA256]++
		} else {
			wantOther[m.SHA256]++
		}
	}

	tel, err := api.Telemetry()
	if err != nil {
		r.gate("telemetry", false, "%v", err)
		return r
	}
	r.gate("nothing dropped: events + quarantined == vault records == ingested", tel.EventsTotal+tel.QuarantinedTotal == int(tel.Vault.Records) && int(tel.Vault.Records) == len(recs),
		"events %d + quarantined %d, vault %d, manifest %d", tel.EventsTotal, tel.QuarantinedTotal, tel.Vault.Records, len(recs))

	evs, err := api.Events()
	if err != nil {
		r.gate("events", false, "%v", err)
		return r
	}
	type seen struct {
		ev  types.NormalizedEvent
		raw RawResponse
		b   []byte
	}
	var got []seen
	var bad []string
	left := map[string]int{}
	for k, v := range wantParse {
		left[k] = v
	}
	for _, ev := range evs {
		raw, err := api.Raw(ev.EventID)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: raw: %v", ev.EventID, err))
			continue
		}
		b, err := base64.StdEncoding.DecodeString(raw.RawBase64)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: raw_base64: %v", ev.EventID, err))
			continue
		}
		h := sha(b)
		switch {
		case h != raw.RawSHA256 || h != ev.RawSHA256:
			bad = append(bad, fmt.Sprintf("%s: the served bytes hash to %.12s, raw_sha256 says %.12s, the event says %.12s", ev.EventID, h, raw.RawSHA256, ev.RawSHA256))
		case !raw.ShaMatch:
			bad = append(bad, fmt.Sprintf("%s: sha_match is false", ev.EventID))
		case ev.RecordID != raw.RecordID:
			bad = append(bad, fmt.Sprintf("%s: event record_id %d, raw record_id %d", ev.EventID, ev.RecordID, raw.RecordID))
		}
		m, known := byHash[h]
		if !known || m.Expect != "parse" {
			bad = append(bad, fmt.Sprintf("%s: an event for bytes the manifest says must not parse (%s)", ev.EventID, h[:12]))
			continue
		}
		if left[h]--; left[h] < 0 {
			bad = append(bad, fmt.Sprintf("%s: more events than manifest records with these bytes", ev.EventID))
			continue
		}
		if msg := agrees(m, ev); msg != "" {
			bad = append(bad, fmt.Sprintf("%s (%s): %s", ev.EventID, m.ID, msg))
		}
		got = append(got, seen{ev, raw, b})
	}
	r.gate("every event is byte-exact and agrees with the manifest", len(bad) == 0, "%d events checked; %s", len(evs), orNone(bad))

	var missing []string
	miss := 0
	for h, n := range left {
		if n > 0 {
			miss += n
			missing = append(missing, fmt.Sprintf("%s x%d", byHash[h].ID, n))
		}
	}
	sort.Strings(missing)
	r.gate("every record with expect=parse produced an event", miss == 0, "%d missing: %s", miss, orNone(missing))

	qs, err := api.Quarantined()
	if err != nil {
		r.gate("quarantine", false, "%v", err)
	} else {
		lq := map[string]int{}
		for k, v := range wantOther {
			lq[k] = v
		}
		var extra []string
		for _, s := range qs {
			h := sha(s.Raw)
			if lq[h]--; lq[h] < 0 {
				extra = append(extra, fmt.Sprintf("record %d (%.12s)", s.RecordID, h))
			}
		}
		var lost []string
		n := 0
		for h, c := range lq {
			if c > 0 {
				n += c
				lost = append(lost, byHash[h].ID)
			}
		}
		sort.Strings(lost)
		r.gate("every unparsed record is in quarantine, byte-exact, and nothing else is", len(extra) == 0 && n == 0,
			"%d quarantined; %d not quarantined (%s); %d unexpected (%s)", len(qs), n, orNone(lost), len(extra), orNone(extra))
	}

	r.lineageGates(api, got2(got, func(s seen) (types.NormalizedEvent, RawResponse, []byte) { return s.ev, s.raw, s.b }), tel, opt)
	return r
}

func got2[T any](in []T, f func(T) (types.NormalizedEvent, RawResponse, []byte)) []lineageItem {
	out := make([]lineageItem, len(in))
	for i, x := range in {
		e, r, b := f(x)
		out[i] = lineageItem{e, r, b}
	}
	return out
}

type lineageItem struct {
	ev  types.NormalizedEvent
	raw RawResponse
	b   []byte
}

func (r *Report) lineageGates(api API, items []lineageItem, tel Telemetry, opt Step1Options) {
	max := opt.MaxLineage
	if max == 0 {
		max = 100
	}
	step := 1
	if len(items) > max {
		step = len(items) / max
	}
	var bad []string
	sealed, pending := 0, 0
	for i := 0; i < len(items); i += step {
		it := items[i]
		l, err := api.Lineage(it.ev.EventID)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", it.ev.EventID, err))
			continue
		}
		if l.RawSHA256 != it.ev.RawSHA256 || l.RecordID != it.ev.RecordID {
			bad = append(bad, fmt.Sprintf("%s: lineage disagrees with the event about which record this is", it.ev.EventID))
			continue
		}
		if !l.Sealed {
			pending++
			if l.Proof != nil {
				bad = append(bad, fmt.Sprintf("%s: sealed=false but a proof was returned", it.ev.EventID))
			}
			continue
		}
		sealed++
		p := l.Proof
		if p == nil {
			bad = append(bad, fmt.Sprintf("%s: sealed=true but proof is null", it.ev.EventID))
			continue
		}
		rec := types.RawRecord{SourceID: it.ev.SourceID, ReceivedAt: it.raw.ReceivedAt, Origin: it.raw.Origin, Term: it.raw.Terminator, Frag: it.raw.Fragment, Raw: it.b}
		body, err := record.Encode(nil, it.raw.RecordID, rec)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: cannot re-encode the served record: %v", it.ev.EventID, err))
			continue
		}
		switch {
		case merkle.LeafHash(body) != p.LeafHash:
			bad = append(bad, fmt.Sprintf("%s: the proof's leaf is not the hash of the record the API served (source, origin, time, terminator and bytes are all in the leaf)", it.ev.EventID))
		case !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root):
			bad = append(bad, fmt.Sprintf("%s: the inclusion proof does not verify", it.ev.EventID))
		case !merkle.VerifyChainLink(*p):
			bad = append(bad, fmt.Sprintf("%s: the chain link does not verify", it.ev.EventID))
		}
	}
	r.gate("lineage: proofs verify independently, and unsealed records say so", len(bad) == 0, "%d sealed and %d pending checked; %s", sealed, pending, orNone(bad))
	if tel.Vault.Segments > 0 {
		r.gate("at least one sealed record was actually verified", sealed > 0, "%d sealed segments reported, %d sealed events verified", tel.Vault.Segments, sealed)
	}
	rep, err := api.VerifyChain(true)
	r.gate("vault verify --deep", err == nil && rep.OK, "%+v err=%v", struct {
		OK       bool
		Segments int
		Records  uint64
		Reason   string
	}{rep.OK, rep.Segments, rep.Records, rep.Reason}, err)
}

func orNone(a []string) string {
	if len(a) == 0 {
		return "none"
	}
	return first(a, 3)
}

// agrees compares an event with what the manifest knows; a nil expected_* is never a failure.
func agrees(m Record, ev types.NormalizedEvent) string {
	o := conformance.Flatten(ev.OCSF)
	var bad []string
	chk := func(path string, want any, ok bool) {
		if ok && !conformance.Equal(o[path], want) {
			bad = append(bad, fmt.Sprintf("%s = %v, want %v", path, o[path], want))
		}
	}
	if m.SrcIP != nil {
		chk("src_endpoint.ip", *m.SrcIP, true)
	}
	if m.DstIP != nil {
		chk("dst_endpoint.ip", *m.DstIP, true)
	}
	if m.SrcPort != nil {
		chk("src_endpoint.port", *m.SrcPort, true)
	}
	if m.DstPort != nil {
		chk("dst_endpoint.port", *m.DstPort, true)
	}
	if m.Proto != nil {
		chk("connection_info.protocol_name", *m.Proto, true)
	}
	if m.Time != nil {
		if t, err := time.Parse(time.RFC3339, *m.Time); err == nil {
			if got, ok := o["time"].(float64); !ok || int64(got)/1000 != t.Unix() { // the manifest keeps whole seconds
				bad = append(bad, fmt.Sprintf("time = %v, want %d s", o["time"], t.Unix()))
			}
		}
	}
	return strings.Join(bad, "; ")
}

// Step5 is "identity resolution into the pipeline" (step 5): every firewall record resolved to the right user, and
// no user invented in the gaps.
func Step5(api API, man Manifest) Report {
	r := Report{Step: "step 5: identity resolution"}
	recs := man.In("identity_firewall.log")
	byHash := map[string][]Record{}
	users := map[string]map[string]bool{}
	for _, m := range recs {
		byHash[m.SHA256] = append(byHash[m.SHA256], m)
		if m.User != nil && m.SrcIP != nil {
			if users[*m.SrcIP] == nil {
				users[*m.SrcIP] = map[string]bool{}
			}
			users[*m.SrcIP][*m.User] = true
		}
	}
	evs, err := api.Events()
	if err != nil {
		r.gate("events", false, "%v", err)
		return r
	}
	total, right, gaps, gapsRight, reassigned, reassignedRight := 0, 0, 0, 0, 0, 0
	var wrong []string
	for _, ev := range evs {
		raw, err := api.Raw(ev.EventID)
		if err != nil {
			continue
		}
		b, _ := base64.StdEncoding.DecodeString(raw.RawBase64)
		ms := byHash[sha(b)]
		if len(ms) == 0 {
			continue
		}
		m := ms[0]
		total++
		got := ""
		for _, e := range ev.Entities {
			if e.Type == "user" && e.Role == "src" {
				got = e.ID
			}
		}
		want := ""
		if m.User != nil {
			want = *m.User
		}
		ok := got == want
		if ok {
			right++
		} else {
			wrong = append(wrong, fmt.Sprintf("%s %s: got %q want %q", m.ID, *m.SrcIP, got, want))
		}
		if want == "" {
			gaps++
			if got == "" {
				gapsRight++
			}
		}
		if len(users[*m.SrcIP]) > 1 {
			reassigned++
			if ok {
				reassignedRight++
			}
		}
	}
	r.gate("every firewall record has an event", total == len(recs), "%d of %d records found", total, len(recs))
	acc := 0.0
	if total > 0 {
		acc = float64(right) / float64(total)
	}
	r.gate("at least 99% of users are correct", acc >= 0.99, "%d/%d correct (%.1f%%); %s", right, total, 100*acc, orNone(wrong))
	r.gate("100% correct across IP reassignment", reassigned > 0 && reassignedRight == reassigned, "%d/%d records on reassigned addresses", reassignedRight, reassigned)
	r.gate("no user is invented in the gaps between tenancies", gaps > 0 && gapsRight == gaps, "%d/%d gap records have no user", gapsRight, gaps)

	tl, err := api.Timeline("10.1.4.9")
	var carol, heidi *Binding
	for i := range tl {
		switch tl[i].User {
		case "carol":
			carol = &tl[i]
		case "heidi":
			heidi = &tl[i]
		}
	}
	ok := err == nil && carol != nil && heidi != nil && carol.ValidTo != nil && !carol.ValidTo.After(heidi.ValidFrom)
	r.gate("timeline for 10.1.4.9 shows carol, then heidi, without overlap", ok, "err=%v bindings=%d", err, len(tl))
	return r
}
