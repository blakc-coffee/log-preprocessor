package gen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadTruth(t *testing.T, dir string) Truth {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "identity_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tr Truth
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return v
}

func lines(t *testing.T, dir, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// TestTruthMatchesDHCPLines is the check the PRD's test plan asks for: the
// answer key must not contradict the logs it claims to summarise. Every
// interval's start must be an actual DHCPACK in dhcp.log, and every closed
// interval's end an actual DHCPRELEASE, both naming the same address, MAC and
// host. If the generator ever drifts from its own truth file, the identity
// accuracy metric becomes meaningless, and this is what catches that.
func TestTruthMatchesDHCPLines(t *testing.T) {
	dir := corpus(t)
	tr := loadTruth(t, dir)
	dhcp := lines(t, dir, "dhcp.log")

	if len(tr.Intervals) != len(identityIPs)*2 {
		t.Fatalf("got %d intervals, want %d (two tenancies per address)", len(tr.Intervals), len(identityIPs)*2)
	}

	has := func(substr string) bool {
		for _, l := range dhcp {
			if strings.Contains(l, substr) {
				return true
			}
		}
		return false
	}

	for _, iv := range tr.Intervals {
		from := mustTime(t, iv.From)
		ack := fmt.Sprintf("%s dhcp01 dhcpd[1123]: DHCPACK on %s to %s (%s) via eth1",
			from.Format("Jan _2 15:04:05"), iv.IP, iv.MAC, iv.Host)
		if !has(ack) {
			t.Errorf("interval %s/%s starts at %s but dhcp.log has no matching DHCPACK:\n  want: %s",
				iv.IP, iv.User, iv.From, ack)
		}
		if iv.To == nil {
			continue
		}
		to := mustTime(t, *iv.To)
		rel := fmt.Sprintf("%s dhcp01 dhcpd[1123]: DHCPRELEASE of %s from %s (%s) via eth1 (found)",
			to.Format("Jan _2 15:04:05"), iv.IP, iv.MAC, iv.Host)
		if !has(rel) {
			t.Errorf("interval %s/%s ends at %s but dhcp.log has no matching DHCPRELEASE:\n  want: %s",
				iv.IP, iv.User, *iv.To, rel)
		}
	}
}

// TestRadiusSessionsFallInsideTheirInterval proves the second evidence source
// agrees with the answer key. A RADIUS accounting record that named a user
// outside that user's lease would be evidence the resolver is right to
// disbelieve, which is not what this corpus is for.
func TestRadiusSessionsFallInsideTheirInterval(t *testing.T) {
	dir := corpus(t)
	tr := loadTruth(t, dir)

	// A key can hold more than one span: nothing stops the same user from
	// being handed the same address twice, so the record only has to fall
	// inside one of them.
	type span struct{ from, to time.Time }
	byKey := map[string][]span{}
	for _, iv := range tr.Intervals {
		s := span{from: mustTime(t, iv.From)}
		if iv.To != nil {
			s.to = mustTime(t, *iv.To)
		}
		byKey[iv.IP+"|"+iv.User] = append(byKey[iv.IP+"|"+iv.User], s)
	}

	checked := 0
	for _, l := range lines(t, dir, "radius.log") {
		user, ok := between(l, `User-Name="`, `"`)
		if !ok {
			continue
		}
		ip, ok := between(l, "Framed-IP-Address=", " ")
		if !ok {
			continue
		}
		spans, ok := byKey[ip+"|"+user]
		if !ok {
			continue // background traffic, not part of the scenario
		}
		at := mustTime(t, syslogInstant(t, l))
		inside := false
		for _, s := range spans {
			if !at.Before(s.from) && (s.to.IsZero() || !at.After(s.to)) {
				inside = true
				break
			}
		}
		if !inside {
			t.Errorf("radius.log: %s/%s accounted at %s, outside every lease that pair holds (%d span(s))",
				ip, user, at.Format(time.RFC3339), len(spans))
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no scenario RADIUS records found; the cross-check proved nothing")
	}
}

// TestIntervalsDoNotOverlapPerIP proves each address has exactly one holder at
// a time, and that the gap between tenancies is real. Without a genuine gap
// the "expected_user is null" cases are unreachable and the hardest part of
// requirement (h) goes untested.
func TestIntervalsDoNotOverlapPerIP(t *testing.T) {
	tr := loadTruth(t, corpus(t))

	byIP := map[string][]TruthInterval{}
	for _, iv := range tr.Intervals {
		byIP[iv.IP] = append(byIP[iv.IP], iv)
	}
	for _, ip := range identityIPs {
		ivs := byIP[ip]
		if len(ivs) != 2 {
			t.Errorf("%s: got %d intervals, want 2", ip, len(ivs))
			continue
		}
		a, b := ivs[0], ivs[1]
		if a.To == nil {
			t.Errorf("%s: the first tenancy must be closed, or there is no gap", ip)
			continue
		}
		aEnd, bStart := mustTime(t, *a.To), mustTime(t, b.From)
		if !aEnd.Before(bStart) {
			t.Errorf("%s: tenancies overlap: first ends %s, second starts %s", ip, *a.To, b.From)
		}
		if a.User == b.User {
			t.Errorf("%s: both tenancies are %s, so reassignment is never exercised", ip, a.User)
		}
	}
}

// TestResolutionCasesAgreeWithIntervals resolves every question in the answer
// key the way B7 is expected to: find the interval covering (ip, at) and
// report its user, or nobody. It is the test that proves the questions and the
// intervals are the same ground truth rather than two independent guesses.
func TestResolutionCasesAgreeWithIntervals(t *testing.T) {
	tr := loadTruth(t, corpus(t))

	type span struct {
		from, to time.Time
		user     string
	}
	var spans []span
	byIP := map[string][]span{}
	for _, iv := range tr.Intervals {
		s := span{from: mustTime(t, iv.From), user: iv.User}
		if iv.To != nil {
			s.to = mustTime(t, *iv.To)
		}
		spans = append(spans, s)
		byIP[iv.IP] = append(byIP[iv.IP], s)
	}
	_ = spans

	var gapCases int
	for _, c := range tr.Cases {
		at := mustTime(t, c.At)
		var got []string
		for _, s := range byIP[c.IP] {
			if at.Before(s.from) {
				continue
			}
			if !s.to.IsZero() && !at.Before(s.to) {
				continue // half-open: the release instant is already unleased
			}
			got = append(got, s.user)
		}
		switch {
		case c.User == nil:
			gapCases++
			if len(got) != 0 {
				t.Errorf("%s at %s: expected nobody, intervals say %v", c.IP, c.At, got)
			}
		case len(got) != 1:
			t.Errorf("%s at %s: expected exactly %s, intervals say %v", c.IP, c.At, *c.User, got)
		case got[0] != *c.User:
			t.Errorf("%s at %s: expected %s, intervals say %s", c.IP, c.At, *c.User, got[0])
		}
	}

	if gapCases != len(identityIPs) {
		t.Errorf("got %d unleased-gap cases, want one per address (%d)", gapCases, len(identityIPs))
	}
	if len(tr.Cases) != len(identityIPs)*casesPerIP {
		t.Errorf("got %d resolution cases, want %d", len(tr.Cases), len(identityIPs)*casesPerIP)
	}
}

// TestFirewallManifestCarriesExpectedUser proves the firewall records and the
// answer key say the same thing. These records are what the end-to-end
// identity accuracy metric is measured on, so the manifest's expected_user has
// to match resolution_cases exactly, nulls included.
func TestFirewallManifestCarriesExpectedUser(t *testing.T) {
	dir := corpus(t)
	tr := loadTruth(t, dir)

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	want := map[string]*string{}
	for _, c := range tr.Cases {
		want[c.IP+"|"+mustTime(t, c.At).Truncate(time.Second).Format(time.RFC3339)] = c.User
	}

	var seen, withUser, withoutUser int
	for _, r := range m.Records {
		if r.SourceFile != "identity_firewall.log" {
			continue
		}
		seen++
		if r.ExpectedSrcIP == nil || r.ExpectedTime == nil {
			t.Errorf("%s: missing expected_src_ip or expected_time", r.RecordID)
			continue
		}
		key := *r.ExpectedSrcIP + "|" + *r.ExpectedTime
		exp, ok := want[key]
		if !ok {
			t.Errorf("%s: no resolution case for %s", r.RecordID, key)
			continue
		}
		switch {
		case exp == nil:
			withoutUser++
			if r.ExpectedUser != nil {
				t.Errorf("%s: expected_user is %q, but the address was unleased at %s",
					r.RecordID, *r.ExpectedUser, *r.ExpectedTime)
			}
		case r.ExpectedUser == nil:
			t.Errorf("%s: expected_user is null, want %q", r.RecordID, *exp)
		case *r.ExpectedUser != *exp:
			t.Errorf("%s: expected_user is %q, want %q", r.RecordID, *r.ExpectedUser, *exp)
		default:
			withUser++
		}
	}

	if seen != len(tr.Cases) {
		t.Errorf("identity_firewall.log has %d manifest records, want %d", seen, len(tr.Cases))
	}
	if withoutUser != len(identityIPs) {
		t.Errorf("got %d records inside a lease gap, want %d", withoutUser, len(identityIPs))
	}
	if withUser == 0 {
		t.Error("no attributable firewall records: the scenario proves nothing")
	}
}

// TestScenarioSpecialCases pins the two awkward cases the PRD calls for: one
// user holding two addresses at once, and one address attested by both RADIUS
// and VPN over overlapping windows.
func TestScenarioSpecialCases(t *testing.T) {
	dir := corpus(t)
	tr := loadTruth(t, dir)

	if len(tr.Notes.SameUserTwoIPs) == 0 {
		t.Error("no user holds two addresses; that case is untested")
	}
	if len(tr.Notes.OverlappingVPN) == 0 {
		t.Fatal("no address has overlapping RADIUS and VPN evidence; that case is untested")
	}

	// The VPN learn must name the same address and user the lease does, and
	// fall inside that lease.
	ip := tr.Notes.OverlappingVPN[0]
	var iv *TruthInterval
	for i := range tr.Intervals {
		if tr.Intervals[i].IP == ip && tr.Intervals[i].To != nil {
			iv = &tr.Intervals[i]
			break
		}
	}
	if iv == nil {
		t.Fatalf("no closed interval for %s", ip)
	}

	found := false
	for _, l := range lines(t, dir, "openvpn.log") {
		if !strings.Contains(l, "MULTI: Learn: "+ip+" ->") {
			continue
		}
		found = true
		if !strings.Contains(l, iv.User+"/") {
			t.Errorf("openvpn.log learns %s for a different user than the lease (%s):\n  %s", ip, iv.User, l)
		}
		at := mustTime(t, syslogInstant(t, l))
		from, to := mustTime(t, iv.From), mustTime(t, *iv.To)
		if at.Before(from) || !at.Before(to) {
			t.Errorf("openvpn.log learns %s at %s, outside the lease [%s, %s)",
				ip, at.Format(time.RFC3339), iv.From, *iv.To)
		}
	}
	if !found {
		t.Errorf("openvpn.log has no MULTI: Learn for %s", ip)
	}
}

// between returns the text between the first open and the next close.
func between(s, open, close string) (string, bool) {
	i := strings.Index(s, open)
	if i < 0 {
		return "", false
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// syslogInstant recovers the RFC 3339 instant from an RFC 3164 "Jan _2
// 15:04:05" prefix. These formats carry no year and no zone, which is exactly
// why the manifest declares the zone instead; the corpus never spans a year
// boundary, so BaseTime's year is the right one.
func syslogInstant(t *testing.T, line string) string {
	t.Helper()
	if len(line) < 15 {
		t.Fatalf("line too short to carry a syslog timestamp: %q", line)
	}
	ts, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], IST)
	if err != nil {
		t.Fatalf("parsing syslog timestamp from %q: %v", line[:15], err)
	}
	return ts.AddDate(BaseTime.Year(), 0, 0).Format(time.RFC3339)
}
