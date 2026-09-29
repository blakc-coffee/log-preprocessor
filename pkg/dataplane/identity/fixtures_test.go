package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// The acceptance test from PRD_CONTRACTS 6.4: replay the DHCP, RADIUS and
// OpenVPN fixtures as facts, then resolve every firewall record in the
// manifest. Ground truth is the generator's manifest, not this package.

const corpus = "../../../testdata"

var ist = time.FixedZone("IST", 5*3600+1800)

var (
	reDHCP = regexp.MustCompile(`^(\w{3} +\d+ [\d:]+) \S+ dhcpd\[\d+\]: (DHCPACK|DHCPRELEASE) (?:on|of) ([\d.]+) (?:to|from) ([0-9a-f:]{17}) \(([^)]*)\)`)
	reRAD  = regexp.MustCompile(`^(\w{3} +\d+ [\d:]+) \S+ radiusd\[\d+\]: Acct-Status-Type=(Start|Stop) User-Name="([^"]*)" Framed-IP-Address=([\d.]+) Calling-Station-Id="([^"]*)"`)
	reVPN  = regexp.MustCompile(`^(\w{3} +\d+ [\d:]+) \S+ openvpn\[\d+\]: MULTI: Learn: ([\d.]+) -> ([^/]+)/`)
	reASA  = regexp.MustCompile(`^<\d+>(\w{3} +\d+ \d{4} [\d:]+) \S+ : %ASA-\d-302013: Built \w+ TCP connection \d+ for \w+:([\d.]+)/`)
)

func syslogTime(t *testing.T, s string) time.Time {
	t.Helper()
	layout, in := "2006 Jan _2 15:04:05", "2026 "+s
	if regexp.MustCompile(`^\w{3} +\d+ \d{4} `).MatchString(s) { // ASA carries its own year
		layout, in = "Jan _2 2006 15:04:05", s
	}
	tm, err := time.ParseInLocation(layout, in, ist)
	if err != nil {
		t.Fatal(err)
	}
	return tm.UTC()
}

func lines(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus, file))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func loadFacts(t *testing.T) []types.IdentityFact {
	t.Helper()
	var fs []types.IdentityFact
	rec := types.RecordID(0)
	add := func(f types.IdentityFact) { rec++; f.RecordID = rec; fs = append(fs, f) }
	for _, l := range lines(t, "dhcp.log") {
		if m := reDHCP.FindStringSubmatch(l); m != nil {
			f := types.IdentityFact{Kind: "dhcp", Action: "bind", IP: m[3], MAC: m[4], Host: m[5], At: syslogTime(t, m[1]), SourceID: "dhcp"}
			if m[2] == "DHCPRELEASE" {
				f.Action = "release"
			}
			add(f)
		}
	}
	for _, l := range lines(t, "radius.log") {
		if m := reRAD.FindStringSubmatch(l); m != nil {
			f := types.IdentityFact{Kind: "radius", Action: "bind", IP: m[4], User: m[3], MAC: strings.ReplaceAll(strings.ToLower(m[5]), "-", ":"), At: syslogTime(t, m[1]), SourceID: "radius"}
			if m[2] == "Stop" {
				f.Action = "release"
			}
			add(f)
		}
	}
	for _, l := range lines(t, "openvpn.log") {
		if m := reVPN.FindStringSubmatch(l); m != nil {
			add(types.IdentityFact{Kind: "vpn", Action: "bind", IP: m[2], User: m[3], At: syslogTime(t, m[1]), SourceID: "vpn"})
		}
	}
	return fs
}

func TestIdentityTruthOnFixtures(t *testing.T) {
	fs := loadFacts(t)
	if len(fs) != 186 {
		t.Fatalf("parsed %d facts, want 186 (86 dhcp + 100 radius + vpn learns): the fixture regexes are wrong", len(fs))
	}
	r := New(Config{})
	for _, f := range fs {
		if _, err := r.Observe(f); err != nil {
			t.Fatal(err)
		}
	}

	var man struct {
		Records []struct {
			File string  `json:"source_file"`
			IP   *string `json:"expected_src_ip"`
			User *string `json:"expected_user"`
		} `json:"records"`
	}
	b, _ := os.ReadFile(filepath.Join(corpus, "manifest.json"))
	if err := json.Unmarshal(b, &man); err != nil {
		t.Fatal(err)
	}
	var truth []struct {
		IP string  `json:"ip"`
		At string  `json:"at"`
		U  *string `json:"expected_user"`
	}
	tb, _ := os.ReadFile(filepath.Join(corpus, "identity_truth.json"))
	var tj struct {
		Cases []struct {
			IP   string  `json:"ip"`
			At   string  `json:"at"`
			User *string `json:"expected_user"`
		} `json:"resolution_cases"`
	}
	_ = truth
	if err := json.Unmarshal(tb, &tj); err != nil {
		t.Fatal(err)
	}

	fw := lines(t, "identity_firewall.log")
	i, total, right, gaps, gapsRight := 0, 0, 0, 0, 0
	for _, rec := range man.Records {
		if rec.File != "identity_firewall.log" {
			continue
		}
		m := reASA.FindStringSubmatch(fw[i])
		i++
		if m == nil {
			t.Fatalf("firewall line %d does not parse", i)
		}
		total++
		got := users(r.ResolveAt(m[2], syslogTime(t, m[1])))
		want := ""
		if rec.User != nil {
			want = *rec.User
		}
		if got == want {
			right++
		} else {
			t.Errorf("%s at %s: got %q, want %q", m[2], m[1], got, want)
		}
		if want == "" {
			gaps++
			if got == "" {
				gapsRight++
			}
		}
	}
	if total != 45 || gaps == 0 {
		t.Fatalf("expected 45 firewall records with some gap cases, saw %d and %d", total, gaps)
	}
	t.Logf("%d/%d firewall records resolved correctly; %d/%d gap records correctly unresolved; %d facts replayed", right, total, gapsRight, gaps, len(fs))
	if right != total {
		t.Fatalf("accuracy %d/%d; the acceptance bar is 99%% overall and 100%% across reassignment and gaps", right, total)
	}

	// The same answers from identity_truth.json's own resolution_cases.
	for _, c := range tj.Cases {
		at, _ := time.Parse(time.RFC3339, c.At)
		want := ""
		if c.User != nil {
			want = *c.User
		}
		if got := users(r.ResolveAt(c.IP, at)); got != want {
			t.Errorf("truth case %s at %s: got %q want %q", c.IP, c.At, got, want)
		}
	}

	// Order independence on real data: the reverse arrival order gives the same answers.
	rev := New(Config{})
	for j := len(fs) - 1; j >= 0; j-- {
		_, _ = rev.Observe(fs[j])
	}
	for _, c := range tj.Cases {
		at, _ := time.Parse(time.RFC3339, c.At)
		if a, b := users(r.ResolveAt(c.IP, at)), users(rev.ResolveAt(c.IP, at)); a != b {
			t.Errorf("arrival order changed the answer for %s at %s: %q vs %q", c.IP, c.At, a, b)
		}
	}
}
