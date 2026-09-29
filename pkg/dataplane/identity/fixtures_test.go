package identity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
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

// State is derived data, so a restart rebuilds it from the vault instead of loading a database. This is that
// claim, tested: identity records go into a real vault, a fresh resolver replays them, and every answer and
// every timeline equals the live resolver's, including after a second replay and after a partial replay
// followed by the rest.
func TestReplayFromVaultRebuildsTheSameState(t *testing.T) {
	ctx := context.Background()
	live := New(Config{})
	mv := memvault.New(memvault.Options{SealEvery: 64})

	type entry struct {
		rec  types.RawRecord
		fact types.IdentityFact
	}
	var entries []entry
	for _, f := range loadFacts(t) {
		raw, _ := json.Marshal(f)
		entries = append(entries, entry{types.RawRecord{SourceID: f.SourceID, ReceivedAt: f.At, Origin: types.Origin{Kind: types.OriginFile, Addr: "x"}, Term: types.TermLF, Raw: raw}, f})
	}
	// mix in records that are not identity facts at all
	var rs []types.RawRecord
	for i, e := range entries {
		rs = append(rs, e.rec)
		if i%25 == 0 {
			rs = append(rs, types.RawRecord{SourceID: "cisco_asa", ReceivedAt: e.fact.At, Term: types.TermLF, Raw: []byte("<166>Sep 28 2026 09:00:00 asa01 : not an identity record")})
		}
	}
	receipts, err := mv.PutBatch(ctx, rs)
	if err != nil {
		t.Fatal(err)
	}
	// the live resolver sees the same facts under the same record ids the vault assigned, as it would in the data plane
	next := 0
	for i, e := range entries {
		for rs[next].SourceID == "cisco_asa" {
			next++
		}
		f := e.fact
		f.RecordID = receipts[next].ID
		if _, err := live.Observe(f); err != nil {
			t.Fatal(err)
		}
		next++
		_ = i
	}

	extract := func(rec types.RawRecord, rc types.Receipt) (*types.IdentityFact, error) {
		if !strings.HasPrefix(string(rec.Raw), "{") {
			return nil, nil
		}
		var f types.IdentityFact
		return &f, json.Unmarshal(rec.Raw, &f)
	}
	same := func(name string, r *Resolver) {
		t.Helper()
		for _, ip := range []string{"10.1.4.7", "10.1.4.8", "10.1.4.9", "10.1.4.10", "10.1.4.11", "10.1.4.12", "10.1.4.13", "10.1.4.14", "10.1.4.15", "10.8.0.249"} {
			a, b := live.Timeline(ip, time.Time{}, time.Time{}), r.Timeline(ip, time.Time{}, time.Time{})
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("%s: timeline of %s differs\n live: %+v\n got:  %+v", name, ip, a, b)
			}
			for m := 0; m < 200; m += 3 {
				at := time.Date(2026, 9, 28, 3, 30, 0, 0, time.UTC).Add(time.Duration(m) * time.Minute)
				if x, y := key(live.ResolveAt(ip, at)), key(r.ResolveAt(ip, at)); x != y {
					t.Fatalf("%s: %s at +%dm: %q vs %q", name, ip, m, x, y)
				}
			}
		}
	}

	// a record from a source that is NOT an identity source but happens to look like a fact must be ignored:
	// the source filter, not the extractor, is what keeps foreign data out of the resolver
	decoy, _ := json.Marshal(types.IdentityFact{Kind: "radius", Action: "bind", IP: "10.1.4.9", User: "mallory", At: time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)})
	if _, err := mv.Put(ctx, types.RawRecord{SourceID: "webhook-untrusted", ReceivedAt: time.Now(), Term: types.TermLF, Raw: decoy}); err != nil {
		t.Fatal(err)
	}
	idSources := map[string]bool{"dhcp": true, "radius": true, "vpn": true}
	fresh := New(Config{})
	st, err := Replay(ctx, mv, 1, idSources, extract, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if st.Facts != len(entries) || st.Skipped == 0 || st.Scanned != len(rs)+1 {
		t.Fatalf("stats %+v, want %d facts and the non-identity records skipped", st, len(entries))
	}
	same("full replay", fresh)

	if _, err := Replay(ctx, mv, 1, idSources, extract, fresh); err != nil { // replaying again changes nothing
		t.Fatal(err)
	}
	same("second replay", fresh)

	partial := New(Config{}) // a crash halfway through recovery, then the rest
	half := types.RecordID(len(rs) / 2)
	for _, from := range []types.RecordID{half, 1} {
		if _, err := Replay(ctx, mv, from, idSources, extract, partial); err != nil {
			t.Fatal(err)
		}
	}
	same("interrupted replay", partial)

	if _, err := Replay(ctx, mv, 1, nil, func(types.RawRecord, types.Receipt) (*types.IdentityFact, error) { return nil, errors.New("boom") }, New(Config{})); err == nil {
		t.Fatal("an extractor error must stop the replay and be reported with its record id")
	}
}
