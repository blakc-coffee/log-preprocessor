package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/contracts"
)

const corpus = "../../testdata/sample"

var examples = []string{"cisco_asa", "fortinet", "palo_alto_traffic", "suricata_eve", "isc_dhcpd"}

func fixtureLines(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus, file))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, strings.TrimRight(l, "\r"))
		}
	}
	return out
}

// manifestFor returns the manifest's expected_* values for each line of file,
// in line order.
func manifestFor(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range m.Records {
		if r["source_file"] == file {
			out = append(out, r)
		}
	}
	return out
}

func TestExamplesAreWellFormed(t *testing.T) {
	idRe := regexp.MustCompile(`^[a-z0-9_]+$`)
	verRe := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	for _, name := range examples {
		t.Run(name, func(t *testing.T) {
			p := loadParser(name)
			if !idRe.MatchString(p.ID) || !verRe.MatchString(p.Version) || p.ID != name {
				t.Fatalf("bad id/version %q %q", p.ID, p.Version)
			}
			sig := regexp.MustCompile(p.Match.Signature)
			seen := map[string]bool{}
			for _, e := range p.Extractors {
				if !idRe.MatchString(e.ID) || seen[e.ID] {
					t.Fatalf("bad or duplicate extractor id %q", e.ID)
				}
				seen[e.ID] = true
				if len(e.Tests) == 0 {
					t.Errorf("%s has no test vectors", e.ID)
				}
				names := map[string]bool{}
				if e.Kind == "regex" {
					re := regexp.MustCompile(e.Pattern) // RE2 only: lookaround would panic here
					for _, n := range re.SubexpNames() {
						if n != "" {
							names[n] = true
						}
					}
					for _, ph := range regexp.MustCompile(`\{([a-z_0-9]+)\}`).FindAllStringSubmatch(strings.NewReplacer("{{", "", "}}", "").Replace(e.Render), -1) {
						if !names[ph[1]] {
							t.Errorf("%s: render placeholder {%s} is not a capture", e.ID, ph[1])
						}
					}
				}
				for _, c := range e.Columns {
					if c != "_" {
						names[c] = true
					}
				}
				for i, m := range e.Map {
					if m.To == "" {
						t.Errorf("%s map[%d]: no to", e.ID, i)
					}
					if m.Const == nil && len(m.froms()) == 0 {
						t.Errorf("%s map[%d]: neither from nor const", e.ID, i)
					}
					if e.Kind == "regex" || e.Kind == "csv" {
						for _, f := range m.froms() {
							if !names[f] {
								t.Errorf("parser %q extractor %q map[%d] (from: %s): capture %q is not defined by the pattern", p.ID, e.ID, i, f, f)
							}
						}
					}
				}
				for _, v := range e.Tests {
					if !sig.MatchString(v.Raw) {
						t.Errorf("%s: test vector does not match match.signature", e.ID)
					}
				}
			}
		})
	}
}

// Vectors must be real fixture lines, never invented ones.
func TestVectorsAreRealFixtureLines(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(corpus, "*"))
	real := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, ".json") && !strings.HasSuffix(f, "suricata.json") {
			continue
		}
		for _, l := range fixtureLines(t, filepath.Base(f)) {
			real[l] = true
		}
	}
	for _, name := range examples {
		for _, e := range loadParser(name).Extractors {
			for _, v := range e.Tests {
				if !real[v.Raw] {
					t.Errorf("%s/%s: vector is not a line of testdata/sample: %.70s...", name, e.ID, v.Raw)
				}
			}
		}
	}
}

// renderRegex re-serializes a regex extractor's captures per parser_dsl.md
// section 4 and returns the record it would reproduce.
func renderRegex(e extractor, raw string) string {
	re := regexp.MustCompile(e.Pattern)
	m := re.FindStringSubmatch(raw)
	val := map[string]string{}
	for i, n := range re.SubexpNames() {
		if n != "" {
			val[n] = m[i]
		}
	}
	typed := func(name, s string) string {
		for _, me := range e.Map {
			for _, f := range me.froms() {
				if f != name {
					continue
				}
				switch me.Type {
				case "int", "uint", "port":
					n, _ := strconv.Atoi(s)
					return strconv.Itoa(n)
				case "ip":
					return canonIP(s)
				case "mac":
					return strings.ToLower(strings.ReplaceAll(s, "-", ":"))
				case "time":
					layout := fmt.Sprint(mapLayout(e, name))
					if tm, err := time.Parse(layout, s); err == nil {
						return tm.Format(layout)
					}
				}
			}
		}
		return s
	}
	var out strings.Builder
	r := strings.NewReplacer("{{", "\x00L", "}}", "\x00R").Replace(e.Render)
	for i := 0; i < len(r); i++ {
		if r[i] == '{' {
			j := strings.IndexByte(r[i:], '}')
			name := r[i+1 : i+j]
			out.WriteString(typed(name, val[name]))
			i += j
			continue
		}
		out.WriteByte(r[i])
	}
	return strings.NewReplacer("\x00L", "{", "\x00R", "}").Replace(out.String())
}

func mapLayout(e extractor, name string) string {
	b, _ := yamlLayouts()[e.ID+"/"+name]
	return b
}

// yamlLayouts extracts `layout:` per (extractor, capture); the mapEntry struct
// deliberately omits it because only this test needs it.
func yamlLayouts() map[string]string {
	out := map[string]string{}
	for _, name := range examples {
		b, _ := contracts.DSLExamples.ReadFile("dsl/examples/" + name + ".yaml")
		var cur string
		for _, l := range strings.Split(string(b), "\n") {
			if m := regexp.MustCompile(`^\s+- id: (\w+)`).FindStringSubmatch(l); m != nil {
				cur = m[1]
			}
			if m := regexp.MustCompile(`from: (\w+), to: time, type: time, layout: "([^"]+)"`).FindStringSubmatch(l); m != nil {
				out[cur+"/"+m[1]] = m[2]
			}
		}
	}
	return out
}

// Regex extractors: every fixture line the parser is written for matches,
// renders back byte for byte, and agrees with the manifest's ground truth.
func TestRegexExamplesOnFixtures(t *testing.T) {
	type job struct{ parser, file, marker string }
	for _, j := range []job{
		{"cisco_asa", "cisco_asa.log", ""}, {"cisco_asa", "identity_firewall.log", ""}, {"isc_dhcpd", "dhcp.log", ""},
	} {
		t.Run(j.parser+"/"+j.file, func(t *testing.T) {
			p := loadParser(j.parser)
			truth := manifestFor(t, j.file)
			lines := fixtureLines(t, j.file)
			if len(truth) != len(lines) {
				t.Fatalf("manifest has %d records, file %d lines", len(truth), len(lines))
			}
			matched := 0
			for i, l := range lines {
				var ex *extractor
				for k := range p.Extractors {
					if regexp.MustCompile(p.Extractors[k].Pattern).MatchString(l) {
						ex = &p.Extractors[k]
						break
					}
				}
				if ex == nil {
					continue // other message ids: this example does not claim them
				}
				matched++
				if got := renderRegex(*ex, l); got != l {
					t.Errorf("line %d render-back mismatch\n raw: %s\n got: %s", i+1, l, got)
				}
				re := regexp.MustCompile(ex.Pattern)
				m := re.FindStringSubmatch(l)
				get := func(n string) string { return m[re.SubexpIndex(n)] }
				want := func(k string) string { return fmt.Sprint(truth[i][k]) }
				if j.parser == "cisco_asa" {
					// A null expected_* means the manifest does not know it (106023
					// records carry no expected source port); skip, never fail.
					for cap, key := range map[string]string{"src_ip": "expected_src_ip", "dst_ip": "expected_dst_ip", "src_port": "expected_src_port", "dst_port": "expected_dst_port", "proto": "expected_proto"} {
						if truth[i][key] == nil {
							continue
						}
						if g := strings.ToLower(get(cap)); g != want(key) {
							t.Errorf("line %d: %s = %q, manifest %s = %q: %s", i+1, cap, g, key, want(key), l)
						}
					}
				} else if get("ip") != want("expected_src_ip") {
					t.Errorf("line %d: ip %s, manifest says %s", i+1, get("ip"), want("expected_src_ip"))
				}
			}
			if matched == 0 {
				t.Fatal("no fixture line matched: the example claims nothing")
			}
			t.Logf("%d of %d lines matched, rendered back and agreed with the manifest", matched, len(lines))
		})
	}
}

// kv: the keys the example maps exist on every line it is meant for, and are
// really absent on the drifted file, which is what makes drift detectable.
func TestFortinetKeysAndDrift(t *testing.T) {
	e := loadParser("fortinet").extractor("fgt_traffic")
	var keys []string
	for k := range e.mapped() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, l := range fixtureLines(t, "fortinet.log") {
		_, vals := kvPairs(l)
		for _, k := range keys {
			if _, ok := vals[k]; !ok {
				t.Fatalf("mapped key %q missing from a fortinet.log line", k)
			}
		}
	}
	for _, l := range fixtureLines(t, "fortinet_drift.log") {
		_, vals := kvPairs(l)
		if _, ok := vals["srcip"]; ok {
			t.Fatal("drift file still has srcip: the fixture no longer exercises drift")
		}
		if !regexp.MustCompile(loadParser("fortinet").Match.Signature).MatchString(l) {
			t.Fatal("signature should still match drifted lines: drift means extract fails, not detect")
		}
	}
	// A quoted value containing key=value must not create a key.
	_, vals := kvPairs(`a=1 msg="x srcip=9.9.9.9 y" b=2`)
	if _, injected := vals["srcip"]; injected || vals["msg"] != "x srcip=9.9.9.9 y" || vals["b"] != "2" {
		t.Fatalf("kv tokenizer let a value inject a key: %v", vals)
	}
}

// csv: columns line up with the manifest's ground truth for all 50 records.
func TestPaloAltoColumnsMatchManifest(t *testing.T) {
	e := loadParser("palo_alto_traffic").extractor("pan_traffic")
	col := map[string]int{}
	for i, c := range e.Columns {
		if c != "_" {
			col[c] = i
		}
	}
	truth := manifestFor(t, "palo_alto_unknown.log")
	lines := fixtureLines(t, "palo_alto_unknown.log")
	for i, l := range lines {
		f, err := csv.NewReader(strings.NewReader(l)).Read()
		if err != nil {
			t.Fatal(err)
		}
		if len(f) < e.Min || fmt.Sprint(e.When["equals"]) != f[3] {
			t.Fatalf("line %d: %d columns (min %d), type %q", i+1, len(f), e.Min, f[3])
		}
		for c, k := range map[string]string{"src_ip": "expected_src_ip", "dst_ip": "expected_dst_ip", "src_port": "expected_src_port", "dst_port": "expected_dst_port", "proto": "expected_proto", "action": "expected_action"} {
			if f[col[c]] != fmt.Sprint(truth[i][k]) {
				t.Errorf("line %d column %s = %q, manifest %s = %v", i+1, c, f[col[c]], k, truth[i][k])
			}
		}
	}
}

// json: every alert line has every mapped path; other event types are skipped
// by `when`.
func TestSuricataPathsAndRouting(t *testing.T) {
	e := loadParser("suricata_eve").extractor("eve_alert")
	alerts := 0
	for _, l := range fixtureLines(t, "suricata.json") {
		flat := map[string]any{}
		leaves("", decodeJSON(l), flat)
		if fmt.Sprint(flat[fmt.Sprint(e.When["path"])]) != fmt.Sprint(e.When["equals"]) {
			continue
		}
		alerts++
		for p := range e.mapped() {
			if _, ok := flat[p]; !ok {
				t.Fatalf("alert line lacks mapped path %q: %s", p, l)
			}
		}
	}
	if alerts == 0 {
		t.Fatal("no alert lines in the fixture")
	}
}

func flattenKeys(prefix string, m map[string]any, out map[string]bool) {
	for k, v := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		if c, ok := v.(map[string]any); ok {
			flattenKeys(p, c, out)
		} else {
			out[p] = true
		}
	}
}

// The OCSF paths a golden event carries are exactly those its DSL example
// sets (plus what the engine itself adds), so the goldens cannot claim a
// mapping the DSL does not perform.
func TestOCSFPathsMatchDSL(t *testing.T) {
	for _, c := range []struct{ golden, parser, extractor string }{
		{"event_asa_built", "cisco_asa", "asa_302013"}, {"event_asa_deny", "cisco_asa", "asa_106023"},
		{"event_with_entities", "cisco_asa", "asa_302013"}, {"event_fortinet", "fortinet", "fgt_traffic"},
		{"event_suricata_alert", "suricata_eve", "eve_alert"}, {"identity_dhcp_bind", "isc_dhcpd", "dhcp_lease"},
	} {
		t.Run(c.golden, func(t *testing.T) {
			g, _ := contracts.Golden(c.golden)
			var ev struct {
				OCSF map[string]any `json:"ocsf"`
			}
			if err := json.Unmarshal(g, &ev); err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			flattenKeys("", ev.OCSF, got)

			p := loadParser(c.parser)
			want := map[string]bool{"type_uid": true, "metadata.version": true, "metadata.product.vendor_name": true, "metadata.product.name": true}
			for k := range p.OCSFDefaults {
				want[k] = true
			}
			for _, m := range p.extractor(c.extractor).Map {
				want[m.To] = true
			}
			var extra, missing []string
			for k := range got {
				if !want[k] {
					extra = append(extra, k)
				}
			}
			for k := range want {
				if !got[k] {
					missing = append(missing, k)
				}
			}
			sort.Strings(extra)
			sort.Strings(missing)
			if len(extra)+len(missing) > 0 {
				t.Fatalf("golden has paths the DSL does not set: %v; DSL sets paths the golden lacks: %v", extra, missing)
			}
		})
	}
}
