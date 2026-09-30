// Package conformance checks a parser engine against the parser DSL specification.
//
// Parsing's engine implements Engine (a thin adapter is enough) and calls Run from one test:
//
//	func TestDSLConformance(t *testing.T) { conformance.Run(t, myAdapter{}, conformance.Options{}) }
//
// Three groups run, each as subtests:
//
//	cases     cases.yaml: language-neutral cases derived from contracts/parser_dsl.md, one behaviour each
//	examples  every `tests:` vector of the five parsers in contracts/dsl/examples
//	fixtures  those parsers over the fixture corpus, checked against testdata/manifest.json
//
// The cases were first run against an independent implementation (the sidecar's Python reference
// evaluator), so a failure here points at the engine, or at an ambiguity the spec must resolve, and
// not at a typo in a case. A case that no implementation can satisfy is a bug in the spec: say so.
package conformance

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dark-14100/sluice/contracts"
	types "github.com/dark-14100/sluice/pkg/types"
)

// Engine compiles a parser document.
type Engine interface {
	// Load compiles one parser YAML document. A document the spec says to reject must return an error whose
	// text names the parser, the extractor and the field, in that order (parser_dsl.md section 8).
	Load(yaml []byte) (Parser, error)
}

// Parser turns one raw record into a result.
type Parser interface {
	// Parse returns (nil, nil) when no extractor matches: the record would be quarantined.
	Parse(raw []byte, receivedAt time.Time) (*Result, error)
}

// Result is what an engine reports for one record. Field names follow types.NormalizedEvent.
type Result struct {
	ExtractorID  string
	OCSF         map[string]any // nested, as NormalizedEvent.OCSF; time in epoch milliseconds
	Unmapped     map[string]any
	Flags        []string
	Coverage     types.Coverage
	RenderBackOK *bool
	Identity     *types.IdentityFact
}

// Options tunes a run.
type Options struct {
	// Root is the repository root. Empty means: walk up from the working directory to go.mod.
	Root string
	// Skip lets an engine that does not implement everything yet say so, by case name, instead of failing.
	// Every skip is logged so it cannot hide. Return true to skip.
	Skip func(caseName string, pythonModelled bool) bool
}

//go:embed cases.yaml
var casesYAML []byte

// Case is one entry of cases.yaml.
type Case struct {
	Name       string `yaml:"name"`
	Spec       string `yaml:"spec"`
	Parser     string `yaml:"parser"`
	Raw        string `yaml:"raw"`
	ReceivedAt string `yaml:"received_at"`
	LoadError  string `yaml:"load_error"`
	Python     bool   `yaml:"python"`
	Expect     Expect `yaml:"expect"`
}

// Expect is the assertion half of a case.
type Expect struct {
	Matched        bool           `yaml:"matched"`
	Extractor      string         `yaml:"extractor"`
	OCSF           map[string]any `yaml:"ocsf"`
	OCSFAbsent     []string       `yaml:"ocsf_absent"`
	Unmapped       map[string]any `yaml:"unmapped"`
	UnmappedAbsent []string       `yaml:"unmapped_absent"`
	Flags          []string       `yaml:"flags"`
	FlagsAbsent    []string       `yaml:"flags_absent"`
	CoverageSums   bool           `yaml:"coverage_sums"`
	RenderBackOK   *bool          `yaml:"render_back_ok"`
	Identity       map[string]any `yaml:"identity"`
}

// Cases returns the parsed cases.yaml.
func Cases() ([]Case, error) {
	var doc struct {
		Cases []Case `yaml:"cases"`
	}
	if err := yaml.Unmarshal(casesYAML, &doc); err != nil {
		return nil, err
	}
	return doc.Cases, nil
}

// Run executes every group against e.
func Run(t *testing.T, e Engine, opt Options) {
	t.Helper()
	if opt.Root == "" {
		opt.Root = repoRoot(t)
	}
	t.Run("cases", func(t *testing.T) { runCases(t, e, opt) })
	t.Run("examples", func(t *testing.T) { runExamples(t, e) })
	t.Run("fixtures", func(t *testing.T) { runFixtures(t, e, opt.Root) })
}

func repoRoot(t *testing.T) string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir = parent
			continue
		}
		t.Fatal("conformance: no go.mod above the working directory; set Options.Root")
	}
}

var refTime = time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)

// ---- cases ------------------------------------------------------------------------------------------

func runCases(t *testing.T, e Engine, opt Options) {
	cases, err := Cases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 30 {
		t.Fatalf("only %d cases loaded", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if opt.Skip != nil && opt.Skip(c.Name, c.Python) {
				t.Skipf("skipped by the engine's Options.Skip (spec %s)", c.Spec)
			}
			p, err := e.Load([]byte(c.Parser))
			if c.LoadError != "" {
				if err == nil {
					t.Fatalf("spec %s: the document must be rejected with an error containing %q, but it loaded", c.Spec, c.LoadError)
				}
				if !strings.Contains(err.Error(), c.LoadError) {
					t.Fatalf("spec %s: error %q must contain %q (parser, extractor, field, in that order)", c.Spec, err, c.LoadError)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec %s: a valid parser was rejected: %v", c.Spec, err)
			}
			ra := refTime
			if c.ReceivedAt != "" {
				if ra, err = time.Parse(time.RFC3339, c.ReceivedAt); err != nil {
					t.Fatal(err)
				}
			}
			r, err := p.Parse([]byte(c.Raw), ra)
			if err != nil {
				t.Fatalf("spec %s: %v", c.Spec, err)
			}
			if problems := check(c.Expect, r, len(c.Raw)); len(problems) > 0 {
				t.Errorf("spec %s: %s\n  raw: %.200s", c.Spec, strings.Join(problems, "\n  "), c.Raw)
			}
		})
	}
}

func check(x Expect, r *Result, rawLen int) (problems []string) {
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	if (r != nil) != x.Matched {
		bad("matched = %v, want %v", r != nil, x.Matched)
		return
	}
	if r == nil {
		return
	}
	if x.Extractor != "" && r.ExtractorID != x.Extractor {
		bad("extractor %q, want %q", r.ExtractorID, x.Extractor)
	}
	oc := Flatten(r.OCSF)
	for k, want := range x.OCSF {
		if got, ok := oc[k]; !ok || !Equal(got, want) {
			bad("ocsf[%s] = %v, want %v", k, oc[k], want)
		}
	}
	for _, k := range x.OCSFAbsent {
		if v, ok := oc[k]; ok {
			bad("ocsf[%s] = %v, want it absent", k, v)
		}
	}
	um := Flatten(without(r.Unmapped, "_dupes"))
	for k, want := range x.Unmapped {
		if k == "_dupes" {
			a, _ := json.Marshal(r.Unmapped["_dupes"])
			b, _ := json.Marshal(want)
			if string(a) != string(b) {
				bad("unmapped._dupes = %s, want %s", a, b)
			}
		} else if got, ok := um[k]; !ok || !Equal(got, want) {
			bad("unmapped[%s] = %v, want %v", k, um[k], want)
		}
	}
	for _, k := range x.UnmappedAbsent {
		if v, ok := um[k]; ok {
			bad("unmapped[%s] = %v, want it absent (mapped or empty values never appear there)", k, v)
		}
	}
	have := map[string]bool{}
	for _, f := range r.Flags {
		have[f] = true
	}
	for _, f := range x.Flags {
		if !have[f] {
			bad("flag %q missing (have %v)", f, r.Flags)
		}
	}
	for _, f := range x.FlagsAbsent {
		if have[f] {
			bad("flag %q must not be set", f)
		}
	}
	if x.CoverageSums {
		c := r.Coverage
		if sum := c.MappedBytes + c.UnmappedBytes + c.ConstantBytes + c.UncoveredBytes; sum != rawLen {
			bad("coverage %+v sums to %d, the record is %d bytes", c, sum, rawLen)
		}
	}
	if x.RenderBackOK != nil && (r.RenderBackOK == nil || *r.RenderBackOK != *x.RenderBackOK) {
		bad("render_back_ok = %v, want %v", r.RenderBackOK, *x.RenderBackOK)
	}
	if x.Identity != nil {
		if r.Identity == nil {
			bad("no identity fact produced")
		} else {
			got := map[string]any{"kind": r.Identity.Kind, "action": r.Identity.Action, "ip": r.Identity.IP, "mac": r.Identity.MAC, "host": r.Identity.Host}
			for k, want := range x.Identity {
				if got[k] != want {
					bad("identity.%s = %v, want %v", k, got[k], want)
				}
			}
		}
	}
	return
}

func without(m map[string]any, k string) map[string]any {
	out := map[string]any{}
	for a, b := range m {
		if a != k {
			out[a] = b
		}
	}
	return out
}

// Flatten turns nested maps into dotted paths.
func Flatten(m map[string]any) map[string]any {
	out := map[string]any{}
	var walk func(p string, v any)
	walk = func(p string, v any) {
		if mm, ok := v.(map[string]any); ok {
			for k, c := range mm {
				if p != "" {
					k = p + "." + k
				}
				walk(k, c)
			}
			return
		}
		out[p] = v
	}
	walk("", m)
	return out
}

// Equal compares values the way JSON and YAML do: every number is a float64, an IP is its canonical text.
func Equal(a, b any) bool {
	fa, oka := num(a)
	fb, okb := num(b)
	if oka || okb {
		return oka && okb && fa == fb
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return math.NaN(), false
}

// ---- the DSL examples -------------------------------------------------------------------------------

var exampleNames = []string{"cisco_asa", "fortinet", "palo_alto_traffic", "suricata_eve", "isc_dhcpd"}

type doc struct {
	ID         string `yaml:"id"`
	Extractors []struct {
		ID    string `yaml:"id"`
		Tests []struct {
			Raw    string         `yaml:"raw"`
			Expect map[string]any `yaml:"expect"`
		} `yaml:"tests"`
	} `yaml:"extractors"`
}

func loadExample(t *testing.T, name string) ([]byte, doc) {
	b, err := contracts.DSLExamples.ReadFile("dsl/examples/" + name + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return b, d
}

func runExamples(t *testing.T, e Engine) {
	for _, name := range exampleNames {
		t.Run(name, func(t *testing.T) {
			src, d := loadExample(t, name)
			p, err := e.Load(src)
			if err != nil {
				t.Fatalf("the spec's own example does not load: %v", err)
			}
			n := 0
			for _, ex := range d.Extractors {
				for _, v := range ex.Tests {
					n++
					r, err := p.Parse([]byte(v.Raw), refTime)
					if err != nil || r == nil {
						t.Errorf("%s: vector did not parse (err %v): %.90s", ex.ID, err, v.Raw)
						continue
					}
					if r.ExtractorID != ex.ID {
						t.Errorf("%s: extractor %q won instead", ex.ID, r.ExtractorID)
					}
					got := Flatten(r.OCSF)
					for k, want := range v.Expect {
						if !Equal(got[k], want) {
							t.Errorf("%s: %s = %v, want %v", ex.ID, k, got[k], want)
						}
					}
				}
			}
			if n == 0 {
				t.Fatal("example has no test vectors")
			}
		})
	}
}

// ---- the fixture corpus -----------------------------------------------------------------------------

type record struct {
	File  string  `json:"source_file"`
	SrcIP *string `json:"expected_src_ip"`
	DstIP *string `json:"expected_dst_ip"`
	SrcPt *int    `json:"expected_src_port"`
	DstPt *int    `json:"expected_dst_port"`
	Proto *string `json:"expected_proto"`
	Time  *string `json:"expected_time"`
}

func manifest(t *testing.T, root string) map[string][]record {
	b, err := os.ReadFile(filepath.Join(root, "testdata", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Records []record `json:"records"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	by := map[string][]record{}
	for _, r := range m.Records {
		by[r.File] = append(by[r.File], r)
	}
	return by
}

var (
	reASA  = regexp.MustCompile(`%ASA-\d-(?:302013|106023):`)
	reDHCP = regexp.MustCompile(`dhcpd\[\d+\]: DHCP(?:ACK|RELEASE) `)
)

// What each example parser claims over the corpus: which lines it must match, and which it must NOT.
var claims = []struct {
	parser, file string
	must         func(line string) bool
}{
	{"cisco_asa", "cisco_asa.log", reASA.MatchString},
	{"cisco_asa", "identity_firewall.log", reASA.MatchString},
	{"fortinet", "fortinet.log", func(string) bool { return true }},
	{"fortinet", "fortinet_drift.log", func(string) bool { return false }}, // the drift is real: the old parser fails on every line
	{"palo_alto_traffic", "palo_alto_unknown.log", func(string) bool { return true }},
	{"suricata_eve", "suricata.json", func(l string) bool { return strings.Contains(l, `"event_type":"alert"`) }},
	{"isc_dhcpd", "dhcp.log", reDHCP.MatchString},
}

func runFixtures(t *testing.T, e Engine, root string) {
	man := manifest(t, root)
	loaded := map[string]Parser{}
	for _, c := range claims {
		t.Run(c.parser+"/"+c.file, func(t *testing.T) {
			p, ok := loaded[c.parser]
			if !ok {
				src, _ := loadExample(t, c.parser)
				var err error
				if p, err = e.Load(src); err != nil {
					t.Fatalf("load: %v", err)
				}
				loaded[c.parser] = p
			}
			b, err := os.ReadFile(filepath.Join(root, "testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			truth := man[c.file]
			if len(truth) != len(lines) {
				t.Fatalf("manifest has %d records, file has %d lines", len(truth), len(lines))
			}
			matched, wrong := 0, 0
			var first []string
			for i, l := range lines {
				l = strings.TrimRight(l, "\r")
				r, err := p.Parse([]byte(l), refTime)
				if err != nil {
					t.Fatalf("line %d: %v", i+1, err)
				}
				if want := c.must(l); (r != nil) != want {
					wrong++
					if len(first) < 3 {
						first = append(first, fmt.Sprintf("line %d matched=%v want=%v: %.100s", i+1, r != nil, want, l))
					}
					continue
				}
				if r == nil {
					continue
				}
				matched++
				if msg := agrees(truth[i], Flatten(r.OCSF)); msg != "" {
					wrong++
					if len(first) < 3 {
						first = append(first, fmt.Sprintf("line %d %s: %.100s", i+1, msg, l))
					}
				}
			}
			if wrong > 0 {
				t.Errorf("%d of %d lines wrong; first:\n  %s", wrong, len(lines), strings.Join(first, "\n  "))
			}
			t.Logf("%d of %d lines matched and agreed with the manifest", matched, len(lines))
		})
	}
}

// agrees compares what the manifest knows. A null expected_* means "not known", never a failure.
func agrees(r record, o map[string]any) string {
	var bad []string
	str := func(name string, want *string, path string) {
		if want != nil && !Equal(o[path], *want) {
			bad = append(bad, fmt.Sprintf("%s = %v, want %s", path, o[path], *want))
		}
	}
	pt := func(want *int, path string) {
		if want != nil && !Equal(o[path], *want) {
			bad = append(bad, fmt.Sprintf("%s = %v, want %d", path, o[path], *want))
		}
	}
	str("", r.SrcIP, "src_endpoint.ip")
	str("", r.DstIP, "dst_endpoint.ip")
	str("", r.Proto, "connection_info.protocol_name")
	pt(r.SrcPt, "src_endpoint.port")
	pt(r.DstPt, "dst_endpoint.port")
	if r.Time != nil {
		want, err := time.Parse(time.RFC3339, *r.Time)
		got, ok := num(o["time"])
		if err != nil || !ok || int64(got)/1000 != want.Unix() { // the manifest keeps whole seconds
			bad = append(bad, fmt.Sprintf("time = %v, want %d ms", o["time"], want.UnixMilli()))
		}
	}
	sort.Strings(bad)
	return strings.Join(bad, "; ")
}

// CheckForTest exposes the assertion logic to the harness's own tests; it returns "" when r satisfies x.
func CheckForTest(x Expect, r *Result, rawLen int) string {
	return strings.Join(check(x, r, rawLen), "; ")
}
