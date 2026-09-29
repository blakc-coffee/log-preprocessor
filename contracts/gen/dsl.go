package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/log-preprocessor/contracts"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// A just-enough reader for the DSL examples (contracts/dsl/examples), used to
// derive each golden event's `unmapped` and `coverage` from the same document
// that specifies the parser, so the goldens cannot drift from the DSL. It is
// not the parser engine: it does no typing, no OCSF mapping and no rendering.

type mapEntry struct {
	From  any    `yaml:"from"`
	To    string `yaml:"to"`
	Type  string `yaml:"type"`
	Const any    `yaml:"const"`
}

// froms returns the capture/key/path names an entry reads.
func (m mapEntry) froms() []string {
	switch f := m.From.(type) {
	case string:
		return []string{f}
	case []any:
		var out []string
		for _, x := range f {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

type extractor struct {
	ID         string     `yaml:"id"`
	Kind       string     `yaml:"kind"`
	Pattern    string     `yaml:"pattern"`
	SkipPrefix string     `yaml:"skip_prefix"`
	Min        int        `yaml:"min_columns"`
	Columns    []string   `yaml:"columns"`
	Sep        string     `yaml:"sep"`
	Map        []mapEntry `yaml:"map"`
	Render     string     `yaml:"render"`
	Tests      []struct {
		Raw    string         `yaml:"raw"`
		Expect map[string]any `yaml:"expect"`
	} `yaml:"tests"`
	When map[string]any `yaml:"when"`
}

type parserDoc struct {
	ID           string                     `yaml:"id"`
	Vendor       string                     `yaml:"vendor"`
	Product      string                     `yaml:"product"`
	Version      string                     `yaml:"version"`
	Timezone     string                     `yaml:"timezone"`
	Match        struct{ Signature string } `yaml:"match"`
	OCSFDefaults map[string]any             `yaml:"ocsf_defaults"`
	Extractors   []extractor                `yaml:"extractors"`
}

func loadParser(name string) parserDoc {
	b, err := contracts.DSLExamples.ReadFile("dsl/examples/" + name + ".yaml")
	die(err)
	var p parserDoc
	die(yaml.Unmarshal(b, &p))
	return p
}

func (p parserDoc) extractor(id string) extractor {
	for _, e := range p.Extractors {
		if e.ID == id {
			return e
		}
	}
	die(fmt.Errorf("parser %s has no extractor %s", p.ID, id))
	return extractor{}
}

func (e extractor) mapped() map[string]bool {
	m := map[string]bool{}
	for _, me := range e.Map {
		for _, f := range me.froms() {
			m[f] = true
		}
	}
	return m
}

// account is the coverage and unmapped result for one record.
type account struct {
	unmapped map[string]any
	cov      types.Coverage
}

func (e extractor) finish(a *account, raw string, mapped, unmapped int) {
	a.cov.MappedBytes, a.cov.UnmappedBytes = mapped, unmapped
	a.cov.ConstantBytes = len(raw) - mapped - unmapped
	a.cov.MappedFields = len(e.Map)
	a.cov.UnmappedFields = len(a.unmapped)
	a.cov.Applicable = e.Kind == "regex" || e.Kind == "kv"
	if a.cov.Applicable {
		ok := true
		a.cov.RenderBackOK = &ok
	}
}

// accountRegex applies a regex extractor. Every named group that no map entry
// reads is unmapped; literals between groups are constant bytes.
func (e extractor) accountRegex(raw string) account {
	re := regexp.MustCompile(e.Pattern)
	m := re.FindStringSubmatch(raw)
	if m == nil {
		die(fmt.Errorf("extractor %s does not match %q", e.ID, raw))
	}
	used := e.mapped()
	a := account{unmapped: map[string]any{}}
	mb, ub := 0, 0
	for i, n := range re.SubexpNames() {
		if n == "" || m[i] == "" {
			continue
		}
		if used[n] {
			mb += len(m[i])
		} else {
			a.unmapped[n] = m[i]
			ub += len(m[i])
		}
	}
	e.finish(&a, raw, mb, ub)
	return a
}

// kvPairs is the spec's tokenizer for space-separated key=value with double
// quotes: values are never re-scanned for keys.
func kvPairs(raw string) (keys []string, vals map[string]string) {
	vals = map[string]string{}
	i := 0
	for i < len(raw) {
		for i < len(raw) && raw[i] == ' ' {
			i++
		}
		j := i
		for j < len(raw) && raw[j] != '=' && raw[j] != ' ' {
			j++
		}
		k := raw[i:j]
		v := ""
		if j < len(raw) && raw[j] == '=' {
			j++
			if j < len(raw) && raw[j] == '"' {
				end := strings.IndexByte(raw[j+1:], '"')
				if end < 0 {
					v, j = raw[j+1:], len(raw)
				} else {
					v, j = raw[j+1:j+1+end], j+end+2
				}
			} else {
				s := j
				for j < len(raw) && raw[j] != ' ' {
					j++
				}
				v = raw[s:j]
			}
		}
		if k != "" {
			if _, dup := vals[k]; !dup {
				keys = append(keys, k)
				vals[k] = v
			}
		}
		i = j
	}
	return
}

func (e extractor) accountKV(raw string) account {
	keys, vals := kvPairs(raw)
	used := e.mapped()
	a := account{unmapped: map[string]any{}}
	mb, ub := 0, 0
	for _, k := range keys {
		if used[k] {
			mb += len(vals[k])
		} else {
			a.unmapped[k] = vals[k]
			ub += len(vals[k])
		}
	}
	e.finish(&a, raw, mb, ub)
	return a
}

// leaves flattens decoded JSON into dotted paths.
func leaves(prefix string, v any, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			leaves(p, c, out)
		}
	default:
		out[prefix] = v
	}
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		n, ok := m[p].(map[string]any)
		if !ok {
			n = map[string]any{}
			m[p] = n
		}
		m = n
	}
	m[parts[len(parts)-1]] = v
}

func (e extractor) accountJSON(raw string) account {
	doc := decodeJSON(raw)
	flat := map[string]any{}
	leaves("", doc, flat)
	used := e.mapped()
	a := account{unmapped: map[string]any{}}
	mb, ub := 0, 0
	paths := make([]string, 0, len(flat))
	for p := range flat {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		n := len(fmt.Sprint(flat[p]))
		if used[p] {
			mb += n
		} else {
			setPath(a.unmapped, p, flat[p])
			ub += n
		}
	}
	e.finish(&a, raw, mb, ub)
	// nested unmapped counts leaves, not top-level keys
	a.cov.UnmappedFields = len(paths) - len(used)
	return a
}

func (e extractor) account(raw string) account {
	switch e.Kind {
	case "regex":
		return e.accountRegex(raw)
	case "kv":
		return e.accountKV(raw)
	case "json":
		return e.accountJSON(raw)
	}
	die(fmt.Errorf("accounting for kind %q not needed by any golden", e.Kind))
	return account{}
}

// canonIP is used by tests to compare addresses the way the engine will.
func canonIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	return a.String()
}

func decodeJSON(raw string) map[string]any {
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	die(d.Decode(&m))
	return m
}
