package parsers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Engine struct{}

func New() *Engine { return &Engine{} }

var (
	idRE      = regexp.MustCompile(`^[a-z0-9_]+$`)
	semverRE  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	badRE2    = regexp.MustCompile(`\(\?[=!<]|\\[1-9]`)
	knownPath = regexp.MustCompile(`^(x|class_uid|category_uid|activity_id|type_uid|time|severity_id|action_id|disposition_id|message|duration|src_endpoint\.(ip|port|mac|hostname)|dst_endpoint\.(ip|port|mac|hostname)|connection_info\.(protocol_name|protocol_num)|traffic\.(bytes_in|bytes_out|packets_in|packets_out)|actor\.user\.name)$`)
)

func (e *Engine) Load(src []byte) (*Parser, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("parser document: %w", err)
	}
	var doc Document
	if err := root.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parser document: %w", err)
	}
	if !idRE.MatchString(doc.ID) || !semverRE.MatchString(doc.Version) || doc.Vendor == "" || doc.Product == "" {
		return nil, fmt.Errorf("parser %q: id, semver, vendor and product are required", doc.ID)
	}
	if doc.Match.Signature == "" {
		return nil, fmt.Errorf("parser %q match.signature: required", doc.ID)
	}
	sig, err := compileRE(doc.ID, "", "match.signature", doc.Match.Signature)
	if err != nil {
		return nil, err
	}
	zone, err := parseZone(doc.Timezone)
	if err != nil {
		return nil, fmt.Errorf("parser %q timezone: %w", doc.ID, err)
	}
	seen := map[string]bool{}
	for i := range doc.Extractors {
		x := &doc.Extractors[i]
		if !idRE.MatchString(x.ID) || seen[x.ID] {
			return nil, fmt.Errorf("parser %q extractor %q id: invalid or duplicate", doc.ID, x.ID)
		}
		seen[x.ID] = true
		switch x.Kind {
		case "regex":
			x.re, err = compileRE(doc.ID, x.ID, "pattern", x.Pattern)
		case "kv":
			if x.SkipPrefix != "" {
				x.skipRE, err = compileRE(doc.ID, x.ID, "skip_prefix", x.SkipPrefix)
			}
		case "json", "csv", "cef", "leef":
		default:
			err = fmt.Errorf("unsupported kind %q", x.Kind)
		}
		if err != nil {
			return nil, err
		}
		if err := validateMaps(doc.ID, x); err != nil {
			return nil, err
		}
	}
	if len(doc.Extractors) == 0 {
		return nil, fmt.Errorf("parser %q extractors: required", doc.ID)
	}
	return &Parser{doc: doc, signature: sig, zone: zone}, nil
}

func compileRE(parser, extractor, field, pattern string) (*regexp.Regexp, error) {
	prefix := fmt.Sprintf("parser %q", parser)
	if extractor != "" {
		prefix += fmt.Sprintf(" extractor %q", extractor)
	}
	if pattern == "" || badRE2.MatchString(pattern) {
		return nil, fmt.Errorf("%s %s: RE2 does not support expression", prefix, field)
	}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", prefix, field, err)
	}
	return r, nil
}

func validateMaps(parser string, x *Extractor) error {
	groups := map[string]bool{}
	if x.re != nil {
		for _, name := range x.re.SubexpNames() {
			if name != "" {
				groups[name] = true
			}
		}
	}
	for i := range x.Map {
		m := &x.Map[i]
		m.hasConst = m.Const != nil
		m.hasDef = m.Default != nil
		if !knownPath.MatchString(m.To) {
			return fmt.Errorf("parser %q extractor %q map[%d] (to: %s): unknown OCSF path", parser, x.ID, i, m.To)
		}
		if x.Kind == "regex" && !m.hasConst {
			for _, from := range fromNames(m.From) {
				if !groups[from] {
					return fmt.Errorf("parser %q extractor %q map[%d] (from: %s): capture %q is not defined by the pattern", parser, x.ID, i, from, from)
				}
			}
		}
	}
	return nil
}

func parseZone(s string) (*time.Location, error) {
	if len(s) != 6 || (s[0] != '+' && s[0] != '-') || s[3] != ':' {
		return nil, fmt.Errorf("want +HH:MM")
	}
	h, e1 := strconv.Atoi(s[1:3])
	m, e2 := strconv.Atoi(s[4:])
	if e1 != nil || e2 != nil || h > 23 || m > 59 {
		return nil, fmt.Errorf("want +HH:MM")
	}
	off := h*3600 + m*60
	if s[0] == '-' {
		off = -off
	}
	return time.FixedZone(s, off), nil
}

func fromNames(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case []string:
		return x
	default:
		if v == nil {
			return nil
		}
		return []string{strings.TrimSpace(fmt.Sprint(v))}
	}
}
