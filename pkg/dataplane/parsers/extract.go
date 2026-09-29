package parsers

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type field struct {
	name  string
	value string
	start int
	end   int
}

type extracted struct {
	fields    []field
	values    map[string]string
	dupes     []map[string]any
	flags     []string
	accounted int
}

func (p *Parser) extract(x *Extractor, raw []byte) (*extracted, error) {
	switch x.Kind {
	case "regex":
		return extractRegex(x, raw), nil
	case "kv":
		return extractKV(x, raw), nil
	case "csv":
		return extractCSV(x, raw)
	case "json":
		return extractJSON(x, raw)
	case "cef":
		return extractCEF(raw), nil
	case "leef":
		return extractLEEF(raw), nil
	}
	return nil, nil
}

func extractRegex(x *Extractor, raw []byte) *extracted {
	idx := x.re.FindSubmatchIndex(raw)
	if idx == nil {
		return nil
	}
	out := &extracted{values: map[string]string{}, accounted: idx[1] - idx[0]}
	names := x.re.SubexpNames()
	for i := 1; i < len(names); i++ {
		if names[i] == "" || idx[i*2] < 0 {
			continue
		}
		f := field{name: names[i], value: string(raw[idx[i*2]:idx[i*2+1]]), start: idx[i*2], end: idx[i*2+1]}
		out.fields = append(out.fields, f)
		out.values[f.name] = f.value
	}
	return out
}

func extractKV(x *Extractor, raw []byte) *extracted {
	start := 0
	if x.skipRE != nil {
		if loc := x.skipRE.FindIndex(raw); loc != nil && loc[0] == 0 {
			start = loc[1]
		}
	}
	pairSep, kvSep, quote := x.PairSep, x.KVSep, x.Quote
	if pairSep == "" {
		pairSep = " "
	}
	if kvSep == "" {
		kvSep = "="
	}
	if quote == "" {
		quote = `"`
	}
	out := &extracted{values: map[string]string{}, accounted: len(raw)}
	text := string(raw[start:])
	for pos := 0; pos < len(text); {
		for strings.HasPrefix(text[pos:], pairSep) {
			pos += len(pairSep)
			if pos >= len(text) {
				break
			}
		}
		if pos >= len(text) {
			break
		}
		keyStart := pos
		sep := strings.Index(text[pos:], kvSep)
		if sep < 0 {
			break
		}
		sep += pos
		key := text[keyStart:sep]
		pos = sep + len(kvSep)
		valueStart := pos
		value := ""
		if strings.HasPrefix(text[pos:], quote) {
			pos += len(quote)
			valueStart = pos
			end := strings.Index(text[pos:], quote)
			if end < 0 {
				value = text[pos:]
				pos = len(text)
				out.flags = append(out.flags, types.FlagKeyInjectionSuspect)
			} else {
				value = text[pos : pos+end]
				pos += end + len(quote)
			}
		} else {
			end := strings.Index(text[pos:], pairSep)
			if end < 0 {
				value = text[pos:]
				pos = len(text)
			} else {
				value = text[pos : pos+end]
				pos += end
			}
		}
		addField(out, field{name: key, value: value, start: start + valueStart, end: start + valueStart + len(value)})
	}
	return out
}

func addField(out *extracted, f field) {
	if _, exists := out.values[f.name]; exists {
		out.dupes = append(out.dupes, map[string]any{"key": f.name, "value": f.value})
		if !contains(out.flags, types.FlagDuplicateKey) {
			out.flags = append(out.flags, types.FlagDuplicateKey)
		}
		return
	}
	out.fields = append(out.fields, f)
	out.values[f.name] = f.value
}

func extractCSV(x *Extractor, raw []byte) (*extracted, error) {
	sep, quote := ',', '"'
	if x.Sep != "" {
		sep, _ = utf8.DecodeRuneInString(x.Sep)
	}
	if x.Quote != "" {
		quote, _ = utf8.DecodeRuneInString(x.Quote)
	}
	if quote != '"' {
		return nil, fmt.Errorf("csv quote %q is unsupported", string(quote))
	}
	r := csv.NewReader(bytes.NewReader(raw))
	r.Comma = sep
	r.FieldsPerRecord = -1
	cols, err := r.Read()
	if err != nil {
		return nil, nil
	}
	if len(cols) < x.MinColumns || !whenColumn(x.When, cols) {
		return nil, nil
	}
	out := &extracted{values: map[string]string{}, accounted: len(raw)}
	for i, value := range cols {
		name := fmt.Sprintf("col_%d", i)
		if i < len(x.Columns) && x.Columns[i] != "" && x.Columns[i] != "_" {
			name = x.Columns[i]
		}
		addField(out, field{name: name, value: value})
	}
	return out, nil
}

func whenColumn(w *When, cols []string) bool {
	if w == nil || w.Column == nil {
		return true
	}
	if *w.Column < 0 || *w.Column >= len(cols) {
		return false
	}
	return matches(cols[*w.Column], w.Equals, w.In)
}

func extractJSON(x *Extractor, raw []byte) (*extracted, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, nil
	}
	flat := map[string]string{}
	flags := []string{}
	count := 0
	var walk func(string, any, int)
	walk = func(path string, value any, depth int) {
		if depth > 32 {
			if !contains(flags, types.FlagNestedTooDeep) {
				flags = append(flags, types.FlagNestedTooDeep)
			}
			return
		}
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				next := key
				if path != "" {
					next = path + "." + key
				}
				walk(next, child, depth+1)
			}
		case []any:
			for i, child := range value {
				next := strconv.Itoa(i)
				if path != "" {
					next = path + "." + next
				}
				walk(next, child, depth+1)
			}
		case nil:
			flat[path] = ""
		default:
			count++
			if count <= 512 {
				flat[path] = fmt.Sprint(value)
			}
		}
	}
	walk("", root, 0)
	if count > 512 {
		flags = append(flags, types.FlagTooManyFields)
	}
	if x.When != nil && !matches(flat[x.When.Path], x.When.Equals, x.When.In) {
		return nil, nil
	}
	out := &extracted{values: flat, flags: flags, accounted: len(raw)}
	for name, value := range flat {
		out.fields = append(out.fields, field{name: name, value: value})
	}
	return out, nil
}

func extractCEF(raw []byte) *extracted {
	start := bytes.Index(raw, []byte("CEF:"))
	if start < 0 {
		return nil
	}
	parts, rest, ok := splitEscaped(string(raw[start+4:]), '|', 7)
	if !ok {
		return nil
	}
	names := []string{"cef.version", "cef.vendor", "cef.product", "cef.device_version", "cef.signature_id", "cef.name", "cef.severity"}
	out := &extracted{values: map[string]string{}, accounted: len(raw)}
	for i, name := range names {
		addField(out, field{name: name, value: unescape(parts[i])})
	}
	re := regexp.MustCompile(`(?:^| )([A-Za-z0-9_.-]+)=`)
	locs := re.FindAllStringSubmatchIndex(rest, -1)
	for i, loc := range locs {
		end := len(rest)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		addField(out, field{name: rest[loc[2]:loc[3]], value: unescape(strings.TrimSpace(rest[loc[1]:end]))})
	}
	return out
}

func splitEscaped(s string, sep byte, count int) ([]string, string, bool) {
	parts := []string{}
	start := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
			if len(parts) == count {
				return parts, s[start:], true
			}
		}
	}
	return nil, "", false
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func extractLEEF(raw []byte) *extracted {
	start := bytes.Index(raw, []byte("LEEF:"))
	if start < 0 {
		return nil
	}
	s := string(raw[start+5:])
	versionEnd := strings.IndexByte(s, '|')
	if versionEnd < 0 {
		return nil
	}
	version := s[:versionEnd]
	need := 4
	if version == "2.0" {
		need = 5
	}
	parts, rest, ok := splitEscaped(s[versionEnd+1:], '|', need)
	if !ok {
		return nil
	}
	delim := "\t"
	if version == "2.0" {
		delim = parts[4]
		parts = parts[:4]
		if strings.HasPrefix(delim, "x") && len(delim) == 3 {
			if n, err := strconv.ParseUint(delim[1:], 16, 8); err == nil {
				delim = string(byte(n))
			}
		}
	}
	out := &extracted{values: map[string]string{}, accounted: len(raw)}
	names := []string{"leef.vendor", "leef.product", "leef.product_version", "leef.event_id"}
	addField(out, field{name: "leef.version", value: version})
	for i, name := range names {
		addField(out, field{name: name, value: unescape(parts[i])})
	}
	for _, pair := range strings.Split(rest, delim) {
		if at := strings.IndexByte(pair, '='); at >= 0 {
			addField(out, field{name: pair[:at], value: pair[at+1:]})
		}
	}
	return out
}

func matches(got string, equals any, in []any) bool {
	if equals != nil {
		return got == fmt.Sprint(equals)
	}
	for _, value := range in {
		if got == fmt.Sprint(value) {
			return true
		}
	}
	return len(in) == 0
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
