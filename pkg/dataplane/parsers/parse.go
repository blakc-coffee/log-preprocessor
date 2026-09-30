package parsers

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	types "github.com/blakc-coffee/sluice/pkg/types"
)

func (p *Parser) Parse(raw []byte, receivedAt time.Time) (*Result, error) {
	probe := raw
	if len(probe) > 512 {
		probe = probe[:512]
	}
	if !p.signature.Match(probe) {
		return nil, nil
	}
	for i := range p.doc.Extractors {
		x := &p.doc.Extractors[i]
		ex, err := p.extract(x, raw)
		if err != nil {
			return nil, err
		}
		if ex == nil {
			continue
		}
		result, matched, err := p.normalize(x, ex, raw, receivedAt)
		if err != nil {
			return nil, err
		}
		if matched {
			return result, nil
		}
	}
	return nil, nil
}

func (p *Parser) normalize(x *Extractor, ex *extracted, raw []byte, receivedAt time.Time) (*Result, bool, error) {
	ocsf := cloneMap(p.doc.OCSFDefaults)
	unmapped := map[string]any{}
	used := map[string]bool{}
	typed := map[string]any{}
	flags := append([]string(nil), ex.flags...)
	mappedBytes, mappedFields := 0, 0
	for _, m := range x.Map {
		if m.hasConst {
			setPath(ocsf, m.To, m.Const)
			mappedFields++
			continue
		}
		names := fromNames(m.From)
		values := make([]string, 0, len(names))
		missing := false
		for _, name := range names {
			value, ok := ex.values[name]
			if !ok {
				missing = true
				break
			}
			values = append(values, value)
		}
		if missing {
			if m.Optional {
				continue
			}
			return nil, false, nil
		}
		empty := false
		for _, value := range values {
			if value == "" {
				empty = true
			}
		}
		if empty {
			for _, name := range names {
				used[name] = true
			}
			continue
		}
		value, flag, err := p.convert(m, strings.Join(values, " "), receivedAt)
		if err != nil {
			return nil, false, nil
		}
		if flag != "" && !contains(flags, flag) {
			flags = append(flags, flag)
		}
		if flag != types.FlagTimeUnparseable {
			setPath(ocsf, m.To, value)
			typed[names[0]] = value
			mappedFields++
		}
		for _, name := range names {
			used[name] = true
			for _, f := range ex.fields {
				if f.name == name {
					mappedBytes += len(f.value)
					break
				}
			}
		}
	}
	if class, ok := numberAt(ocsf, "class_uid"); ok {
		if activity, ok := numberAt(ocsf, "activity_id"); ok {
			setPath(ocsf, "type_uid", class*100+activity)
		}
	}
	for _, f := range ex.fields {
		if f.value == "" || used[f.name] {
			continue
		}
		setPath(unmapped, f.name, f.value)
	}
	if len(ex.dupes) > 0 {
		unmapped["_dupes"] = ex.dupes
	}
	for _, f := range ex.fields {
		if len(f.value) > 64*1024 && !contains(flags, types.FlagOversizeField) {
			flags = append(flags, types.FlagOversizeField)
		}
	}
	unmappedBytes := 0
	for _, f := range ex.fields {
		if f.value != "" && !used[f.name] {
			unmappedBytes += len(f.value)
		}
	}
	uncovered := len(raw) - ex.accounted
	if uncovered < 0 {
		uncovered = 0
	}
	constant := len(raw) - mappedBytes - unmappedBytes - uncovered
	if constant < 0 {
		constant = 0
	}
	coverage := types.Coverage{Applicable: x.Kind == "regex" || x.Kind == "kv", MappedBytes: mappedBytes, UnmappedBytes: unmappedBytes, ConstantBytes: constant, UncoveredBytes: uncovered, MappedFields: mappedFields, UnmappedFields: len(ex.fields) - len(used)}
	var renderOK *bool
	if x.Render != nil {
		ok := p.render(x, ex, typed) == string(raw)
		renderOK = &ok
		coverage.RenderBackOK = &ok
		if !ok {
			flags = append(flags, types.FlagRenderBackMismatch)
		}
	}
	identity := p.identity(ex, typed, receivedAt)
	return &Result{ExtractorID: x.ID, OCSF: ocsf, Unmapped: unmapped, Flags: flags, Coverage: coverage, RenderBackOK: renderOK, Identity: identity}, true, nil
}

func (p *Parser) convert(m MapEntry, raw string, receivedAt time.Time) (any, string, error) {
	switch m.Type {
	case "", "string":
		if m.Lower {
			raw = strings.ToLower(raw)
		}
		return raw, "", nil
	case "int":
		v, err := strconv.ParseInt(raw, 10, 64)
		return v, "", err
	case "uint", "bytes":
		v, err := strconv.ParseUint(raw, 10, 64)
		return v, "", err
	case "float":
		v, err := strconv.ParseFloat(raw, 64)
		return v, "", err
	case "ip":
		v, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, "", err
		}
		return v.Unmap().String(), "", nil
	case "port":
		v, err := strconv.ParseUint(raw, 10, 16)
		return v, "", err
	case "mac":
		v, err := net.ParseMAC(raw)
		if err != nil {
			return nil, "", err
		}
		return strings.ToLower(v.String()), "", nil
	case "bool":
		v, err := strconv.ParseBool(raw)
		return v, "", err
	case "duration":
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, "", err
		}
		mul := float64(1000)
		if m.Unit == "ms" {
			mul = 1
		}
		if m.Unit == "ns" {
			mul = 1e-6
		}
		return int64(math.Round(v * mul)), "", nil
	case "enum":
		if v, ok := m.Enum[raw]; ok {
			return v, "", nil
		}
		if m.hasDef {
			return m.Default, "", nil
		}
		return nil, "", fmt.Errorf("enum %q", raw)
	case "time":
		t, err := p.parseTime(raw, m.Layout, receivedAt)
		if err != nil {
			return nil, types.FlagTimeUnparseable, nil
		}
		return t.UnixMilli(), "", nil
	default:
		return nil, "", fmt.Errorf("unknown type %q", m.Type)
	}
}

func (p *Parser) parseTime(value, layout string, receipt time.Time) (time.Time, error) {
	switch layout {
	case "epoch_s", "epoch_ms", "epoch_ns":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, err
		}
		if layout == "epoch_s" {
			return time.Unix(n, 0).UTC(), nil
		}
		if layout == "epoch_ms" {
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(0, n).UTC(), nil
	case "rfc3339":
		return time.Parse(time.RFC3339, value)
	}
	hasYear := strings.Contains(layout, "2006") || strings.Contains(layout, "06")
	if hasYear {
		t, err := time.ParseInLocation(layout, value, p.zone)
		return t.UTC(), err
	}
	t, err := time.ParseInLocation(layout, value, p.zone)
	if err != nil {
		return time.Time{}, err
	}
	year := receipt.In(p.zone).Year()
	if int(t.Month()) > int(receipt.In(p.zone).Month())+1 {
		year--
	}
	return time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), p.zone).UTC(), nil
}

func (p *Parser) render(x *Extractor, ex *extracted, typed map[string]any) string {
	if fmt.Sprint(x.Render) == "auto" {
		return renderKV(x, ex)
	}
	template := fmt.Sprint(x.Render)
	var b strings.Builder
	for i := 0; i < len(template); {
		if strings.HasPrefix(template[i:], "{{") {
			b.WriteByte('{')
			i += 2
			continue
		}
		if strings.HasPrefix(template[i:], "}}") {
			b.WriteByte('}')
			i += 2
			continue
		}
		if template[i] == '{' {
			end := strings.IndexByte(template[i+1:], '}')
			if end >= 0 {
				name := template[i+1 : i+1+end]
				if value, ok := typed[name]; ok {
					b.WriteString(fmt.Sprint(value))
				} else {
					b.WriteString(ex.values[name])
				}
				i += end + 2
				continue
			}
		}
		b.WriteByte(template[i])
		i++
	}
	return b.String()
}

func renderKV(x *Extractor, ex *extracted) string {
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
	parts := make([]string, 0, len(ex.fields))
	for _, f := range ex.fields {
		value := f.value
		if strings.Contains(value, pairSep) {
			value = quote + value + quote
		}
		parts = append(parts, f.name+kvSep+value)
	}
	return strings.Join(parts, pairSep)
}

func (p *Parser) identity(ex *extracted, typed map[string]any, receivedAt time.Time) *types.IdentityFact {
	id := p.doc.Identity
	if id == nil || !matches(ex.values[id.When.Field], id.When.Equals, id.When.In) {
		return nil
	}
	action := ""
	if id.Action.Field != "" {
		action = fmt.Sprint(id.Action.Enum[ex.values[id.Action.Field]])
	} else {
		action = fmt.Sprint(id.Action)
	}
	at := receivedAt
	if value, ok := typed[id.At]; ok {
		if ms, err := strconv.ParseInt(fmt.Sprint(value), 10, 64); err == nil {
			at = time.UnixMilli(ms).UTC()
		}
	}
	return &types.IdentityFact{Kind: id.Kind, Action: action, IP: ex.values[id.IP], MAC: ex.values[id.MAC], Host: ex.values[id.Host], User: ex.values[id.User], At: at}
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func setPath(root map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	cur := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}
func numberAt(root map[string]any, path string) (int64, bool) {
	var cur any = root
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = m[part]
	}
	switch n := cur.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		v, e := strconv.ParseInt(fmt.Sprint(n), 10, 64)
		return v, e == nil
	}
}
