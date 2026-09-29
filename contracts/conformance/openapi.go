package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/log-preprocessor/contracts"
)

// The admin API contract as an executable check. Parsing's handler tests call ValidateResponse on real
// responses, and ValidateRequest on the bodies their tests send; the control plane does the same for the
// requests it makes. A response the OpenAPI file does not describe is an error, not a pass.

type spec struct {
	paths map[string]map[string]any // template -> lower-case method -> operation
	comps map[string]any
	uef   any
}

var (
	once    sync.Once
	loaded  *spec
	loadErr error
)

func api() (*spec, error) {
	once.Do(func() {
		var doc map[string]any
		if err := yaml.Unmarshal(contracts.OpenAPIYAML, &doc); err != nil {
			loadErr = err
			return
		}
		s := &spec{paths: map[string]map[string]any{}, comps: doc["components"].(map[string]any)}
		for p, item := range doc["paths"].(map[string]any) {
			s.paths[p] = map[string]any{}
			for m, op := range item.(map[string]any) {
				s.paths[p][strings.ToLower(m)] = op
			}
		}
		s.uef, loadErr = jsonschema.UnmarshalJSON(bytes.NewReader(contracts.SchemaJSON))
		loaded = s
	})
	return loaded, loadErr
}

// match finds the OpenAPI path template for a concrete path.
func (s *spec) match(path string) (string, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var hits []string
	for tpl := range s.paths {
		ts := strings.Split(strings.Trim(tpl, "/"), "/")
		if len(ts) != len(segs) {
			continue
		}
		ok := true
		for i := range ts {
			if strings.HasPrefix(ts[i], "{") {
				ok = ok && segs[i] != ""
			} else {
				ok = ok && ts[i] == segs[i]
			}
		}
		if ok {
			hits = append(hits, tpl)
		}
	}
	// a literal segment beats a parameter: /admin/parsers/dryrun over /admin/parsers/{id}
	sort.Slice(hits, func(i, j int) bool { return strings.Count(hits[i], "{") < strings.Count(hits[j], "{") })
	if len(hits) == 0 {
		return "", false
	}
	return hits[0], true
}

// rewrite turns '#/components/schemas/X' references into the resource names used when compiling.
func rewrite(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, c := range x {
			if k == "$ref" {
				if r, ok := c.(string); ok && strings.HasPrefix(r, "#/components/schemas/") {
					out[k] = "api-" + strings.TrimPrefix(r, "#/components/schemas/") + ".json"
					continue
				}
			}
			out[k] = rewrite(c)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, c := range x {
			out[i] = rewrite(c)
		}
		return out
	}
	return v
}

func (s *spec) resolve(v any) any {
	for {
		m, ok := v.(map[string]any)
		if !ok {
			return v
		}
		r, ok := m["$ref"].(string)
		if !ok || !strings.HasPrefix(r, "#/components/") || strings.HasPrefix(r, "#/components/schemas/") {
			return v
		}
		parts := strings.Split(strings.TrimPrefix(r, "#/components/"), "/")
		v = s.comps[parts[0]].(map[string]any)[parts[1]]
	}
}

func (s *spec) validate(schema any, body []byte) error {
	c := jsonschema.NewCompiler()
	if err := c.AddResource("uef.schema.json", s.uef); err != nil {
		return err
	}
	for name, sc := range s.comps["schemas"].(map[string]any) {
		b, _ := json.Marshal(rewrite(sc))
		d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := c.AddResource("api-"+name+".json", d); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(rewrite(schema))
	d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err := c.AddResource("target.json", d); err != nil {
		return err
	}
	sch, err := c.Compile("target.json")
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("body is not JSON: %w", err)
	}
	return sch.Validate(inst)
}

// ValidateResponse checks one response against contracts/admin.openapi.yaml: the operation exists, the status is
// documented, and a JSON body satisfies the documented schema. path is the concrete request path without a query.
func ValidateResponse(method, path string, status int, contentType string, body []byte) error {
	s, err := api()
	if err != nil {
		return err
	}
	tpl, ok := s.match(path)
	if !ok {
		return fmt.Errorf("conformance: %s is not an endpoint of admin.openapi.yaml", path)
	}
	op, ok := s.paths[tpl][strings.ToLower(method)]
	if !ok {
		return fmt.Errorf("conformance: %s %s is not an operation of admin.openapi.yaml", method, tpl)
	}
	resps := op.(map[string]any)["responses"].(map[string]any)
	r, ok := resps[strconv.Itoa(status)]
	if !ok {
		var have []string
		for k := range resps {
			have = append(have, k)
		}
		sort.Strings(have)
		return fmt.Errorf("conformance: %s %s answered %d, which the contract does not document (documented: %v)", method, tpl, status, have)
	}
	content, _ := s.resolve(r).(map[string]any)["content"].(map[string]any)
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt == "" {
		mt = "application/json"
	}
	media, ok := content[mt].(map[string]any)
	if !ok {
		if len(content) == 0 && len(bytes.TrimSpace(body)) == 0 {
			return nil
		}
		return fmt.Errorf("conformance: %s %s %d: content type %q is not documented", method, tpl, status, mt)
	}
	sch, ok := media["schema"]
	if !ok || mt != "application/json" {
		return nil // e.g. text/yaml or octet-stream: nothing structural to check
	}
	if err := s.validate(sch, body); err != nil {
		return fmt.Errorf("conformance: %s %s %d body violates the contract:\n%w", method, tpl, status, err)
	}
	return nil
}

// ValidateRequest checks a request body against the operation's documented requestBody schema.
func ValidateRequest(method, path string, body []byte) error {
	s, err := api()
	if err != nil {
		return err
	}
	tpl, ok := s.match(path)
	if !ok {
		return fmt.Errorf("conformance: %s is not an endpoint of admin.openapi.yaml", path)
	}
	op, ok := s.paths[tpl][strings.ToLower(method)]
	if !ok {
		return fmt.Errorf("conformance: %s %s is not an operation of admin.openapi.yaml", method, tpl)
	}
	rb, ok := op.(map[string]any)["requestBody"]
	if !ok {
		if len(bytes.TrimSpace(body)) > 0 {
			return fmt.Errorf("conformance: %s %s takes no body", method, tpl)
		}
		return nil
	}
	sch := s.resolve(rb).(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"]
	if err := s.validate(sch, body); err != nil {
		return fmt.Errorf("conformance: %s %s request body violates the contract:\n%w", method, tpl, err)
	}
	return nil
}
