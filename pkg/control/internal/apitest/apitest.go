// Package apitest validates admin API responses against the frozen contract:
// contracts/admin.openapi.yaml for the envelope of each operation and
// contracts/uef.schema.json for the payloads it references. Test-only.
package apitest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/sluice/contracts"
)

// Contract holds the compiled schemas.
type Contract struct {
	c       *jsonschema.Compiler
	openapi map[string]any
	mu      sync.Mutex
	cache   map[string]*jsonschema.Schema
}

var (
	once   sync.Once
	shared *Contract
	err    error
)

// Load compiles the contract once per test binary.
func Load(t testing.TB) *Contract {
	t.Helper()
	once.Do(func() { shared, err = load() })
	if err != nil {
		t.Fatalf("apitest: %v", err)
	}
	return shared
}

func load() (*Contract, error) {
	schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(contracts.SchemaJSON))
	if err != nil {
		return nil, err
	}
	var y any
	if err := yaml.Unmarshal(contracts.OpenAPIYAML, &y); err != nil {
		return nil, err
	}
	// Round-trip through JSON so the schema library sees plain JSON types.
	b, err := json.Marshal(y)
	if err != nil {
		return nil, err
	}
	api, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("uef.schema.json", schema); err != nil {
		return nil, err
	}
	if err := c.AddResource("admin.openapi.json", api); err != nil {
		return nil, err
	}
	return &Contract{c: c, openapi: api.(map[string]any), cache: map[string]*jsonschema.Schema{}}, nil
}

func (k *Contract) compile(loc string) (*jsonschema.Schema, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.cache[loc]; ok {
		return s, nil
	}
	s, err := k.c.Compile(loc)
	if err != nil {
		return nil, err
	}
	k.cache[loc] = s
	return s, nil
}

// Def validates body against uef.schema.json#/$defs/<name>.
func (k *Contract) Def(t testing.TB, name string, body []byte) {
	t.Helper()
	s, err := k.compile("uef.schema.json#/$defs/" + name)
	if err != nil {
		t.Fatalf("apitest: compile %s: %v", name, err)
	}
	validate(t, s, name, body)
}

// Response validates body against the JSON schema the OpenAPI document gives
// for method + path template (for example "/admin/events/{event_id}") and
// status. It fails the test when the contract has no such response.
func (k *Contract) Response(t testing.TB, method, path string, status int, body []byte) {
	t.Helper()
	ptr, ok := k.responsePointer(strings.ToLower(method), path, status)
	if !ok {
		t.Fatalf("apitest: the contract defines no JSON response for %s %s -> %d", method, path, status)
	}
	s, err := k.compile("admin.openapi.json#" + ptr)
	if err != nil {
		t.Fatalf("apitest: compile %s: %v", ptr, err)
	}
	validate(t, s, method+" "+path, body)
}

func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// responsePointer finds the JSON pointer to the response schema, following a
// $ref into components/responses when the response is shared.
func (k *Contract) responsePointer(method, path string, status int) (string, bool) {
	paths, _ := k.openapi["paths"].(map[string]any)
	op, _ := paths[path].(map[string]any)
	o, _ := op[method].(map[string]any)
	resps, _ := o["responses"].(map[string]any)
	code := strconv.Itoa(status)
	r, ok := resps[code].(map[string]any)
	if !ok {
		return "", false
	}
	base := fmt.Sprintf("/paths/%s/%s/responses/%s", escape(path), method, code)
	if ref, ok := r["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/responses/")
		comps := k.openapi["components"].(map[string]any)["responses"].(map[string]any)
		r, base = comps[name].(map[string]any), "/components/responses/"+escape(name)
	}
	content, _ := r["content"].(map[string]any)
	if _, ok := content["application/json"]; !ok {
		return "", false
	}
	return base + "/content/application~1json/schema", true
}

func validate(t testing.TB, s *jsonschema.Schema, what string, body []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: response is not JSON: %v\n%s", what, err, trunc(body))
	}
	if err := s.Validate(v); err != nil {
		t.Fatalf("%s: response violates the contract: %v\n%s", what, err, trunc(body))
	}
}

func trunc(b []byte) string {
	if len(b) > 2000 {
		return string(b[:2000]) + "..."
	}
	return string(b)
}
