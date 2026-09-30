package contracts_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/sluice/contracts"
)

// Every endpoint in PRD_CONTRACTS section 3 exists, and nothing is dangling:
// each $ref resolves and each example file exists. There is no OpenAPI
// validator in the module (no new dependency for this), so the checks that
// matter to consumers are done here.
func TestOpenAPI(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(contracts.OpenAPIYAML, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %v", doc["openapi"])
	}

	want := []string{
		"GET /admin/events", "GET /admin/events/{event_id}", "GET /admin/events/{event_id}/raw", "GET /admin/lineage/{event_id}",
		"GET /admin/quarantine", "GET /admin/samples", "POST /admin/drift", "GET /admin/drift", "POST /admin/proposals", "GET /admin/proposals",
		"GET /admin/proposals/{id}", "POST /admin/proposals/{id}/reject", "POST /admin/parsers/dryrun", "POST /admin/parsers/approve",
		"POST /admin/parsers/{id}/rollback", "GET /admin/parsers", "GET /admin/parsers/{id}/versions/{v}", "GET /admin/replay/{job_id}",
		"POST /admin/replay", "GET /admin/identity/resolve", "GET /admin/identity/timeline", "GET /admin/identity/graph",
		"GET /admin/vault/segments", "GET /admin/vault/verify", "GET /admin/telemetry", "GET /healthz",
	}
	paths := doc["paths"].(map[string]any)
	got := map[string]bool{}
	for p, item := range paths {
		for m, o := range item.(map[string]any) {
			got[strings.ToUpper(m)+" "+p] = true
			op := o.(map[string]any)
			if op["operationId"] == nil || op["responses"] == nil {
				t.Errorf("%s %s: operationId and responses are required", m, p)
			}
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing endpoint %s", w)
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("endpoint %s is in the OpenAPI file but not in PRD_CONTRACTS section 3", extra)
	}

	var uef map[string]any
	if err := json.Unmarshal(contracts.SchemaJSON, &uef); err != nil {
		t.Fatal(err)
	}
	uefDefs := uef["$defs"].(map[string]any)
	comps := doc["components"].(map[string]any)

	golden := map[string]bool{}
	for _, n := range contracts.GoldenNames() {
		golden[n] = true
	}

	var walk func(v any, at string)
	walk = func(v any, at string) {
		switch x := v.(type) {
		case map[string]any:
			if r, ok := x["$ref"].(string); ok {
				switch {
				case strings.HasPrefix(r, "uef.schema.json#/$defs/"):
					if uefDefs[strings.TrimPrefix(r, "uef.schema.json#/$defs/")] == nil {
						t.Errorf("%s: dangling %s", at, r)
					}
				case strings.HasPrefix(r, "#/components/"):
					parts := strings.Split(strings.TrimPrefix(r, "#/components/"), "/")
					if c, _ := comps[parts[0]].(map[string]any); c == nil || c[parts[1]] == nil {
						t.Errorf("%s: dangling %s", at, r)
					}
				default:
					t.Errorf("%s: unexpected ref %s", at, r)
				}
			}
			if e, ok := x["externalValue"].(string); ok {
				if n := strings.TrimSuffix(strings.TrimPrefix(e, "golden/"), ".json"); !golden[n] {
					t.Errorf("%s: example %s is not a golden file", at, e)
				}
			}
			for k, c := range x {
				walk(c, at+"/"+k)
			}
		case []any:
			for i, c := range x {
				walk(c, fmt.Sprintf("%s/%d", at, i))
			}
		}
	}
	walk(doc, "")

	// The API-local schemas are real JSON Schema, and can validate a payload.
	schemas := comps["schemas"].(map[string]any)
	c := jsonschema.NewCompiler()
	uefDoc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(contracts.SchemaJSON))
	_ = c.AddResource("uef.schema.json", uefDoc)
	for name, s := range schemas {
		b, _ := json.Marshal(s)
		sd, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := c.AddResource("api-"+name+".json", sd); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.Compile("api-" + name + ".json"); err != nil {
			t.Errorf("schema %s does not compile: %v", name, err)
		}
	}
}

// Every golden that a response example points at is used by some endpoint, so
// a golden nobody can reach is noticed.
func TestEveryGoldenIsDocumented(t *testing.T) {
	for _, n := range contracts.GoldenNames() {
		if !bytes.Contains(contracts.OpenAPIYAML, []byte("golden/"+n+".json")) {
			t.Errorf("golden %s is not referenced from admin.openapi.yaml", n)
		}
	}
}
