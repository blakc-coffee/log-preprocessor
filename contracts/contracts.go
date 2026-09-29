// Package contracts embeds the machine-readable contract files so other
// workstreams can import them: the mock admin server and the packaging tests
// use the goldens, and the conformance tests use the schema. //go:embed cannot
// reach parent directories, which is why this package lives at contracts/.
//
// Files here are owned by the Contracts workstream and change only through a
// contract PR (see CODEOWNERS and docs/integration.md).
package contracts

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed golden/*.json
var golden embed.FS

// SchemaJSON is uef.schema.json (JSON Schema 2020-12).
//
//go:embed uef.schema.json
var SchemaJSON []byte

// DSLExamples holds the five complete parser examples (dsl/examples/*.yaml)
// that parser_dsl.md specifies. They are what the goldens are derived from and
// what Parsing's engine tests can run against.
//
//go:embed dsl/examples/*.yaml
var DSLExamples embed.FS

// OpenAPIYAML is admin.openapi.yaml (OpenAPI 3.1).
//
//go:embed admin.openapi.yaml
var OpenAPIYAML []byte

// GoldenSchema maps each golden file (without .json) to the name of the
// definition in uef.schema.json it must validate against.
var GoldenSchema = map[string]string{
	"event_asa_built":      "normalized_event",
	"event_asa_deny":       "normalized_event",
	"event_fortinet":       "normalized_event",
	"event_suricata_alert": "normalized_event",
	"event_with_entities":  "normalized_event",
	"identity_dhcp_bind":   "normalized_event",
	"quarantine_list":      "quarantine_list",
	"drift_alert":          "drift_alert",
	"proposal_palo_alto":   "proposal",
	"dryrun_result":        "dryrun_result",
	"lineage_sealed":       "lineage",
	"lineage_pending":      "lineage",
	"telemetry":            "telemetry",
	"replay_job":           "replay_job",
	"raw_response":         "raw_response",
	"parsers_list":         "parsers_list",
	"error":                "error_response",
}

// Golden returns the named golden file, for example Golden("event_asa_built").
func Golden(name string) ([]byte, error) {
	b, err := golden.ReadFile("golden/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("contracts: no golden %q", name)
	}
	return b, nil
}

// GoldenNames lists every embedded golden, sorted.
func GoldenNames() []string {
	ents, _ := golden.ReadDir("golden")
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}
