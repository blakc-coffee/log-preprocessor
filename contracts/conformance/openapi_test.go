package conformance_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blakc-coffee/sluice/contracts"
	"github.com/blakc-coffee/sluice/contracts/conformance"
)

func golden(t *testing.T, name string) []byte {
	b, err := contracts.Golden(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every golden is a documented response of the endpoint that serves it, so the OpenAPI file, the schema and the
// goldens cannot drift apart. This is the same call Parsing's handler tests make on real responses.
func TestGoldensAreValidResponsesOfTheirEndpoints(t *testing.T) {
	for _, c := range []struct {
		golden, method, path string
		status               int
	}{
		{"event_asa_built", "GET", "/admin/events/1.cisco_asa@1.0.0", 200},
		{"event_with_entities", "GET", "/admin/events/7.cisco_asa@1.0.0", 200},
		{"raw_response", "GET", "/admin/events/1.cisco_asa@1.0.0/raw", 200},
		{"lineage_sealed", "GET", "/admin/lineage/1.cisco_asa@1.0.0", 200},
		{"lineage_pending", "GET", "/admin/lineage/10.fortinet@1.0.0", 200},
		{"quarantine_list", "GET", "/admin/quarantine", 200},
		{"drift_alert", "POST", "/admin/drift", 201},
		{"proposal_palo_alto", "POST", "/admin/proposals", 201},
		{"dryrun_result", "POST", "/admin/parsers/dryrun", 200},
		{"replay_job", "GET", "/admin/replay/replay-01", 200},
		{"parsers_list", "GET", "/admin/parsers", 200},
		{"telemetry", "GET", "/admin/telemetry", 200},
		{"error", "GET", "/admin/events/999.x@1.0.0", 404},
	} {
		t.Run(c.golden, func(t *testing.T) {
			if err := conformance.ValidateResponse(c.method, c.path, c.status, "application/json", golden(t, c.golden)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRequestBodiesAreChecked(t *testing.T) {
	if err := conformance.ValidateRequest("POST", "/admin/drift", golden(t, "drift_alert")); err != nil {
		t.Fatal(err)
	}
	if err := conformance.ValidateRequest("POST", "/admin/parsers/approve", []byte(`{"yaml":"id: x","approved_by":"a","comment":"","replay":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := conformance.ValidateRequest("POST", "/admin/parsers/approve", []byte(`{"yaml":"id: x","comment":""}`)); err == nil {
		t.Fatal("a request missing approved_by and replay was accepted")
	}
	if err := conformance.ValidateRequest("GET", "/admin/telemetry", []byte(`{}`)); err == nil {
		t.Fatal("a GET with a body was accepted")
	}
}

// The check must be able to say no.
func TestValidateResponseRejects(t *testing.T) {
	ev := string(golden(t, "event_asa_built"))
	cases := []struct {
		name, method, path string
		status             int
		ct, body, want     string
	}{
		{"an undocumented status", "GET", "/admin/telemetry", 418, "application/json", `{}`, "does not document"},
		{"an unknown endpoint", "GET", "/admin/nope", 200, "application/json", `{}`, "not an endpoint"},
		{"an unknown method", "DELETE", "/admin/telemetry", 200, "application/json", `{}`, "not an operation"},
		{"a missing required field", "GET", "/admin/events/1.cisco_asa@1.0.0", 200, "application/json", strings.Replace(ev, `"event_id"`, `"event_idX"`, 1), "violates"},
		{"a non-JSON body", "GET", "/admin/telemetry", 200, "application/json", `not json`, "not JSON"},
		{"an undocumented content type", "GET", "/admin/telemetry", 200, "text/html", `<html>`, "not documented"},
		{"an error in the wrong shape", "GET", "/admin/events/1.x@1.0.0", 404, "application/json", `{"error":"nope"}`, "violates"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := conformance.ValidateResponse(c.method, c.path, c.status, c.ct, []byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
	// literal segments win over parameters: dryrun is not a parser id
	var dry map[string]any
	_ = json.Unmarshal(golden(t, "dryrun_result"), &dry)
	if err := conformance.ValidateResponse("POST", "/admin/parsers/dryrun", 200, "application/json", golden(t, "dryrun_result")); err != nil {
		t.Fatal(err)
	}
}

func TestTextAndBinaryResponsesAreNotForcedThroughJSONSchema(t *testing.T) {
	if err := conformance.ValidateResponse("GET", "/admin/parsers/fortinet/versions/1.0.0", 200, "text/yaml; charset=utf-8", []byte("id: fortinet\n")); err != nil {
		t.Fatal(err)
	}
	if err := conformance.ValidateResponse("GET", "/admin/events/1.a@1.0.0/raw", 200, "application/octet-stream", []byte{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
}
