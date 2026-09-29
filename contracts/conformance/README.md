# conformance

The executable form of `contracts/parser_dsl.md` and `contracts/admin.openapi.yaml`, for the workstreams that
implement them. Import it from a test; there is nothing to run by hand.

## Parsing: check your engine against the DSL

```go
type adapter struct{}                                  // wrap your engine
func (adapter) Load(y []byte) (conformance.Parser, error) { ... }   // errors must name parser, extractor, field
func (p myParser) Parse(raw []byte, at time.Time) (*conformance.Result, error) { ... }  // (nil, nil) = quarantine

func TestDSLConformance(t *testing.T) {
    conformance.Run(t, adapter{}, conformance.Options{})
}
```

Three groups run as subtests:

| Group | What | Source |
|---|---|---|
| `cases` | 33 single-behaviour cases: empty means absent, exact enums, quoted kv values never re-scanned for keys, duplicate keys, extractor order, csv `min_columns`/`when`, json routing, year inference, time zones, unparseable time, load errors that name parser/extractor/field, coverage, render-back, limits, the `identity:` block | `cases.yaml` |
| `examples` | every `tests:` vector of the five parsers in `contracts/dsl/examples/` | the spec's own examples |
| `fixtures` | those parsers over `testdata/`, values checked against `manifest.json`; `fortinet_drift.log` must match nothing, and non-target lines (other ASA message ids, non-alert Suricata events) must not match | ground truth |

An engine that is not finished can pass `Options.Skip` (by case name); every skip is logged as a `SKIP`. A case that
fails names the spec section. If you believe a case is wrong, that is a spec bug: open a contract PR, do not skip it.

Cases marked `python: false` are the ones the sidecar's reference evaluator does not model (coverage, render-back,
limits, identity); they are for your engine only, so **they have not been run against any implementation yet.**
Expect to find mistakes in those first.

## Anyone with an admin API: check real requests and responses

```go
err := conformance.ValidateResponse("GET", "/admin/events/1.cisco_asa@1.0.0", 200, "application/json", body)
err := conformance.ValidateRequest("POST", "/admin/parsers/approve", body)
```

An endpoint, method, status or content type the OpenAPI file does not describe is an error, not a pass. Text and
binary responses (`text/yaml`, `application/octet-stream`) are checked for being documented, not for structure.

## How this was checked

`python_engine_test.go` drives the sidecar's Python evaluator (`intel/ulpf_intel/dsl_cli.py`) as an `Engine` and runs
the whole harness against it, so the cases and the harness agree with an independent implementation. It also runs five
deliberately broken engines (case-insensitive enum, keeps empty values, loads a lookaround, injects keys from values,
matches nothing or everything) and requires each to fail. It skips itself with a message when `intel/.venv` is absent.
