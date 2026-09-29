# Control plane (`pkg/control`, `cmd/control`)

Serves the UI and the control API on `127.0.0.1:8000`, in front of the data plane's admin API (`:9000`).
Owned by the Frontend workstream.

```
browser ──► :8000  server   /           embedded SPA (ui), SPA fallback, CSP, gzip
                            /api/*      control API ──► adminclient ──► :9000 admin (or mock)
                            /healthz    {"status":"ok","admin":"reachable|unreachable|unhealthy"}
                   registry SQLite: who approved, rejected or rolled back what
```

| Package | What it is |
|---|---|
| `server` | `server.New(Config)`: the `http.Handler` `cmd/ulpf` embeds. Pass-through routes plus the combined views below. |
| `adminclient` | Thin client for the admin API over HTTP, or in process against an `http.Handler` (`NewInProcess`). Classifies failures as `ErrUnreachable` / `ErrTimeout`. |
| `registry` | Approval history in SQLite (`modernc.org/sqlite`, pure Go). The row is written *before* the admin call and finished after it, so a crash leaves a `pending` row. |
| `mock` | The admin API in process, for `--mock`, UI development and tests. Raw lines go into a real `memvault`, so hashes and Merkle proofs are real and the browser verifier checks them for real. |
| `ui` | `go:embed` of `dist/` (filled by `make ui`) with SPA fallback and cache headers. |
| `internal/apitest` | Test helper: validates responses against `contracts/admin.openapi.yaml` and `contracts/uef.schema.json`. |

## Run

```sh
make control-demo                                   # UI + mock, http://127.0.0.1:8000
./bin/control --admin-url http://127.0.0.1:9000     # against cmd/dataplane
./bin/control --healthcheck                         # container health check, exit 0/1
```

Flags: `--listen`, `--admin-url`, `--mock`, `--mock-seed`, `--mock-tick`, `--registry-db`
(default `data/control/registry.db`, `:memory:` keeps nothing), `--healthcheck`.

Mock-only routes (with `--mock`): `POST /mock/advance` (steady → drift → approved → steady),
`POST /mock/tick?n=N`, `POST /mock/reset`, `GET /mock/state`.

## Control API

Pass-through, same shapes as the admin API: `GET /api/events`, `/api/events/{id}`, `/api/events/{id}/raw`,
`/api/lineage/{id}`, `/api/quarantine`, `/api/samples`, `/api/drift`, `/api/proposals`, `/api/replay/{job}`,
`/api/parsers`, `/api/identity/{timeline,resolve,graph}`, `/api/vault/{segments,verify}`, `/api/telemetry`.

Added by the control plane:

| Route | Behaviour |
|---|---|
| `GET /api/proposals/{id}` | `{proposal, active_yaml}`: `active_yaml` is the base version's YAML, for the diff. A wrapper rather than an extra field, because `proposal` is `additionalProperties: false` in the schema. |
| `POST /api/proposals/{id}/dryrun` | `{yaml?}`. Admin dry run of the (possibly edited) YAML on the proposal's own samples. |
| `POST /api/proposals/{id}/approve` | `{approved_by, comment, yaml?}`. Registry row, admin approve with `replay: true`, row finished. `409 stale_base_version` when the base moved. |
| `POST /api/proposals/{id}/reject` | `{by, comment}`. Recorded, then forwarded. |
| `GET /api/parsers/{id}/versions` | Admin versions merged with registry history. |
| `GET /api/parsers/{id}/versions/{v}` | Parser YAML (text/yaml). |
| `POST /api/parsers/{id}/rollback` | `{to_version, by, comment, replay}`. Recorded, then forwarded. |
| `POST /api/parsers/{id}/verify` | Dry run of the active version on recent samples of the source with the same id. No side effects. |
| `GET /api/history` | Registry rows, newest first; `?parser_id=`. |

Errors are `{"error":{"code","message"}}`. Stable codes: `admin_unreachable` (502), `admin_timeout` (504),
`bad_upstream` (502, the admin broke the contract), `stale_base_version` (409), `bad_request` (400).
Upstream admin errors keep their own status and code. Timeouts: 5 s, and 30 s for dry run, approve and deep verify.

**No authentication in v1.** Keep it on loopback. Approver names are recorded, not verified; the UI says so.
The PRD's optional `--auth-token-file` (P2) is not implemented.

## Test

```sh
make control-test    # go test -race ./pkg/control/... ./cmd/control/...
```

Covers: every mock admin route validated against the OpenAPI document (and the validator is itself
tested to reject bad bodies); the mock's proofs verified from raw bytes with the production `merkle`
package; the drift → approve → replay scenario; identity across the reassignment gap; determinism; the
approve flow's registry ordering, stale 409, reject and rollback rows; unreachable and slow admin;
SPA fallback (including event ids with dots), cache headers, CSP, gzip; health.

## Gaps in the admin contract, found while building this

Reported, not worked around in other workstreams' files:

- No endpoint to mark a quarantined record `ignored`, although the Parsing PRD says the status is set "by API".
- No event filter for "current versions only" (the PRD's explorer toggle), nor for a raw hash (the Figma's search placeholder).
- Samples carry no `raw_sha256`, so the queue can show a browser-computed digest but cannot verify a *quarantined* record against the vault; that becomes possible once it is normalized and has lineage.
- `parsers_list` has no source ids, so "Run verification" assumes the source id equals the parser id (true for the goldens and the mock).
- Identity evidence is a record id, and there is no way to open a record by id, only by event id.
