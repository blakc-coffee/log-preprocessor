# integration

`docs/integration.md` as code. `make integrate STEP=1|2|4|5|all` runs the gates of a linking step against a running data
plane; `cmd/integrate` is the CLI, `Step1`, `Step2`, `Step4`, `Step5` the library.

| Step | Gates |
|---|---|
| 1 ingest -> vault -> parse | nothing dropped (events + quarantined == vault == manifest); every event's served bytes re-hash to `raw_sha256` and agree with the manifest; every `expect=parse` record has exactly one event; every unparsed record is quarantined byte-exact; lineage proofs verify **independently** (the leaf is recomputed from the record the API served, then the RFC 9162 inclusion and the chain link); unsealed records say so; `vault verify --deep` |
| 2 quarantine -> approve -> replay | before: source fully quarantined; dry-run thresholds; approve returns a replay job; the replay finishes with 0 failures; the quarantine drains; events are current and from the approved parser; a second replay creates no duplicates |
| 4 sidecar | exactly one alert (score >= 0.6, renamed keys named) and one patch proposal of the active version with a passing dry-run; waiting adds nothing |
| 5 identity | >= 99% users correct; 100% across reassignment; no user invented in the gaps; the timeline shows carol then heidi without overlap |

## What proves the checks

`plane_test.go` builds a "perfect data plane": the sample corpus through a real `memvault`, events carrying exactly the
manifest's values, real Merkle proofs. `checks_test.go` requires it to pass, then breaks it one way at a time (about 40
defects: a missing or duplicated event, a wrong address, an altered byte, a quarantined record lost, a flipped proof bit,
a changed `received_at` or origin, a wrong chain hash, a stale patch, a duplicate proposal, ...) and requires **the
gate written for that defect** to fail. `http_test.go` serves the plane over HTTP, runs the steps through the real client,
and corrupts single responses to prove contract violations are reported.

Limits: `/admin/samples` has a `limit` and no cursor, so at most 500 quarantined records per source are read. The perfect
plane is not the data plane; the first real run will find things this could not.
