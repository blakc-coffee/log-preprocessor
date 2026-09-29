# Integration checklist (Phase 2 linking)

Run in order. A step passes only when its gate command exits 0 and prints what is listed. A failure goes back to the
owning workstream with the failing command and the expected output, and the checklist stops there: later steps depend on
earlier ones. Status column is as of this writing; "not yet" means the owning workstream has not delivered.

**The gates for steps 1, 2, 4 and 5 are executable**: `make integrate STEP=1` (or `2`, `4`, `5`, `all`) runs them against
the data plane on `--admin` (default `127.0.0.1:9000`) and exits 0 only if every gate passes. Every response is also
validated against `admin.openapi.yaml`. Step 3 (sinks) is Packaging's and step 6 is a walk-through. The checks live in
`contracts/integration/`; each gate was proven able to fail (see its tests).

Prerequisite for every step: `make check` green on `master`, and `make contract-test` green.

| # | Link | Owner of a failure | Status |
|---|---|---|---|
| 1 | ingest -> vault -> parse/normalize on the golden corpus | Ingestion, Parsing | vault and ingest exist; `cmd/dataplane` not yet |
| 2 | quarantine -> approve -> replay with `palo_alto_unknown.log` | Parsing, Frontend | not yet |
| 3 | sinks and measured compression | Packaging | not yet |
| 4 | intelligence sidecar on live quarantine with `fortinet_drift.log` | Contracts, Parsing | sidecar not yet (starts after Gate 0) |
| 5 | identity resolution into the pipeline | Contracts, Parsing | resolver not yet (starts after Gate 0) |
| 6 | UI on the real admin API | Frontend, Parsing | not yet |

## 1. Ingest to vault to parse and normalize

```sh
make build
./bin/ingestd --config configs/ingest.dev.yaml --once &      # or: scripts/send_samples.sh
./bin/dataplane --config configs/dataplane.dev.yaml           # Parsing
```

Gates, all required:

- Every record in `testdata/sample/manifest.json` with `expect: parse` yields a `NormalizedEvent` whose `src_endpoint.ip`,
  `dst_endpoint.ip`, ports, protocol and `time` equal the manifest's `expected_*` (null means unknown, never a failure).
- Every record with `expect: unknown_format` or `raw_only` is in quarantine, not dropped, and `vaultctl get <id> --raw`
  hashes to the manifest's `expected_sha256`.
- `vaultctl verify --deep` exits 0.
- `GET /admin/lineage/{event_id}` for a sealed record returns a proof that verifies against `testdata/merkle_vectors.json`
  rules (RFC 9162) with no help from the data plane; for an unsealed record, `sealed:false, proof:null`.
- `GET /admin/telemetry` counts: `events_total + quarantined_total == vault.records`.
- Every response validates against `contracts/admin.openapi.yaml` (Parsing's tests do this on real responses).

## 2. Quarantine, approve, replay

1. Feed `palo_alto_unknown.log`. Expect: all records quarantined, `quarantine_open == 50` (sample corpus).
2. Post the reference parser (`tests/testdata/parsers/palo_alto_traffic.yaml`, Packaging) via `POST /admin/parsers/dryrun`.
   Expect `match_rate >= 0.95`, `mean_coverage >= 0.9`.
3. `POST /admin/parsers/approve` with `replay:true`. Expect `200 {parser_id, version, replay_job_id}`, then
   `GET /admin/replay/{job}` reaches `done` with `failed == 0`.
4. Expect `quarantine_open == 0`, and the replayed events carry `parser_id: palo_alto_traffic`, `current: true`.
5. Approve the same proposal again with a stale `base_version`: expect `409` and the proposal `stale`.
6. Replay twice: the second run creates no duplicate events (idempotent by `event_id`).

## 3. Sinks and compression

Parquet written from the golden corpus reads back to the same rows; the OCSF/ECS/HEC/CEF exporters round-trip a
fixed sample; the compression table in `benchmarks/results/` names the corpus, the codec and the hardware. A ratio quoted
anywhere must appear there.

## 4. Intelligence sidecar on live quarantine

1. Run the data plane with `fortinet.log` ingested (baseline), then feed `fortinet_drift.log`.
2. Expect within `poll_interval * 2`: a `DriftAlert` with `score >= 0.6` and signals naming `srcip->src`-style renames;
   the alert for a fresh sample of `fortinet.log` scores below 0.1.
3. Expect a `Proposal` of `kind: patch`, `base_version` equal to the active version, dry-run `match_rate >= 0.95`.
4. A second loop pass creates no duplicate alert and no duplicate proposal.
5. Approve it in step-2 fashion; `fortinet_drift.log` events appear, quarantine drains.
6. `python -m ulpf_intel --egress-check` exits non-zero only if an outbound attempt succeeded, so inside the container
   under `--network none` it must exit 0.

## 5. Identity into the pipeline

Ingest `dhcp.log`, `radius.log`, `openvpn.log` first, then `identity_firewall.log`. Against
`testdata/identity_truth.json` and each firewall record's `expected_user`:

- at least 99% correct overall;
- 100% correct for records on either side of an IP reassignment (10.1.4.7 alice -> frank, 10.1.4.8 bob -> grace, 10.1.4.9 carol -> heidi);
- `null` (no user entity) for records in the gaps between a release and the next bind;
- `GET /admin/identity/timeline?ip=10.1.4.9` shows carol then heidi with no overlap;
- a fact delivered late invalidates only the window it changes (`Invalidation`), and re-enrichment corrects exactly those events.

## 6. UI on the real admin API

Run `scripts/demo.sh` (Packaging) and walk the beat sheet in `presentation/demo_video_script.md`: live events, the split
view with the browser-side SHA-256 match, the Merkle proof and chain status, drift -> proposal -> approve -> replay,
the identity timeline, the telemetry numbers. Every screen loads with no request leaving `127.0.0.1`.
