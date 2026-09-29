# ULPF System Specification
## Universal Log Pre-processing Framework · SIH26156 · NTRO
### Version 1.1.0 · Owned by the Contracts workstream · changes only through a contract PR

Supersedes the 1.0.0 draft. The draft described an earlier design (per-source zstd NDJSON vault, `/api/*` on `:9000`,
syslog on `:514`, a ring-buffer store, `event_id = sha256[:8]`, single-regex parsers, "losslessness is not render-back").
None of that is what was built or what the PRDs specify; it is replaced here so the specification, the contract
(`pkg/types`, `contracts/`) and the code say the same thing. Where they ever disagree again, the contract files win,
then this document, and the disagreement is a bug to fix in whichever is wrong.

Companion documents: `prd/PRD_MASTER_ulpf.md` (what and why), `prd/PRD_00_index_and_roster.md` (ownership, gates,
decisions D1-D10), `docs/vault-format.md` (the vault on disk), `contracts/parser_dsl.md`, `contracts/admin.openapi.yaml`,
`contracts/uef.schema.json`, `docs/integration.md` (linking checklist).

---

## 1. Scope

Perimeter-device logs (firewall, IDS/IPS, proxy, VPN, WAF) in any format, plus DHCP, RADIUS and VPN logs as identity
sources. ULPF keeps the raw event byte-exact, produces an OCSF-aligned normalized event with full lineage back to the
raw bytes, proposes parsers for formats it has not seen, and resolves IP-at-time-T to user and host.

Out of scope in v1: multi-node vault, clock-skew inference, authentication on the admin and control APIs (loopback
only, section 9), encryption at rest, retention, any LLM on the required path.

## 2. Ports (locked)

| Port | Service | Owner | Published on host |
|---|---|---|---|
| 5514/udp+tcp | Syslog | Ingestion | yes, loopback by default |
| 6514/tcp | TLS syslog | Ingestion | yes, loopback by default |
| 8080/tcp | HTTP stream ingest | Ingestion | yes, loopback by default |
| 9100/tcp | Prometheus `/metrics`, `/healthz` | Parsing (`cmd/dataplane`) | no |
| 9000/tcp | Admin API (`contracts/admin.openapi.yaml`) | Parsing | no, loopback only |
| 8000/tcp | Control plane: UI and control API | Frontend | yes, `127.0.0.1` only |

No component binds any other port. Ports below 1024 are never used, so nothing needs a capability.

## 3. Data flow

```
source ─► [Ingest: frame, sniff] ─► [Vault: WAL, group commit, Merkle seal] ─► [Parse: DSL extractors]
              record boundaries        durable BEFORE anything downstream          │
              and nothing else                                                     ├─ fail ─► [Quarantine] ─┐
                                                                                   ▼                        │
                                                                    [Normalize: OCSF, unmapped, coverage]   │
                                                                                   │                        │
                                                                    [Identity enrich: Resolver.ResolveAt]   │
                                                                                   ▼                        │
                                                                  [Event store] + [Sinks: Parquet, OCSF,     │
                                                                                   ECS, HEC, CEF]           │
                                                                                                            ▼
   [Intelligence sidecar, Python] ◄── admin API: samples, quarantine ── drift, typing, proposal, dry-run
                 │ proposes only
                 ▼
   [Control plane: registry, review queue] ── human approval ──► data plane activates ──► replay from the vault
```

Invariants, each enforced by a test in the owning workstream:

1. Raw bytes are never modified; raw lives only in the vault and everything else holds a `RecordID`.
2. Nothing goes downstream before the vault reports durable (vault-before-forward).
3. Every queue is bounded and every wire-read length is capped. Overload back-pressures; it never drops silently.
4. A failed fsync is never retried; the vault enters its terminal `ErrFailed` state and `/healthz` returns 503.
5. The intelligence plane only proposes. The registry, after human approval, is the only thing that changes what the
   data plane runs.

## 4. The contract

| Artifact | Purpose |
|---|---|
| `pkg/types/` | Go types and interfaces (`Vault`, `Sink`, `Resolver`), the integrity-flag constants. String wire forms for `OriginKind` and `Terminator` (`json.go`). |
| `contracts/uef.schema.json` | JSON Schema 2020-12 for every payload that crosses a boundary. |
| `contracts/admin.openapi.yaml` | OpenAPI 3.1 for every admin endpoint; payloads are `$ref`s into the schema. |
| `contracts/parser_dsl.md`, `contracts/dsl/examples/` | The normative parser DSL and five complete examples checked against the fixtures. |
| `contracts/golden/` | One realistic, mutually consistent example per payload, generated from real fixtures and real Merkle output (`make contract-golden`). |
| `contracts/ocsf/` | Vendored OCSF 1.1.0 subset. |

`make contract-test` validates every golden against the schema, decodes each into its Go type with unknown fields
refused, verifies the sealed golden's inclusion proof with the production `merkle` package, checks the OpenAPI file for
dangling references and missing endpoints, runs every DSL example against the fixture corpus and the manifest's
ground truth, and fails if the checked-in goldens differ from a fresh generation. The schema is also proven able to
reject: a table of deliberate violations must each be refused.

Conventions across all JSON: snake_case keys; RFC 3339 UTC timestamps with nanosecond precision allowed; lowercase hex
for hashes; standard base64 for raw bytes; IPs as strings; OCSF `time` in epoch milliseconds.

**Event identity (D1).** `event_id = "<RecordID>.<parser_id>@<parser_version>"`, so the same line received twice stays
two events and a re-normalization by a newer parser is a new event that supersedes (`current: false` on the old one).
**Template (D9).** `template_id = "<parser_id>/<extractor_id>"`.

## 5. Vault (summary)

Global, single-node, hash-chained, append-only. Records get a global monotonic `RecordID` (D3). Segments seal under an
RFC 6962 Merkle root and are linked by a chain hash (`SHA-256(0x02 || prev || root || segment_be64 || count_be64)`).
Seal order is footer, fsync, ledger, fsync. "Sealed" means a valid footer is on disk and nothing else. Full format,
recovery rules and tamper matrix are in `docs/vault-format.md`.

Normalization happens before a record's segment is sealed, so a normalized event carries `record_id` and `segment`
only; the inclusion proof is resolved lazily through `GET /admin/lineage/{event_id}` (D2), which returns `sealed: false`
and `proof: null` until the segment seals.

Verification is available to anyone: an RFC 9162 inclusion proof needs only the leaf, the path and the root. An
inclusion proof does **not** by itself bind the tree size; the segment root held by the verifier does.

## 6. Parsing, quarantine, replay

Parsers are DSL documents (`contracts/parser_dsl.md`): ordered extractors of kind `regex` (RE2), `kv`, `json`, `csv`,
`cef`, `leef`; typed `map` entries onto OCSF paths; everything unmapped kept under its own name; an optional
render-back template; byte-accounting coverage. First extractor to succeed wins. A record no parser accepts goes to
quarantine with its stage and reason; its raw bytes are safe in the vault.

Replay re-reads records from the vault and re-normalizes them under the currently active parser set. It is idempotent by
`event_id`. Only the data plane owns the active set (D10): `data/parsers.d/<id>/<version>.yaml` plus `active.json`.

## 7. Intelligence sidecar

Python, off the hot path, opens no listener. It reads samples and quarantine through the admin API only, scores
structural drift, types unknown fields from value shapes, generates a proposal (new parser or patch), validates it with
`POST /admin/parsers/dryrun`, and posts it. It never touches the vault, the parser store or the pipeline. A proposal that
misses its acceptance thresholds is still posted, flagged, never silently dropped. No LLM in the baseline.

## 8. Identity

Facts (`IdentityFact`) produced by identity-source parsers via the DSL `identity:` block are the only input (D8).
The resolver keeps time-bounded claims per IP: a `bind` opens one, a `release` or a newer `bind` of the same kind
closes it, unclosed claims expire by TTL. `ResolveAt(ip, t)` returns entities valid at `t` and **nothing** when no
claim covers `t`: it never guesses and never carries a user across a release. A fact arriving late that changes answers
already given yields an `Invalidation` window so stored events can be re-enriched. Persistence is derived data,
rebuildable by replaying identity-source records.

## 9. Threat model

Assets: the raw record (evidence), the chain of custody (proofs), the parser set (what the system believes), the
availability of ingest.

| Threat | Mitigation | Residual |
|---|---|---|
| **Log injection**: attacker-controlled text forges fields (`msg="x srcip=1.2.3.4"`) or crafts regex-DoS input | RE2 only (linear time); the kv tokenizer is single pass and never re-scans a value for keys; field, key, value and depth limits with integrity flags instead of crashes; raw payload is never printed unescaped | A parser author can still map the wrong field; render-back and dry-run catch most of it |
| **Log flooding / DoS** | Bounded queues everywhere; back-pressure, not drops; length caps on every wire read; UDP kernel-drop counter exposed | UDP delivery is best-effort by nature; a saturated disk stops ingest, loudly |
| **Tampering after the fact** (edit, delete, reorder, truncate) | Merkle seal per segment and a chain across segments; a 10-row tamper matrix, every row detected and located to a segment | Tamper-*evident*, not tamper-proof: someone with write access to the whole directory can rewrite it consistently. Only an externally held chain head (`vaultctl head`) defeats that |
| **Insider approves a bad parser** | Proposals need a named human approver; approval history is kept; rollback is one call; replay is reproducible from the vault | The reviewer is trusted |
| **Compromised intelligence sidecar** | Propose-only; admin API is the sole interface; dry-run runs in the data plane with no side effects | A malicious proposal still needs a human |
| **Admin API abuse** | Loopback bind only, not published to the host | **No authentication in v1.** Anything running on the host can call it, including approve. Documented limitation, not a mitigation |
| **Exfiltration / supply chain** | No network at runtime, vendored dependencies, `--network none` self-test, egress probes | The synthetic corpus proves nothing about a real network |
| **Power loss** | fsync discipline, group commit, failed fsync is terminal | Crash tests kill the process; they do not cut power. Not claimed |

## 10. Losslessness, defined

The claim is **byte-exact raw preservation**: for any ingested record, at any later time, `Vault.Get(RecordID)` returns
exactly the bytes that arrived (invalid UTF-8, NULs, CR/LF, empty payloads and 1.5 MiB records included), the terminator
is recorded rather than stripped, and `SHA-256(raw)` equals `raw_sha256` on the event. Recomputable in the browser.

Two further mechanisms show nothing was dropped *in normalization*, which is a transformation and is **not** claimed to be
lossless: `unmapped` keeps every capture no mapping reads, and `coverage` accounts bytes as mapped, unmapped, constant
or uncovered. **Render-back** (regex and kv parsers) re-serializes the typed values through the extractor's template and
compares with the raw record; a mismatch sets `render_back_mismatch`. It is a strong check that the mapping did not
mis-assign fields, and it applies only to template parsers.

## 11. OCSF alignment

Version 1.1.0, vendored in `contracts/ocsf/`. v1 maps every perimeter event to Network Activity (4001), Suricata
alerts included, with alert detail in `unmapped`; a Detection Finding mapping is a possible later stretch. Identity-source
events map to DHCP Activity (4004). Core 4001 fields populated: `class_uid`, `category_uid`, `activity_id`, `type_uid`,
`time`, `severity_id`, `action_id`, `disposition_id`, `src_endpoint`, `dst_endpoint`, `connection_info.{protocol_num,
protocol_name}`, `traffic.*`, `metadata.*`, `unmapped`. Enum values are pinned from the vendored files, not memory
(for example DHCP `activity_id`: 5 Ack, 7 Release).

## 12. Requirement traceability (PS a-k)

| PS req | Requirement | Where it is built and how it is shown |
|---|---|---|
| (a) No information loss | Byte-exact raw preservation; coverage and `unmapped` for normalization | Vault: round-trip of 7598 records across 13 fixtures, before and after compaction, 200 kill -9 cycles with 0 acknowledged records lost. Parsing: coverage |
| (b) Extract source attributes | DSL extractors: regex, kv, json, csv, cef, leef | `parser_dsl.md`; examples checked against fixtures |
| (c) Common taxonomy | OCSF 1.1.0 subset, `unmapped` | `contracts/ocsf/`, goldens |
| (d) Traceability | `record_id` + `segment` on every event; lineage endpoint returns a real inclusion proof and chain head | `GET /admin/lineage/{id}`, `lineage_sealed.json` verified by production merkle code |
| (e) Plug-and-play onboarding | DSL + drift detection + typed, dry-run-validated proposals + approval + replay | Intelligence sidecar; `dryrun`, `approve`, `replay` |
| (f) Unified visibility | One schema across vendors; lineage explorer | Frontend |
| (g) SIEM / data lake | Parquet, OCSF JSON, ECS, HEC, CEF | Packaging (sinks) |
| (h) AI/ML-ready | Typed OCSF fields, entities, entity graph, dictionary-encoded Parquet | Identity; sinks |
| (i) Reduced parser effort | DSL, proposal generation, acceptance thresholds | Sidecar; Parsing |
| (j) Air-gapped | Vendored deps, offline bundle, `--network none`, egress probes | Packaging |
| (k) Container | Multi-stage, non-root, slim images, compose | Packaging |

## 13. Claims

**Supported and measured:** byte-exact round-trip of the fixture corpus, before and after compaction; 0 acknowledged
records lost across 200 process-kill cycles; 10 of 10 tamper rows detected; machine-independent compression ratios.

**Not claimed:** lossless *normalization*; power-loss durability; tamper-*proof* storage; UDP delivery guarantees; any
throughput, latency or memory figure (none has been measured on a target machine; Gate 1's recorded-benchmark and RSS
items remain unmet, see `DECISIONS.log`); billions of events per day (only ever a labelled projection). The corpus is
synthetic and is labelled as such wherever it appears.

## 14. Gates

| Gate | Condition |
|---|---|
| 0 | `pkg/types` compiles; schema, OpenAPI, DSL, goldens, OCSF subset present; `make contract-test` green; decisions D1-D10 answered or defaulted; design approved |
| 1 | Every workstream passes its own tests standalone; `app.New` and `server.New` exist; real vault and ingest exist |
| 3 | All tests pass inside the container offline (`verify_airgap.sh` exit 0) |
| Submission | README, five slides, two-page architecture document, demo script and video, every number traceable to a results file |

Contract changes after Gate 0 go through a PR that updates Go types, schema, OpenAPI, goldens and the relevant PRD text
together, passes `make contract-test`, and is approved by the user.
