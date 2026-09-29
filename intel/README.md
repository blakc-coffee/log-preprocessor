# intel: the intelligence sidecar

Propose-only, off the hot path, opens no listener. It reads samples and quarantine through the admin API
(`contracts/admin.openapi.yaml`), scores structural drift, types unknown fields from value shapes, generates a parser
proposal, asks the data plane to dry-run it, and posts it for a human. It never touches the vault, the parser store
or the pipeline, and no code path can call approve, reject, rollback or replay (a test asserts the request log).

```sh
cd intel
python3.13 -m venv .venv && . .venv/bin/activate          # 3.11+ required
pip install -e '.[test]'
pytest                                                     # 100+ tests, warnings are errors

python -m ulpf_intel --admin http://127.0.0.1:9000 --state-dir ./intel-state   # the loop
python -m ulpf_intel --once                                # one pass and exit
python -m ulpf_intel --healthcheck                         # GET /healthz; exit 0 healthy, 1 not (no shell in the image)
python -m ulpf_intel --egress-check                        # exit non-zero if ANY outbound attempt succeeds
```

`--egress-check` is the air-gap probe: a public DNS lookup and TCP connects to 1.1.1.1:443 and 8.8.8.8:53, 2 s each.
All three are expected to fail; on a machine with internet access it correctly reports `FAIL`.

## What each module does

| Module | |
|---|---|
| `fingerprint.py` | Structural fingerprint of raw lines (delimiters, key set, value shapes, Drain3 templates) and the drift score with human-readable signals (`keys renamed: srcip->src`). |
| `typer.py` | Semantic typing of a column from its values: IPs, ports, timestamps (with the Go layout), protocol, action, user names. Headerless columns supported. Source vs destination disambiguation. Abstains below 0.6. |
| `propose.py` | Proposal generators: `propose_csv` (headerless CSV), `propose_kv_patch` (drifted kv parser -> patch), `propose_json` (routes on `event_type`), `propose_text` (Drain3 templates -> anchored RE2 with typed named groups). |
| `dsl_eval.py` | A small reference evaluator of the parser DSL. NOT the engine: it derives the `tests:` vectors of a proposal and gives a local pre-check. |
| `validate.py` | Acceptance thresholds, RE2-safety check (Python's `re` accepts lookaround the Go engine refuses), local dry-run. |
| `client.py`, `state.py`, `loop.py`, `egress.py`, `__main__.py` | The admin client (bounded retries), JSON baselines, the loop, the air-gap probe, the CLI. |
| `models.py` | Pydantic mirrors of the contract types (`extra="forbid"`). |

## The loop, per source

1. Fetch recent samples (parsed and quarantined). Fewer than `min_samples` (50): do nothing.
2. Compare with the stored baseline. No baseline and a high quarantine rate: "never parsed".
3. Score >= 0.35, or quarantine rate > 0.2: post **one** `DriftAlert` (reused while open).
4. At least `min_cluster` (50) quarantined records of one shape: generate a proposal, dry-run it via
   `POST /admin/parsers/dryrun`, post it. One proposal per alert.
5. A proposal that misses its thresholds (`match_rate >= 0.95`, `mean_coverage >= 0.9`) is still posted, with
   `acceptance:` warnings, so the UI shows it as needing edits. It is never dropped.
6. The baseline is refreshed only from healthy passes, never while the source is drifting.

## Measured (fixtures, reference evaluator; the data plane's dry-run is authoritative and not built yet)

| Check | Result |
|---|---|
| Drift, `fortinet.log` vs a fresh half of itself | 0.00 (bar < 0.1) |
| Drift, `fortinet.log` vs `fortinet_drift.log` | 0.54 structure only, 0.63 with the drifted file's quarantine rate 0.94 (bar >= 0.6 holds only with the quarantine term) |
| Typing, `palo_alto_unknown.log` | 7 of 7 manifest fields typed to the right column, all values matching (bar 90%) |
| Proposal, Palo Alto CSV | 500/500 records parsed, manifest reproduced |
| Proposal, Fortinet drift patch | old parser 0/500, patch 500/500 |
| Proposal, Suricata JSON | 2000/2000 |
| Proposal, Cisco ASA text | 2000/2000 parsed; source/destination agrees with the manifest for 1458/2000 (see below) |

## Known limits

- **ASA direction.** The fixture manifest orients 302013/302014 with the well-known port on the *source*; the real ASA does
  the opposite, and 302015/302016 are the other way round, so no rule agrees with all of it. The proposal follows the evidence
  (cue words, `->`, port behaviour), flags weak decisions with the other path as an alternative, and the reviewer confirms.
  A test pins the exact split.
- A brand-new **kv** source (no parser to patch) is not generated; nor are CEF/LEEF proposals (P1) or the optional LLM step (P2).
- The reference evaluator has no render-back, so `render_back_ok_rate` comes only from the data plane's dry-run.
- Timestamps without a zone use `--timezone` (default `+00:00`) and every such proposal says so in its warnings.
- "Stale" marking of proposals whose base version moved is done by the data plane on approve (`409`); the sidecar only avoids re-proposing.
