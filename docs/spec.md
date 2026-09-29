# ULPF System Specification
## Universal Log Pre-processing Framework · SIH26156 · NTRO
### Version 1.0.0 · Owned by Antigravity Pro · Do Not Modify Without Owner Approval

---

## 1. Scope

This document specifies the complete technical design of the Universal Log Pre-processing Framework (ULPF). It is the authoritative reference for all agents building this system.

---

## 2. Port Contract (Locked)

| Service | Bind Address | Protocol | Owner |
| :--- | :--- | :--- | :--- |
| Data Plane API | `127.0.0.1:9000` | HTTP/1.1 | Claude Code #1 |
| Control UI | `127.0.0.1:8000` | HTTP/1.1 | Claude Code #2 |
| Syslog UDP | `0.0.0.0:514` | UDP | Claude Code #1 |
| Syslog TCP | `0.0.0.0:514` | TCP | Claude Code #1 |

No agent may bind to any other port. The UI proxies all `/api/*` requests to `:9000`.

---

## 3. Data Flow

```
Raw log source (file / UDP / TCP / HTTP POST)
    │
    ▼
[Ingest Layer]
  - Frame log line boundaries (newline-delimited)
  - Record byte_offset_start, byte_offset_end
  - Compute SHA-256 of raw bytes
  - Base64-encode raw bytes
  - Assign event_id (sha256[:8] hex prefix)
  - Emit RawEvent{}
    │
    ▼ ← VAULT WRITE MUST COMPLETE BEFORE ANY FURTHER PROCESSING
[Vault Layer]
  - Persist RawEvent batch to disk as zstd-compressed NDJSON
  - Write SHA-256 → offset index
  - Only return success after fsync()
    │
    ▼
[Parser Engine]
  - Run detection_pattern against raw[:256]
  - If match: run full named-capture regex
  - If no match: route to Quarantine
  - On success: emit ParsedFields map[string]string + parserID
    │
    ├── PARSE FAILURE ──────────► [Quarantine Queue]
    │                               - Write QuarantinedEvent to disk
    │                               - failure_stage: no_matching_parser / regex_mismatch / type_error
    │                               - Raw bytes preserved in QuarantinedEvent.RawBytesBase64
    │
    ▼
[Normalizer]
  - Map ParsedFields → NormalizedEvent (OCSF v1.1.0 Network Activity)
  - Unmapped fields → NormalizedEvent.Unmapped{}
  - Normalize timestamps → UTC ISO-8601
  - Normalize severity → OCSF severity vocabulary
    │
    ▼
[In-Memory Event Store]
  - Ring buffer of last 50,000 NormalizedEvents
  - Indexed by: event_id, raw_sha256, source_id, action, severity
  - Served by GET /api/events
```

---

## 4. Vault Specification

### 4.1 On-Disk Layout

```
{vault_dir}/
  {source_id}/
    batch_00001.zst    ← zstd compressed, binary, contains NDJSON of RawEvent
    batch_00001.idx    ← text file: one entry per line, format: "{sha256} {byte_offset_in_batch}\n"
    batch_00002.zst
    batch_00002.idx
    ...
```

### 4.2 Batch Boundaries

A new batch file is started when:
- Current batch contains ≥ 256 RawEvents, OR
- Uncompressed batch size ≥ 10 MB

### 4.3 Compression

Library: `github.com/klauspost/compress/zstd`
Level: `zstd.SpeedDefault` (level 3)
Rationale: 3-5× compression ratio on log text. ~1.5 GB/s decode for fast replay.

### 4.4 Write Guarantee

`WriteBatch()` must call `file.Sync()` (fsync) before returning success.
If fsync fails, return the error. Never silently drop events.
The index file `.idx` must be written atomically: write to `.idx.tmp` then `os.Rename()`.

### 4.5 Retrieval

`RetrieveRaw(sha256 string) ([]byte, error)`:
1. Scan all `*.idx` files in `{vault_dir}/{source_id}/` to find the batch containing this sha256.
   (For production, maintain an in-memory index; for the demo, linear scan is acceptable.)
2. Open the corresponding `.zst` file.
3. Decompress and scan for the RawEvent with matching `raw_sha256`.
4. Base64-decode `RawBytesBase64`.
5. Return the exact original bytes.

---

## 5. Parser YAML Schema (Complete Reference)

```yaml
id: string            # Unique identifier, snake_case. e.g. "cisco_asa"
version: string       # Semantic version. e.g. "1.0.0"
description: string   # Human-readable description

# Fast pre-filter. Run against raw[:256] ONLY.
# Must be a valid Go stdlib regexp.
detection_pattern: string

# Full named-capture regex. Run only if detection_pattern matches.
# MUST use named captures: (?P<name>...) not (...)
# MUST be valid Go stdlib regexp (no lookaheads, no backreferences, no PCRE)
regex: string

# Maps named capture group values to OCSF NormalizedEvent fields.
# Dot notation: "src_endpoint.ip" → NormalizedEvent.SrcEndpoint.IP
mappings:
  severity: string              # capture group name
  action: string
  src_endpoint.ip: string
  src_endpoint.port: string     # auto-converted to int by normalizer
  dst_endpoint.ip: string
  dst_endpoint.port: string     # auto-converted to int by normalizer
  protocol: string
  event_time: string            # parsed as RFC3339 or common syslog timestamp formats

# Named capture groups that have no OCSF slot.
# These go into NormalizedEvent.Unmapped{} — they are NEVER dropped.
unmapped_captures:
  - string

# Optional translation maps applied by the parser engine before normalization.
# Keys are the raw capture group value; values are the translated string.
severity_map:   { string: string }   # raw_sev_value → OCSF severity
action_map:     { string: string }   # raw_action_value → OCSF action
protocol_map:   { string: string }   # raw_proto_value → OCSF protocol (e.g. "6" → "TCP")
```

---

## 6. REST API Specification

Base URL: `http://127.0.0.1:9000`
All responses: `Content-Type: application/json`
All responses: `Access-Control-Allow-Origin: *`

### 6.1 Events

**GET /api/events**
Query parameters:
- `src_ip` (string, optional)
- `dst_ip` (string, optional)
- `vendor` (string, optional) — matches `source_id` prefix
- `severity` (string, optional) — exact match
- `limit` (int, default 100, max 1000)
- `offset` (int, default 0)

Response:
```json
{
  "events": [ ...NormalizedEvent ],
  "total": 5600,
  "limit": 100,
  "offset": 0
}
```

**GET /api/events/{id}/raw**
Response:
```json
{
  "event_id": "evt_cc3f7a1b",
  "raw_sha256": "cc3f7a1b...",
  "raw_bytes_base64": "JUFTQaaa...",
  "byte_offset_start": 0,
  "byte_offset_end": 142,
  "verified": true
}
```
`verified: true` means `sha256(base64_decode(raw_bytes_base64)) == raw_sha256`.

### 6.2 Quarantine

**GET /api/quarantine**
Query parameters: `source_id` (optional), `limit`, `offset`
Response: `{"events": [...QuarantinedEvent], "total": N}`

### 6.3 Parser Registry

**POST /api/parsers**
Body: `{"config": "<yaml string>"}`
Validates YAML structure and compiles all regexes.
Response: `{"id": "...", "version": "...", "status": "PENDING"}` HTTP 201
Error: `{"error": "regex compile failed: ..."}` HTTP 400

**POST /api/parsers/{id}/approve**
Transitions parser to ACTIVE. Triggers ReplayQuarantine.
Response: `{"id": "...", "processed": N, "succeeded": N}` HTTP 200

**GET /api/parsers**
Response: `{"parsers": [{"id": "...", "version": "...", "status": "ACTIVE|PENDING", "registered_at": "..."}]}`

### 6.4 Telemetry

**GET /api/telemetry**
Response:
```json
{
  "events_ingested": 6100,
  "events_normalized": 5600,
  "quarantine_count": 14,
  "vault_size_bytes": 2400000000,
  "lossless_pct": 100.0,
  "uptime_seconds": 3600
}
```

`lossless_pct = (events_normalized + quarantine_count) / events_ingested * 100`
(Every event is either normalized or quarantined — nothing is silently dropped.)

### 6.5 Ingest

**POST /api/ingest/file**
Body: `{"path": "testdata/cisco_asa.log", "source_id": "cisco_asa_fw01"}`
Triggers background IngestFile goroutine.
Response: `{"status": "ingesting", "source_id": "cisco_asa_fw01"}`

**POST /api/ingest/batch**
Body: `{"source_id": "bench_test", "lines": ["raw line 1", "raw line 2"]}`
Synchronous. Processes all lines before responding.
Response: `{"ingested": N}`

---

## 7. Losslessness Definition

ULPF defines losslessness as: **byte-exact raw retention.**

For any event that was ingested, at any future point in time, the following must hold:
1. `vault.RetrieveRaw(event.RawSHA256)` returns the exact original bytes.
2. `sha256(returned_bytes) == event.RawSHA256`
3. The returned bytes are bit-for-bit identical to the original log line bytes, including:
   - Trailing newlines (`\n` or `\r\n`)
   - Invalid UTF-8 sequences
   - Null bytes (`\x00`)
   - Any other non-printable characters

Losslessness is NOT defined as "render-back check" (re-encoding the NormalizedEvent JSON and comparing to the original). JSON re-encoding changes whitespace, field ordering, and float precision — this is not a reliable proof of losslessness.

---

## 8. Air-Gap Deployment

### 8.1 Docker Internal Bridge

```yaml
networks:
  ulpf_internal:
    driver: bridge
    internal: true   # No default route to host network interface
```

`internal: true` means Docker creates the bridge without a gateway route.
Containers on `ulpf_internal` can communicate with each other but cannot reach external IPs.

### 8.2 Verification

The air-gap is verified by `scripts/verify_airgap.sh`:
- Confirms `curl https://8.8.8.8` fails from inside the container (no route to host)
- Confirms `http://127.0.0.1:8000` responds HTTP 200 from the host machine
- Confirms `http://127.0.0.1:9000/api/telemetry` responds HTTP 200

### 8.3 Headless Batch Mode

For environments with no UI:
```bash
./bin/dataplane --input testdata/cisco_asa.log --output out.jsonl --headless
```
Processes the file, writes normalized OCSF JSON to `out.jsonl`, exits with code 0 on success.

---

## 9. OCSF Alignment

OCSF Version: 1.1.0
Event Class: Network Activity (class_uid: 4001)

Mandatory OCSF fields and their sources:

| OCSF Field | ULPF Source |
| :--- | :--- |
| `class_uid` | Always `4001` (Network Activity) |
| `category_uid` | Always `4` (Network Activity) |
| `severity_id` | Mapped from NormalizedEvent.Severity |
| `time` | NormalizedEvent.EventTime (epoch milliseconds) |
| `src_endpoint.ip` | NormalizedEvent.SrcEndpoint.IP |
| `dst_endpoint.ip` | NormalizedEvent.DstEndpoint.IP |
| `connection_info.protocol_name` | NormalizedEvent.Protocol |
| `activity_name` | NormalizedEvent.Action |
| `unmapped` | NormalizedEvent.Unmapped |

Source-specific fields that have no OCSF slot go in the `unmapped` object.
This is the correct OCSF pattern for non-standard vendor fields.

---

## 10. Phase Gates Summary

| Gate | Condition | Unblocks |
| :--- | :--- | :--- |
| Gate 0 | `go.mod` + `events.go` + `spec.md` + `DESIGN.md` on `main` | All agents can start |
| Gate 1 | `testdata/manifest.json` verified correct | Claude Code #1 and #2 start |
| Gate 2 | Data plane builds + React UI renders with mock data | Codex #2 starts |
| Gate 3 | All benchmarks pass + AIRGAP_VERIFIED | Antigravity writes submission assets |
| Gate 4 | PPT + arch doc + demo video + GitHub public | SIH portal submission |
