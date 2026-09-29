# 2-Minute Demo Video Script
## Universal Log Pre-processing Framework · SIH26156

Strict timing. Every beat is locked.

---

## Setup Before Recording

- Docker compose running: `docker-compose up`
- Browser open at `http://127.0.0.1:8000` on the Lineage Explorer view
- `testdata/` directory ready with all 5 log files
- Screen resolution: 1440×900 or higher
- No notifications. Do Not Disturb mode. Full screen browser.

---

## Beat 1 — 0:00 to 0:30 — Ingest Live Logs

**Screen action:**
Open terminal split below the browser.
Run:
```bash
curl -s -X POST http://127.0.0.1:9000/api/ingest/file \
  -H "Content-Type: application/json" \
  -d '{"path":"testdata/cisco_asa.log","source_id":"cisco_asa_fw01"}'
```

Wait 2 seconds. Run:
```bash
curl -s -X POST http://127.0.0.1:9000/api/ingest/file \
  -H "Content-Type: application/json" \
  -d '{"path":"testdata/fortinet.log","source_id":"fortinet_core01"}'
```

**What the judge sees:** The EPS counter on the Telemetry Strip climbs from 0 to ~4,800. Cisco ASA and Fortinet events appear in the Lineage Explorer table in real time. Both vendors show identical OCSF column structure: Timestamp · Source · Src→Dst · Protocol · Action · Status.

**Narration (say this aloud):**
> "We're streaming 4,000 raw log lines from two vendors — Cisco ASA and Fortinet — into the data plane. They have completely different formats. Watch the unified table: every event normalised to the same OCSF schema in real time."

---

## Beat 2 — 0:30 to 1:00 — Byte-Exact Forensic Inspector

**Screen action:**
Click on any Cisco ASA row in the Lineage Explorer table.
The Split Modal opens.

**What the judge sees:**
- Left pane: clean OCSF JSON with `event_id`, `parser_id: "cisco_asa@1.0.0"`, `src_endpoint.ip`, `dst_endpoint.ip`, `action: "Built"`, `unmapped: {"msg_id": "302013"}`
- Right pane: raw hex dump from the vault showing the exact original bytes `%ASA-6-302013: Built TCP...`
- Footer: Mint dot + **"Vault Raw Byte Verification: PASSED"** — with the SHA-256 hash

**Narration:**
> "One click opens the forensic inspector. On the left: the normalised OCSF record. On the right: the exact original bytes retrieved from the vault. The SHA-256 matches. This proves byte-exact losslessness — not a claim, a cryptographic proof."

Pause 3 seconds on the PASSED badge for maximum impact. Close modal.

---

## Beat 3 — 1:00 to 1:25 — Unknown Format Triggers Quarantine

**Screen action:**
In the terminal, run:
```bash
curl -s -X POST http://127.0.0.1:9000/api/ingest/file \
  -H "Content-Type: application/json" \
  -d '{"path":"testdata/palo_alto_unknown.log","source_id":"palo_alto_fw01"}'
```

Click the **"Review Queue"** tab in the masthead.

**What the judge sees:**
- The Quarantine count in the Telemetry Strip jumps from 0 to 14 (or higher as ingest completes)
- The Review Queue shows a Palo Alto cluster card
- The diff block shows the raw CSV log on the left vs the Drain3 mined template on the right
- Match rate: 99.4% · Token coverage: 91.2%
- The proposed YAML parser config is displayed

**Narration:**
> "We just fed in Palo Alto PAN-OS logs — a format we've never seen before. Instead of crashing or dropping the data, every record is safely quarantined with its raw bytes intact in the vault. Drain3 — our offline template miner — has already analysed the pattern and proposed a parser."

---

## Beat 4 — 1:25 to 2:00 — Approve & Replay from Vault

**Screen action:**
Read the proposed parser config briefly on screen (2 seconds of pause).
Click **"Approve & Replay from Vault"** button (white button, bottom right of the quarantine card).

Switch back to **"Lineage Explorer"** tab.

**What the judge sees:**
- The Quarantine count drops from 14 (or full count) to 0 within 1-2 seconds
- 500 Palo Alto events flood into the Lineage Explorer table, all tagged `parser_id: "palo_alto@1.0.0"`
- Their `src_endpoint.ip` and `dst_endpoint.ip` are populated
- Click one Palo Alto event → Split Modal → SHA-256 PASSED (vault bytes still intact)

**Narration:**
> "One click — approve and replay. The system re-reads every quarantined record from the vault, runs them through the newly approved parser, and normalises all 500 events to OCSF. Zero data lost. Zero manual reprocessing. The vault bytes are still there, still verified."

Hold on the full normalised Palo Alto row for 5 seconds.

---

## End Card — 2:00

**Screen action:** Stay on Lineage Explorer. All three vendors visible in the table. Telemetry strip showing 100% lossless.

**Narration:**
> "ULPF: universal, lossless, air-gapped. One system, every vendor."

---

## Recording Tips

- Use OBS or any screen recorder at 1080p 30fps minimum
- Record audio via a decent microphone (avoid laptop mic)
- Do a dry run twice before recording
- Keep the browser developer tools closed during recording
- If any step fails: stop, reset docker-compose, start over — do not continue with a broken state
- Upload to a private YouTube link or Google Drive for SIH portal submission
