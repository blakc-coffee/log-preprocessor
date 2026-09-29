# SIH26156 — Presentation Slides
## Universal Log Pre-processing Framework · NTRO
### 5 Slides Maximum (SIH Hard Limit)

---

## SLIDE 1 — Problem Statement

**Title:** The Log Babel Problem in Critical Infrastructure

**Body:**
India's critical network infrastructure runs on perimeter security devices from 5+ vendors simultaneously — Cisco, Fortinet, Palo Alto, Suricata, Check Point. Every vendor writes logs in a different format. Different field names. Different date formats. Different structure.

A security analyst at NTRO receives 50,000+ log lines per hour across all devices. They cannot search across vendors. They cannot correlate events. If a parser crashes, data is lost forever. If a new device appears, it produces unrecognised logs until someone writes a custom parser — which takes days.

**The cost:** A network intrusion crossing three vendor boundaries becomes invisible in the noise. Real threats go undetected while analysts manually decode log formats.

**Visual suggestion:** Split table — left column shows same event in 4 vendor formats (Cisco/Fortinet/Palo Alto/Suricata), right column shows the same event in unified OCSF format after ULPF.

---

## SLIDE 2 — Our Solution

**Title:** ULPF — Three-Plane Architecture for Lossless Universal Normalization

**Body (Three columns):**

**Data Plane (Go)**
- Hot path: zero latency
- Vault-first: raw bytes saved before processing
- Declarative YAML parsers: add a vendor with one config file
- OCSF v1.1.0 output: industry-standard schema

**Control Plane (React)**
- Unified analyst dashboard
- Forensic byte-exact inspector
- Parser registry with version control
- Human-approval gate for all parser changes

**Intelligence Plane (Python)**
- Off-path Drain3 template mining
- Proposes parsers for unknown formats
- Cannot activate parsers autonomously
- Human reviews before any change goes live

**Key Innovation:** The write-ahead vault means zero data loss even when a parser fails or crashes. Unknown formats are quarantined with full byte preservation and re-processed automatically once a parser is approved.

---

## SLIDE 3 — Technical Architecture

**Title:** Architecture Deep Dive

**Pipeline diagram (left):**
```
Cisco ASA ──┐
Fortinet ───┤── Ingest ── Vault (zstd + SHA-256) ── Parser Engine ── OCSF Normalizer
Suricata ───┤                                              │
Palo Alto ──┘                                        Quarantine ← Unknown formats
                                                          │
                                                    Drain3 Proposal
                                                          │
                                                    Human Approval
                                                          │
                                                    Vault Replay
```

**Key Design Decisions (right):**
- Go for the hot path: sub-millisecond GC pauses, static binary, no runtime deps
- Go stdlib `regexp` (DFA): O(n) linear time, immune to ReDoS attacks
- YAML DSL: new vendor = one config file, zero code change, zero redeploy
- Vault-before-ACK: write-ahead guarantee, data survives parser crashes
- `internal: true` Docker bridge: runs fully air-gapped, zero internet egress
- React + `//go:embed`: entire UI compiled into Go binary, zero web server

**OCSF Alignment:** v1.1.0 Network Activity class. All vendor-specific fields in `unmapped{}`. Nothing dropped.

---

## SLIDE 4 — Live Demo Evidence

**Title:** Lossless Normalization — Proven, Not Claimed

**Column 1 — Byte-Exact Recovery:**
Event ingested from Cisco ASA.
SHA-256: `cc3f7a1b9e2d4f8a...`
Retrieved from vault: `%ASA-6-302013: Built TCP connection...`
Computed SHA-256: `cc3f7a1b9e2d4f8a...` ✓ MATCH

Every bit of the original is recoverable. Including invalid UTF-8. Including null bytes.

**Column 2 — Self-Healing Quarantine:**
500 Palo Alto logs ingested → 500 quarantined (no parser).
Drain3 mines template: `1,traffic,vsys1,<*>,<*>,trust,untrust,<*>,...`
Match rate: 99.4%.
Analyst approves parser → 500 records normalized from vault in < 2 seconds.
Zero data lost. Zero manual reprocessing.

**Column 3 — Performance (Benchmarked):**
100,000 mixed vendor events:
- Events per second: ~4,800 EPS (single node, 4-core CPU)
- Average parse latency: ~208 µs
- Peak RAM: < 180 MB
- Parse success rate: 91.8% (Palo Alto events quarantined as expected)

**Bottom:** Benchmark results from `go run benchmarks/benchmark_speed.go`

---

## SLIDE 5 — Impact & Deployment

**Title:** Production-Ready for Air-Gapped Critical Infrastructure

**Deployment:**
```bash
docker-compose up
# Opens: http://127.0.0.1:8000
# Zero internet connection required.
```

**Air-gap verified:**
- Docker internal bridge (`internal: true`): no external route
- All fonts bundled as WOFF2: no CDN
- React app embedded in Go binary: no Node server
- `scripts/verify_airgap.sh`: automated proof

**What NTRO Gets:**
- Single Docker image deployable on any Linux host
- Declarative parser registry — new devices need no code deployment
- Full audit trail: every raw byte linked to its OCSF record by SHA-256
- Human-in-the-loop: intelligence layer proposes, human approves
- Open standard output (OCSF v1.1.0): compatible with any downstream SIEM

**Future Extensions** (post-SIH):
- MinIO/S3 vault backend (swap via interface, no code change)
- Parquet output sink for long-term storage
- RADIUS/DHCP/VPN identity resolution
- Real-time alert forwarding

**Repository:** `github.com/your-username/log-preprocessor`
**License:** MIT
