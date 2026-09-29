# Frontend work: what was built, changes from the Figma, and inconsistencies found

Sources compared: the Figma export (`ULPF Basedash Midnight Terminal.pdf`, 3 screens), `DESIGN.md`, and
the Frontend PRD. Rule applied: **DESIGN.md decides styling, the Figma decides layout, the PRD decides
behaviour.** Items marked *(user)* were decided by you.

## 0. What I did

Workstream: Control plane & frontend (Claude Code #2). Branch `feature/control-plane`, not yet committed.
Only my own paths were touched (`frontend/`, `pkg/control/`, `cmd/control/`). The shared files got
additions only: a labelled Makefile section, and `modernc.org/sqlite` in `go.mod`/`go.sum`. I chose a
sqlite version that added lines without bumping anything else; the newest one would have raised the
repo's Go version.

**Backend (Go)**
- `cmd/control`: serves the UI and the control API on `127.0.0.1:8000`. Flags: `--mock`, `--admin-url`, `--healthcheck`.
- `pkg/control/server`: the control API. It passes admin calls through, adds combined views (a proposal with the YAML of the version it patches, parser versions with their approval history), maps failures to stable error codes (`admin_unreachable`, `stale_base_version`, …), and sets security headers (strict CSP), gzip and SPA serving.
- `pkg/control/registry`: SQLite approval log. The row is written *before* the admin call and finished after it, so a crash in between leaves evidence.
- `pkg/control/mock`: the whole admin API in process, with a steady → drift → approved scenario. Raw lines are stored in the Ingestion team's `memvault`, so hashes and Merkle proofs are real.
- `pkg/control/adminclient`: HTTP or in-process client for the admin API.

**Frontend (React 18, TypeScript, Vite, Tailwind v4)**
- Six screens: Lineage Explorer (virtualized, cursor-paged, live tail, keyboard navigation), the forensic event pop-up, Review Queue, Parser Registry, Identity Timeline, Vault & Chain.
- Browser-side verification: SHA-256 of the raw bytes, the vault record rebuilt from the raw bytes to its Merkle leaf, the RFC 9162 inclusion proof, and the chain link. It never trusts the server's `sha_match`.
- Review flow: typed-field edits rewrite the YAML (one line per edit), a diff against the base version, re-running the dry run, a recorded approver name, "approve anyway" below the acceptance thresholds, a stale-version message, and live replay progress.
- `DESIGN.md` tokens in `src/design/tokens.css`, with Tailwind's default colours, shadows and blurs removed. Fonts are self-hosted, nothing is loaded from outside, and an About panel states the v1 limitations.

**Checks**
- 55 frontend tests: the Merkle test vectors, tamper cases, and screens tested against the contract's golden files. Go tests pass under `-race`, and every mock and proxied response is validated against the OpenAPI spec.
- Lint bans HTML-injection sinks. `check-design.mjs` enforces the `DESIGN.md` rules. `check-dist.mjs` enforces the no-external-URL rule and the bundle budget (87 KB of 300 KB).
- Checked in the browser at 1440×900 and 1024×768: no overlap or text spill, only #333 borders, and no shadows, gradients or blur. The demo was run end to end: drift → approve → 77/77 records recovered → recovered events shown.
- Bugs found and fixed along the way: event-id deep links returned 404; conflicting utility classes caused an overlap; a stale bundle broke lazy-loaded screens after a rebuild; and a test helper hid validator failures.

## 1. Changes from the Figma

| Screen | Figma | Built | Why |
|---|---|---|---|
| All | 3 tabs | 5 tabs (+ Identity, Vault) | Required by the PRD; built only from existing components *(user)* |
| All | Page padding about 24px | 16px | DESIGN.md `--space-page` |
| All | Masthead fill looks black | `#050607` | DESIGN.md masthead spec |
| All | "AIR-GAPPED" pill, no explanation | Same pill; clicking opens an About panel (no login, names not verified, nothing external loaded) | The PRD requires the limitations to be stated in the UI |
| Explorer | EPS card taller than the other three | All four cards 88px; sparkline beside the value | DESIGN.md telemetry strip is 88px |
| Explorer | Sparkline is one dim block | 8 lavender bars | DESIGN.md sparkline spec |
| Explorer | "Vault size", "Lossless", "Quarantined" show a number only | Short sub-line added (records and ratio, sealed-through, "open · review") | The PRD strip also needs records, ratio, chain status and peak EPS |
| Explorer | Filters: search, "All sources", "Severity: All" (borderless) | Adds Action, Flags, Time range and Live; all bordered | PRD filter list; DESIGN.md input spec requires a border |
| Explorer | Search "by IP, vendor, or raw hash" | "by IP, user, host or vendor" | The admin API has no raw-hash filter |
| Explorer | 6 columns | 10 columns (adds Severity, User / host, Confidence, Flags); 7 below 1280px | PRD column list; the narrow set keeps 1024px free of overlap |
| Explorer | Status shows as `( OCSF )` | A proper pill | The Figma badge rendered incorrectly |
| Explorer | A "QUARANTINED" row among events | Not shown in the explorer | Quarantined records are not events; they are in the Review Queue |
| Explorer | Action values Built / Accept / Denied / Alert | Allowed / Denied (OCSF `action_id`) | One schema across vendors, which is the product's point |
| Explorer | "8 of 4,827 events" | "N loaded of M events" | The list is cursor-paged, so the total comes from telemetry |
| Review Queue | Approves one record ("Approve mapping" / "Keep quarantined") | Approves a parser proposal ("Approve & Replay from Vault" / "Reject") | The admin API only approves proposals *(user)* |
| Review Queue | Rows are quarantined records with a "confidence" | Rows are proposals, drift alerts and quarantine clusters, with a Score column | Quarantined records have no confidence in the contract |
| Review Queue | Stat cards: Open cases, High priority, Median age, Lossless | Open cases, Pending proposals, Drift alerts, Lossless | The API has no priority or age |
| Review Queue | Detail: raw event, 4 mapped fields, "PASSED raw payload hash verified" | Typed-fields table, YAML / diff / edit, dry-run results, replay progress | PRD Screen 3 content |
| Review Queue | Secondary button borderless | Bordered | DESIGN.md secondary button spec |
| Parser Registry | Columns: Coverage, Last run; cards: Coverage, Test fixtures | Version and Last change; cards: Versions, Approvals recorded | The API provides neither coverage nor fixture counts |
| Parser Registry | "PASSED - 48 fixtures verified" always shown | Shown after "Run verification", which dry-runs the active version | Showing it unrun would be a claim with no measurement behind it |
| Parser Registry | "View fixtures" | "Versions & history" (diff, audit trail, rollback) | PRD parser-versions drawer |
| Parser Registry | Lists Zeek, Windows XML and similar | Lists whatever the data plane reports | Data, not design |

## 2. Inconsistencies found

**Figma vs DESIGN.md**
- The primary button is 6px in both, but the PRD calls it a "white pill" → kept 6px (DESIGN.md also bans fully rounded CTAs).
- DESIGN.md says a 1px `#333` border on every card and input; the Figma's filter selects and ghost buttons have none → bordered.
- DESIGN.md makes the OCSF badge mint; the Figma shows it grey → grey. Mint is kept for verified states, so every row does not light up.
- DESIGN.md's Screen 1 layout has no page title; the Figma has one on every screen → kept the title (34px, DESIGN.md's section size).
- DESIGN.md describes the Review Queue as "cards, one per vendor cluster", which matches neither the Figma nor the PRD *(user)*.

**Inside DESIGN.md**
- The Screen 2 backdrop is "blurred/darkened", but `backdrop-filter: blur` is banned → darkened only.
- "Zero system font fallback for display font", but its own Tailwind block lists `Georgia, serif` → no Georgia, and `font-display: block`.
- Its Tailwind v4 block uses v3 key names (`--font-family-*`, `--border-radius-*`), so `font-ui` and `rounded-card` would never exist → v4 names (`--font-*`, `--radius-*`).
- The usage example uses `tracking-widest` (0.1em); the spec says 0.08em → a `tracking-label` token.
- The masthead may have one live dot per screen, but the Figma pill and a live-tail indicator would make two → only the masthead has the dot; Live is a text button.
- A 24px card padding and a 24px metric value don't fit the 88px strip with a label → value sized at 24px, the tallest that fits.
- No colour exists for failures or diff lines → FAILED in white words; diffs use `+`/`−`, weight and strike-through.

**DESIGN.md vs the PRD**
- `outline: none` on focus vs "visible focus rings" → a 1px white outline on keyboard focus only *(user)*.
- An 8-bar sparkline vs "last 60 samples" → 8 bars, each averaging part of up to 64 samples.
- Fonts in `frontend/public/fonts` with `@font-face` in `tokens.css`, vs fontsource npm packages → both: the packages are the source, and the files are copied into `public/fonts`.
- `tokens.css` with a v4 `@theme` vs `tailwind.config.ts` reading `tokens.ts` → DESIGN.md's approach.

**Figma or PRD vs the admin API contract** (reported to Contracts, not worked around)
- There is no "current versions only" filter and no raw-hash filter.
- There is no endpoint to mark a quarantined record "ignored".
- Samples carry no hash, so a quarantined record cannot be verified against the vault until it has been normalized.
- The parser list has no source ids, so verification assumes source id = parser id.
- Identity evidence gives a record id, but records can only be opened by event id.
