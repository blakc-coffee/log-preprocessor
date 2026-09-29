# ULPF control-plane UI

React 18 + TypeScript (strict) + Vite + Tailwind v4. Built into `frontend/dist`, copied into
`pkg/control/ui/dist` by `make ui`, and embedded into `cmd/control` with `go:embed`. At runtime it
loads nothing from the network: fonts are self-hosted WOFF2 files in `public/fonts/` (SIL OFL,
licences alongside), and the server's CSP allows this origin only.

## Run it

```sh
make control-demo            # builds the UI and the binary, serves http://127.0.0.1:8000 against the built-in mock
curl -X POST 127.0.0.1:8000/mock/advance    # steady -> drift -> approved -> steady
```

Against a real data plane: `./bin/control --admin-url http://127.0.0.1:9000`.

For UI work, run `./bin/control --mock` and then `npm run dev` here (Vite on :5173 proxies `/api` to :8000).

## Screens

| Route | Screen | Source |
|---|---|---|
| `/` | Unified Lineage Explorer: telemetry, filters, virtualized cursor-paged table, live tail | Figma 1 |
| `/events/:id` | Forensic split modal: OCSF tree, hex dump, three browser-side checks | DESIGN.md Screen 2 |
| `/review/:kind/:id` | Review Queue: proposals, drift alerts, quarantine; typed fields, YAML/diff, dry run, approve and replay | Figma 2 |
| `/parsers/:id` | Parser Registry: active set, mapping, verification (dry run), versions, audit trail, rollback | Figma 3 |
| `/identity` | Identity timeline for an IP | PRD screen 4, built from existing components |
| `/vault` | Segments, chain head, shallow and deep chain verification | PRD screen 5, built from existing components |

Keyboard: `/` search, `j`/`k` move, `Enter` open, `Esc` close. Table rows in the queue and registry take focus and `Enter`.

## Verification in the browser (`src/lib/merkle.ts`)

The modal never trusts the server's `sha_match`:

1. **SHA-256** of the raw bytes, compared with the event's `raw_sha256`.
2. **Merkle inclusion and chain.** The vault's record body is rebuilt from the raw bytes plus the record
   metadata (record id, nanosecond `received_at`, source, origin, terminator, fragment), hashed to the
   leaf, compared with the proof's leaf, folded up the RFC 9162 path to the segment root, and the chain
   link `SHA-256(0x02 || prev || root || segment || count)` is recomputed. Rebuilding the leaf is what
   ties *these bytes* to the proof; a proof alone shows only that some leaf is in the tree. An unsealed
   segment is reported as pending, not as a failure.
3. **Render-back and coverage.** The byte accounting must sum to the raw length.

Tested against every tree and leaf in `testdata/merkle_vectors.json`, the contract goldens, and tamper cases.

## How the design sources were reconciled

`DESIGN.md` is the rulebook, the Figma PDF is the layout, and the Frontend PRD is the behaviour. Where
they disagreed:

| Conflict | Resolution |
|---|---|
| Review Queue: Figma approves one record ("Approve mapping"), DESIGN.md shows vendor-cluster cards, the PRD and admin API approve parser *proposals* | Figma's layout (stat cards, queue table, detail panel) carrying the PRD's content. The admin API has no per-record approve. *Decided with the user.* |
| Focus: DESIGN.md says `outline: none`, the PRD requires visible keyboard focus | 1px white outline on `:focus-visible` only. No colour, no ring utilities. *Decided with the user.* |
| Identity and Vault screens are in the PRD, not in the Figma | Added as tabs, built only from existing components. *Decided with the user.* |
| Primary button: PRD says "white pill", DESIGN.md says 6px radius and bans fully rounded CTAs | 6px radius (DESIGN.md and the Figma agree). |
| DESIGN.md's Tailwind block uses v3 key names (`--font-family-*`, `--border-radius-*`), which v4 ignores, so `rounded-card` would not exist | v4 namespaces (`--font-*`, `--radius-*`). The default palette, shadows and blurs are reset so they cannot be used. |
| Modal backdrop: DESIGN.md says "blurred/darkened" but bans `backdrop-filter` | Darkened only (`rgb(0 0 0 / 0.7)`). |
| Sparkline: DESIGN.md says 8 bars, the PRD says 60 samples | 8 lavender bars, each averaging a slice of up to 64 samples (about two minutes). |
| Figma stat cards differ in height (EPS card taller for its sparkline) | All cards are 88px (DESIGN.md telemetry strip); the sparkline sits beside the value. |
| Figma "OCSF" status badges render as `( OCSF )` | A proper pill. OCSF badges are muted: mint is reserved for *verified* states (hash checks, lossless), so not every row lights up. |
| Figma filter selects are borderless | Bordered, per DESIGN.md's input spec. |
| Figma table columns (timestamp, source, src to dst, protocol, action, status) vs PRD columns (adds severity, user/host, confidence, flags) | Both. At 1024px, severity, confidence and flags drop out so nothing overlaps. |
| Figma explorer shows a quarantined row among events | Quarantined records are not events (they have no normalization); they live in the Review Queue. |
| Figma "Lossless 100%" | Shown only when the last chain verification passed (`telemetry.lossless.last_verify_ok`); "FAILED" otherwise. |
| Figma parser table has coverage, last run and fixture counts | The admin API does not provide them. The table shows format, version and last change (registry); "Run verification" dry-runs the active version on demand. |
| Search placeholder "IP, vendor, or raw hash" | No admin filter exists for a raw hash, so the box says so instead of silently ignoring it. |
| No red or green in the palette for failures and diffs | A failure is white text reading FAILED; diffs use `+`/`−`, weight and strike-through. |

Enforced mechanically: `scripts/check-design.mjs` (run by `npm run lint`) rejects colour literals,
shadows, rings, gradients, blur, off-token radii and arbitrary values in components.
`scripts/check-dist.mjs` (run by `npm run build`) fails on external URLs in loading positions and on
the bundle budget (initial JS ≤ 300 KB gzipped; measured 87 KB).

## Tests

```sh
make ui-test        # typecheck, ESLint (bans dangerouslySetInnerHTML, innerHTML, eval), design check, Vitest
```

Vitest runs the Merkle vectors, the helper libraries, and component tests against msw handlers that
serve `contracts/golden/*.json`: explorer, the modal's three checks (pass, tampered, lying `sha_match`,
unsealed), the approve flow (recorded name, below-threshold confirmation, stale 409, replay progress),
structured YAML edits, and the admin-down banner.

## Dependencies

Pinned exactly in `package.json`; `.npmrc` sets `ignore-scripts=true`. Versions respect this
machine's npm `min-release-age` (3 days). TanStack Table from the PRD's list is not used: the
virtualized explorer renders rows directly, one dependency fewer.
