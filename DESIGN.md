# ULPF Design System
## Basedash Midnight Data Terminal
### Owned by Antigravity Pro — Governs all frontend decisions

---

## Design Philosophy

Midnight data terminal with frosted type.
A dark observatory where metrics glow in violet and green,
serif headlines float above the noise,
and white pill buttons are the only bright objects in a room of soft black surfaces.

**Aesthetic:** Dark mode command surface. Pure black canvas. Near-black elevated cards.
White type reads like a terminal. Calm and technical — never colorful, never playful.

---

## Color Tokens (Complete)

| Token Name | Hex | Usage |
| :--- | :--- | :--- |
| `--color-canvas` | `#000000` | Page background. Nothing else. |
| `--color-card` | `#050607` | All card, table row, modal, and input backgrounds. |
| `--color-text-primary` | `#ffffff` | All primary text, metric values, headings. |
| `--color-text-muted` | `#b3b3b3` | Labels, secondary text, inactive nav, muted copy. |
| `--color-border` | `#333333` | 1px border on ALL cards, inputs, tables, modals, pills. **The only permitted border color.** |
| `--color-mint` | `#3fcb7f` | Live status dots (1 per screen max). Verified badges. Lossless metric value. NOTHING ELSE. |
| `--color-lavender` | `#9984d8` | Chart sparkline fills and bar fills ONLY. Never used as text or border. |

### Color Rules — Non-Negotiable

1. **ZERO colored borders.** Never `#3fcb7f`, `#9984d8`, or any other color as a border.
   Every border is 1px solid `#333333`. No exceptions.

2. **ZERO shadows.** No `box-shadow`, no `drop-shadow`, no `text-shadow`.
   Elevation is achieved exclusively by surface value contrast: `#000000` (canvas) vs `#050607` (card).

3. **Mint and Lavender are accent colors only.** Mint for live status and verified states.
   Lavender for data visualizations. Neither color is used for interactive elements, borders, or general text.

4. **White buttons only.** The primary CTA button is always `#ffffff` fill with `#000000` text.
   No colored buttons. No gradient buttons.

---

## Typography

### Typefaces

| Role | Font | Weight | Size |
| :--- | :--- | :--- | :--- |
| Display/Editorial | Cormorant Garamond | 300 (Light) | 48px (hero), 34px (section) |
| UI Labels & Body | Inter | 400, 500, 600 | 11px–16px |
| Log / Hex / Code | JetBrains Mono | 400 | 13px (body), 11px (hex dump), 12px (YAML) |

### Type Scale

```
48px / 300 / Cormorant Garamond   ← Hero headline (unused in current screens)
34px / 300 / Cormorant Garamond   ← Section headline (Review Queue title)
16px / 600 / Inter                ← Modal heading
14px / 700 / Inter -0.03em        ← Brand name, tab labels, CTA buttons
13px / 400 / Inter                ← Primary body text, table rows
12px / 400 / JetBrains Mono       ← Code blocks, YAML, JSON display
11px / 500 / Inter +0.08em        ← Table column headers (uppercase), secondary labels
11px / 400 / JetBrains Mono       ← Hex dump, SHA-256 strings
```

### Tracking

All Inter UI text uses `letter-spacing: -0.03em` for optical tightening.
All uppercase table headers use `letter-spacing: 0.08em` for legibility at small size.

### Font Loading

Fonts MUST be bundled as local WOFF2 files in `frontend/public/fonts/`.
Zero Google Fonts CDN references. Zero system font fallback for display font.
`@font-face` declarations in `src/design/tokens.css`.

---

## Spacing & Layout

| Token | Value | Usage |
| :--- | :--- | :--- |
| `--space-page` | `16px` | Horizontal padding for all full-width sections |
| `--space-card` | `24px` | Internal padding for all cards and modals |
| `--space-row` | `48px` | Table row height |
| `--space-topbar` | `56px` | Masthead / top navigation bar height |
| `--space-telemetry` | `88px` | Telemetry strip total height |

---

## Component Specifications

### Card

```css
background: #050607;
border-radius: 16px;
border: 1px solid #333333;
padding: 24px;
/* NO box-shadow */
/* NO drop-shadow */
```

### Input / Select / Dropdown

```css
background: #050607;
border: 1px solid #333333;
border-radius: 6px;
color: #ffffff;
font-family: Inter;
font-size: 13px;
padding: 8px 12px;
outline: none;
/* On focus: border stays #333333 — never a colored ring */
```

### Primary Button (CTA)

```css
background: #ffffff;
color: #000000;
border: none;          /* ZERO border */
border-radius: 6px;
padding: 12px 24px;
font-family: Inter;
font-size: 14px;
font-weight: 700;
cursor: pointer;
/* NO box-shadow */
/* On hover: opacity 0.9 */
/* NO color change on hover */
```

### Secondary / Ghost Button

```css
background: #050607;
color: #b3b3b3;
border: 1px solid #333333;
border-radius: 6px;
padding: 8px 16px;
font-size: 13px;
cursor: pointer;
```

### Pill Badge (Status / Vendor)

```css
background: #050607;
border: 1px solid #333333;
border-radius: 999px;
padding: 2px 10px;
font-size: 11px;
color: #b3b3b3;
/* For OCSF verified badge: color: #3fcb7f */
/* For QUARANTINED badge: color: #b3b3b3 */
/* NEVER a colored border */
```

### Live Status Dot

```css
width: 8px;
height: 8px;
border-radius: 50%;
background: #3fcb7f;
display: inline-block;
/* Optional: subtle pulse animation at 2s interval */
```

### Sparkline Bar (Lavender only)

```css
/* A row of 8 thin bars representing metric history */
height: 24px;
background: #9984d8;
border-radius: 2px;
opacity: 0.7;
/* NO border */
```

### Table

```css
/* Header row */
background: #000000;
border-bottom: 1px solid #333333;
font-size: 11px;
font-weight: 500;
letter-spacing: 0.08em;
text-transform: uppercase;
color: #b3b3b3;

/* Data rows - even */
background: #050607;
/* Data rows - odd */
background: #000000;

/* All rows */
height: 48px;
border-bottom: 1px solid #333333;

/* Hover */
background: rgba(255, 255, 255, 0.03);
cursor: pointer;
```

### Masthead (Top Bar)

```css
height: 56px;
background: #050607;
border-bottom: 1px solid #333333;
padding: 0 16px;
display: flex;
align-items: center;
justify-content: space-between;
```

### Modal Overlay

```css
/* Backdrop */
position: fixed;
inset: 0;
background: rgba(0, 0, 0, 0.7);
z-index: 100;
display: flex;
align-items: center;
justify-content: center;

/* Modal box */
background: #050607;
border-radius: 16px;
border: 1px solid #333333;
width: 1080px;
max-height: 80vh;
overflow: hidden;
/* NO box-shadow */
```

---

## Screen Specifications

### Screen 1 — Unified Lineage Explorer (1440×900)

Layout (top to bottom):
```
[Masthead — 56px]
[Telemetry Strip — 88px]
[Filter Bar — 52px]
[Event Table — remaining height]
```

### Screen 2 — Byte-Exact Forensic Split Modal (1440×900)

Base: Lineage Explorer screen (blurred/darkened).
Modal centered: 1080×640px.
```
[Modal Header — 52px]
[Split Body — two equal columns, 1px #333333 divider — remaining height]
[Modal Footer — 52px]
```

### Screen 3 — Self-Healing Review Queue (1440×900)

Layout:
```
[Masthead — 56px with "Review Queue" tab active]
[Section Header — 64px]
[Quarantine Cards — scrollable, one per vendor cluster]
```

---

## Anti-Slop Rules (Enforcement List)

These are patterns that indicate a generic AI-generated UI. None of these appear in ULPF.

❌ Purple/violet card borders
❌ Gradient buttons (`linear-gradient(...)`)
❌ Drop shadows (`box-shadow: 0 4px 6px rgba(0,0,0,0.1)`)
❌ Light mode or mixed light/dark mode
❌ Rounded full buttons for primary actions (`border-radius: 9999px` on full-width CTA)
❌ Google Fonts CDN links
❌ Tailwind `ring-*` utility classes used as focus indicators (use `outline: none`)
❌ `border-color: #3fcb7f` or `border-color: #9984d8` on any element
❌ Glassmorphism (`backdrop-filter: blur(...)`)
❌ Color fills in table header backgrounds (only `#000000`)
❌ Status badges with solid colored backgrounds (only `#050607` fill with `#333333` border)

---

## Tailwind CSS v4 Theme Config

Add to `frontend/src/design/tokens.css`:

```css
@import "tailwindcss";

@theme {
  --color-canvas: #000000;
  --color-card: #050607;
  --color-text-primary: #ffffff;
  --color-text-muted: #b3b3b3;
  --color-border: #333333;
  --color-mint: #3fcb7f;
  --color-lavender: #9984d8;

  --font-family-ui: 'Inter', system-ui, sans-serif;
  --font-family-display: 'Cormorant Garamond', Georgia, serif;
  --font-family-mono: 'JetBrains Mono', 'Courier New', monospace;

  --border-radius-card: 16px;
  --border-radius-button: 6px;
  --border-radius-pill: 999px;
}
```

Usage in JSX:
```tsx
// Card
<div className="bg-card rounded-card border border-border p-6">

// Primary button
<button className="bg-text-primary text-canvas rounded-button px-6 py-3 font-bold text-sm">

// Muted text
<span className="text-text-muted text-xs uppercase tracking-widest">

// Status dot
<span className="inline-block w-2 h-2 rounded-full bg-mint">
```
