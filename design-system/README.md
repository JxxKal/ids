# CYJAN IDS Design System

> **CYJAN – The OT-Sentrymode**
> Passive network intrusion-detection for OT / ICS environments.
> *"Protect · Detect · Respond."*

This folder is a living design system for the CYJAN IDS product line: a self-contained bundle of tokens, fonts, icons, logos, CSS, and recreated UI kits that lets a design agent mock new screens, slides, landing pages, and product surfaces in the CYJAN voice without reinventing the look.

---

## The company in one paragraph

CYJAN is a passive, header-only intrusion-detection system purpose-built for operational-technology and industrial-control-system networks (SCADA, Modbus TCP, DNP3, EtherNet/IP, BACnet, S7). It lives on a switch mirror port, never touches payloads, and combines a Rust sniffer, Kafka event bus, Python signature engine, an Isolation-Forest ML anomaly engine with a self-learning feedback loop, and a React / Vite / TypeScript dashboard. It ships either as a Debian Live ISO or as a Docker-Compose stack, and it's MIT-licensed, open source.

The personality: **serious, technical, German-engineered, confident about the boring-but-critical problem it solves.** The visual language is "control-room at 2 a.m." — a dark slate canvas, a cyan tactical accent, monospace where data lives, and just enough glow to feel alive without being sci-fi costume.

---

## Sources — where the truth lives

| Source | What's in it | Where to find it |
|---|---|---|
| `JxxKal/cyjan-ids-website` (GitHub, main) | Single-file marketing HTML (`index.html`, 1200 lines), Tailwind CDN, hex-grid hero, feature grid, architecture diagram, quick-start, brochure PDF download. | `github.com/JxxKal/cyjan-ids-website` |
| `JxxKal/ids` (GitHub, main) | Full product: 14 microservices, React/Vite/TS dashboard in `frontend/`, logo SVGs at the repo root, comprehensive German README. | `github.com/JxxKal/ids` |
| `uploads/cyjan_splash_screen.svg` | Full splash / hero composition with pentagon-shield, CYJAN wordmark, "PROTECT · DETECT · RESPOND". | project `assets/logos/` |
| `uploads/cyjan_logo_cyan.svg` · `cyjan_logo_cyan_max.svg` | Two variants of the pentagon-shield logo used in marketing + dashboard header. | project `assets/logos/` |

Nothing here assumes the reader can reach those sources live — every token, style, and component we needed has been captured locally.

---

## Products covered

| Product | Surface | Codebase | UI kit folder |
|---|---|---|---|
| **Marketing website** | Single-page landing — hero, features, live-demo tabs, architecture diagram, quick-start, open-source CTA, brochure download. | `cyjan-ids-website/index.html` | `ui_kits/website/` |
| **IDS Dashboard** | In-product React app — alert feed (live / grouped / snapshot), threat-level gauge, host inventory, network inventory, test scenarios, settings (users, SAML, ML config, rule sources). Login gate in front. | `ids/frontend/` (React + Vite + TS + Tailwind) | `ui_kits/dashboard/` |

Both surfaces share the same palette and visual motifs but diverge on density: the marketing site is open, headline-driven, sans-serif; the dashboard is compact, monospace-first, table-heavy.

---

## Folder index

```
.
├── README.md                     ← you are here
├── SKILL.md                      ← Agent-Skills compatible entry point
├── colors_and_type.css           ← all design tokens (--cy-* custom props) + semantic type classes
├── assets/
│   └── logos/                    ← five logo SVGs (wordmark, compact, shield, splash)
├── preview/                      ← small HTML cards that populate the Design System tab
├── ui_kits/
│   ├── website/                  ← marketing site recreation (index.html + components)
│   └── dashboard/                ← IDS dashboard recreation (index.html + components)
└── fonts/                        ← empty — see note under Typography
```

---

## CONTENT FUNDAMENTALS

### Voice & tone

CYJAN speaks like a senior control-room engineer who has been paged too many times. Short declarative sentences. No marketing fluff. Facts, versions, port numbers, ISO links. When it brags, it brags about the absence of things: *"Zero payload access. Zero blind spots."*

- **Register:** technical-direct, mildly authoritative. Not playful. Not scary either — the product's value is calm availability, not FUD.
- **Person:** second person ("your OT environment", "choose yours") when addressing operators; third person / passive when describing the system ("headers only, no payload, no decryption"). Never "we" for the product team.
- **Authority markers:** exact numbers ("~40,000 Emerging Threats rules", "128 B snaplen", "14 microservices"), named technologies ("Isolation Forest", "TPACKET_V3", "KRaft"), named partners ("Digital Bond", "Positive Technologies", "IRMA").

### Languages

CYJAN is bilingual, and the split is structural, not translation:

- **Marketing website → English** (hero, features, quick-start).
  - Exception: the "Die App in Aktion" live-demo section is **German** because it talks to the actual operator persona.
- **Dashboard → German** (nav labels, buttons, filter labels, tooltips).
  - Exception: domain/technical terms stay English: `Alerts`, `Score`, `Tags`, `Threat Level`, `Live`, `Settings`, `Feedback`, `True Positive / False Positive`, `Snapshot`. Protocol names (`Modbus TCP`, `DNP3`) are always English.

Pattern: when in doubt, keep the UI label German and keep the data-layer noun English. Mixing them in one sentence is normal and on-brand (*"Gefilterte Alerts als CSV exportieren"*, *"Keine Alerts"*, *"Tags durchsuchbar über das globale Suchfeld"*).

### Casing

- **Sentence case** for UI buttons, nav tabs, feature titles: *"Quick Start"*, *"View on GitHub"*, *"Host-Inventar"*, *"Anmelden"*.
- **UPPERCASE with wide tracking** for eyebrows/micro-labels above sections (`CAPABILITIES`, `ARCHITECTURE`, `QUICK START`, `PRODUKTIVE INSTALLATION`, `SERVICE ENDPOINTS`) and inside the logo (`CYJAN`, `INTRUSION DETECTION SYSTEM`, `PROTECT · DETECT · RESPOND`).
- **UPPERCASE with `·` separators** for brand motto lines: `PROTECT · DETECT · RESPOND`.
- **`lowercase monospace` for identifiers, hostnames, and config keys** when they appear in running copy (e.g. `ids-update`, `docker compose`, `source=external`).

### Emoji

Emoji is **rare and intentional, never decorative**. The only uses in the whole product:

- Three glyph bullets in the marketing *Open Source* section: 🔍 Auditable · 🔧 Extensible · 🤝 Community.
- A handful of lucide-react icons *masquerading* as emoji positions (feature-card icons).
- Zero emoji inside the dashboard. Trust and severity are signalled with `✓` / `⚠` / `×N` glyphs and colour.

**Rule:** if you can replace an emoji with a lucide icon, replace it. If it's already in the brochure-style Open-Source section, you may keep the three existing ones but don't add more.

### Unicode glyphs used as icons

These appear throughout; copy-paste rather than substitute:

- `↓` download arrow (CTAs and table pcap button: `↓ pcap`, `↓ CSV`)
- `→` pipeline arrow (architecture diagram)
- `·` dot separator (motto, nav)
- `✓` confirmation (trust badge, FP)
- `⚠` warning (TP badge)
- `×N` multiplier (alert group count: `×3`, `×12`)
- `⊞` / `≡` view-toggle (grouped vs single)

### Copy samples — verbatim, for tone calibration

> **Hero:** Passive IDS · for OT/ICS environments. Header-only packet analysis at the mirror port. Signature detection + ML anomaly engine + self-learning feedback loop. Zero payload access. Zero blind spots.

> **Feature card:** Zero network impact. Rust-based sniffer with AF_PACKET/TPACKET_V3 captures traffic at line rate — headers only, no payload, no decryption.

> **Dashboard empty state:** Keine Alerts

> **Dashboard tooltip:** Kein PCAP – Sniffer läuft nicht oder kein Paketpuffer für diesen Alert

> **Quick Start:** Plug in, boot, done. First-boot wizard configures interface, IPs, and passwords. No OS admin skills needed.

### Punctuation & formatting quirks

- Em-dash (`—`) is heavily used to break compound sentences.
- Middle-dot (`·`) replaces commas in lists of tags and in the motto.
- Numbers get thousands separators (German-style `5.000`, `~40.000`) in German copy; bare (`5,000`) in English copy.
- Filenames and commands **always** in monospace, **never** in sentence prose without backticks.
- Service endpoints display as bare ports (`:3000`, `:8001/api/docs`) rather than full URLs.

---

## VISUAL FOUNDATIONS

### Colour

CYJAN runs on a **two-axis palette**: deep slate for everything structural, cyan/sky for everything signalling — plus one orange family reserved exclusively for OT/ICS tags, and severity colours that never escape their alert context.

| Role | Token(s) | Hex | Usage |
|---|---|---|---|
| Page void (behind hex grid) | `--cy-bg-void` | `#020617` | full-page background |
| Dashboard body | `--cy-bg-base` | `#0b1120` | dashboard body bg |
| Card surface | `--cy-bg-raised` | `#0f172a` | card fill, fake browser chrome |
| Input / chip | `--cy-bg-input` | `#1e293b` | input field, muted badge |
| Primary brand | `--cy-sky-500` | `#0ea5e9` | borders, CTAs, glow, logo accent, "Live" dot |
| Secondary / link | `--cy-sky-400` | `#38bdf8` | link hover, logo eye ring, links in running copy |
| Soft accent | `--cy-sky-300` | `#7dd3fc` | gradient text midpoint |
| Pure cyan (logo) | `--cy-cyan-500` | `#06b6d4` | appears in the uploaded logo SVGs |
| OT/ICS tag | `--cy-orange-400` | `#fb923c` | only for OT tag badges & severity `medium` |
| IRMA / external | `--cy-violet-400` | `#a78bfa` | external-bridge alerts |
| Body text | `--cy-fg-body` | `#e2e8f0` | default copy on dark |
| Secondary copy | `--cy-fg-muted` | `#94a3b8` | feature-card descriptions |
| Meta / labels | `--cy-fg-dim` | `#64748b` | timestamps, field labels |
| Severity critical | `--cy-sev-critical` | `#ef4444` | red row border + fill tint |
| Severity high | `--cy-sev-high` | `#dc2626` | red row border + fill tint (deeper) |
| Severity medium | `--cy-sev-medium` | `#f97316` | orange row border |
| Severity low | `--cy-sev-low` | `#22c55e` | green row border |

**Rules:**

- The page is **always dark**. There is no light-mode.
- **One accent hue per surface.** The marketing hero uses sky-500 and its gradient; the dashboard alert row uses a single severity colour. Don't stack two accents.
- **Orange = OT only.** Never use orange for a button or a link; it means "industrial protocol" or "medium severity" and nothing else.
- **Violet = external source only.** Reserved for the IRMA bridge badge.
- **Severity colours never leave the alert context.** Don't colour a marketing card red; use a cyan card and put a red badge inside it.

### Typography

Two families, carrying different jobs:

- **Inter** — UI + marketing display/body. Weights shipped: 300, 400, 500, 600, 700, 800, 900.
- **JetBrains Mono** — code, identifiers, IPs, port numbers, rule IDs, AND the dashboard's default body text (the dashboard deliberately feels like a terminal).

Both are loaded from Google Fonts CDN (no local files needed):

```
https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900
&family=JetBrains+Mono:wght@400;500;600&display=swap
```

**Note on fonts:** we have not shipped local TTF/WOFF2 files in `fonts/`. The CDN URL above is the source of truth. If you need offline/embedded artifacts, self-host Inter and JetBrains Mono from Google Fonts' zip downloads — both are OFL/Apache licensed — and drop them into `fonts/`. **No substitution has been made.**

Display sizes scale from 14 px body all the way to 72 px hero display. Letter-spacing is **tight** on big display copy, **wider** than normal on eyebrows and the CYJAN wordmark. See `colors_and_type.css` for the full scale.

### Spacing & density

A strict **4 px base grid**. The two surfaces sit at opposite ends of it:

- **Marketing:** generous. Section padding is `96 px` (vertical), cards are `24 px` inside, grid gaps `16–24 px`, hero breathing room ≥ `80 px`.
- **Dashboard:** tight. Table row padding is `8 px / 12 px`, chip padding `2–6 px`, borderless 1 px dividers between rows, toolbar gap `8 px`.

### Radii

| Token | Px | Used for |
|---|---|---|
| `--cy-radius-sm` | 4 | dashboard inputs, small chips |
| `--cy-radius-md` | 6 | dashboard cards (tailwind `rounded`) |
| `--cy-radius-lg` | 8 | elevated dashboard panels |
| `--cy-radius-xl` | 12 | marketing buttons, protocol chips |
| `--cy-radius-2xl` | 16 | marketing feature cards, hero screenshot frame |
| `--cy-radius-full` | 9999 | pill badges, live-dot, avatar |

### Borders

CYJAN uses **very thin, low-opacity borders** in the brand hue rather than solid slate outlines. Typical: `1 px solid rgba(14, 165, 233, 0.15)` for card rest, escalating to `0.3` on hover. Dashboard uses `1 px solid #1e293b` (slate-800) for table dividers.

### Shadows, glows, and the cyan halo

The **cyan halo** is the signature effect — a `0 0 20–30 px rgba(14, 165, 233, 0.05–0.15)` soft outer glow layered with a 1 px border in the same hue. It appears on every card on the marketing site, on the CTAs (stronger, 30 % opacity), on the logo (`drop-shadow(0 0 40 px)`), and on the hero section. Tokens: `--cy-glow-border` / `--cy-glow-border-hover` / `--cy-glow-cta` / `--cy-glow-logo`.

Dashboard does **not** use the halo — dashboard cards get a solid-slate border and a black drop shadow instead. The halo reads as "brand", not "inside the app".

### Backgrounds

Three recurring treatments:

1. **Hex-grid tile** — 56 × 100 SVG tile, cyan strokes at `0.12` opacity, repeated. This is the site's signature backdrop. Tokenised as `--cy-bg-hexgrid`. Applied on hero and `#features` and `#quickstart` sections.
2. **Hero radial halo** — `radial-gradient(ellipse 80% 60% at 50% 0%, rgba(14,165,233,0.08) 0%, transparent 60%)`, layered on top of the hex grid behind the hero logo. Tokenised as `--cy-grad-hero-halo`.
3. **Flat slate** — `#0b1120` for dashboard body, `#0f172a` for cards, no texture.

**Never** use: glossy gradients, bokeh/photography, full-bleed marketing photos, stock illustration, noise/grain textures, geometric hero illustrations that aren't hex/network based.

### Imagery mood

Imagery is **generated by the product itself**: screenshots of the dashboard, architecture diagrams, pipeline flows. When we need a literal image (brochure cover, hero), it is always **synthetic, schematic, monochrome-cyan-on-slate**. Never warm, never grainy, never people-in-office, never abstract-data-waves. The user's brief calls for a **rotating globe with network hosts making/breaking connections** — that motif lives directly in this vocabulary.

### Iconography

Lucide-react as the primary icon system, at consistent 14–24 px stroke-1.5. See the dedicated section below.

### Animation & motion

All motion is **purposeful and short** (150–800 ms). The vocabulary:

| Animation | Duration | Easing | Used on |
|---|---|---|---|
| `fade-in` | `0.8 s` ease-out forwards | gentle | hero entrance, card reveal |
| `scan` | `3 s` linear infinite | linear | vertical scan line on logo |
| `pulse-dot` | `2 s` ease-in-out infinite | ease | "Live" dot, status LEDs |
| `ticker` | `20 s` linear infinite | linear | alert ticker below nav |
| Hover transitions | `150–250 ms` | `cubic-bezier(0.4, 0, 0.2, 1)` | all interactive elements |

**No bounces. No spring. No parallax. No scroll-triggered choreography.** Motion should read as monitoring equipment, not as a product launch.

### Hover states

Pattern is **brighten the accent, not change the colour**:

- Links: `text-slate-400 → text-sky-400`.
- Ghost buttons: border `sky-700/50 → sky-500`, text `sky-300 → sky-200`.
- Card: `box-shadow` moves from `--cy-glow-border` to `--cy-glow-border-hover`.
- Dashboard table rows: `filter: brightness(1.25)`.

### Press / active states

Minimal — CYJAN does **not** shrink or press buttons. Active states are achieved by darkening the background one step and keeping the border colour.

### Focus states

Focus ring is `outline-none` + `border-color: var(--cy-sky-500)` on inputs (per `.input` component). Buttons inherit the same cyan border treatment when focused. Always visible, never hidden.

### Transparency & blur

Used for two things only:

1. **Cards on the marketing site** — `rgba(15, 23, 42, 0.80)` + `backdrop-filter: blur(8px)` to let the hex-grid bleed through.
2. **Sticky nav / ticker** — `rgba(2, 6, 23, 0.85)` + `backdrop-filter: blur(16px)`.

Don't apply blur elsewhere. The dashboard uses **zero** blur.

### Layout rules

- **Fixed top nav** on the marketing site with 65 px height, then a 26 px alert ticker directly under it.
- **Section widths:** `max-w-7xl` (~1280 px) for marketing content; `max-w-5xl` for text-heavy sections (open-source, quick-start); `max-w-3xl` for the brochure block.
- **Grid defaults:** `md:grid-cols-2 lg:grid-cols-3` for feature cards; `md:grid-cols-2` for the two quick-start options.
- **Dashboard:** full-bleed. Header `bg-slate-900` sits above a flexed main that fills the viewport; table rows inside scroll.

---

## ICONOGRAPHY

### The primary system — Lucide

CYJAN's dashboard uses **[lucide-react](https://lucide.dev)** exclusively (see `frontend/package.json` → `lucide-react@^1.8.0`). All in-product icons are stroke-based, 1.5 weight, 14–16 px inside compact UI and 20–24 px in feature callouts. You can pull the full set from the Lucide CDN — no copying needed:

```html
<script src="https://unpkg.com/lucide@latest"></script>
<i data-lucide="shield"></i>
<!-- …or per-icon SVG:  -->
<!-- https://unpkg.com/lucide-static@latest/icons/shield.svg -->
```

Icons verified in use in the dashboard codebase:

`LayoutDashboard` · `Network` · `Server` · `FlaskConical` · `Settings` · `LogOut` · and a long tail in the settings/alerts screens.

**Colour rules:**

- Default icon colour: `var(--cy-fg-dim)` (slate-500).
- Hover / active icon colour: `var(--cy-sky-400)`.
- Severity or status icons take the matching semantic colour (`--cy-sev-*`).

### Inline-SVG icons on the marketing site

The marketing `index.html` ships **hand-written SVG icons inlined** inside each feature card, using Heroicons-style stroke paths at `stroke-width="1.5"`. They share Lucide's DNA (stroke-based, 24 × 24 viewbox) but are not pulled from the Heroicons library. When adding marketing content, prefer Lucide via CDN for consistency — substitute-flag this if you change it.

### Logos (in `assets/logos/`)

| File | What it is | When to use |
|---|---|---|
| `cyjan_splash_screen.svg` | Full splash composition — large pentagon-shield, CYJAN wordmark, "INTRUSION DETECTION SYSTEM" sub-lockup, "PROTECT · DETECT · RESPOND" bottom line, hex halo. | splash screens, print covers, brochure hero |
| `cyjan_logo_cyan_max.svg` | Full-resolution pentagon-shield + CYJAN wordmark, cyan accent. | marketing hero, login screen (currently used), section headers |
| `cyjan_logo_cyan.svg` | Lighter cyan version, same composition. | light-accent contexts, secondary placements |
| `cyjan_ids_logo_v2.svg` | Pentagon-shield + "CYJAN IDS" lockup v2. | fallback / earlier version |
| `cyjan_logo_compact.svg` | Compact shield-only, horizontal-friendly. | header marks, favicons, tiny surfaces |

All five are **SVG, vector, flat-cyan on dark**. The shield is a stretched-pentagon outline with a hex-grid interior pattern and a central "eye" (ellipse + concentric circles). The wordmark is set in a heavy geometric sans with wide tracking. **Never re-draw this logo** — always use the SVGs.

### Emoji

Avoid — see *Content Fundamentals → Emoji*.

### Unicode glyphs

Covered above under *Content Fundamentals*. The set is tight and intentional: `↓ → · ✓ ⚠ ×`.

### Substitution flag

We have **not substituted** any icon system. Lucide via CDN matches exactly what the codebase ships.

---

## Quick reference — the 10 tokens you'll use most

```css
background: var(--cy-bg-void);              /* page */
color:      var(--cy-fg-body);              /* body text */
color:      var(--cy-fg-primary);           /* headings */
border:     1px solid var(--cy-card-border);/* card outline */
box-shadow: var(--cy-glow-border);          /* card halo */
color:      var(--cy-sky-400);              /* links, accent text */
background: var(--cy-grad-primary);         /* CTA */
font-family:var(--cy-font-mono);            /* identifiers, data */
background-image: var(--cy-bg-hexgrid);     /* signature pattern */
animation: pulse-dot 2s ease-in-out infinite; /* live dot */
```

Everything else — spacing, radii, severities — is in `colors_and_type.css`.
