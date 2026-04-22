---
name: cyjan-ids-design
description: Use this skill to generate well-branded interfaces and assets for CYJAN IDS (The OT-Sentrymode — passive network intrusion detection for OT/ICS environments), either for production or throwaway prototypes/mocks/slides/landing pages. Contains design tokens, colors, type, fonts, logos, icons, and full UI kit recreations of the marketing site and in-product dashboard.
user-invocable: true
---

Read the `README.md` file at the root of this skill to understand the CYJAN product, the bilingual (English marketing / German dashboard) voice, the two-axis palette (slate structure + cyan signal + orange-only-for-OT + violet-only-for-IRMA), the cyan-halo motif, and the hex-grid signature background. Then explore the other files:

- `colors_and_type.css` — every design token (`--cy-*`) you'll ever need; import it directly or copy the values.
- `assets/logos/` — five SVG logos (shield, wordmark, compact, splash). Never re-draw the logo.
- `ui_kits/website/` — marketing-site recreation with a live animated network globe (`NetworkGlobe.jsx`) that matches the brief's "Weltkugel mit Netzwerkhosts" centerpiece.
- `ui_kits/dashboard/` — in-product dashboard recreation with sidebar, alert table, threat gauge, host inventory.
- `preview/` — small reference cards showing colors, type, shadows, chips, inputs, severity badges.

## If creating visual artifacts (slides, mocks, throwaway prototypes):

1. Copy the needed logo(s) from `assets/logos/` into your output folder.
2. Link `colors_and_type.css` (or copy the `:root` block) for tokens.
3. Reuse components from `ui_kits/*/` by copying their JSX files — they're self-contained, window-exposed, and require only React 18 + Babel.
4. Keep the hex-grid + hero-halo combo as the default background for heroes / splash surfaces.
5. Use Inter 900 with the `linear-gradient(135deg, #e0f2fe, #7dd3fc, #0ea5e9)` + text-shadow for display headlines.
6. Mono for all data, identifiers, IPs, timestamps, rule IDs.

## If working on production code:

Adopt the palette and type tokens exactly — they're already compatible with the live Tailwind config on both repos. The dashboard uses `JetBrains Mono` as its default body face (deliberate — it reads as a control-room terminal); the marketing site uses Inter. Never mix the halo and the dashboard.

## If the user invokes this skill without other guidance:

Ask what they want to build (landing section? new dashboard panel? slide? brochure?), confirm whether they want marketing-voice (English, open, headline-driven) or product-voice (German, tight, mono-first), confirm the surface size, and ask whether the rotating globe should appear. Then act as an expert CYJAN designer who outputs HTML artifacts or production code depending on the need.

## Non-negotiable brand rules

- Page is always dark. No light mode.
- Orange is OT-only — never a button, never a link.
- Violet is IRMA-only — external bridge alerts, nothing else.
- Severity colours never leave the alert context.
- No emoji in the dashboard. Marketing tolerates only the three existing open-source bullets.
- No bounces, no springs, no parallax — motion reads as monitoring equipment.
- Never re-draw the pentagon-shield logo. Always use the SVG.
