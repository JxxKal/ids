# CYJAN Dashboard — UI Kit

Recreation of the in-product React dashboard (source: `JxxKal/ids/frontend/`).

## Files
- `index.html` — app shell with sidebar nav, top bar + KPIs, dashboard overview (threat gauge + severity/protocol breakdowns), live alert table with tabs + filters, host inventory screen.
- `DashboardComponents.jsx` — `DashSidebar`, `DashTopBar`, `SevBadge`, `AlertTable`, `ThreatGauge`, `HostRow`.

## Interactive behaviour
- Sidebar nav switches between Dashboard / Hosts (mocked) and placeholder screens for the three others.
- Severity filter buttons + search field filter alerts live.
- Live tab injects a fresh alert every 3.5 s to simulate the Kafka-backed live feed.
- Feedback glyphs (`✓` / `⚠`) hint at the true/false-positive flow.

## Notes
- German UI copy, English data nouns — matches the original's bilingual convention.
- Mono-first typography throughout; dashboard never uses the cyan halo.
