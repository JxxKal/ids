# CYJAN Website — UI Kit

Recreation of the CYJAN IDS marketing landing page (source: `JxxKal/cyjan-ids-website/index.html`).

## Files
- `index.html` — full page, hero with live animated globe, capabilities grid, architecture diagram, quick-start options, open-source section, footer.
- `WebsiteComponents.jsx` — `CyjanMark`, `TopNav`, `AlertTicker`, `FeatureCard`, `CtaButton`, `Section`.
- `NetworkGlobe.jsx` — the rotating globe with dynamic network hosts forming & dissolving connections over time (TCP cyan / UDP orange / ICMP violet / red threats). The hero centerpiece the brief asked for.

## Design notes
- Hero uses hex-grid bg + radial sky halo + gradient display type + glow text-shadow.
- Every card is `rgba(15,23,42,0.8) + blur(8) + 1px cyan border at 15% → 50% on hover`.
- Motion is tight: 0.8 s fade-in on entry, 150–250 ms hovers, ticker 35 s linear, globe rotates at 0.15 °/frame.
- Copy is verbatim-styled to match the source site.
