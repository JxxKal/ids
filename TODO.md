# TODO / Feature-Roadmap

Lebende Liste angedachter Features. Status-Marker:

- 🔴 geplant, noch nicht angefangen
- 🟡 in Arbeit
- ✅ erledigt (nach Merge entfernen oder unter "Erledigt" archivieren)

---

## Supply-Chain / Code-Integrity

### Signierte Update-ZIPs (cosign keyless via GitHub Actions)

🔴 **Phase B — Update-ZIPs signieren**, Aufwand ~3–4 d.

Heute werden `cyjan-ids-update-<tag>.zip` aus dem GitHub-Build-Workflow ohne kryptographische Signatur veröffentlicht. HTTPS schützt nur den Transport — wer GitHub Releases kompromittiert oder einen MITM mit gültigem Cert macht, kann den ganzen Stack tampern (die ZIPs enthalten die Docker-Images).

**Lösung:** Sigstore cosign keyless mit GitHub Actions OIDC.

- Build-Workflow `build-release.yml` signiert die ZIP nach dem Zippen mit
  `cosign sign-blob --yes <zip>` — kein Key-Management, ephemeral Cert via
  Fulcio, Eintrag in Rekor-Transparenz-Log.
- IDS hat `cosign` (single-Go-binary) im api-Image vendored.
- `api/src/routers/update.py:_run_update` ruft vor `_extract` ein
  `cosign verify-blob --certificate-identity '…workflow:build-release.yml@…'` auf.
  Bei fehlgeschlagener Verifikation → 400 mit Hinweis, force-Flag akzeptiert
  unsignierte ZIPs für Notfall-Recovery.
- UI bekommt eine Checkbox "Signaturprüfung erzwingen" (Default: an).
- Doku in README erweitert: Update-Pfad mit Verifikationsschritt.

### Signierter Reverse-Channel Master → Tap

🔴 **Phase C — Master signiert das Rule-Bundle vor Versand an Taps**, Aufwand ~2 d.

Heute mTLS-authentifiziert, aber inhaltlich ungesigned: ein kompromittierter
Master könnte böse Heuristik-Rules an alle gepairten Taps pushen.

- Master generiert beim ersten Boot einen dedizierten Reverse-Channel-Key
  (analog zur Master-CA, im `master-ca`-Volume).
- Public Key kommt beim Pairing mit der CA mit (`tap-uplink` legt ihn neben
  dem Trust-Anchor ab).
- `master-uplink` signiert `/config`-Bundle vor dem Senden.
- `tap-uplink` verifiziert vor `inotify`-Apply ins lokale signature-rules-Volume.
- Kein User-facing UI nötig — passiert komplett unter der Haube.

### SHA256-Verifikation für Suricata-Rule-Quellen

🔴 **Phase A — SHA256-Hash-Match gegen offizielles `index.yaml`**, Aufwand ~1–2 d.

Realität: ET Open & Co. publishen keine Detached-Signaturen, aber alle
relevanten Quellen liefern SHA256-Sums in `index.yaml`. Heute ziehen wir
die `.tar.gz` ohne Hash-Match.

- Beim Download: `index.yaml` von der gleichen Quelle holen, SHA256 des
  geladenen Tarballs vergleichen.
- Bei Mismatch: Source-Status in der UI auf "Hash-Mismatch" + nicht aktivieren.
- Optional: `suricata-update`-Wrapper integrieren statt selbstgebauter Pipeline
  — der macht's nativ.

---

## OT-Boundary V2

### Top-Pair-Aufschlüsselung im Wochenbericht nach Zone

🔴 **Heatmap zeigt aktuell aggregierte Counts pro `(src_zone, dst_zone)`**,
Aufwand ~1 d.

V2-Backlog: jede Zelle der Heatmap klickbar machen → öffnet ein Drilldown
mit den Top-N (src_ip, dst_ip)-Pairs für genau diese Zone-Kombination.

### Per-Severity-Floor-Constraint im rule-tuner

🔴 **DOS-Rules wieder tunbar machen**, Aufwand ~2 d.

DOS-Rules sind aktuell per Default auf der Tuner-Blacklist (siehe
`014_dos_blacklist_default.sql`), weil Quantil-Tuning auf P99,5 normalen
Top-Tail (Streaming, VoIP) nicht von Flood-Beginn unterscheidet.

Plan:
- YAML-Rules deklarieren ein optionales `tuner_quantile:`-Feld pro Rule.
  SCAN/RECON nutzen weiter 0,995 (Default), DOS deklariert
  `tuner_quantile: 0.9999` — der absolute Tail jenseits aller Streaming-Spitzen.
- Plus `severity`-basierter Floor-Constraint:
  `Threshold ≥ YAML_default × 0,5` für `severity ∈ {critical, high}`.
  Konservative Sanity-Bremse, die unabhängig vom Quantil greift.
- Beides zusammen → DOS-Blacklist-Default in 014 kann entfernt werden.

---

## Weekly Report V2

### Drill-Down pro Zone-Zelle (siehe oben)

### Per-Alert-Metric-Values im Detail-Drawer anzeigen

🔴 **Phase 4.5 schreibt sie in die DB**, Aufwand ~0.5 d.

Frontend zeigt sie noch nicht. Bei einem Alert-Detail-Drawer soll der User
sehen welche Metric-Werte zum Triggern geführt haben (z.B.
`unique_dst_ports=87`).

### Sparklines pro `rule_baselines`-Eintrag

🔴 V2-Backlog aus Phase 5, Aufwand ~1 d.

Settings → Regel-Anpassungen → ML-Tuning-Card zeigt heute nur den letzten
Stand. Kleine Time-Series-Charts (recharts/chartjs) für die Quantile-
Entwicklung pro `(rule, param, scope)` wären nett.

---

## Operational

### Auto-Update-Cron für GeoIP-DBs

🔴 Aufwand ~1 d.

Heute sind GeoIP-Files entweder im Update-ZIP enthalten (kommen also nur
beim System-Update mit) oder werden manuell hochgeladen. DB-IP veröffentlicht
am 1. jedes Monats — ein monatlicher Cron könnte automatisch ziehen
(idempotent: nur wenn neuer Stand verfügbar).

- Optional, weil die DBs auch über Update-ZIPs ankommen.
- Nice für Setups, die nicht jeden Monat ein Update einspielen.

### Backfill für Pre-V2-Boundary-Alerts

🔴 Aufwand ~2 d.

Bestandsalerts vor Migration 017 haben `boundary_src_zone`/`_dst_zone = NULL`.
Im Wochenbericht landen sie unter "unzoned". Ein einmaliger Backfill-Job
könnte sie nachträglich klassifizieren — Voraussetzung: alte
`enrichment.dst_geo` etc. ist vorhanden, plus `known_networks` zum
Zeitpunkt des Alerts (das ändern sich aber).

Alternative: einfach laufen lassen, nach 30 Tagen ist's per Retention durch.

---

## Erledigt

(Hier landen Einträge nach Merge — als Mini-Changelog für künftige Audits.)

- ✅ 2026-04-29 Heuristik-Rules `parameters:`-Block + Override-UI
- ✅ 2026-04-29 ML-Tuner Phase 1–6 (Schema, Shadow-Pipeline, DB-State, rule-tuner-Service, FP/TP-Constraints, UI, Eligibility-Filter)
- ✅ 2026-04-30 Tap-Auto-Pairing + Auto-Approve-Flow
- ✅ 2026-05-01 Heartbeat im Dashboard für Remote-Taps
- ✅ 2026-05-04 Wochenbericht Phase 1+2 (Live-Aggregat + MinIO-Archivierung + History-Liste)
- ✅ 2026-05-04 GeoIP-Datenbanken: Auto-Bundle im Update-ZIP + Settings-Upload-UI
- ✅ 2026-05-04 OT-Boundary V2: Phase A (`known_networks.kind`) + Phase B (Pipeline + V2-Map) + Phase C (3×3-Matrix-UI + Zone-Aufschlüsselung im Wochenbericht)
