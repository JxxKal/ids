# CYJAN – The OT-Sentrymode

Passives Netzwerk-IDS das an einem Mirror-Port eines Switches Traffic mitschneidet, anhand von Signaturen und ML Alarme erzeugt und ein Webdashboard mit Self-Learning-Feedback-Loop bietet. Spezieller Fokus auf **OT/ICS-Umgebungen** (SCADA, Modbus, DNP3, EtherNet/IP, BACnet).

**Scope:** Nur Header-Analyse – kein SSL Deep Inspection, kein Payload-Zugriff.

---

## Architektur

```
Mirror Port
    │
    ▼
┌─────────────┐   pcap-headers   ┌──────────────┐
│  Sniffer    │ ───────────────► │              │
│  (Rust)     │   raw-packets    │    Kafka     │
└─────────────┘ ───────────────► │   (KRaft)    │◄── irma-bridge (IRMA REST-API Poll)
                                 └──────┬───────┘◄── snort-bridge (Suricata EVE JSON)
                                        │
                     ┌──────────────────┼──────────────────┐
                     ▼                  ▼                   ▼
            ┌──────────────┐  ┌──────────────┐   ┌──────────────┐
            │    Flow      │  │  Signature   │   │  ML Engine   │
            │  Aggregator  │  │   Engine     │   │  (Python)    │
            │  (Python)    │  │  (Python)    │   └──────┬───────┘
            └──────┬───────┘  └──────┬───────┘          │
                   │  flows          │ alerts-raw        │
                   └────────┬────────┘                   │
                            ▼                            │
                   ┌──────────────┐◄────────────────────┘
                   │    Alert     │
                   │   Manager   │
                   └──────┬───────┘
                          │ alerts-enriched
               ┌──────────▼──────────┐
               │  Enrichment Service │
               │  DNS/Ping/GeoIP     │
               └──────────┬──────────┘
                          │ alerts-enriched-push
               ┌──────────▼──────────┐
               │    TimescaleDB      │
               └──────────┬──────────┘
                          │
               ┌──────────▼──────────┐   WebSocket / REST
               │    API Backend      │ ──────────────────► Frontend (React)
               │    (FastAPI)        │◄────────────────────  (Feedback, Config)
               └──────────┬──────────┘
                          │ feedback
               ┌──────────▼──────────┐
               │   Training Loop     │
               └─────────────────────┘

PCAP Store ──(pcap-headers + alerts-enriched)──► MinIO (ids-pcaps)
```

---

## Module

| Modul | Sprache | Status | Beschreibung |
|---|---|---|---|
| `sniffer` | Rust | ✅ | AF_PACKET Capture, Header-Parsing, Kafka-Publishing (raw-packets + pcap-headers) |
| `flow-aggregator` | Python | ✅ | Pakete → Flows, statistische Features (Welford, IAT-Entropie) |
| `signature-engine` | Python | ✅ | Regelbasierte Erkennung mit Sliding-Window-Kontext und Hot-Reload |
| `ml-engine` | Python | ✅ | Anomalie-Erkennung mit Isolation Forest, Bootstrap aus DB, inkrementeller Scaler-Update, konfigurierbarer Threshold → **[ausführliche Doku](docs/ML_ENGINE.md)** |
| `alert-manager` | Python | ✅ | Deduplication (Sliding Window), Score-Normierung, DB-Write + Weiterleitung |
| `enrichment-service` | Python | ✅ | Reverse-DNS, ICMP-Ping, GeoIP/ASN (DB-IP Lite oder MaxMind), Known-Network-Lookup, Host-Trust, **OT-Boundary V2 Zone-Klassifikation** (ot/it/internet) |
| `rule-tuner` | Python | ✅ | *(nur Master)* Reservoir-Sampling über `rule-metrics`-Topic, Quantil-basiertes Schwellwert-Tuning für Heuristik-Rules, schreibt Overrides nach 6h-Cycle (siehe [ML-Tuning](#ml-tuning--automatische-schwellwert-anpassung)) |
| `pcap-store` | Python | ✅ | Sliding-Window-Paketpuffer, PCAP-Writer, MinIO-Upload, DB-Update, WS-Push nach Upload |
| `api` | Python FastAPI | ✅ | REST + WebSocket, JWT-Auth (8h / 365d API), Swagger UI mit Bearer-Auth, alle Datenpfade |
| `frontend` | React + Vite + TS | ✅ | Echtzeit Alert-Feed, Verbindungsgraph, PCAP-Download, Feedback, ML-Konfiguration, Sidebar-Navigation |
| `training-loop` | Python | ✅ | Feedback-Collector (Kafka), semi-supervised Retrain, atomares Modell-Update |
| `traffic-generator` | Python/Scapy | ✅ | 5 Test-Szenarien, Alert-Polling, TestRun-Update in DB |
| `snort` | Suricata | ✅ | Paketerfassung auf Mirror-/Test-Interface, ET Open + OT/ICS-Regelsets, EVE JSON Output |
| `snort-bridge` | Python | ✅ | Liest Suricata EVE JSON → normalisiert → Kafka alerts-raw (`source=suricata`) |
| `irma-bridge` | Python | ✅ | Pollt IRMA REST-API, importiert externe Alarme → Kafka alerts-raw (`source=external`) |
| `master-uplink` | Python (aiohttp) | ✅ | mTLS-Endpoint (Port 8443) für Remote-Taps. WebSocket `/uplink` für Alert-/Metric-/PCAP-Frames, `/config` für Rule-Sync, **`/tap-update/<file>` mit Streaming via `sendfile`** für Update-Bundle-Auslieferung. Pollt `taps.update_requested_at` und sendet Update-Push-Frames an die WS-Connection. |
| `tap-uplink` | Python | ✅ | *(nur Tap)* mTLS-Client zum Master. Konsumiert lokales `alerts-raw` + `rule-metrics` und forwarded mit Outage-Buffer (SQLite, 1 GB Cap) zum Master. **Zusätzlich Mini-PCAP-Store**: konsumiert `pcap-headers`, hält ±60 s in-memory Ringbuffer, baut bei Tap-Alarmen ein libpcap-File und sendet es als `pcap_upload`-Frame. Empfängt `update_now`-Trigger vom Master und schreibt `/run/cyjan-update/trigger` (host bind-mount) — systemd-path-watcher startet `cyjan-tap update --from-master -y`. Reverse-Pull der Heuristik-Rules + Overrides + `known_networks` alle 5 min. |
| `tap-api` | Python | ✅ | *(nur Tap)* Minimaler Status-View + Maschinen-Endpoints für die `cyjan-tap`-CLI |

---

## Tech Stack

| Komponente | Technologie |
|---|---|
| Packet Capture | Rust + `pcap` (libpcap/TPACKET_V3) + `pnet` |
| Message Broker | Apache Kafka 3.7 (KRaft – kein Zookeeper) |
| Datenbank | TimescaleDB (PostgreSQL 16, Hypertables) |
| Cache / Enrichment | Redis 7 |
| PCAP Storage | MinIO (S3-kompatibel) |
| ML | Python, Scikit-learn (IsolationForest), River (Online-Scaler) |
| API | Python FastAPI + WebSocket |
| Frontend | React + Vite + TypeScript + Tailwind CSS |
| Deployment | Docker Compose / Debian Live ISO |

---

## Installation

### Option A – Debian Live ISO (empfohlen für Produktion)

Fertige ISO von GitHub Releases herunterladen oder selbst bauen (siehe [ISO bauen](#iso-bauen)).

```bash
# ISO auf USB-Stick schreiben
dd if=cyjan-ids-v1.x.x.iso of=/dev/sdX bs=4M status=progress

# Von USB-Stick booten (UEFI oder BIOS)
# → First-Boot-Wizard startet automatisch auf der Konsole
```

Der **First-Boot-Wizard** (`ids-setup`) führt durch:

1. **Proxy** – HTTP/HTTPS/No-Proxy für apt, Docker-Daemon, git und System
2. **Management-IP + Port** – für Web-Interface und API
3. **Mirror-Interface** – für den Packet-Sniffer (optional)
4. **Passwörter** – PostgreSQL, MinIO (Zufallsgeneration möglich), API-Secret (immer zufällig)
5. **IRMA-Integration** – URL, Benutzer, Passwort (optional)
6. **Suricata** – optionales Compose-Profil aktivieren
7. → schreibt `/opt/ids/.env`, baut Docker-Images, startet den Stack

Nach dem Setup:

```bash
# System aktualisieren (git pull + docker compose build + up)
sudo ids-update

# Konfiguration erneut aufrufen
sudo ids-setup
```

### Option B – Manuell (Docker Compose)

#### Voraussetzungen

- Docker Engine (Linux) oder Docker Desktop (Mac/Windows)
- `docker compose` v2

#### Konfiguration

```bash
cp .env.example .env
# .env anpassen (Interfaces, Passwörter, IPs)
```

#### Test-Mode (Docker Desktop / Entwicklung)

Synthetischer Testverkehr via `traffic-generator`, kein physisches Interface nötig.

```bash
# TEST_MODE=true in .env setzen
docker compose --profile test up -d
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8001 |
| **Swagger UI** | **http://localhost:8001/api/docs** |
| ReDoc | http://localhost:8001/api/redoc |
| Kafka UI | http://localhost:8080 |
| MinIO Console | http://localhost:9001 |

#### Produktion

Separates Mirror- und Management-Interface.

```bash
# .env: MIRROR_IFACE, MANAGEMENT_IFACE, MANAGEMENT_IP, TEST_MODE=false
docker compose --profile prod up -d
```

#### Mit Suricata

```bash
# Produktion + Suricata
docker compose --profile prod --profile snort up -d

# Test/Dev + Suricata
docker compose --profile test --profile snort-test up -d
```

---

## ISO bauen

Das `distro/`-Verzeichnis enthält eine vollständige `live-build`-Konfiguration für ein Debian Bookworm (amd64) Live-ISO.

### Automatisch via GitHub Actions

Bei jedem Tag-Push (`v*`) baut GitHub Actions automatisch eine ISO und hängt sie als Release-Asset an:

```bash
git tag v1.0.0
git push origin v1.0.0
# → ISO erscheint unter github.com/JxxKal/ids/releases
```

Manueller Build: Actions → „Build Cyjan IDS ISO" → **Run workflow**

> **Hinweis Offline-Update:** Release-ZIPs von GitHub enthalten vorgebaute Docker-Images (`images.tar.gz`). Nur diese ZIPs funktionieren auf Air-Gap-Systemen ohne Docker-Hub-Zugriff. Source-ZIPs (GitHub → Code → Download ZIP) enthalten keine Images.

### Lokal bauen (Debian/Ubuntu)

```bash
sudo apt-get install -y live-build debootstrap squashfs-tools xorriso

cd distro
sudo lb config
sudo lb build
# → live-image-amd64.hybrid.iso
```

---

## DB-Migrationen

Beim ersten Start (leeres Volume) laufen alle Migrations automatisch über `docker-entrypoint-initdb.d`.

Bei **bestehendem Volume** neue Migrationen manuell ausführen:

```bash
docker compose exec -T timescaledb psql -U ids -d ids \
  -f /docker-entrypoint-initdb.d/008_itop_cmdb.sql
```

| Migration | Inhalt |
|---|---|
| `001_initial.sql` | Alle Basistabellen, Hypertables, Funktionen |
| `002_host_trust.sql` | Trust-Quellen-Spalten für host_info |
| `003_users.sql` | Benutzerverwaltung + Standard-Admin |
| `004_alert_tags.sql` | `tags TEXT[]`-Spalte für alerts + GIN-Index |
| `005_api_role.sql` | `api`-Rolle in users-Tabellen CHECK-Constraint |
| `006_suricata_source.sql` | `suricata` als gültige Alert-Quelle |
| `007_external_source.sql` | `external` als gültige Alert-Quelle (IRMA-Bridge) |
| `008_itop_cmdb.sql` | `cmdb` als gültige Trust-Quelle (iTop-Integration) |
| `010_egress_boundary.sql` | Egress-Boundary-Klassifikation V1 + Whitelist-Tabelle |
| `011_remote_taps.sql` | mTLS-Pairing, Cert-Speicher, Heartbeat |
| `012_rule_tuner_baselines.sql` | `rule_baselines` für ML-Tuner + Tuning-Status-Config |
| `013_alert_metric_values.sql` | `alerts.metric_values` für FP/TP-Constraints im Tuner |
| `014_dos_blacklist_default.sql` | Default-Blacklist DOS-Rules im ML-Tuner |
| `015_tap_auto_pair.sql` | Tap-Auto-Pairing (Pending-Liste, Audit-Log) |
| `016_known_networks_kind.sql` | `known_networks.kind` (`ot`\|`it`) für OT-Boundary V2 |
| `017_alerts_boundary_zones.sql` | `alerts.boundary_{src,dst}_zone` + V2-Priority-Matrix in `system_config` |
| `018_tap_version.sql` | `taps.version` + `version_reported_at` — Tap meldet seine Version per `hello`-Frame, UI zeigt sie pro Tap |
| `019_tap_update_trigger.sql` | `taps.update_requested_at` + `update_requested_by` + `update_acked_at` — Backbone für den Pro-Tap-Update-Push aus der Master-GUI |

---

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|---|---|---|
| `TEST_MODE` | `false` | `true` = Docker Desktop / Entwicklung |
| `MIRROR_IFACE` | – | Mirror-Port Interface (Pflicht in Prod) |
| `MANAGEMENT_IFACE` | `eth0` | Management Interface (API, Ping, DNS) |
| `MANAGEMENT_IP` | `0.0.0.0` | IP für Port-Binding |
| `TEST_IFACE` | `eth0` | Interface bei TEST_MODE=true |
| `CAPTURE_SNAPLEN` | `128` | Bytes pro Paket (nur Header) |
| `CAPTURE_RING_BUFFER_MB` | `64` | AF_PACKET Ring-Buffer |
| `POSTGRES_PASSWORD` | `ids-change-me` | TimescaleDB Passwort |
| `MINIO_ACCESS_KEY` | `ids-access` | MinIO Access Key |
| `MINIO_SECRET_KEY` | `ids-secret-change-me` | MinIO Secret Key |
| `API_SECRET_KEY` | `change-me-in-production` | JWT Signing Key |
| `API_PORT` | `8001` | Externer API-Port |
| `FLOW_TIMEOUT_S` | `30` | Flow-Inaktivitäts-Timeout |
| `DEDUP_WINDOW_S` | `300` | Alert-Deduplication Zeitfenster |
| `PCAP_WINDOW_S` | `60` | ±Sekunden PCAP-Fenster pro Alert |
| `RETRAIN_INTERVAL_S` | `86400` | ML Retrain-Interval (24h) |
| `ML_BOOTSTRAP_MIN` | `500` | Mindest-Flows vor ML-Aktivierung |
| `IDS_OWN_IPS` | – | Self-Traffic-Filter: kommagetrennte Liste eigener IPs/CIDRs (z.B. `192.168.1.81,192.168.1.94` für Multi-IF-Master). Flows mit src ODER dst auf einer dieser IPs werden vor der Rule-Auswertung verworfen — verhindert FPs durch enrichment-ICMP-Pings (DOS_ICMP_001-Flood), Master-eigene DNS-Lookups, IRMA/iTop-Polls. Auch im Tap-Compose verfügbar. |
| `IRMA_BASE_URL` | `https://10.133.168.115/rest` | IRMA REST-API Basis-URL |
| `IRMA_USER` | – | IRMA-Benutzername (Rolle: RestAPI) |
| `IRMA_PASS` | – | IRMA-Passwort |
| `IRMA_POLL_INTERVAL` | `30` | Sekunden zwischen IRMA-Abfragen |
| `IRMA_SSL_VERIFY` | `false` | SSL-Zertifikat der IRMA prüfen |
| `HTTP_PROXY` | – | HTTP-Proxy (für apt, Docker, git) |
| `HTTPS_PROXY` | – | HTTPS-Proxy |
| `NO_PROXY` | – | Proxy-Ausnahmen (kommagetrennt) |

---

## Dashboard

Das UI ist bewusst nicht "Standard-SaaS-Dunkel" sondern hat einen **OT-Operator-Panel-Charakter**: hexagonales Background-Pattern als Brand-Anker, segmented LED-Style-Bars für Severity (vom VU-Meter inspiriert), corner-bracket-Treatments auf KPI-Cards, pulsierender Edge-Glow auf der Threat-Gauge im Critical-State, tabular-numerals auf allen Hero-Werten (kein Wackeln beim Live-Update), staggered Page-Load-Fade-In. Gleicher Look auf Desktop und Mobile.

### Mobile / Responsive

Die Web-Oberfläche ist von Grund auf für Touch-Devices ausgelegt — keine "Desktop-Site mit Zoom":

- **Bottom-Navigation** auf <768 px: Icon-only mit cyan-Glow auf dem aktiven Tab, Tap-Feedback (`scale(0.96)`), Glassmorphism-Hintergrund (`backdrop-blur`).
- **TopBar Mini-Threat-Donut** zeigt den aktuellen Threat-Score (22 px-Donut + Zahl) auf **jedem** Tab — Operator sieht den Status auch beim Konfigurieren von Settings/Hosts.
- **Card-Layouts statt Tabellen** für Alert-Feed, Hosts, Networks. Severity-Stripe links, Hex-Pattern-Atmosphäre als ::after, Critical-Pulse als sanfte 4 s-Animation.
- **Bottom-Sheets** für Alert-Detail, PCAP-Preview, Verbindungsgraph, Host-Connections — Drag-Handle oben, full-screen-Höhe, kein Quetschen-im-Modal.
- **Connection-Graph** rendert auf Mobile eine kompakte Connection-Liste (Proto-Stripe-Farbig, Port + Direction-Pfeil + Flow-Counter + Bytes/Pkt) statt des SVG-Graphs, der auf 390 px nicht mehr lesbar ist.
- **Alert-Feed-Filter** sind hinter einem `≡ Filter ▾`-Toggle gebündelt; Suche + Severity-Pills bleiben oben sichtbar. Counter zeigt non-default-Filter ohne Aufklappen.
- **Settings als Hamburger-Drawer** auf Mobile (240 px slide-in von links), Desktop unverändert mit vertikaler Sub-Sidebar.
- **Dismissable Mobile-Hint** (`localStorage`) in Sektionen die für Desktop optimiert sind, plus collapsible Help-Texte ("Was macht das hier?") in dichten Settings-Pages.

### Alert-Feed

- **Echtzeit-Stream** via WebSocket, automatischer Reconnect mit Token-Auth
- **Gruppiert / Einzeln** umschaltbar
- **Zeitfenster-Selector** – Live, 1 Min, 15 Min, 1 Std, 4 Std, 1 Tag
- **Quellenfilter** – Alle / Signatur / ML·KI / Suricata / Extern (IRMA)
- **Feedback-Filter** – Alle / Kein Feedback / False Positive / True Positive
- **Tag-Suche** – Tags durchsuchbar über das globale Suchfeld
- **Threat-Level Gauge** – 0–100 (grün → rot), Gewichtung nach Severity
- **Tags** – Suricata/Signatur-Tags je Alert (OT/ICS-Tags orange hervorgehoben)
- **IRMA-Badge** – violettes „IRMA"-Label bei Alarmen aus der IRMA-Bridge
- **IRMA ASSET-Filter** – Toggle-Schalter „∅ ASSET" blendet IRMA-Alarme mit `rule_id=ASSET::*` aus (bei Alarmstürmen durch Asset-Warnungen)
- **Enrichment** – Hostname, Netzwerk-Badge, Trust-Status, GeoIP, ASN
- **FP/TP-Badge** – grün (False Positive) / rot (True Positive) direkt in der Zeile
- **PCAP-Button** – grau (nicht verfügbar) / blau (Download bereit), mit Tooltip
- **CSV-Export** – gefilterte Alerts als CSV (max. 5.000 Zeilen)

### Alert-Detailansicht

- Alle Felder inkl. vollständiges Enrichment-Panel
- **Verbindungsgraph** – SVG-Overlay mit allen Flows zwischen Quelle und Ziel im ±5-min-Fenster
  - Pfeile mit Richtung (wer initiiert), Protokoll:Port, Anzahl Flows, Datenmenge
  - Farbcodierung: TCP=blau, UDP=orange, ICMP=lila
- **PCAP herunterladen** – Wireshark-kompatibles `.pcap` (nur Header, kein Payload)
- **Feedback geben** – True/False Positive mit optionaler Notiz
  - Feedback-Banner nach Setzen (grün/rot) mit Zeitstempel und Notiz
  - Fließt beim nächsten ML-Retrain als Trainings-Sample ein
  - **Adaptive Suppression**: alle nachfolgenden Alerts mit gleicher Regel +
    gleicher Verbindung (bidirektional) werden automatisch auf `low`
    herabgestuft. Details: [docs/ML_ENGINE.md](docs/ML_ENGINE.md)

### Netzwerke

- Bekannte Netzwerke (CIDR + Name + Beschreibung + Farbe + **Zone**) anlegen und löschen
- **Zone-Tag** (`kind`): `ot` (Default, OT-Scope) oder `it` (Corporate-IT, nicht im OT-Scope) — steuert die [OT-Boundary V2 Klassifikation](#ot-boundary-klassifikation-v2)
- **CSV-Import** – Bulk-Import aus Datei (5. Spalte `kind` optional, Default `ot`; Re-Imports erhalten manuell auf `it` getaggte Einträge)
- **iTop-Import** – Netzwerke aus CMDB synchronisieren (grün markiert, `kind=ot` explizit gesetzt; manuell auf `it` umgetaggte iTop-Netze bleiben `it` auch beim Re-Sync)
- **Beispiel-CSV** – Download-Button (authentifizierter Fetch)

### Hosts

- Host-Verzeichnis mit Trust-Status, Hostname, ASN, GeoIP, Last-Seen
- Manuell anlegen, Display-Namen und Trust-Flag bearbeiten, löschen
- **CSV-Import** – `Hostname;IP` oder `IP;Hostname`, Semikolon oder Komma
- **iTop-Import** – Hosts aus CMDB (CI-Namen + Management-IPs, grüner „iTop/CMDB"-Badge)
- **Beispiel-CSV** – Download-Button (authentifizierter Fetch)

### Tests

- 5 Test-Szenarien direkt aus dem Dashboard auslösen
- Ergebnis-Protokoll: Latenz, Alert-ID, Treffer-Status

### Wochenbericht

Aggregierter Detection-/Operations-Bericht für eine ISO-Woche mit Vergleich zur Vorwoche. ISO-Wochen-Selector, Print/PDF, JSON-Download, CSV-Bundle (ZIP) für Excel/Power-BI.

**Inhalt:**

- **Executive Summary** – Severity-Donut, Headline (z.B. *„4 kritische Alerts diese Woche; Spitzenreiter: SCAN_001 mit 67 Treffern."*), Trend-Pfeil ggü. Vorwoche
- **Detection** – gestapeltes Tagesdiagramm (Severity), Top-10 Regeln, Top-10 Source-IPs, Top-10 externe Ziele mit Länderflagge + ASN
- **OT-Boundary** – aktive Breaches per Priority + 3×3 **Zone-Aufschlüsselung** (Source × Destination), Top-Talker Richtung unbekannter Netze, Top-Pairs mit Geo/ASN; whitelist-suppressed Alerts werden separat ausgewiesen
- **Betrieb** – Remote-Tap-Heartbeat + Wochen-Volumen, ML/Tuner-Aktivität (FP/TP-Marks, Tuner-Cycles), Top-5 Suricata-SIDs
- **Audit** – aktive User der Woche, Whitelist-Adds

**Archivierung (MinIO):**

Beim ersten Tick nach Mo 00:00 UTC wird die abgeschlossene Woche als JSON-Snapshot in den `ids-reports`-Bucket geschrieben (`weekly/YYYY-Wnn.json`). Vergangene Wochen werden aus dem Archiv-Snapshot gelesen — robust gegen retention-Pruning der `alerts`-Hypertable, FP-Markierungen wirken auf den live-Pfad ab dem nächsten Build-Tick rückwirkend nicht mehr (frozen view). UI-Toolbar zeigt eine **History-Liste** der letzten 12 archivierten Wochen mit Headline + Total zum Schnellsprung. Endpunkte: `GET /api/reports/weekly?week=YYYY-Wnn` (JSON oder `?fmt=csv` für ZIP), `GET /api/reports/history?limit=12`.

### Settings (Sidebar-Navigation)

#### Benutzer

Lokale und SAML-synchronisierte Benutzer: Tabelle, Anlegen, Inline-Bearbeitung, Löschen.
Standard nach Erstinstallation: `admin` / `***REDACTED***` → **sofort ändern!**

**Rollen:**

| Rolle | Token-Laufzeit | Beschreibung |
|---|---|---|
| `admin` | 8 Stunden | Vollzugriff inkl. Benutzerverwaltung |
| `viewer` | 8 Stunden | Lesezugriff, Feedback setzen |
| `api` | 365 Tage | Service-Account für externe Integrationen |

Für API-User wird kein Passwort benötigt – nach dem Anlegen wird ein langlebiges JWT **einmalig** angezeigt. Über den „Token"-Button in der Benutzertabelle kann jederzeit ein neues Token generiert werden.

#### SAML / SSO

SAML 2.0 Single Sign-On, getestet mit FortiAuthenticator als IdP.

- **IdP-Metadaten XML-Import** – XML aus dem IdP einfügen, füllt Entity-ID, SSO-URL, SLO-URL und X.509-Zertifikat automatisch
- **SP Entity-ID** – bei Eingabe werden ACS-URL und SLS-URL automatisch abgeleitet
- **SP Metadata XML** – Download-Button für den IdP-Import (nur wenn aktiviert)
- **Attribut-Mapping** – konfigurierbare SAML-Attributnamen für Benutzername, E-Mail, Anzeigename
- **Standard-Rolle** – Rolle für neu angelegte SAML-Benutzer (viewer / admin)
- SAML-Benutzer werden bei Login automatisch angelegt bzw. aktualisiert
- Konflikt mit lokalem Benutzer gleichen Namens wird abgewiesen

**Flow:** Browser → `/api/auth/saml/login` → IdP → POST `/api/auth/saml/acs` → JWT → `/?saml_token=JWT` → React

#### ML-Status

Live-Anzeige: Phase (Passthrough / Learning / Active), Bootstrap-Fortschritt, 24h-Statistiken, Top-Anomalie-Features.

#### ML-Filter-Konfiguration

- Alert-Threshold, Contamination, Bootstrap-Min-Samples, Partial-Fit-Interval
- Slider mit Preset-Buttons, sofort wirkende Kontaminationsänderung löst Retrain aus

#### Regelquellen

Toggle-Schalter je Quelle, eigene URLs hinzufügen, Update-Button (Suricata Live-Reload via SIGUSR2).

Vorkonfigurierte OT/ICS-Quellen (deaktiviert, bei Bedarf aktivieren):

| Quelle | Protokoll/Fokus |
|---|---|
| ET SCADA / ICS | Allgemeine SCADA-Signaturen |
| Digital Bond Quickdraw – Modbus TCP | Modbus-Anomalien |
| Digital Bond Quickdraw – DNP3 | DNP3-Protokollmissbrauch |
| Digital Bond Quickdraw – EtherNet/IP | Rockwell/Allen-Bradley |
| Digital Bond Quickdraw – BACnet | Gebäudeautomation |
| Positive Technologies SCADA | ICS-Angriffserkennung |

#### Regelübersicht

Alle aktiven Regeln, Suche, Pagination, Aktion-Badges.

#### Regel-Anpassungen (Heuristik-Schwellwerte tunen)

Pro Heuristik-Regel der Signature-Engine lassen sich **Schwellwerte, Severity und Aktivierung** über die GUI anpassen. Der Pfad ist explizit dafür gedacht, den klassischen Alert-Sturm-Konflikt sauber aufzulösen:

- **Schwellwert hochdrehen** (z.B. SCAN_001 `port_count` von 50 → 200) wenn normaler Traffic den Default überschreitet — echte Scans bleiben damit erkannt.
- **Severity runterstufen** nur als Notnagel — das maskiert auch echte Treffer.
- **Regel deaktivieren** wenn sie für die Umgebung gar nicht passt.

Das funktioniert, weil jede Builtin-Regel ihre Schwellwerte als `parameters:`-Block deklariert (mit `default`, `min`, `max`, `label`):

```yaml
- id: SCAN_001
  name: "TCP SYN Port Scan"
  severity: high
  parameters:
    port_count: { type: int, default: 50, min: 5, max: 65535, label: "Min. Zielports" }
    window_s:   { type: int, default: 60, min: 5, max: 3600,  label: "Zeitfenster (s)" }
  condition: |
    flow.get('proto') == 'TCP'
    and ctx.unique_dst_ports(flow.get('src_ip', ''), params.window_s) > params.port_count
```

Die GUI rendert pro Rule eine Number-Input-Maske mit Range-Hinweis und Reset-Button. Werte werden gegen `min`/`max` geclampt, default-konforme Werte automatisch aus dem Override entfernt. Persistiert in `signature-rules`-Volume als `_overrides.json`:

```json
{
  "SCAN_001":  { "parameters": { "port_count": 200 } },
  "DOS_SYN_001": { "parameters": { "syn_count": 1500 } },
  "DNS_AMP_001": { "enabled": false }
}
```

- **Hot-Reload**: signature-engine reagiert via inotify, Änderungen greifen ohne Restart binnen Sekunden.
- **Reverse-Sync auf Taps**: gepairte Remote-Taps pullen das geänderte File alle 5 min und übernehmen die Schwellwerte automatisch (siehe [Remote-Tap](#remote-tap-verteilte-erfassung)).
- **Suricata** wird separat gepflegt (Rule-Sources / Eigene Signaturen) — dort gibt es einen analogen `_suricata_overrides.json`-Mechanismus für Severity + Disable, Threshold-Tuning auf Rule-Body-Ebene ist Roadmap.

#### SSL / TLS-Zertifikat

- **Server-Hostname** – setzt nginx `server_name` (wird beim nächsten Container-Neustart aktiv)
- **PEM-Upload** – Zertifikat + privater Schlüssel + optionale CA-Chain
- **PFX / PKCS#12-Import** – Windows-CA-Export direkt importieren, Passwort für privaten Schlüssel optional
- **Self-Signed generieren** – CN/Hostname, Gültigkeit, Land, Organisation
- **ACME / Let's Encrypt** – Konfiguration speichern, Zertifikatsbezug via certbot/acme.sh

nginx-Konfiguration wird beim Container-Start aus `/certs/cert.pem` + `/certs/key.pem` gelesen:
- Zertifikat vorhanden → HTTPS auf 443, HTTP→HTTPS-Redirect auf 80
- Kein Zertifikat → HTTP auf 80

#### IRMA-Integration

URL, Benutzername, Passwort, Poll-Intervall, SSL-Verifikation. Hot-Reload der Konfiguration ohne Container-Neustart.

#### iTop CMDB

Synchronisation mit iTop IP-Management (TeemIP-Extension):

- **Verbindungstest** – prüft API-Erreichbarkeit und listet Organisationen
- **Konfiguration** – Base-URL, Benutzer, Passwort, Organisations-Filter, SSL-Verifikation
- **Synchronisieren** – importiert Subnets und Hosts mit Live-Log und Statistiken

**Was synchronisiert wird:**

| iTop-Klasse | Ziel | Felder |
|---|---|---|
| `IPv4Subnet` | `known_networks` | CIDR, Name, Kommentar → grüne Farbe |
| `IPv4Address` (status=assigned) | `host_info` | IP, short_name/FQDN als Hostname |
| `Server`, `NetworkDevice`, `PC`, `ApplicationServer` | `host_info` | CI-Name, Management-IP |

- Network IP, Gateway und Broadcast werden automatisch übersprungen (`usage_name`)
- CI-Namen überschreiben DNS-Hostnamen (höhere Priorität)
- Manuell gesetzte Trust-Quellen (`manual`) werden nicht überschrieben
- CMDB-Assets erhalten das Badge **✓ iTop/CMDB** und grüne Netzwerkfarbe

#### System-Update

Offline-Update via ZIP-Upload direkt aus dem Dashboard:

1. Release-ZIP von GitHub herunterladen (enthält `images.tar.zst` + aktuelle DB-IP-Lite-GeoIP-Files + `tap-update/`-Bundle für gepairte Taps)
2. In Settings → System-Update hochladen
3. Fortschrittsbalken (0–100%) und Live-Log verfolgen
4. Nach ~20 Sekunden Seite neu laden

**Ablauf:**
- ZIP wird entpackt (`.env` und `.git` bleiben erhalten); GeoIP-`.mmdb`-Files landen in `/opt/ids/geoip/`, `tap-update/`-Inhalt für Pro-Tap-Push wird gestaged
- `docker load` lädt vorgebaute Images
- Unabhängiger Runner-Container startet `docker compose up -d --force-recreate` (überlebt api-Neustart, enrichment-service zieht die frischen GeoIP-DBs automatisch)
- `scripts/post-update.sh` läuft idempotent durch: `daemon.json`, `cyjan-maintenance.{service,timer}`, `cyjan-mirror-tune.service`, `cyjan-tap-update.{path,service}` werden installiert/aktualisiert. Auf Bestandsystemen: `sudo bash /opt/ids/scripts/post-update.sh` einmalig nachziehen.

#### PCAP-Retention

MinIO-Lifecycle-Rule für den `ids-pcaps`-Bucket: Settings → System → "PCAP Retention". Default 14 Tage, einstellbar. UI zeigt aktuellen Bucket-Verbrauch (Anzahl Files + Größe). Plus Force-Cleanup-Button für sofortigen Run der Lifecycle-Rule wenn das Volume gerade zu groß wurde. Konsistent zum Hosts-/Networks-Pattern in den Settings-Pages.

#### Remote-Tap-Update-Push

Settings → Remote Taps zeigt pro Tap die laufende Version (aus dem `hello`-Frame des `tap-uplink`-Connects). Wenn die Master-Version neuer ist als die Tap-Version, erscheint ein **„Update senden"-Button** pro Zeile. Klick → `taps.update_requested_at = now()` → `master-uplink` pollt die Spalte alle 5 s und schickt einen `update_now`-Frame über die existierende mTLS-WS-Connection an den Tap. Tap-uplink schreibt `/host/cyjan-update/trigger`, der `cyjan-tap-update.path`-systemd-Watcher startet `cyjan-tap update --from-master -y` als root am Host. Ack über `update_acked_at`. Voraussetzung: Master hat `tap-update/`-Bundle gestaged (passiert automatisch beim System-Update).

#### GeoIP-Datenbanken

Der `enrichment-service` braucht zwei `.mmdb`-Files unter `/opt/ids/geoip/` (`GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb`) für Land- und ASN-Lookup. Frei und ohne Account: [DB-IP Lite](https://db-ip.com/db/lite.php) (monatliches Update); MaxMind GeoLite2 funktioniert ebenfalls.

- **Auto-Bundle**: Update-ZIPs aus dem GitHub-Build-Workflow enthalten automatisch die aktuellen DB-IP-Lite-DBs (Fallback auf -1/-2 Monate, wenn der aktuelle Monat noch nicht released ist; failsoft falls download.db-ip.com nicht erreichbar). Beim System-Update werden sie ins `geoip/`-Volume entpackt und der enrichment-service neu gestartet.
- **Settings-Upload**: für Air-Gap-Hosts oder Custom-DBs zeigt die GUI Status pro File (Größe, Alter, MaxMind-Magic-Validierung) und akzeptiert Upload (raw `.mmdb` oder `.gz`). Atomic-Write (`.tmp` + rename), automatischer Restart des `enrichment-service` über einen unabhängigen Runner-Container.

#### OT-Boundary

3×3-Matrix für die V2-Klassifikation: pro `(Source-Zone × Destination-Zone)` eine Priority `P0`–`P3` oder `—` (kein Alert). Zonen kommen aus `known_networks.kind`: `ot` (OT-Scope), `it` (Corporate-IT, nicht im OT-Scope), `internet` (alles außerhalb). Default-Map:

|  | → OT | → IT | → Internet |
|---|---|---|---|
| **OT** | – | P2 | **P0** |
| **IT** | P1 | – | P2 |
| **Internet** | P0 | P2 | – |

Persistiert in `system_config['boundary_priority_map_v2']`, wird vom `enrichment-service` binnen 60s ohne Restart aufgepickt. Hint zur Networks-Page (IT-Netz-Pflege) inline.

---

## OT-Boundary Klassifikation (V2)

Pro Alert tagged der `enrichment-service` zwei zusätzliche Spalten und eine Priority:

```
src_ip ── known_networks.kind ──┬─► boundary_src_zone   ('ot' | 'it' | 'internet')
                                 │
dst_ip ── known_networks.kind ──┴─► boundary_dst_zone

(boundary_src_zone, boundary_dst_zone)
        │
        ▼  Lookup in system_config['boundary_priority_map_v2']
        │  (Fallback: In-Code-Default in enrichment-service/src/boundary.py)
        ▼
   boundary_priority   P0 | P1 | P2 | P3 | NULL
```

Der spezifischste CIDR-Match gewinnt: ein `/16` mit `kind=it` mit einem darin liegenden `/24` mit `kind=ot` klassifiziert IPs im `/24` korrekt als `ot`. IPs außerhalb aller `known_networks` zählen als `internet`.

**Whitelisting**: legitimer Egress-Verkehr (z.B. Office365-Telemetrie eines bekannten Hosts) wird per `egress_whitelist`-Tabelle ausgenommen — die Korrelation läuft zur Query-Zeit, kein Batch-Update auf der `alerts`-Hypertable. UI-Pfad: Alert-Detail → „Whitelist".

**Backwards-Compat**: Bestandsalerts vor Migration 017 haben `boundary_src_zone`/`boundary_dst_zone = NULL`; ihre alte `boundary_priority` aus der V1-Klassifikation bleibt unverändert. Im Wochenbericht werden sie unter „unzoned" aufgeschlüsselt. V1-Felder `boundary_net_known/_src_known/_dst_known` werden weiter befüllt für den Alert-Detail-View.

---

## Self-Traffic-Filter

Der `enrichment-service` macht für jede Alert-IP einen ICMP-Ping als Reachability-Check + Reverse-DNS-Lookup. Wenn der Mirror-Port den Master-eigenen Traffic mit-erfasst (Switch-Span-Konfiguration), tauchen diese Pings im `flows`-Topic auf — und Heuristik-Rules wie `DOS_ICMP_001` feuern mit `src=Master-IP` als FP-Flood-Alert.

Ähnliches Risiko bei Master-eigenen DNS-Lookups (DOS_UDP_001), IRMA/iTop-Polls (ML-Anomaly), Tap-Uplink-Heartbeats Richtung Master.

**Filter** in der `signature-engine`: env-Var `IDS_OWN_IPS` akzeptiert kommagetrennte Liste von Single-IPs UND CIDRs:

```env
IDS_OWN_IPS=192.168.1.81,192.168.1.94,fd00::1,10.0.0.0/24
```

In `evaluate()` und `compute_metrics()` wird vor jeder Rule-Auswertung geprüft ob `src_ip OR dst_ip` einer dieser IPs entspricht. Match → keine Alerts, keine `rule-metrics`-Samples (sonst Reservoir-Kontamination im `rule-tuner`). Beide Compose-Files (Master + Tap) reichen die Variable durch.

**Defense-in-Depth, kein Ersatz** für die Direction-Heuristik im `flow-aggregator`: die hat eigenständig eine ICMP-Type-Stage (Echo Reply 0/129 → src/dst gedreht, sodass `src` immer der Original-Initiator bleibt — auch bei Mid-Capture wo der Reply zuerst gesehen wurde).

---

## ML-Tuning – automatische Schwellwert-Anpassung

Heuristik-Regeln deklarieren ihre Schwellwerte als `parameters:`-Block (siehe [Regel-Anpassungen](#regel-anpassungen-heuristik-schwellwerte-tunen)). Ein dedizierter `rule-tuner`-Service lernt per Reservoir-Sampling das Normalverhalten des Netzes und passt diese Schwellwerte automatisch an, ohne Heuristiken während der Lernphase abzuschalten.

```
signature-engine                          rule-tuner (Master-only)
   │                                          │
   │  pro Flow → metric_value berechnet        │  Reservoir-Sampling (Algorithm R)
   │                                          │  pro (rule_id, param_name, scope) → 10k Samples
   ▼                                          ▼
Kafka rule-metrics  ──────────────────────►  Reservoirs (in-memory)
                                              │
                                              │  alle 60s: P50/P99/P995/P999 → rule_baselines (TimescaleDB)
                                              │
                                              │  alle 6h im 'tuning'-State:
                                              ▼
                                       PUT /api/sig-rules/overrides
                                              │
                                              ▼
                                    _overrides.json (signature-rules-Volume)
                                              │
                                              ▼  inotify ──► signature-engine reload
                                              │  Reverse-Channel ──► Tap-Hosts
```

**State-Maschine** (Settings → Regel-Anpassungen → ML-Tuning-Card): `idle` → `training` (10 d Default, einstellbar) → `tuning` (Continuous-Loop, 6h-Cadence, max ±20 % pro Cycle) → `paused` (manueller Pause-Button, Reservoirs füllen sich weiter aber kein Override-Write).

**Quantil-basiert + FP/TP-Constraint**:
- Schwellwert = `Quantil(samples) × Sicherheitsmarge`, geclamped auf `min`/`max` aus dem YAML-Schema
- FP-Markierungen aus dem Alert-Feedback ziehen die Untergrenze nach oben (`threshold ≥ max(metric_at_fp) + 1`); TP-Markierungen ziehen sie nach unten (`threshold ≤ min(metric_at_tp)`); Konflikt → alten Wert behalten + Warnung loggen
- Mindestens 3 Markierungen pro Rule sonst FP/TP-Pfad inaktiv (zu wenig Signal)

**Provenance**: jeder Param-Override im `_overrides.json` trägt `source: 'manual' | 'ml'`. Manuelle Bearbeitung in der GUI lockt den Param (`manual`); der Tuner fasst ihn dann nicht mehr an, bis der User in der UI explizit „ML wieder übernehmen" klickt.

**Eligibility-Filter**: pro `parameters:`-Block kann eine `eligibility:`-Condition deklariert sein (gleiche Sandbox-Sprache wie `condition:`). Nur passende Flows landen im Reservoir. Verhindert dass z.B. UDP-/ICMP-Flows ein TCP-SYN-Scan-Reservoir kontaminieren — das war 2026-04 die Ursache für falsch getunte SCAN_001-Schwellwerte und ist seit Phase 6 abgestellt.

**DOS-Default-Blacklist**: `DOS_SYN_001`, `DOS_CONN_001`, `DOS_UDP_001`, `DOS_ICMP_001` sind out-of-the-box auf der Tuner-Blacklist (`ml_tuning_config.blacklist`). Quantil-basiertes Tuning funktioniert für diese Rules nicht zuverlässig, weil normaler Top-Tail (Streaming, VoIP, mDNS-Bursts) sich mit echtem Flood-Beginn überlappt. Konservative YAML-Defaults bleiben aktiv, User kann Rules bewusst aus der Blacklist nehmen.

**Endpunkte**: `GET /api/sig-rules/ml/status`, `POST /api/sig-rules/ml/start-training`, `POST /api/sig-rules/ml/pause`, `POST /api/sig-rules/ml/resume`, `GET /api/sig-rules/ml/baselines?rule_id=…`. Alle admin-only.

---

## IRMA-Bridge

Integriert Alarme eines externen [IRMA IDS](https://irma-security.de) in den Cyjan Alert-Feed.

```
IRMA REST-API (https://10.x.x.x/rest)
    │  GET /alarm?after={last_id}  (alle 30 s)
    ▼
irma-bridge
    │  IRMA-Token läuft 2 min ab → proaktive Erneuerung alle 90 s
    │  Letzte Alarm-ID persistiert in /data/irma_last_id (kein Doppel-Import)
    ▼
Kafka alerts-raw  →  Alert-Manager  →  TimescaleDB + WebSocket
```

**Alarm-Mapping:**

| IRMA-Feld | Cyjan-Feld |
|---|---|
| `createTimestamp` | `ts` |
| `note` | `rule_id` |
| `msg` | `description` |
| `srcIp` / `dstIp` | `src_ip` / `dst_ip` |
| `port` | `dst_port` |
| `proto` | `proto` |
| – | `source = "external"` |
| – | `tags = ["irma", "external"]` |
| – | `severity` (Heuristik via note/proto, Standard: medium) |

OT-Protokolle (Modbus, DNP3, EtherNet/IP, BACnet, S7) erhalten automatisch `severity=high` und den `ot`-Tag.

**Konfiguration (.env):**

```env
IRMA_BASE_URL=https://10.133.168.115/rest
IRMA_USER=restuser
IRMA_PASS=geheim
IRMA_POLL_INTERVAL=30   # Sekunden
IRMA_SSL_VERIFY=false   # false für selbstsignierte Zertifikate
```

**Deploy:**

```bash
docker compose build irma-bridge
docker compose up -d irma-bridge
docker compose logs -f irma-bridge
```

---

## API – Swagger UI

Die API stellt eine vollständige interaktive Dokumentation bereit:

- **Swagger UI:** `http://<host>:8001/api/docs`
- **ReDoc:** `http://<host>:8001/api/redoc`
- **OpenAPI JSON:** `http://<host>:8001/api/openapi.json`

### Authentifizierung in der Swagger UI

1. `POST /api/auth/login` aufrufen (Username + Passwort im Request Body)
2. `access_token` aus der Antwort kopieren
3. Oben rechts **Authorize** klicken
4. Token eintragen → alle weiteren Requests werden automatisch authentifiziert

---

## API – Endpunkte

### Authentifizierung

| Method | Path | Beschreibung |
|---|---|---|
| POST | `/api/auth/login` | Login, gibt JWT zurück (kein Auth erforderlich) |
| GET | `/api/auth/me` | Eingeloggter Benutzer |
| GET | `/api/auth/saml/enabled` | SAML aktiviert? (öffentlich) |
| GET | `/api/auth/saml/login` | SP-initiierter SAML-Login → Redirect zum IdP |
| POST | `/api/auth/saml/acs` | Assertion Consumer Service (IdP POST) |
| GET | `/api/auth/saml/metadata` | SP-Metadata XML für IdP-Import |
| GET/POST | `/api/auth/saml/sls` | Single Logout Service |

### Alerts

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/alerts` | Alert-Liste (Filter: severity, source, rule_id, src_ip, is_test, ts_from, ts_to, feedback) |
| GET | `/api/alerts/{id}` | Einzelner Alert |
| PATCH | `/api/alerts/{id}/feedback` | Feedback setzen (`fp` / `tp` + optionale Notiz) |
| GET | `/api/alerts/{id}/pcap` | PCAP-Download (MinIO-Proxy, Wireshark-kompatibel) |
| GET | `/api/alerts/export.csv` | Gefilterte Alerts als CSV (max. 5.000 Zeilen, alle Filter) |

### Flows

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/flows` | Flow-Liste (Filter: src_ip, dst_ip, proto, dst_port) |
| GET | `/api/flows/graph` | Verbindungsgraph: alle Flows zwischen zwei IPs im Zeitfenster |

`/api/flows/graph` Parameter: `src_ip`, `dst_ip`, `center_ts` (Unix-Sekunden), `window_min` (Standard: 5).

### Netzwerke

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/networks` | Bekannte Netzwerke |
| POST | `/api/networks` | Netzwerk anlegen (CIDR, Name, Farbe) |
| DELETE | `/api/networks/{id}` | Netzwerk löschen |
| POST | `/api/networks/import/csv` | Bulk-Import aus CSV |
| GET | `/api/networks/example.csv` | Beispiel-CSV herunterladen |

### Hosts

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/hosts` | Host-Liste (`?trusted=`, `?search=`) |
| POST | `/api/hosts` | Host anlegen (trust_source=manual) |
| PUT | `/api/hosts/{ip}` | Display-Name / trusted-Flag ändern |
| DELETE | `/api/hosts/{ip}` | Host entfernen |
| POST | `/api/hosts/import/csv` | Bulk-Import aus CSV |
| GET | `/api/hosts/example.csv` | Beispiel-CSV herunterladen |

### ML / KI-Engine

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/ml/status` | Aktueller ML-Status (Phase, Bootstrap, 24h-Stats, Top-Features) |
| GET | `/api/ml/config` | ML-Konfiguration lesen |
| PATCH | `/api/ml/config` | ML-Konfiguration aktualisieren |
| POST | `/api/ml/retrain` | Sofortigen Retrain auslösen |

### Regeln

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/rules/sources` | Konfigurierte Regelquellen |
| POST | `/api/rules/sources` | Neue Quelle hinzufügen |
| PATCH | `/api/rules/sources/{id}` | Quelle aktivieren/deaktivieren |
| DELETE | `/api/rules/sources/{id}` | Benutzerdefinierte Quelle entfernen |
| GET | `/api/rules` | Aktive Regeln (`?search=`, `?limit=`, `?offset=`) |
| POST | `/api/rules/update` | Update-Trigger (Suricata Live-Reload) |
| GET | `/api/rules/update/status` | Update-Status |

### Benutzer

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/users` | Benutzerliste |
| POST | `/api/users` | Lokalen Benutzer anlegen (Rollen: admin, viewer, api) |
| PATCH | `/api/users/{id}` | Benutzer aktualisieren (Rolle, Passwort, aktiv) |
| DELETE | `/api/users/{id}` | Benutzer löschen (letzter Admin geschützt) |
| POST | `/api/users/{id}/token` | 365-Tage-JWT für API-User generieren |

### SSL / TLS

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/ssl/status` | Zertifikat-Status (Aussteller, Ablauf, Domains, Hostname) |
| POST | `/api/ssl/upload` | PEM-Zertifikat + Schlüssel + optionale CA-Chain hochladen |
| POST | `/api/ssl/upload-pfx` | PFX/PKCS#12-Datei mit Passwort importieren |
| POST | `/api/ssl/self-signed` | Self-Signed Zertifikat generieren |
| POST | `/api/ssl/acme` | ACME-Konfiguration speichern |
| GET | `/api/ssl/hostname` | Konfigurierten nginx-Hostnamen lesen |
| POST | `/api/ssl/hostname` | nginx `server_name` setzen |

### iTop CMDB

| Method | Path | Beschreibung |
|---|---|---|
| POST | `/api/itop/sync` | Synchronisation starten (Background-Task) |
| GET | `/api/itop/sync/status` | Sync-Status + Live-Log + Statistiken |
| POST | `/api/itop/test` | Verbindungstest (listet Organisationen) |

### System

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/stats/threat-level` | Threat-Level 0–100 (letzte 15 min) |
| GET | `/api/config` | Alle System-Config-Keys |
| PATCH | `/api/config/{key}` | Config-Key aktualisieren |
| POST | `/api/tests/run` | Test-Szenario auslösen |
| GET | `/api/tests/runs` | Test-Run-Protokoll |
| POST | `/api/system/update` | Offline-Update via ZIP starten |
| GET | `/api/system/update/status` | Update-Status + Fortschritt (0–100%) |
| GET | `/api/system/version` | Installierte Version |
| GET | `/health` | Health-Check (kein Auth) |

### WebSocket

| Protokoll | Path | Beschreibung |
|---|---|---|
| WS | `/ws/alerts?token=<jwt>` | Echtzeit-Alert-Stream (JWT als Query-Parameter) |

---

## WebSocket-Protokoll

Verbindung: `ws://<host>:8001/ws/alerts?token=<jwt>`

```jsonc
// Initial beim Verbinden (letzte 50 Alerts aus DB):
{ "type": "initial", "data": [ /* Alert-Objekte */ ] }

// Neuer Alert in Echtzeit:
{ "type": "alert", "data": { /* Alert-Objekt */ } }

// Live-Enrichment-Update (DNS/Ping/GeoIP asynchron):
{ "type": "alert_enriched", "data": { "alert_id": "uuid", "enrichment": { /* ... */ } } }

// PCAP wurde archiviert und ist zum Download bereit:
{ "type": "pcap_available", "data": { "alert_id": "uuid" } }

// Feedback wurde von einem User gesetzt (Multi-Client-Sync):
{ "type": "feedback_updated", "data": { "alert_id": "uuid", "feedback": "fp|tp", "feedback_ts": "ISO", "feedback_note": "..." } }
```

---

## Threat-Level

Score basiert auf Alerts der letzten 15 Minuten (Testverkehr ausgeschlossen):

| Severity | Gewicht | Level | Farbe |
|---|---|---|---|
| critical | 10 | ≥ 75 | rot |
| high | 5 | ≥ 50 | orange |
| medium | 2 | ≥ 25 | gelb |
| low | 1 | < 25 | grün |

Score wird auf 0–100 normiert (Cap bei 200 Rohpunkten).

---

## Host-Trust-System

| Trust-Quelle | Badge | Beschreibung |
|---|---|---|
| `dns` | ✓ DNS | Hostname automatisch per Reverse-DNS aufgelöst |
| `csv` | ✓ CSV | Import über CSV-Datei |
| `manual` | ✓ Manuell | Direkt im Dashboard oder via API angelegt |
| `cmdb` | ✓ iTop/CMDB | Import über iTop CMDB-Synchronisation |

Trust wird nie herabgestuft – manuell gesetztes `trusted=true` bleibt auch bei erneutem CMDB-Sync erhalten.

**UNKNOWN_HOST-Alert:** Der Enrichment-Service erzeugt automatisch einen Alert (`UNKNOWN_HOST_001`, Severity `low`) wenn ein privater IP-Host auftaucht, der nicht als trusted hinterlegt ist. Deduplication: max. 1 Alert pro IP pro Stunde.

### CSV-Format Hosts

```csv
# Spalten: hostname;ip  (oder ip;hostname – wird automatisch erkannt)
# Trennzeichen: Semikolon oder Komma
hostname;ip
router.local;192.168.1.1
fileserver;192.168.1.10
```

### CSV-Format Netzwerke

```csv
# Spalten: cidr;name;description;color
# description und color sind optional
cidr;name;description;color
192.168.1.0/24;LAN Büro;Hauptbüro;#3b82f6
10.0.0.0/8;VPN;VPN-Tunnel;#8b5cf6
```

---

## Kafka Topics

| Topic | Producer | Consumer | Beschreibung |
|---|---|---|---|
| `raw-packets` | sniffer | flow-aggregator | Geparste Pakete (JSON) |
| `flows` | flow-aggregator | signature-engine, ml-engine | Aggregierte Flows + Features |
| `pcap-headers` | sniffer | pcap-store | Rohe Header-Bytes für PCAP-Archiv |
| `alerts-raw` | signature-engine, ml-engine, snort-bridge, irma-bridge | alert-manager | Rohe Alarme aller Quellen |
| `alerts-enriched` | alert-manager | enrichment-service, api, pcap-store | Angereicherte Alarme |
| `alerts-enriched-push` | enrichment-service, pcap-store, api | api (WebSocket) | Live-Updates: Enrichment, PCAP, Feedback |
| `feedback` | api | training-loop | FP/TP-Feedback für ML-Training |
| `test-commands` | api | traffic-generator | Test-Szenarien |

---

## Datenbank (TimescaleDB)

| Tabelle | Typ | Beschreibung |
|---|---|---|
| `flows` | Hypertable | Aggregierte Netzwerkflows mit statistischen Features |
| `alerts` | Hypertable | Alarme mit Enrichment, Feedback, Tags, PCAP-Referenz |
| `host_info` | Tabelle | Enrichment-Cache pro IP (Hostname, Trust, GeoIP, ASN) |
| `known_networks` | Tabelle (GiST) | Bekannte Netzwerke – CIDR-Containment via `>>` Operator |
| `system_config` | Tabelle | Betriebskonfiguration (key/value JSONB) – SAML, IRMA, iTop, Syslog |
| `training_samples` | Tabelle | Gelabelte Flows für ML-Retrain |
| `test_runs` | Hypertable | Ergebnis-Protokoll der Dashboard-Tests |
| `users` | Tabelle | Lokale und SAML-synchronisierte Benutzer (Rollen: admin, viewer, api) |

PostgreSQL `LISTEN/NOTIFY` auf Channel `config_changed` für Interface-Änderungen ohne Polling.

---

## ML Engine – Details

### Phasen

| Phase | Beschreibung |
|---|---|
| `passthrough` | Zu wenig Trainingsdaten – alle Flows durchgelassen |
| `learning` | Bootstrap läuft – Modell sammelt Baseline-Daten |
| `active` | Modell aktiv – anomale Flows erzeugen ML-Alerts |

### Konfiguration (via Dashboard oder `PATCH /api/ml/config`)

| Parameter | Standard | Beschreibung |
|---|---|---|
| `alert_threshold` | `0.7` | Anomalie-Score ab dem ein Alert erzeugt wird (0–1) |
| `contamination` | `0.01` | Erwarteter Anteil anomaler Flows (1% = 1 von 100) |
| `bootstrap_min_samples` | `500` | Mindest-Flows für erste Modell-Erstellung |
| `partial_fit_interval` | `500` | Flows zwischen inkrementellen Scaler-Updates |

Kontaminationsänderung löst sofortigen Retrain aus.

---

## Training Loop – Details

### Feedback → Training

```
feedback (Kafka)  { alert_id, feedback=tp/fp }
    │
    ▼  alert → flow JOIN in DB → Features extrahieren
    └──► training_samples (label: tp→attack, fp→normal)

[Alle RETRAIN_INTERVAL_S oder nach Trigger]
    │
    ▼  IsolationForest retrain (semi-supervised)
    └──► /models/iforest.joblib + scaler.joblib (atomar via tmp→rename)
         /models/meta.json
```

---

## PCAP Store – Details

```
pcap-headers (Kafka)       alerts-enriched (Kafka)
     │  ts_sec, ts_usec,        │  alert_id, ts
     │  data_b64                │
     ▼                          ▼
PacketBuffer              PendingAlert (ready_at = jetzt + window_s)
(sliding window ±120s)         │
     │                         │  wenn Zeit abgelaufen:
     └─────────────────────────┤
                               ▼
                    Pakete extrahieren [ts ± window_s]
                               │
                    ┌──────────▼──────────┐
                    │  PCAP bauen         │  libpcap-Format, nur Header
                    │  MinIO upload       │  ids-pcaps/alerts/{id}.pcap
                    │  DB: pcap_available │
                    │  WS: pcap_available │  → Frontend-Button wird blau
                    └─────────────────────┘
```

PCAP-Dateien sind im nativen libpcap-Format (`LINKTYPE_ETHERNET`). Sie enthalten nur Header-Bytes (snaplen 128), **keinen Payload**. Öffenbar mit Wireshark, tcpdump, tshark.

---

## Traffic Generator – Test-Szenarien

| Szenario | Methode | Ausgelöste Regel |
|---|---|---|
| `TEST_001` | TCP SYN+FIN+URG+PSH an Port 65535 | TEST_001 |
| `SCAN_001` | 100 TCP SYN an zufällige Ports in ~3s | SCAN_001 |
| `DOS_SYN_001` | 600 TCP SYN an Port 80 in ~6s | DOS_SYN_001 |
| `RECON_003` | ICMP Echo an 25 IPs | RECON_003 |
| `DNS_DGA_001` | 15 DNS-Queries mit Hochentropie-Domains | DNS_DGA_001 |

---

## Datenschemas

### PcapRecord (pcap-headers Topic)

```jsonc
{
  "ts_sec":  1713000000,    // Sekunden seit Epoch
  "ts_usec": 123456,        // Mikrosekunden-Anteil
  "orig_len": 60,           // Originale Paketlänge
  "data_b64": "RQAA..."     // Base64-kodierte rohe Header-Bytes (max snaplen)
}
```

### AlertEvent (alerts-enriched Topic)

```jsonc
{
  "alert_id":    "uuid-v4",
  "ts":          "2026-04-19T14:15:57.624665+00:00",
  "flow_id":     "uuid-v4",
  "source":      "signature",  // signature | ml | suricata | external | test
  "rule_id":     "SCAN_001",
  "severity":    "high",       // low | medium | high | critical
  "score":       0.87,
  "src_ip":      "192.168.1.10",
  "dst_ip":      "10.0.0.1",
  "proto":       "TCP",
  "dst_port":    443,
  "description": "TCP SYN Portscan – 73 Ports in 60s",
  "tags":        ["recon", "scan"],
  "enrichment": {
    "src_hostname":    "laptop.local",
    "dst_hostname":    "cloudflare.com",
    "src_network":     { "cidr": "192.168.1.0/24", "name": "Office LAN", "color": "#4CAF50" },
    "src_trusted":     true,
    "src_trust_source": "cmdb",
    "dst_asn":         { "number": 13335, "org": "Cloudflare" },
    "dst_geo":         { "country": "US", "city": "San Jose" }
  },
  "pcap_available": true,
  "pcap_key":    "alerts/uuid-v4.pcap",
  "feedback":    null,         // null | fp | tp
  "is_test":     false
}
```

---

## Suricata Integration (optional)

Suricata läuft als parallele Detection-Engine auf demselben Mirror-Port. Alerts fließen über einen Bridge-Service in die bestehende Kafka-Pipeline.

```
Mirror Port ──► Rust Sniffer ──► Signature Engine ─┐
              │                ──► ML Engine         ├──► alerts-raw ──► Alert-Manager
              └──► Suricata ──► eve.json ──► snort-bridge ──────────────┘
```

Suricata-Alerts erscheinen mit `source=suricata`, `rule_id=SURICATA:GID:SID:REV`. Feedback und Enrichment funktionieren identisch zu eigenen Signaturen.

### Regelsets

| `SNORT_RULESET` | Quelle | Signaturen |
|---|---|---|
| `emerging-threats` (Standard) | emergingthreats.net | ~40.000 ET Open |
| `none` | – | 0 |

Live-Reload: Dashboard → Settings → Regelquellen → Update starten (SIGUSR2 an Suricata, kein Neustart).

---

## Remote-Tap (verteilte Erfassung)

Ein zentraler **Master** kann beliebig viele physisch entfernte **Remote-Taps** anbinden — kompakte Sniffer-Knoten an entfernten Switch-Mirror-Ports, die ihre Alarme über mTLS an den Master schicken und im Gegenzug Heuristik-Rules + Overrides automatisch vom Master ziehen. Die Bedienung am Tap selbst erfolgt über eine schlanke CLI; die Master-GUI verwaltet Pairing, Status und Konfiguration zentral.

### Topologie

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Master-IDS (192.168.1.81)                                           │
   │                                                                      │
   │  Mirror-Port (lokal)                                                 │
   │      │                                                               │
   │      ▼                                                               │
   │   Sniffer → Flow-Aggregator → Signature-Engine ─┐                    │
   │                                                  ▼                   │
   │                                          alerts-raw (Kafka)          │
   │                                                  ▲                   │
   │                                                  │                   │
   │                                            master-uplink             │
   │                                          (mTLS-WSS, Port 8443)       │
   │                                            │  │  │   │               │
   └────────────────────────────────────────────┼──┼──┼───┼───────────────┘
                                                │  │  │   │ mTLS
                            ┌───────────────────┘  │  │   └────────────────┐
                            ▼                      ▼  ▼                    ▼
                        Tap A                  Tap B                    Tap C
                  (192.168.1.95)             (Standort 2)          (Mobile-Sensor)
                  Mirror → Sniffer →           Mirror → …           Mirror → …
                  Flow-Agg → Sig-Eng →          (lokales Kafka)
                  alerts-raw → tap-uplink ─►  Master-Kafka
                                       ◄─── Reverse-Channel
                                            (Rules + Overrides)
```

Jeder Tap betreibt seine eigene Mini-Pipeline (Sniffer → Flow-Aggregator → Signature-Engine → lokales Kafka). Heuristiken laufen **lokal** auf dem Tap — nur fertige Alarme gehen über die Wire. Damit bleibt die Bandbreitenlast minimal, und ein temporärer Verbindungsverlust zum Master verhindert keine Erkennung.

### Pairing

1. **Master**: *Settings → Remote Taps → Pairing-Token erzeugen*. Modal fragt `Name` (frei wählbarer Tap-Bezeichner), `Standort` (optional) und `TTL` ab. Das Token wird genau einmal angezeigt — danach ist nur noch der Hash in der DB.
2. **Tap**: per SSH (oder direkt am Boot-Wizard für ISO-Installs):

   ```bash
   sudo cyjan-tap pair
   # → fragt interaktiv Master-URL (wss://192.168.1.81:8443/uplink) + Token ab
   ```

3. Der Tap-Wizard tauscht das Token gegen ein mTLS-Client-Cert + die Master-CA. Cert/Key landen im Tap-Cert-Volume, und der `tap-uplink`-Container startet automatisch die Verbindung zum Master.
4. Sobald der erste Heartbeat ankommt, erscheint der Tap im Master-UI mit `last_seen`, Standort und Anzahl bisher empfangener Alarme.

### mTLS

- Master hält eine eigene CA (`master-ca`-Volume, vom api-Container beim ersten Boot generiert).
- Pro Tap signiert der Master ein Client-Cert mit `CN=<Tap-Name>`, gültig 10 Jahre.
- master-uplink akzeptiert nur Verbindungen mit gültigem Client-Cert gegen die eigene CA.
- tap-uplink prüft das Master-Cert gegen die beim Pairing übermittelte Master-CA — kein Trust-on-First-Use, kein Zertifikat von „außen".
- **Revoke**: Master-UI → Tap-Zeile → ✕ — der Tap-Eintrag wird gelöscht, sein Cert in die Sperrliste aufgenommen, weitere Alarme werden abgewiesen.

### Outage-Buffer

`tap-uplink` schreibt jeden Alarm zunächst in eine SQLite-Queue (`/var/lib/cyjan/queue.sqlite`):

- **Online**: Alarm wird sofort an den Master geschickt und nach Ack aus der Queue gelöscht.
- **Offline**: Alarme stapeln sich in der Queue (kein Limit jenseits Festplattenkapazität).
- **Reconnect**: tap-uplink reicht den Backlog in Reihenfolge nach. Der Master deduplicated über `alert_id` — Mehrfachzustellungen sind harmlos.
- **Sichtbar im Tap-UI** (`http://<tap-ip>/`): Queue-Tiefe + letzter erfolgreicher Forward in Echtzeit.

### Reverse-Channel (Rule-Sync)

`master-uplink` stellt unter `GET /config` (mTLS-authentifiziert) ein Bundle aus:

- `builtin/*.yml` – die Heuristik-YAMLs aus `signature-engine/rules/` (Master-Stand)
- `custom/_overrides.json` – Per-Regel Disable/Severity-Override/Schwellwert-Tuning
- `custom/_suricata_overrides.json` – Per-SID Suricata-Overrides
- `custom/*.yml` – eigene Custom-Regeln, sofern angelegt
- `_known_networks.json` – aktuelle CIDR-Liste mit `kind` (`ot|it`) für die Tap-eigene OT-Boundary-Klassifikation

`tap-uplink` pullt alle 5 min, schreibt die Files atomar ins lokale `signature-rules`-Volume und triggert die Tap-eigene `signature-engine` per inotify-mtime. Damit sind GUI-Änderungen am Master innerhalb von max. 5 min auf allen verbundenen Taps aktiv, ohne dass irgendwer manuell etwas auf dem Tap-Host macht.

### Tap-PCAP (V1)

Tap-Alerts brauchen genauso PCAP-Anhänge wie Master-Alerts. Da der zentrale `pcap-store` nur am Master läuft, hält der Tap einen **eigenen Mini-Store** in `tap-uplink`:

- Sniffer schreibt `pcap-headers` (jedes Paket header-encoded bis snaplen) ins lokale Tap-Kafka.
- `tap-uplink` konsumiert das Topic, hält ±60 s als in-memory-Ringbuffer (max. 500 k Pakete cap).
- Bei einem Tap-Alarm baut tap-uplink ein libpcap-Format-File aus dem Ringbuffer (Magic 0xA1B2C3D4, LINKTYPE_ETHERNET) und sendet es als `pcap_upload`-Frame (base64) über die bestehende mTLS-WS an den Master.
- `master-uplink` lädt das in MinIO `alerts/<id>.pcap`, setzt `alerts.pcap_available = true` und broadcastet `pcap_available` über `alerts-enriched-push` ans Frontend.

Ergebnis: PCAP-Button wird auch für Tap-Alerts blau und der Download funktioniert über die normale `GET /api/alerts/{id}/pcap`-Route.

### Pro-Tap Update-Push

Master-GUI kann pro Tap einen Update-Befehl auslösen — ohne SSH zum Tap nötig:

```
Master-UI "Update senden"
   │
   ▼  PUT taps.update_requested_at = now()
   │
   ▼  master-uplink poll-loop alle 5s
   │
   ▼  send WebSocket-Frame {"type":"update_now"} über die mTLS-Connection
   │
   ▼  tap-uplink empfängt → schreibt /host/cyjan-update/trigger (bind-mount)
   │
   ▼  systemd-path-watcher cyjan-tap-update.path triggert Service
   │
   ▼  cyjan-tap update --from-master -y
   │       (curl https://master:8443/tap-update/<file> mit mTLS-Client-Cert)
   │       (Bundle wird via web.FileResponse gestreamt — sendfile-Syscall,
   │        keine RAM-Loading-Crashes auch bei 300+ MB-Bundles)
   │
   ▼  docker load + compose up -d --force-recreate
   │
   ▼  Tap-Stack-Restart-Lücke (~30 s) wird vom Outage-Buffer abgefangen
```

Voraussetzung am Tap: einmalig `cyjan-tap-update.path` + `.service`-systemd-Units installiert (passiert automatisch durch `post-update.sh` aus jedem v2.4.x+-Bundle). Voraussetzung am Master: `tap-update/`-Bundle gestaged (geschieht beim regulären System-Update).

### CLI: `cyjan-tap`

Im Tap-ISO ist eine schlanke Verwaltungs-CLI vorinstalliert (`/usr/local/bin/cyjan-tap`):

```bash
sudo cyjan-tap status               # Pair-Status, Master-URL, last_seen, Queue-Tiefe
sudo cyjan-tap connection           # Detail-View der mTLS-Verbindung (Cert-Ablauf, RTT)
sudo cyjan-tap pair                 # Geführter Pair-Flow (interaktiv: URL + Token)
sudo cyjan-tap test                 # Probe-Verbindung zum Master ohne State-Änderung
sudo cyjan-tap reconnect            # tap-uplink-Container neu starten
sudo cyjan-tap logs [<service>]     # Container-Logs (Default: tap-uplink, follow)
sudo cyjan-tap config [get|set]     # Lese/Schreibe Tap-Config-Felder
```

Die CLI hat keine harten Abhängigkeiten außer `bash` und `docker compose` — `jq` wird optional genutzt, fehlt es, fällt der Output auf Roh-JSON zurück.

### Tap-ISO

Eigenes ISO-Build (`distro/tap-config/`), erzeugt parallel zum Master-ISO im Workflow `build-release.yml`. Enthält:

- Debian Bookworm Live + Installer
- Vorgebaute Docker-Images für `sniffer`, `flow-aggregator`, `signature-engine`, `tap-uplink`, `tap-api`, lokales `kafka`
- `cyjan-tap` CLI in `/usr/local/bin`
- Boot-Wizard, der das Pairing-Token + Master-URL abfragt und sofort den Stack hochfährt

Update auf einem laufenden Tap (drei Pfade, je nach Setup):

1. **Master-Push aus der GUI** — *Settings → Remote Taps → "Update senden"*. Voll automatisch, kein SSH zum Tap nötig (siehe [Pro-Tap Update-Push](#pro-tap-update-push)). Setzt einen `cyjan-tap-update.path`-systemd-Watcher am Tap voraus, der ab v2.4.x mit jedem `post-update.sh`-Run installiert wird.
2. **CLI am Tap-Host** — `sudo cyjan-tap update --from-master`: Tap zieht selbst das Bundle aus `https://master:8443/tap-update/...`. Sinnvoll wenn der Tap gerade keine WS-Connection hat (z.B. nach längerem Outage).
3. **Klassisch via Git** — `cd /opt/ids && git pull && docker compose -f docker-compose.tap.yml build && up -d`. Fall-back wenn das Bundle am Master nicht gestaged ist.

Heuristik-Rule-Änderungen kommen ohnehin separat über den Reverse-Channel (`/config`) und brauchen keinen Container-Rebuild.
