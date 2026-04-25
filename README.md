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
| `enrichment-service` | Python | ✅ | Reverse-DNS, ICMP-Ping, GeoIP/ASN (MaxMind), Known-Network-Lookup, Redis-Cache, Host-Trust-Prüfung |
| `pcap-store` | Python | ✅ | Sliding-Window-Paketpuffer, PCAP-Writer, MinIO-Upload, DB-Update, WS-Push nach Upload |
| `api` | Python FastAPI | ✅ | REST + WebSocket, JWT-Auth (8h / 365d API), Swagger UI mit Bearer-Auth, alle Datenpfade |
| `frontend` | React + Vite + TS | ✅ | Echtzeit Alert-Feed, Verbindungsgraph, PCAP-Download, Feedback, ML-Konfiguration, Sidebar-Navigation |
| `training-loop` | Python | ✅ | Feedback-Collector (Kafka), semi-supervised Retrain, atomares Modell-Update |
| `traffic-generator` | Python/Scapy | ✅ | 5 Test-Szenarien, Alert-Polling, TestRun-Update in DB |
| `snort` | Suricata | ✅ | Paketerfassung auf Mirror-/Test-Interface, ET Open + OT/ICS-Regelsets, EVE JSON Output |
| `snort-bridge` | Python | ✅ | Liest Suricata EVE JSON → normalisiert → Kafka alerts-raw (`source=suricata`) |
| `irma-bridge` | Python | ✅ | Pollt IRMA REST-API, importiert externe Alarme → Kafka alerts-raw (`source=external`) |

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

- Bekannte Netzwerke (CIDR + Name + Beschreibung + Farbe) anlegen und löschen
- **CSV-Import** – Bulk-Import aus Datei
- **iTop-Import** – Netzwerke aus CMDB synchronisieren (grün markiert)
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

### Settings (Sidebar-Navigation)

#### Benutzer

Lokale und SAML-synchronisierte Benutzer: Tabelle, Anlegen, Inline-Bearbeitung, Löschen.
Standard nach Erstinstallation: `admin` / `admin-change-me` → **sofort ändern!**

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

1. Release-ZIP von GitHub herunterladen (enthält `images.tar.gz`)
2. In Settings → System-Update hochladen
3. Fortschrittsbalken (0–100%) und Live-Log verfolgen
4. Nach ~20 Sekunden Seite neu laden

**Ablauf:**
- ZIP wird entpackt (`.env` und `.git` bleiben erhalten)
- `docker load` lädt vorgebaute Images
- Unabhängiger Runner-Container startet `docker compose up -d` (überlebt api-Neustart)

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
