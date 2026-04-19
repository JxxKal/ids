# CYJAN – The OT-Sentrymode

Passives Netzwerk-IDS das an einem Mirror-Port eines Switches Traffic mitschneidet, anhand von Signaturen und ML Alarme erzeugt und ein Webdashboard mit Self-Learning-Feedback-Loop bietet. Spezieller Fokus auf **OT/ICS-Umgebungen** (SCADA, Modbus, DNP3, EtherNet/IP, BACnet).

**Scope:** Nur Header-Analyse – kein SSL Deep Inspection, kein Payload-Zugriff.

---

## Architektur

```
Mirror Port
    │
    ▼
┌─────────────┐   raw-packets    ┌──────────────┐
│  Sniffer    │ ───────────────► │    Kafka     │
│  (Rust)     │   pcap-headers   │   (KRaft)    │
└─────────────┘                  └──────┬───────┘
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
                   ┌──────────────┐                      │
                   │    Alert     │◄─────────────────────┘
                   │   Manager   │
                   └──────┬───────┘
                          │ alerts-enriched
               ┌──────────▼──────────┐         ┌──────────────────────┐
               │  Enrichment Service │         │   Suricata (opt.)    │
               │  DNS/Ping/GeoIP     │         │   + snort-bridge     │
               └──────────┬──────────┘         └──────────┬───────────┘
                          │ alerts-enriched-push           │ alerts-raw
               ┌──────────▼──────────┐◄───────────────────┘
               │    TimescaleDB      │
               └──────────┬──────────┘
                          │
               ┌──────────▼──────────┐   WebSocket
               │    API Backend      │ ──────────────► Frontend (React)
               │    (FastAPI)        │◄────────────────  (Feedback)
               └──────────┬──────────┘
                          │ feedback
               ┌──────────▼──────────┐
               │   Training Loop     │
               │   (Python)          │
               └─────────────────────┘

PCAP Store ──────────────────────────► MinIO (ids-pcaps)
```

---

## Module

| Modul | Sprache | Status | Beschreibung |
|---|---|---|---|
| `sniffer` | Rust | ✅ fertig | AF_PACKET Capture, Header-Parsing, Kafka-Publishing |
| `flow-aggregator` | Python | ✅ fertig | Pakete → Flows, statistische Features (Welford, IAT-Entropie) |
| `signature-engine` | Python | ✅ fertig | Regelbasierte Erkennung mit Sliding-Window-Kontext und Hot-Reload |
| `ml-engine` | Python | ✅ fertig | Anomalie-Erkennung mit Isolation Forest, Bootstrap aus DB, inkrementeller Scaler-Update |
| `alert-manager` | Python | ✅ fertig | Deduplication (Sliding Window), Score-Normierung, DB-Write + Weiterleitung an alerts-enriched |
| `enrichment-service` | Python | ✅ fertig | Reverse-DNS, ICMP-Ping, GeoIP/ASN (MaxMind), Known-Network-Lookup, Redis-Cache, Host-Trust-Prüfung, UNKNOWN_HOST-Alert, Push-Kanal für Live-Enrichment |
| `pcap-store` | Python | ✅ fertig | Sliding-Window-Paketpuffer, PCAP-Datei-Writer, MinIO-Upload, DB-Update |
| `api` | Python FastAPI | ✅ fertig | REST + WebSocket, Alerts/Flows/Networks/Config/Tests/Hosts/Users/Rules, MinIO-Proxy, Threat-Level, CSV-Import |
| `frontend` | React + Vite + TS | ✅ fertig | Echtzeit Alert-Feed (WebSocket), Threat-Level, Enrichment, PCAP-Download, Feedback, Netzwerke, Hosts, Tests, Settings |
| `training-loop` | Python | ✅ fertig | Feedback-Collector (Kafka), semi-supervised Retrain, atomares Modell-Update |
| `traffic-generator` | Python/Scapy | ✅ fertig | 5 Test-Szenarien, Alert-Polling, TestRun-Update in DB |
| `snort` | Suricata | ✅ fertig | Paketerfassung auf Mirror-/Test-Interface, ET Open + OT/ICS-Regelsets, EVE JSON Output, Live-Reload via SIGUSR2 |
| `snort-bridge` | Python | ✅ fertig | Liest Suricata EVE JSON → normalisiert → Kafka alerts-raw; transparente Integration ohne Pipeline-Umbau |

---

## Tech Stack

| Komponente | Technologie |
|---|---|
| Packet Capture | Rust + `pcap` (libpcap/TPACKET_V3) + `pnet` |
| Message Broker | Apache Kafka 3.7 (KRaft – kein Zookeeper) |
| Datenbank | TimescaleDB (PostgreSQL 16, Hypertables) |
| Cache / Enrichment | Redis 7 |
| PCAP Storage | MinIO (S3-kompatibel) |
| ML | Python, Scikit-learn / PyTorch, River (Online-ML) |
| API | Python FastAPI + WebSocket |
| Frontend | React + Vite + TypeScript + Tailwind CSS |
| Deployment | Docker Compose |

---

## Deployment

### Voraussetzungen

- Docker Desktop (Mac/Windows) oder Docker Engine (Linux)
- `docker compose` v2

### Konfiguration

```bash
cp .env.example .env
# .env anpassen (Interfaces, Passwörter, IPs)
```

### Test-Mode (Docker Desktop / Entwicklung)

Ein Interface für alles, synthetischer Testverkehr via `traffic-generator`.

```bash
# TEST_MODE=true in .env setzen
docker compose --profile test up -d
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8001 |
| API Docs | http://localhost:8001/api/docs |
| Kafka UI | http://localhost:8080 |
| MinIO Console | http://localhost:9001 |

### Produktion

Separates Mirror- und Management-Interface. `MIRROR_IFACE`, `MANAGEMENT_IFACE` und `MANAGEMENT_IP` in `.env` setzen.

```bash
# TEST_MODE=false in .env
docker compose --profile prod up -d
```

Dashboard und API sind nur über `MANAGEMENT_IP` erreichbar.

### DB-Migrationen

```bash
# Initial (nach erstem Start):
docker exec -i ids-timescaledb psql -U ids -d ids < infra/timescaledb/migrations/001_initial.sql
docker exec -i ids-timescaledb psql -U ids -d ids < infra/timescaledb/migrations/002_host_trust.sql
docker exec -i ids-timescaledb psql -U ids -d ids < infra/timescaledb/migrations/003_users.sql
```

---

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|---|---|---|
| `TEST_MODE` | `false` | `true` = Docker Desktop / Entwicklung |
| `MIRROR_IFACE` | – | Mirror-Port Interface (Pflicht in Prod) |
| `MANAGEMENT_IFACE` | `eth0` | Management Interface (API, Ping, DNS) |
| `MANAGEMENT_IP` | `192.168.1.100` | IP für Port-Binding |
| `TEST_IFACE` | `eth0` | Interface bei TEST_MODE=true |
| `CAPTURE_SNAPLEN` | `128` | Bytes pro Paket (nur Header) |
| `CAPTURE_RING_BUFFER_MB` | `64` | AF_PACKET Ring-Buffer |
| `POSTGRES_PASSWORD` | – | TimescaleDB Passwort |
| `MINIO_ACCESS_KEY` | `ids-access` | MinIO Zugangsdaten |
| `MINIO_SECRET_KEY` | – | MinIO Secret |
| `API_SECRET_KEY` | – | JWT/Session Signing Key |
| `FLOW_TIMEOUT_S` | `30` | Flow-Inaktivitäts-Timeout |
| `DEDUP_WINDOW_S` | `300` | Alert-Deduplication Zeitfenster |
| `PCAP_WINDOW_S` | `60` | ±Sekunden PCAP-Fenster pro Alert |
| `RETRAIN_INTERVAL_S` | `86400` | ML Retrain-Interval (24h) |

---

## Dashboard

Das React-Frontend bietet fünf Tabs:

### Dashboard

- **Echtzeit Alert-Feed** via WebSocket – gruppierte und Einzelansicht umschaltbar
- **Zeitfenster-Selector** – Live, 1 Min, 15 Min, 1 Std, 4 Std, 1 Tag (Snapshot-Modus)
- **Threat-Level Anzeige** – Gauge 0–100 (grün → rot), basierend auf Alert-Gewichtung der letzten 15 min
- **KI/ML-Filter** – Ansicht auf ML-Alarme einschränken (`source=ml`)
- **Testverkehr-Toggle** – Test-Alerts ein-/ausblenden
- **Tags-Spalte** – Suricata-Regel-Tags je Alert (OT/ICS-Tags orange hervorgehoben)
- **Enrichment** – Hostname, Netzwerk-Badge, Trust-Status, GeoIP, ASN
- **PCAP-Download** – Header-only `.pcap` pro Alert (Wireshark-kompatibel)
- **Feedback** – TP/FP-Bewertung direkt im Alert-Detail → fließt in ML-Training zurück

### Netzwerke

- Bekannte Netzwerke (CIDR + Name + Farbe) anlegen, bearbeiten, löschen
- Alerts zeigen Netzwerk-Badge für bekannte Subnetze

### Hosts

- Host-Verzeichnis mit Trust-Status, Hostname, ASN, GeoIP
- Manuell anlegen, Display-Namen setzen, Trust-Flag ändern
- CSV-Bulk-Import (`Hostname;IP` oder `IP;Hostname`)

### Tests

- Test-Szenarien direkt aus dem Dashboard auslösen
- Ergebnis-Protokoll mit Latenz und Treffer-Status

### Settings

#### User Management

Lokale und SAML-synchronisierte Benutzer verwalten:

- Benutzertabelle mit Rolle, Quelle (lokal/SAML), Last-Login, Aktiv-Toggle
- Neuen lokalen Benutzer anlegen (Username, Passwort, Rolle)
- Inline-Bearbeitung (Anzeigename, E-Mail, Rolle, Passwort-Reset für lokale User)
- Löschen (letzter Admin ist geschützt)

Standard-Login nach Erstinstallation: `admin` / `changeme` → **sofort ändern!**

#### Rules Engine

Suricata-Regelsets verwalten ohne Neustart:

- **Quellen-Verwaltung** – Toggle-Schalter je Quelle, eigene URLs hinzufügen
- **Update-Button** – schreibt Trigger-Datei → Suricata lädt Regeln live neu (SIGUSR2, kein Neustart)
- **Regelübersicht** – alle aktiven Regeln mit Suche, Pagination, Aktion-Badges

Vorkonfigurierte OT/ICS-Quellen (deaktiviert, bei Bedarf aktivieren):

| Quelle | Protokoll/Fokus |
|---|---|
| ET SCADA / ICS | Allgemeine SCADA-Signaturen |
| Digital Bond Quickdraw – Modbus TCP | Modbus-Anomalien und -Angriffe |
| Digital Bond Quickdraw – DNP3 | DNP3-Protokollmissbrauch |
| Digital Bond Quickdraw – EtherNet/IP (CIP) | Rockwell/Allen-Bradley |
| Digital Bond Quickdraw – BACnet | Gebäudeautomation |
| Positive Technologies SCADA Attack Detection | ICS-Angriffserkennung |

#### SAML / SSO

IdP-Metadata-URL, SP Entity-ID, ACS-URL, Attribut-Mapping, Standard-Rolle für neue SSO-User.

---

## Host-Trust-System

Jeder Host kann als **trusted** (bekannt) markiert werden. Das senkt das Alarm-Rauschen für interne Geräte, die nicht via DNS aufgelöst werden.

### Trust-Quellen

| Quelle | Beschreibung |
|---|---|
| `dns` | Hostname automatisch per Reverse-DNS aufgelöst |
| `csv` | Manueller Import über CSV-Datei |
| `manual` | Direkt im Dashboard oder via API angelegt |

Trust wird **nie herabgestuft** – ein manuell gesetztes `trusted=true` bleibt erhalten, auch wenn der DNS-Lookup fehlschlägt.

### UNKNOWN_HOST-Alert

Der Enrichment-Service erzeugt automatisch einen Alert (`UNKNOWN_HOST_001`, Severity `low`) wenn ein privater IP-Host auftaucht, der nicht in `host_info` als trusted hinterlegt ist. Deduplication: max. 1 Alert pro IP pro Stunde.

### CSV-Import

Format: `Hostname;IP-Adresse` oder `IP-Adresse;Hostname` – Semikolon oder Komma als Trennzeichen, `#` für Kommentare.

```
# Netzwerkgeräte
Router;192.168.1.1
192.168.1.2;Drucker-EG
```

**Endpunkt:** `POST /api/hosts/import/csv` (multipart/form-data, Feld `file`)

---

## Suricata Integration (optional)

> **Hinweis:** Ursprünglich als Snort 3 geplant – Snort 3 hat kein offizielles Debian/Ubuntu-Paket. Suricata ist funktional gleichwertig, hat bessere Paket-Verfügbarkeit und die Emerging Threats Open Rules werden primär für Suricata gepflegt.

Suricata läuft als parallele Detection-Engine auf demselben Mirror-Port. Alerts fließen über einen Bridge-Service in die bestehende Kafka-Pipeline – Alert-Manager, Enrichment, Deduplication und Dashboard funktionieren ohne Änderungen.

```
Mirror Port ──► Rust Sniffer ──► flows ──► Signature Engine ─┐
              │                        ──► ML Engine          ├──► alerts-raw ──► Alert-Manager ──► ...
              └──► Suricata ──► eve.json ──► snort-bridge ────┘
                   (Container)  (Shared Vol.)  (Python)
```

### Starten

```bash
# Produktion + Suricata
docker compose --profile prod --profile snort up -d

# Test/Dev + Suricata
docker compose --profile test --profile snort-test up -d
```

### Regelsets

| Wert (`SNORT_RULESET`) | Quelle | Signaturen | Hinweis |
|---|---|---|---|
| `emerging-threats` _(Standard)_ | emergingthreats.net | ~40.000 | ET Open, nativ für Suricata |
| `none` | – | 0 | Nur Traffic-Analyse ohne Signaturen |

Regeln werden beim ersten Start heruntergeladen und im Volume `snort-rules` gecacht. Für Updates über das Dashboard: **Settings → Rules Engine → Update starten**.

Für manuelles Update beim Start:

```bash
SNORT_UPDATE_RULES=true docker compose --profile snort up -d snort
```

### Live-Reload

Das API-Backend und Suricata teilen das `snort-rules` Volume:

1. Dashboard schreibt `update-sources.txt` + `update.trigger` ins Volume
2. Suricata-Entrypoint erkennt den Trigger innerhalb von 30 s
3. Konfigurierte Quellen werden per `curl` heruntergeladen
4. Suricata lädt die neuen Regeln via `SIGUSR2` **ohne Neustart**

### Alert-Erkennung im Dashboard

Suricata-Alerts erscheinen mit `source=suricata` und `rule_id=SURICATA:GID:SID:REV` (z.B. `SURICATA:1:2001219:20`). Severity und Score werden aus dem Suricata-Severity-Feld abgeleitet (1=critical, 2=high, 3=medium, 4=low). Feedback (TP/FP) und Enrichment funktionieren identisch zu eigenen Signaturen.

---

## Kafka Topics

| Topic | Producer | Consumer | Retention | Beschreibung |
|---|---|---|---|---|
| `raw-packets` | sniffer | flow-aggregator | 10 min | Geparste Pakete (JSON) |
| `flows` | flow-aggregator | signature-engine, ml-engine | 1h | Aggregierte Flows + Features |
| `pcap-headers` | sniffer | pcap-store | 30 min | Rohe Header-Bytes für PCAP-Archiv |
| `alerts-raw` | signature-engine, ml-engine, snort-bridge | alert-manager | 24h | Rohe Alarme |
| `alerts-enriched` | alert-manager | enrichment-service, api, db-writer | 7 Tage | Angereicherte Alarme |
| `alerts-enriched-push` | enrichment-service | api (WebSocket) | 1h | Live-Enrichment-Updates |
| `feedback` | api | training-loop | 30 Tage | False-Positive/True-Positive Feedback |
| `test-commands` | api | traffic-generator | 1h | Test-Szenarien auslösen |

---

## Datenbank (TimescaleDB)

| Tabelle | Typ | Beschreibung |
|---|---|---|
| `flows` | Hypertable | Aggregierte Netzwerkflows |
| `alerts` | Hypertable | Alarme mit Enrichment + Feedback |
| `host_info` | Tabelle | Enrichment-Cache pro IP |
| `known_networks` | Tabelle (GiST-Index) | Bekannte Netzwerke (CSV-Import) |
| `system_config` | Tabelle | Betriebskonfiguration (key/value JSONB) |
| `training_samples` | Tabelle | Gelabelte Flows für ML-Retrain |
| `test_runs` | Hypertable | Ergebnis-Protokoll der Dashboard-Tests |
| `users` | Tabelle | Lokale und SAML-synchronisierte Benutzer |

PostgreSQL `LISTEN/NOTIFY` auf Channel `config_changed`: Services reagieren auf Interface-Änderungen ohne Polling.

---

## API – Details

### Endpunkte

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/alerts` | Alert-Liste (Filter: severity, source, rule_id, src_ip, is_test, ts_from, ts_to) |
| GET | `/api/alerts/{id}` | Einzelner Alert |
| PATCH | `/api/alerts/{id}/feedback` | Feedback setzen (`fp` / `tp`) |
| GET | `/api/alerts/{id}/pcap` | PCAP-Download (MinIO-Proxy, Wireshark-kompatibel) |
| GET | `/api/flows` | Flow-Liste (Filter: src_ip, dst_ip, proto, dst_port) |
| GET | `/api/stats/threat-level` | Threat-Level 0–100 (letzte 15 min, gewichtet nach Severity) |
| GET | `/api/networks` | Bekannte Netzwerke |
| POST | `/api/networks` | Netzwerk anlegen (CIDR, Name, Farbe) |
| DELETE | `/api/networks/{id}` | Netzwerk löschen |
| GET | `/api/hosts` | Host-Liste (`?trusted=`, `?search=`) |
| POST | `/api/hosts` | Host anlegen (trust_source=manual) |
| PUT | `/api/hosts/{ip}` | Display-Name / trusted-Flag ändern |
| DELETE | `/api/hosts/{ip}` | Host entfernen |
| POST | `/api/hosts/import/csv` | Bulk-Import aus CSV |
| GET | `/api/users` | Benutzerliste |
| POST | `/api/users` | Lokalen Benutzer anlegen |
| PATCH | `/api/users/{id}` | Benutzer aktualisieren (Rolle, Passwort, aktiv) |
| DELETE | `/api/users/{id}` | Benutzer löschen (letzter Admin geschützt) |
| GET | `/api/rules/sources` | Konfigurierte Rule-Quellen |
| POST | `/api/rules/sources` | Neue Quelle hinzufügen |
| PATCH | `/api/rules/sources/{id}` | Quelle aktivieren/deaktivieren |
| DELETE | `/api/rules/sources/{id}` | Benutzerdefinierte Quelle entfernen |
| GET | `/api/rules` | Aktive Regeln lesen + filtern (`?search=`, `?limit=`, `?offset=`) |
| POST | `/api/rules/update` | Update-Trigger auslösen (Suricata Live-Reload) |
| GET | `/api/rules/update/status` | Update-Status abfragen |
| GET | `/api/config` | Alle System-Config-Keys |
| PATCH | `/api/config/{key}` | Config-Key aktualisieren |
| POST | `/api/tests/run` | Test-Szenario auslösen → `test-commands` Kafka-Topic |
| GET | `/api/tests/runs` | Test-Run-Protokoll |
| WS | `/ws/alerts` | Echtzeit-Alert-Stream (initial: letzte 50 Alerts) |
| GET | `/health` | Health-Check |
| GET | `/api/docs` | Swagger UI |

### WebSocket-Protokoll

```jsonc
// Initial-Nachricht beim Verbinden:
{ "type": "initial", "data": [/* letzte 50 Alert-Objekte */] }

// Neue Alerts in Echtzeit:
{ "type": "alert", "data": { /* Alert-Objekt */ } }

// Live-Enrichment-Updates (DNS/Ping/GeoIP asynchron nachgeliefert):
{ "type": "alert_enriched", "data": { "alert_id": "uuid", "enrichment": { /* Enrichment-Objekt */ } } }
```

### Threat-Level

Score basiert auf Alerts der letzten 15 Minuten (Testverkehr ausgeschlossen):

| Severity | Gewicht | Level | Farbe |
|---|---|---|---|
| critical | 10 | ≥ 75 | rot |
| high | 5 | ≥ 50 | orange |
| medium | 2 | ≥ 25 | gelb |
| low | 1 | < 25 | grün |

Score wird auf 0–100 normiert (Cap bei 200 Rohpunkten).

---

## User Management

### Benutzerquellen

| Quelle | Beschreibung |
|---|---|
| `local` | Passwort-basiert (bcrypt), vollständig vom Admin verwaltbar |
| `saml` | Automatisch beim SSO-Login angelegt/synchronisiert, kein lokales Passwort |

### Standard-Admin

Nach der Migration `003_users.sql` wird automatisch ein Admin-Benutzer angelegt:

- **Username:** `admin`
- **Passwort:** `changeme`

**Das Passwort muss sofort nach der ersten Anmeldung geändert werden!**

### Sicherheitsregeln

- Der letzte aktive Admin-Benutzer kann nicht gelöscht werden
- SAML-Benutzer können kein lokales Passwort setzen
- Passwörter werden mit bcrypt (Faktor 12) gehasht

---

## Training Loop – Details

### Lifecycle

```
feedback (Kafka)
    │  { alert_id, feedback=tp/fp, rule_id, score }
    │
    ▼  [Background-Thread]
alert → flow JOIN in DB → features extrahieren
    │
    └──► training_samples (label=attack/normal)

[Haupt-Thread, alle RETRAIN_INTERVAL_S]
    │
    ├── count_new_samples() ≥ MIN_NEW_SAMPLES?
    │
    ▼
load_flows_for_bootstrap() + load_samples()
    │
    ▼
IsolationForest retrain (semi-supervised)
  normal Flows → Baseline
  attack-labeled Samples → contamination anpassen
    │
    └──► /models/scaler.joblib + iforest.joblib (atomar via tmp→rename)
         /models/meta.json
```

### Label-Mapping

| Feedback | Label | Bedeutung |
|---|---|---|
| `tp` | `attack` | Echter Angriff → als Outlier trainieren |
| `fp` | `normal` | Kein Angriff → als Inlier trainieren |

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka |
| `POSTGRES_DSN` | – | TimescaleDB |
| `MODELS_DIR` | `/models` | Geteiltes Volume mit ml-engine |
| `RETRAIN_INTERVAL_S` | `86400` | Mindestabstand zwischen Retrains (24h) |
| `MIN_NEW_SAMPLES` | `50` | Mindest-Neulabels für Retrain |
| `MAX_TRAIN_SAMPLES` | `100000` | Max. Trainings-Samples |
| `CONTAMINATION` | `0.01` | IsolationForest-Basiswert |

---

## Traffic Generator – Details

### Test-Szenarien

| Szenario | Methode | Ausgelöste Regel |
|---|---|---|
| `TEST_001` | TCP SYN+FIN+URG+PSH an Port 65535 | TEST_001 |
| `SCAN_001` | 100 TCP SYN an zufällige Ports in ~3s | SCAN_001 |
| `DOS_SYN_001` | 600 TCP SYN an Port 80 in ~6s | DOS_SYN_001 |
| `RECON_003` | ICMP Echo an 25 IPs | RECON_003 |
| `DNS_DGA_001` | 15 DNS-Queries mit zufälligen Hochentropie-Domains | DNS_DGA_001 |

### Flow

```
test-commands (Kafka)
    │  { run_id, scenario_id, ts }
    ▼
Scapy-Szenario ausführen
    │
    └── DB pollen: alerts WHERE rule_id=expected AND ts > start_ts (max 30s)
              │
              ├── Alert gefunden → test_runs SET triggered=true, latency_ms, alert_id
              └── Timeout       → test_runs SET triggered=false
```

---

## Datenschemas

### `raw-packets` – PacketEvent

```jsonc
{
  "ts": 1713000000.123456,        // Unix-Timestamp (Mikrosekunden)
  "iface": "eth1",
  "pkt_len": 60,                  // Originale Paketlänge
  "eth": {
    "src_mac": "aa:bb:cc:dd:ee:ff",
    "dst_mac": "11:22:33:44:55:66",
    "ethertype": 2048              // 2048=IPv4, 34525=IPv6, 2054=ARP
  },
  "ip": {
    "version": 4,                  // 4 oder 6
    "src": "192.168.1.10",
    "dst": "10.0.0.1",
    "ttl": 64,
    "proto": 6,                    // 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
    "frag": false,
    "dscp": 0
  },
  "transport": {
    "proto": "TCP",                // TCP|UDP|ICMP|ICMPv6|OTHER
    "src_port": 54321,
    "dst_port": 443,
    "tcp": {
      "flags": ["SYN"],
      "seq": 123456789,
      "ack": 0,
      "window": 65535,
      "options": ["MSS:1460", "SACK_PERM", "WScale:7", "Timestamps"]
    }
  },
  "raw_header_b64": "RQAA..."     // Base64, max snaplen Bytes, kein Payload
}
```

### `alerts-enriched` – AlertEvent

```jsonc
{
  "alert_id": "uuid-v4",
  "ts": 1713000045.0,
  "flow_id": "uuid-v4",
  "source": "signature",           // signature|ml|correlation|suricata
  "rule_id": "SCAN_001",
  "severity": "high",              // low|medium|high|critical
  "score": 0.87,
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.1",
  "proto": "TCP",
  "dst_port": 443,
  "description": "TCP SYN Portscan – 73 Ports in 60s",
  "tags": ["Portscan", "Reconnaissance"],
  "enrichment": {
    "src_hostname": "laptop.local",
    "dst_hostname": "cloudflare.com",
    "src_network": { "cidr": "192.168.1.0/24", "name": "Office LAN", "color": "#4CAF50" },
    "src_trusted": true,
    "src_trust_source": "manual",
    "dst_asn": { "number": 13335, "org": "Cloudflare" },
    "dst_geo": { "country": "US", "city": "San Jose" }
  },
  "pcap_available": true,
  "pcap_key": "alerts/uuid-v4.pcap",
  "feedback": null,                // null|fp|tp
  "is_test": false
}
```

---

## PCAP Store – Details

### Pipeline

```
pcap-headers (Kafka)           alerts-enriched (Kafka)
     │  PacketEvent (JSON)           │  AlertEvent (JSON)
     │  raw_header_b64               │
     ▼                               ▼
PacketBuffer                   PendingAlert anlegen
(sliding window ±window_s*2)   (ready_at = jetzt + window_s)
     │                               │
     └──────────────┬────────────────┘
                    │  wenn Buffer-Timestamp > ready_at:
                    ▼
            Pakete extrahieren
            [alert_ts - window_s, alert_ts + window_s]
                    │
                    ▼
            PCAP-Datei bauen (libpcap-Format, kein Payload)
                    │
                    ├──► MinIO  ids-pcaps/alerts/{alert_id}.pcap
                    └──► DB     alerts SET pcap_available=true, pcap_key=...
```

### PCAP-Format

Natives libpcap-Format (`LINKTYPE_ETHERNET`, little-endian). Enthält nur Header-Bytes (snaplen 128), **keinen Payload**. Öffenbar mit Wireshark, tcpdump, tshark.

### Pending-Alert-Mechanismus

Alerts werden mit `ready_at = jetzt + window_s` gepuffert. Erst wenn der Paketpuffer Pakete bis mindestens `alert_ts + window_s` enthält, wird das PCAP erstellt. Dadurch landen auch Pakete **nach** dem Alert-Timestamp im PCAP.
