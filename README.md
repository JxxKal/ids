# IDS – Intrusion Detection System

Passives Netzwerk-IDS das an einem Mirror-Port eines Switches Traffic mitschneidet, anhand von Signaturen und ML Alarme erzeugt und ein Webdashboard mit Self-Learning-Feedback-Loop bietet.

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
               ┌──────────▼──────────┐
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

Enrichment Service (DNS/Ping/GeoIP) ──► alerts-enriched
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
| `enrichment-service` | Python | ✅ fertig | Reverse-DNS, ICMP-Ping, GeoIP/ASN (MaxMind), Known-Network-Lookup, Redis-Cache, Host-Trust-Prüfung, UNKNOWN_HOST-Alert |
| `pcap-store` | Python | ✅ fertig | Sliding-Window-Paketpuffer, PCAP-Datei-Writer, MinIO-Upload, DB-Update |
| `api` | Python FastAPI | ✅ fertig | REST + WebSocket, Alerts/Flows/Networks/Config/Tests/Hosts, MinIO-Proxy, Threat-Level, CSV-Import |
| `frontend` | React + Vite + TS | ✅ fertig | Echtzeit Alert-Feed (WebSocket), Threat-Level, Enrichment, PCAP-Download, Feedback, Netzwerke, Hosts, Tests |
| `training-loop` | Python | ✅ fertig | Feedback-Collector (Kafka), semi-supervised Retrain, atomares Modell-Update |
| `traffic-generator` | Python/Scapy | ✅ fertig | 5 Test-Szenarien, Alert-Polling, TestRun-Update in DB |

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
| Frontend | React |
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
| API | http://localhost:8000 |
| Kafka UI | http://localhost:8080 |
| MinIO Console | http://localhost:9001 |

### Produktion

Separates Mirror- und Management-Interface. `MIRROR_IFACE`, `MANAGEMENT_IFACE` und `MANAGEMENT_IP` in `.env` setzen.

```bash
# TEST_MODE=false in .env
docker compose --profile prod up -d
```

Dashboard und API sind nur über `MANAGEMENT_IP` erreichbar.

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

### Host-API

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/api/hosts` | Liste (`?trusted=true/false`, `?search=…`) |
| `GET` | `/api/hosts/{ip}` | Einzelner Host |
| `POST` | `/api/hosts` | Host anlegen (trust_source=manual, trusted=true) |
| `PUT` | `/api/hosts/{ip}` | display_name und/oder trusted-Flag ändern |
| `DELETE` | `/api/hosts/{ip}` | Host entfernen |
| `POST` | `/api/hosts/import/csv` | Bulk-Import aus CSV |

---

## Kafka Topics

| Topic | Producer | Consumer | Retention | Beschreibung |
|---|---|---|---|---|
| `raw-packets` | sniffer | flow-aggregator | 10 min | Geparste Pakete (JSON) |
| `flows` | flow-aggregator | signature-engine, ml-engine | 1h | Aggregierte Flows + Features |
| `pcap-headers` | sniffer | pcap-store | 30 min | Rohe Header-Bytes für PCAP-Archiv |
| `alerts-raw` | signature-engine, ml-engine | alert-manager | 24h | Rohe Alarme |
| `alerts-enriched` | alert-manager | api, db-writer | 7 Tage | Angereicherte Alarme |
| `feedback` | api | training-loop | 30 Tage | False-Positive/True-Positive Feedback |
| `test-commands` | api | traffic-generator | 1h | Test-Szenarien auslösen |

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
    "dscp": 0,
    // IPv6-only (optional):
    "flow_label": null,
    "ext_headers": null            // ["HopByHop", "Routing", "Fragment"]
  },
  "transport": {
    "proto": "TCP",                // TCP|UDP|ICMP|ICMPv6|OTHER
    "src_port": 54321,
    "dst_port": 443,
    "tcp": {
      "flags": ["SYN"],            // aktive Flags
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
  "source": "signature",           // signature|ml|correlation
  "rule_id": "SCAN_001",
  "severity": "high",              // low|medium|high|critical
  "score": 0.87,                   // 0.0–1.0
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.1",
  "proto": "TCP",
  "dst_port": 443,
  "description": "TCP SYN Portscan – 73 Ports in 60s",
  "top_features": [                // ML-Erklärbarkeit (nur bei source=ml)
    { "name": "unique_dst_ports", "value": 73, "contribution": 0.42 }
  ],
  "enrichment": {
    "src_hostname": "laptop.local",
    "dst_hostname": "cloudflare.com",
    "src_network": { "cidr": "192.168.1.0/24", "name": "Office LAN", "color": "#4CAF50" },
    "dst_network": null,
    "src_ping_ms": 0.4,
    "dst_ping_ms": null,
    "src_asn": null,
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

PostgreSQL `LISTEN/NOTIFY` auf Channel `config_changed`: Services reagieren auf Interface-Änderungen ohne Polling.

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

## Dashboard Features (geplant)

- **Echtzeit Alert-Feed** via WebSocket
- **Threat-Level Slider** (0–100, grün → rot, basierend auf Alert-Gewichtung der letzten 15 min)
- **Raw Flow Visualisierung** – Timeline, Protokoll-Verteilung, Verbindungsgraph
- **IP-Anreicherung** – Hostname, Netzwerk-Badge, GeoIP, ASN, Ping-Status
- **PCAP-Download** – Header-only `.pcap` pro Alert (±60s Zeitfenster)
- **False-Positive Feedback** – ein Klick → fließt in ML-Training zurück
- **Known Networks** – CSV-Import, Netzwerk-Farbkodierung
- **Rule Engine Tests** – Test-Szenarien direkt aus dem Dashboard auslösen (EICAR-Äquivalent)
- **Settings** – Interface-Konfiguration, Known Networks verwalten

---

## Flow Aggregator – Details

### Pipeline

```
raw-packets (Kafka)
    │  poll(100ms)
    ▼
PacketEvent (Pydantic)
    │  add_packet()
    ▼
FlowState (in-memory dict, key = proto+src+dst+ports)
    │  flush_expired() alle 5s  │  TCP RST/FIN-Closed → sofort
    ▼
FlowRecord
    ├──► Kafka "flows" (confluent-kafka Producer, LZ4)
    └──► TimescaleDB (psycopg2 execute_values, Batch 100)
```

### Statistische Features pro Flow

| Feature | Berechnung |
|---|---|
| `pkt_size` (mean/std/min/max) | Welford Online-Algorithmus |
| `iat` (mean/std/min/max) | Welford auf Inter-Arrival-Times |
| `entropy_iat` | Shannon-Entropie auf 7-Bucket-Log-Histogramm |
| `pps` / `bps` | pkt_count bzw. byte_count / duration_s |
| `tcp_flags` | Anteil jedes Flags (0.0–1.0) |
| `tcp_flags_abs` | Absolute Zählwerte |
| `connection_state` | NEW→SYN_ONLY→ESTABLISHED→FIN_WAIT→CLOSED/RESET |
| `half_open` | SYN gesehen, kein einziges ACK |

### Flow-Timeouts

- **Inaktivitäts-Timeout** (`FLOW_TIMEOUT_S`, default 30s): Flow endet wenn kein Paket mehr kommt
- **Max-Duration** (`FLOW_MAX_DURATION_S`, default 300s): Sehr lange Flows werden periodisch geflushst
- **TCP RST**: Sofortiger Flush
- **TCP FIN+ACK beidseitig**: Sofortiger Flush

---

## API – Details

### Endpunkte

| Method | Path | Beschreibung |
|---|---|---|
| GET | `/api/alerts` | Alert-Liste (Filter: severity, source, rule_id, src_ip, is_test) |
| GET | `/api/alerts/{id}` | Einzelner Alert |
| PATCH | `/api/alerts/{id}/feedback` | Feedback setzen (`fp` / `tp`) |
| GET | `/api/alerts/{id}/pcap` | PCAP-Download (MinIO-Proxy, Wireshark-kompatibel) |
| GET | `/api/flows` | Flow-Liste (Filter: src_ip, dst_ip, proto, dst_port) |
| GET | `/api/stats/threat-level` | Threat-Level 0–100 (letzte 15 min, gewichtet nach Severity) |
| GET | `/api/networks` | Bekannte Netzwerke |
| POST | `/api/networks` | Netzwerk anlegen (CIDR, Name, Farbe) |
| DELETE | `/api/networks/{id}` | Netzwerk löschen |
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

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `POSTGRES_DSN` | – | TimescaleDB Verbindung |
| `REDIS_URL` | `redis://localhost:6379` | Redis |
| `KAFKA_BROKERS` | `localhost:9092` | Kafka (für test-commands + WS-Consumer) |
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | – | MinIO-Zugangsdaten |
| `PCAP_BUCKET` | `ids-pcaps` | MinIO-Bucket für PCAPs |
| `SECRET_KEY` | – | Signing-Key (für spätere Auth-Erweiterung) |
| `TEST_MODE` | `false` | Aktiviert Testverkehr-Flags |

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

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka Bootstrap-Server |
| `POSTGRES_DSN` | – | TimescaleDB Verbindung |
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO Endpoint |
| `MINIO_ACCESS_KEY` | `ids-access` | MinIO Zugangsdaten |
| `MINIO_SECRET_KEY` | – | MinIO Secret |
| `PCAP_BUCKET` | `ids-pcaps` | MinIO Bucket |
| `PCAP_WINDOW_S` | `60` | ±Sekunden um Alert-Timestamp |
| `TEST_MODE` | `false` | Beendet sich nach leerem Topic |

---

## Enrichment Service – Details

### Pipeline

```
alerts-enriched (Kafka)
    │  bereits angereichert? → überspringen
    ▼
src_ip + dst_ip
    │
    ├── Redis-Cache hit? → direkt verwenden
    │
    └── Cache miss:
        ├── Reverse-DNS   (socket.gethostbyaddr)
        ├── ICMP Ping     (icmplib, CAP_NET_RAW)
        ├── GeoIP/ASN     (MaxMind GeoLite2, optional)
        └── Known Network (DB-Funktion get_network_for_ip)
              │
              ├──► Redis-Cache (TTL 3600s)
              └──► host_info-Tabelle (upsert)
                        │
                        └──► alerts.enrichment UPDATE
```

### GeoIP-Datenbanken (optional)

Ohne MaxMind-DBs läuft der Service mit reduziertem Funktionsumfang (kein Geo/ASN). Download mit kostenlosem Account:

```
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
```

Dateien per Volume mounten:
```yaml
volumes:
  - ./geoip/GeoLite2-City.mmdb:/geoip/GeoLite2-City.mmdb:ro
  - ./geoip/GeoLite2-ASN.mmdb:/geoip/GeoLite2-ASN.mmdb:ro
```

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka Bootstrap-Server |
| `POSTGRES_DSN` | – | TimescaleDB Verbindung |
| `REDIS_URL` | `redis://localhost:6379` | Redis für IP-Enrichment-Cache |
| `PING_TIMEOUT_MS` | `1000` | ICMP Ping Timeout |
| `DNS_TIMEOUT_MS` | `2000` | Reverse-DNS Timeout |
| `CACHE_TTL_S` | `3600` | Redis-Cache Ablaufzeit |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | MaxMind City-Datenbank |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | MaxMind ASN-Datenbank |
| `TEST_MODE` | `false` | Beendet sich nach leerem Topic |

---

## Alert Manager – Details

### Pipeline

```
alerts-raw (Kafka)
    │  signature-engine + ml-engine
    ▼
Deduplication (rule_id + src_ip + dst_ip + dst_port, Sliding Window)
    │  Duplikat? → verwerfen
    ▼
Score-Normierung
    │  severity → 0.0–1.0  (Signature)
    │  score direkt        (ML)
    ▼
alert_id (UUID v4) vergeben
    │
    ├──► Kafka "alerts-enriched"  (key=src_ip, LZ4)
    └──► TimescaleDB alerts-Tabelle (Batch 50)
```

### Deduplication

Schlüssel: `(rule_id, src_ip, dst_ip, dst_port)` – innerhalb von `DEDUP_WINDOW_S` (Standard 300s) wird pro Schlüssel nur ein Alert weitergeleitet. In-memory OrderedDict, max. 50.000 Einträge.

### Score-Mapping

| Severity | Score |
|---|---|
| critical | 1.0 |
| high | 0.8 |
| medium | 0.5 |
| low | 0.2 |
| ML-Score | direkt (0.0–1.0) |

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka Bootstrap-Server |
| `POSTGRES_DSN` | – | TimescaleDB Verbindung |
| `DEDUP_WINDOW_S` | `300` | Deduplication-Zeitfenster in Sekunden |
| `TEST_MODE` | `false` | Beendet sich nach leerem Topic |

---

## ML Engine – Details

### Pipeline

```
flows (Kafka)
    │  poll(1s)
    ▼
Feature-Extraktion (14 Dimensionen)
    │
    ├──► Buffer → Scaler partial_fit (alle 200 Flows)
    │
    └──► StandardScaler → IsolationForest.decision_function()
              │  score [0.0–1.0]
              │  score ≥ 0.65 → Alert
              ▼
         alerts (Kafka)
```

### Lifecycle

1. **Gespeichertes Modell laden** (`/models/iforest.joblib`, `scaler.joblib`)
2. **Bootstrap** bei fehlendem Modell: bis zu 100k Flows aus TimescaleDB laden und IsolationForest trainieren
3. **Haupt-Loop**: Flows scoren, bei Score ≥ Schwellwert Alert publizieren
4. **Scaler partial_fit**: alle 200 Flows inkrementell angepasst
5. **Persistenz**: Modell alle 1000 Flows gespeichert (+ bei Shutdown)

### Features (14 Dimensionen)

| Feature | Beschreibung |
|---|---|
| `duration_s` | Flow-Dauer in Sekunden |
| `pkt_count` | Anzahl Pakete |
| `byte_count` | Gesamtbytes |
| `pps` / `bps` | Paket-/Byterate |
| `pkt_size_mean/std` | Paketgröße (Welford) |
| `iat_mean/std` | Inter-Arrival-Time (Welford) |
| `entropy_iat` | Shannon-Entropie IAT |
| `syn/rst/fin_ratio` | TCP-Flag-Anteile |
| `dst_port_norm` | Zielport normiert (0–1) |

### Score → Severity

| Score | Severity |
|---|---|
| ≥ 0.90 | critical |
| ≥ 0.80 | high |
| ≥ 0.70 | medium |
| ≥ 0.65 | low |

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka Bootstrap-Server |
| `POSTGRES_DSN` | – | TimescaleDB für Bootstrap |
| `MODELS_DIR` | `/models` | Persistenz-Verzeichnis |
| `BOOTSTRAP_MIN_SAMPLES` | `500` | Mindest-Flows für initiales Training |
| `PARTIAL_FIT_INTERVAL` | `200` | Flows zwischen Scaler-Updates |
| `SAVE_INTERVAL` | `1000` | Flows zwischen Modell-Saves |
| `CONTAMINATION` | `0.01` | Geschätzter Outlier-Anteil (IsolationForest) |
| `TEST_MODE` | `false` | Beendet sich nach leerem Topic |

---

## Signature Engine – Details

### Pipeline

```
flows (Kafka)
    │  poll(1s)
    ▼
flow dict
    │  ctx.record(flow)   ← Sliding-Window aktualisieren
    ▼
Regel-Evaluation (alle aktiven Regeln)
    │  eval(condition, {flow, ctx})
    ▼
Alerts → Kafka "alerts" (LZ4)
```

### Regelformat (YAML)

```yaml
- id: SCAN_001
  name: "TCP SYN Port Scan"
  description: "SYN-Pakete an >50 Ports in 60s"
  severity: high          # critical | high | medium | low
  tags: [scan, recon]
  condition: |
    flow.get('proto') == 'TCP'
    and flow.get('tcp_flags_abs', {}).get('SYN', 0) > 0
    and ctx.unique_dst_ports(flow.get('src_ip', ''), 60) > 50
```

### Verfügbare Kontextfunktionen

| Funktion | Beschreibung |
|---|---|
| `ctx.unique_dst_ports(src_ip, window_s)` | Eindeutige Ziel-Ports in den letzten N Sekunden |
| `ctx.unique_dst_ips(src_ip, window_s)` | Eindeutige Ziel-IPs in den letzten N Sekunden |
| `ctx.flow_rate(src_ip, window_s)` | Anzahl Flows in den letzten N Sekunden |
| `ctx.syn_count(src_ip, window_s)` | Summe SYN-Pakete in den letzten N Sekunden |

### Regelsets

| Datei | Regeln | Beschreibung |
|---|---|---|
| `scan.yml` | SCAN_001–006 | Port-Scans, Host-Sweep, Stealth-Scans |
| `dos.yml` | DOS_SYN/CONN/UDP/ICMP_001 | SYN Flood, Connection Flood, UDP/ICMP Flood |
| `recon.yml` | RECON_001–003 | Half-Open, Port-Sweep, RST-Scan |
| `dns.yml` | DNS_TUNNEL/DGA/AMP/NONSTANDARD_001 | DNS Tunneling, DGA, Amplification |
| `anomaly.yml` | ANOMALY_*_001 | Lange Flows, Exfiltration, Beaconing, Fragmentierung |
| `test.yml` | TEST_001 | Eingebaute Test-Signatur (immer aktiv) |

### Hot-Reload

Regelfiles werden alle 30s auf Änderungen geprüft (`reload_interval_s`). Geänderte oder neue `.yml`-Dateien werden automatisch neu geladen ohne Neustart.

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka Bootstrap-Server |
| `RULES_DIR` | `/rules` | Verzeichnis mit YAML-Regelfiles |
| `TEST_MODE` | `false` | `true` = Beendet sich nach leerem Topic |

---

## Sniffer – Details

### Thread-Modell

```
capture-thread ──[bounded channel 10k]──► main-thread (publisher)
      │                                          │
   pcap + parse                         rdkafka BaseProducer
   SIGTERM → shutdown-flag              flush on disconnect
```

**Backpressure-Strategie:** Wenn Kafka nicht nachkommt → Channel voll → `try_send` schlägt fehl → Paket verworfen + `pkts_dropped` Zähler. Der Capture-Thread blockiert **niemals**.

### Stats-Logging (alle 10s)

```
INFO sniffer stats pps="14823" drop_pct="0.00%" total_cap=148230 total_drop=0 delta_kafka=14820 parse_errors=0 kafka_errors=0
```

### Umgebungsvariablen

| Variable | Beschreibung |
|---|---|
| `MIRROR_IFACE` | Interface für AF_PACKET (Pflicht) |
| `KAFKA_BROKERS` | Kafka Bootstrap-Server |
| `CAPTURE_SNAPLEN` | Bytes pro Paket (64–65535, default 128) |
| `CAPTURE_RING_BUFFER_MB` | Ring-Buffer-Größe (4–4096 MB, default 64) |
| `TEST_MODE` | `true` = Docker-Bridge statt physischem Interface |
| `RUST_LOG` | Log-Level (default `info`) |

---

## MinIO Buckets

| Bucket | Lifecycle | Inhalt |
|---|---|---|
| `ids-pcaps` | 30 Tage | Header-only PCAPs pro Alert |
| `ids-models` | unbegrenzt | ML-Modell-Snapshots |
| `ids-exports` | 7 Tage | CSV-Exports, Reports |

---

## Known Networks – CSV Format

```csv
cidr,name,description,color
192.168.1.0/24,Office LAN,Hauptbüro,#4CAF50
10.10.0.0/16,Server DMZ,Produktions-Server,#F44336
172.16.0.0/12,VPN Pool,Remote-Mitarbeiter,#FF9800
fd00::/8,ULA Internal,Internes IPv6,#9C27B0
```

`description` und `color` sind optional.

---

## Test-Szenarien (Dashboard)

| Szenario | Erwartete Regel | Beschreibung |
|---|---|---|
| IDS Test Signature | `TEST_001` | EICAR-Äquivalent: XMAS-Scan auf Port 65535 |
| TCP SYN Port Scan | `SCAN_001` | 100 SYN-Pakete an verschiedene Ports in 5s |
| SYN Flood | `DOS_SYN_001` | 500 SYN/s an einen Port |
| ICMP Host Sweep | `RECON_001` | Ping-Sweep über 50 IPs |
| DNS High-Entropy | `DNS_DGA_001` | DGA-ähnliche Subdomain-Queries |
| Large Flow (ML) | ML-basiert | Sustained High-Bandwidth Flow |

---

## Docker Compose Netzwerk

```
ids-net: 172.28.0.0/24
traffic-generator (Test): 172.28.0.100 (feste IP als Angriffsziel)
```

Externe Ports (nur localhost oder MANAGEMENT_IP):

| Port | Service |
|---|---|
| 3000 | Frontend |
| 8000 | API |
| 8080 | Kafka UI |
| 9001 | MinIO Console |
| 5432 | TimescaleDB (nur localhost) |
| 6379 | Redis (nur localhost) |
| 9094 | Kafka External (nur localhost) |
