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
| `enrichment-service` | Python | ✅ fertig | Reverse-DNS, ICMP-Ping, GeoIP/ASN (MaxMind), Known-Network-Lookup, Redis-Cache |
| `pcap-store` | Python | 🔜 geplant | Header-PCAP Archivierung in MinIO |
| `api` | Python FastAPI | 🔜 geplant | REST + WebSocket für Dashboard |
| `frontend` | React | 🔜 geplant | Echtzeit-Dashboard, Threat-Level, Tests |
| `training-loop` | Python | 🔜 geplant | Feedback → ML-Modell-Update |
| `traffic-generator` | Python/Scapy | 🔜 geplant | Synthetischer Testverkehr (nur Test-Mode) |

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
