# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

Dieses Repository (VS Code, macOS) ist die **Source of Truth** und wird auf GitHub (`JxxKal/ids`) gespiegelt.
Der **Docker-Zielhost** ist `192.168.1.79`; Sourcen und Compose-Stack liegen dort unter `/opt/ids`.

### Zyklus

1. **Lokal editieren** in VS Code (`/Users/jankaluza/Desktop/ids`).
2. **Committen & pushen** (GitHub MCP oder `git push`) — der Push ist gleichzeitig das Deployment-Signal.
3. **Dockerhost aktualisieren** via SSH (`ssh-manager` MCP oder direktes SSH zu `192.168.1.79`):
   ```bash
   cd /opt/ids && git pull
   docker compose --profile prod build <geänderter-service>   # nur die betroffenen Services
   docker compose --profile prod up -d
   ```
   - Bei Frontend-Änderungen: `docker compose build frontend && docker compose up -d frontend`
   - Bei API-Änderungen: `docker compose build api && docker compose up -d api`
   - Bei Migrations/DB-Änderungen: ggf. `docker compose exec -T timescaledb psql -U ids -d ids -f /docker-entrypoint-initdb.d/<migration>.sql`
4. **Validieren mit Chrome DevTools** (MCP `chrome-devtools`):
   - UI unter `http://192.168.1.79:8001` öffnen
   - Login: `admin` / `Abcdmin01`
   - Auf Console-Errors, Network-Fehler und funktionale Regressionen prüfen
   - Bei UI-Änderungen: Golden Path + Edge Cases im Browser durchspielen

### Wichtig

- **Niemals direkt auf dem Dockerhost editieren** — jede Änderung geht durch Git.
- **Container-Logs bei Problemen**: `docker compose logs -f <service>` auf dem Host.
- **ISO-Build** läuft in GitHub Actions, nicht auf dem Dockerhost (Tag-Push `v*` oder `workflow_dispatch`).

## Commands

### Running the Stack

```bash
# Development/test mode (synthetic traffic, single interface)
docker compose --profile test up -d

# Production mode (mirror + management interfaces)
docker compose --profile prod up -d

# With Suricata integration
docker compose --profile test --profile snort-test up -d
docker compose --profile prod --profile snort up -d

# Logs
docker compose logs -f <service-name>
```

### Frontend

```bash
cd frontend
npm ci
npm run dev       # Vite dev server on port 3000
npm run build     # TypeScript + Vite build
npm run preview
```

### Sniffer (Rust)

The sniffer only builds inside Docker (needs Linux AF_PACKET). Use:

```bash
docker compose build sniffer
```

### Database Migrations

Migrations auto-run on fresh volume via `docker-entrypoint-initdb.d/`. Manual run:

```bash
docker compose exec -T timescaledb psql -U ids -d ids -f /docker-entrypoint-initdb.d/001_initial.sql
```

### ISO Build

Triggered via GitHub Actions on tag push (`v*`) or `workflow_dispatch`. Produces `live-image-amd64.hybrid.iso` as a GitHub Release asset.

## Architecture

### Data Flow

```
Mirror Port (AF_PACKET)
  → Sniffer (Rust)          → Kafka: raw-packets, pcap-headers
  → Flow-Aggregator (Python) ← raw-packets  → Kafka: flows
  → Signature-Engine (Python) ← flows       → Kafka: alerts-raw
  → ML-Engine (Python)        ← flows       → Kafka: alerts-raw
  → Alert-Manager (Python)    ← alerts-raw  → TimescaleDB + Kafka: alerts-enriched
  → Enrichment-Service (Python) ← alerts-enriched → Kafka: alerts-enriched-push
  → PCAP-Store (Python)       ← pcap-headers + alerts-enriched → MinIO
  → API (FastAPI)             ← TimescaleDB, Redis, MinIO, Kafka
  → Frontend (React/Vite)     ← API REST + WebSocket (/ws/alerts)
```

Optional integrations: Suricata/Snort (EVE JSON → Snort-Bridge → alerts-raw), IRMA (REST poll → IRMA-Bridge → alerts-raw), Traffic-Generator (test flows direct to Kafka).

### Services Summary

| Service | Language | Key Role |
|---------|----------|----------|
| sniffer | Rust | AF_PACKET TPACKET_V3 capture, packet parsing, Kafka publish |
| flow-aggregator | Python | Stateful flow assembly, Welford IAT entropy feature extraction |
| signature-engine | Python | YAML rules, sliding-window context, hot-reload via inotify |
| ml-engine | Python | IsolationForest anomaly detection, partial-fit scaler (River) |
| alert-manager | Python | Dedup (300s window), score normalization, DB write |
| enrichment-service | Python | rDNS, ICMP ping, GeoIP/ASN, Redis cache (TTL 3600s) |
| pcap-store | Python | ±60s packet buffer, libpcap format (128-byte snaplen), MinIO upload |
| api | Python/FastAPI | REST + WebSocket, JWT auth (HS256: 8h user / 365d service) |
| frontend | React + Vite + TS | Real-time alert feed, connection graph, ML config, user mgmt |
| training-loop | Python | Semi-supervised IsolationForest retrain (24h interval, joblib) |

### Infrastructure

- **Kafka 3.7** (KRaft, no Zookeeper): 8 topics — raw-packets (4p), flows (4p), pcap-headers (4p), alerts-raw (2p), alerts-enriched (2p), alerts-enriched-push (1p), feedback (1p), test-commands (1p)
- **TimescaleDB** (PostgreSQL 16): hypertables for `flows`, `alerts`, `test_runs`; `known_networks` with GiST CIDR index; `host_info`, `users`, `training_samples`, `system_config`
- **Redis 7**: enrichment cache (IP → hostname/geo/ASN)
- **MinIO**: S3-compatible PCAP storage, bucket `ids-pcaps`, key format `alerts/{alert_id}.pcap`

### WebSocket Protocol

Endpoint: `/ws/alerts?token=<jwt>`  
Message types: `initial` (50 recent), `alert`, `alert_enriched`, `pcap_available`, `feedback_updated`

### Authentication

- Local users: bcrypt + JWT (HS256)
- SAML/SSO: IdP metadata URL, attribute mapping
- Roles: `admin` (full), `viewer` (read + feedback), `api` (long-lived, no password)

### Configuration

All runtime config lives in `.env` (copy from `.env.example`). Key variables: `MIRROR_INTERFACE`, `MGMT_INTERFACE`, `POSTGRES_PASSWORD`, `JWT_SECRET`, `FLOW_TIMEOUT_S`, `ML_BOOTSTRAP_MIN`, `RETRAIN_INTERVAL_S`, `DEDUP_WINDOW_S`, `PCAP_WINDOW_S`.

### ML Model

Models stored as `/models/iforest.joblib` + `scaler.joblib` inside the ml-engine container. The training-loop service retrains from `training_samples` table and atomically replaces model files. ML activates only after `ML_BOOTSTRAP_MIN` flows (default 500).
