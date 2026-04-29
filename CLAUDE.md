# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

Dieses Repository (VS Code, macOS) ist die **Source of Truth** und wird auf GitHub (`JxxKal/ids`) gespiegelt.

**Hosts (Stand 2026-04-29):**

| IP | Rolle | User | Compose-Profil | Frontend |
|---|---|---|---|---|
| `192.168.1.81` | **Master-IDS** (produktiv) | `ids` (sudo) | `--profile prod` (`docker-compose.yml`) | `http://192.168.1.81/` |
| `192.168.1.95` | **Remote-Tap** (gepairt mit 81) | `ids` (sudo) | `docker-compose.tap.yml` | `http://192.168.1.95/` (Tap-API only) |
| `192.168.1.230` | Dev-Dockerhost (Sandbox) | `root` | `--profile prod` | `http://192.168.1.230/` |

### Zyklus

1. **Lokal editieren** in VS Code.
2. **Committen & pushen** (GitHub MCP oder `git push`) — der Push ist gleichzeitig das Deployment-Signal.
3. **Hosts aktualisieren** via SSH (`ssh-manager` MCP oder direktes SSH; Master/Tap brauchen `sudo` vor jedem `docker`-Befehl):
   ```bash
   cd /opt/ids && git pull
   docker compose --profile prod build <geänderter-service>   # nur die betroffenen Services
   docker compose --profile prod up -d
   ```
   Auf dem Tap stattdessen:
   ```bash
   cd /opt/ids && git pull
   docker compose -f docker-compose.tap.yml build <service>
   docker compose -f docker-compose.tap.yml up -d
   ```
   - Bei Frontend-Änderungen: nur `frontend` neu bauen.
   - Bei API-Änderungen: nur `api` neu bauen.
   - Bei Heuristik-Rule-Änderungen: nur `signature-engine` neu bauen — Custom-YAMLs + `_overrides.json` werden zur Laufzeit hot-reloaded und gehen automatisch per Reverse-Channel auch auf alle gepairten Taps.
   - Bei Migrations/DB-Änderungen: ggf. `docker compose exec -T timescaledb psql -U ids -d ids -f /docker-entrypoint-initdb.d/<migration>.sql`
4. **Validieren mit Chrome DevTools** (MCP `chrome-devtools`):
   - UI unter `http://192.168.1.81/` (Master) oder `http://192.168.1.230/` (Dev) öffnen.
   - Login: auf 230 ist `admin` / `***REDACTED***`; auf 81 hat der User ein eigenes Passwort.
   - Auf Console-Errors, Network-Fehler und funktionale Regressionen prüfen.
   - Bei UI-Änderungen: Golden Path + Edge Cases im Browser durchspielen.

### Wichtig

- **Niemals direkt auf einem Host editieren** — jede Änderung geht durch Git.
- **Container-Logs bei Problemen**: `docker compose logs -f <service>` (Master) bzw. `docker compose -f docker-compose.tap.yml logs -f <service>` (Tap).
- **ISO-Build** läuft in GitHub Actions, nicht auf den Hosts (Tag-Push `v*` oder `workflow_dispatch`). Es gibt zwei ISO-Varianten: Master-ISO (voller Stack) und Tap-ISO (`distro/tap-config/`).

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

Workflow `build-release.yml` baut zwei Artefakte aus einem gemeinsamen Image-Bundle:

- `cyjan-ids-<tag>.iso` — bootbares Live-Installer-ISO mit eingebettetem Image-Bundle (~1,5 GB), für Frischinstallationen.
- `cyjan-ids-update-<tag>.zip` — gleiches Bundle + `docker-compose.yml` + `infra/`, für **Offline-Upgrade** über das Web-Frontend (Settings → System-Update).

**Trigger-Policy** (seit dem ISO-Build stabil ist):

| Auslöser | ISO? | Update-ZIP? |
|---|---|---|
| Tag-Push `vN.M.P` (z.B. `v1.3.4`) | – | ✓ |
| Tag-Push `vN.0.0` (Major-Release) | ✓ | ✓ |
| `workflow_dispatch` mit `build_iso=true` | ✓ | ✓ |
| `workflow_dispatch` ohne Flag (Default) | – | ✓ |

ISO-Builds dauern 25–30 min und lohnen sich nur wenn Wizard, Installer, Distro-Pakete, GRUB-Cmdline, Boot-Hooks oder Splash geändert wurden. Solche Änderungen sammelt man bewusst bis zum nächsten Major-Bump.

**Was kommt wo durch:**

| Änderung | Wie deployen |
|---|---|
| Service-Code (api, frontend, sniffer, …), `docker-compose.yml`, Migrations | Tag pushen → CI baut Update-Paket → in der GUI unter Settings → System-Update einspielen |
| Wizard-Logik (`ids-setup`), Installer (`ids-installer`), Boot-Hooks, Splash, Boot-Menü, Tastatur-/Zeitzone-Defaults, `package-lists/`, GRUB-Cmdline | Sammeln, bis zum nächsten `vN.0.0`-Tag mitnehmen — oder wenn akut: `workflow_dispatch` mit `build_iso=true` |

**Wizard-Bugfixes ohne neues ISO**: der Wizard auf der installierten Maschine pullt in Step 0 ohnehin `git pull origin main` und ersetzt sich selbst, deshalb kommen Bugfixes im Wizard-Skript auch ohne neues ISO an — `sudo ids-setup` auf der Zielmaschine zieht sie. Neue Wizard-**Features** (zusätzliche Steps, neue Auswahl-Optionen) erst beim nächsten Frischinstall aus dem ISO.

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

### Remote-Tap (verteilte Erfassung)

Ein Master-IDS kann beliebig viele **Remote-Taps** anbinden — physisch entfernte, kompakte Sniffer-Knoten, die ihre Alarme via mTLS an den Master schicken und im Gegenzug Heuristik-Rules + Overrides vom Master pullen.

```
[Tap 95] Mirror → Sniffer → Flow-Aggregator → Signature-Engine ─┐
                                                                  ▼
                                                          alerts-raw (Kafka, lokal)
                                                                  │
                                                          tap-uplink ─── (mTLS-WSS) ───►  master-uplink (81)
                                                                  │                          │
                                                       Outage-Buffer                         ▼
                                                       (SQLite, /var/lib/cyjan)        Kafka alerts-raw (Master)
                                                                                              │
                                                       ◄──── Reverse-Channel Pull ─────  GET /config (alle 5min)
                                                       Builtin-YAMLs + _overrides.json
```

- **Pairing**: Master-Admin erzeugt im UI (Settings → Remote Taps) ein einmalig sichtbares Pairing-Token mit TTL. Der Tap-Wizard (`cyjan-tap pair`) tauscht das Token gegen ein mTLS-Cert + CA — danach läuft die Verbindung kennwortlos.
- **mTLS**: Master hält eine eigene CA (`master-ca`-Volume), signiert pro Tap ein Cert mit CN=Tap-Name. master-uplink verifiziert eingehende Verbindungen gegen die CA, tap-uplink prüft das Master-Cert.
- **Outage-Buffer**: tap-uplink schreibt bei Verbindungsverlust alle Alarme nach `/var/lib/cyjan/queue.sqlite`. Sobald die Master-Verbindung wieder steht, werden die Backlog-Einträge in Reihenfolge nachgereicht und nach erfolgreichem Ack gelöscht.
- **Reverse-Channel**: Der master-uplink stellt unter `GET /config` den aktuellen Stand der Heuristik-Rules + Overrides bereit (`builtin/*.yml`, `custom/_overrides.json`, `custom/_suricata_overrides.json`). Tap-uplink pullt alle 5 min und schreibt das Bundle ins lokale `signature-rules`-Volume — die lokale signature-engine reagiert via inotify.
- **CLI**: `cyjan-tap status | pair | unpair | logs` auf dem Tap-Host für Setup und Diagnose, ohne dass ein Web-UI auf dem Tap notwendig wäre.

Stack-Layout pro Rolle:

| Host | Compose-Datei | Services |
|---|---|---|
| Master | `docker-compose.yml` (`--profile prod`) | Volle Pipeline + `master-uplink` |
| Tap | `docker-compose.tap.yml` | `sniffer`, `flow-aggregator`, `signature-engine`, lokales `kafka`, `tap-uplink`, `tap-api` |

### Services Summary

| Service | Language | Key Role |
|---------|----------|----------|
| sniffer | Rust | AF_PACKET TPACKET_V3 capture, packet parsing, Kafka publish |
| flow-aggregator | Python | Stateful flow assembly, Welford IAT entropy feature extraction |
| signature-engine | Python | YAML rules + per-rule `parameters:` block, sliding-window context, hot-reload via inotify, `_overrides.json` für Disable/Severity-Override/Schwellwert-Tuning |
| ml-engine | Python | IsolationForest anomaly detection, partial-fit scaler (River) |
| alert-manager | Python | Dedup (300s window), score normalization, DB write |
| enrichment-service | Python | rDNS, ICMP ping, GeoIP/ASN, Redis cache (TTL 3600s) |
| pcap-store | Python | ±60s packet buffer, libpcap format (128-byte snaplen), MinIO upload |
| api | Python/FastAPI | REST + WebSocket, JWT auth (HS256: 8h user / 365d service), Pairing-Token-API, Tap-Verwaltung |
| frontend | React + Vite + TS | Real-time alert feed, connection graph, ML config, user mgmt, Remote-Taps + Rule-Adjustments UI |
| training-loop | Python | Semi-supervised IsolationForest retrain (24h interval, joblib) |
| master-uplink | Python | mTLS-WSS-Server (Port 8443), nimmt Tap-Alarme ins Master-Kafka auf, serviert Reverse-Channel `/config` mit Rules + Overrides |
| tap-uplink | Python | (Tap-only) mTLS-Client zum Master, Outage-Buffer (SQLite), Reverse-Pull der Rules alle 5 min |
| tap-api | Python/FastAPI | (Tap-only) minimaler Status-View + Maschinen-Endpoints für die `cyjan-tap`-CLI, kein eigener Auth-Stack |

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

### Heuristik-Rules: Schwellwerte tunen

Die YAML-Rules in `signature-engine/rules/*.yml` deklarieren Schwellwerte als benannten `parameters:`-Block (z.B. `port_count`, `window_s`) mit `type` (`int|float`), `default`, optional `min`/`max` und `label`. Die `condition` referenziert sie über `params.<name>` statt einer hartkodierten Zahl. Beispiel:

```yaml
- id: SCAN_001
  parameters:
    port_count: { type: int, default: 50, min: 5, max: 65535, label: "Min. Zielports" }
    window_s:   { type: int, default: 60, min: 5, max: 3600,  label: "Zeitfenster (s)" }
  condition: |
    flow.get('proto') == 'TCP'
    and ctx.unique_dst_ports(flow.get('src_ip', ''), params.window_s) > params.port_count
```

**Override-Pfad** (`_overrides.json` im signature-rules-Volume):

```json
{
  "SCAN_001": { "parameters": { "port_count": 200 }, "enabled": true, "severity": null }
}
```

- Werte werden gegen `min`/`max` aus dem Schema geclampt; unbekannte Param-Namen werden geloggt und ignoriert.
- Settings → Rule Adjustments rendert pro Rule eine Number-Input-Maske mit Range-Hinweis und Reset-Button. Default-konforme Werte werden beim Save automatisch aus dem Override entfernt (kein Müll im File).
- Override-File liegt im **Volume-Root** des Master-`signature-rules`-Volumes (`/sig-rules/_overrides.json` aus API-Sicht, `/rules/custom/_overrides.json` aus signature-engine-Sicht — selber Pfad). Beim Tap erreicht es `/rules/custom/_overrides.json` über den Reverse-Channel.
- **Kein Restart nötig**: signature-engine erkennt mtime-Änderungen am File und lädt innerhalb weniger Sekunden neu.

**Empfehlung**: Bei Heuristik-Floods *Schwellwert hochdrehen* statt Severity runterstufen — letzteres maskiert auch echte Treffer, ersteres unterdrückt nur die Ursache (Normal-Traffic, der den alten Default überschreitet).
