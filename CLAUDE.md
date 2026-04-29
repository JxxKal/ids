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

## Geplant: ML-Schwellwert-Tuner (rule-tuner)

**Status: in Planung (2026-04-29). Code existiert noch nicht.** Ziel ist ein neuer Service, der das Normalverhalten des Netzes über einen Trainingszeitraum (2h Test / 10d Prod, einstellbar) lernt und danach die `parameters:`-Schwellwerte der Heuristik-Rules selbstständig pflegt — sichtbar als provenance-getaggte Einträge im existierenden `_overrides.json`, manuell weiterhin überschreibbar.

### Designentscheidungen (mit User abgestimmt)

- **Verfahren**: Shadow-Evaluation. signature-engine emittiert pro Rule-Auswertung den **Metrik-Wert** (z.B. `unique_dst_ports`) ins neue Kafka-Topic `rule-metrics` — Verteilung lernen, nicht Alerts zählen.
- **Schwellwert-Wahl**: Quantile (Default P99,5) der beobachteten Metrik + Sicherheitsmarge, geclamped auf `min`/`max` des Rule-Schemas.
- **FP/TP-Constraints**: optional, **kein Verlass darauf** (User markiert in der Praxis nicht zuverlässig). Nur wenn ≥3 vorhandene Markierungen pro Rule: TPs setzen Obergrenze (`threshold ≤ min(metric_at_tp)`), FPs setzen Untergrenze (`threshold ≥ max(metric_at_fp) + 1`). Bei Konflikt: alten Wert behalten + Warnung loggen.
- **Während Trainings: Heuristiken feuern weiter** mit Default-Schwellwerten — sonst rutschen echte Angriffe im Lernfenster durch.
- **Scope: global an/aus** (keine Pro-Rule-Opt-ins). Plus konfigurierbare **Blacklist** für Rules, die bewusst pessimistisch hart bleiben sollen (z.B. DOS-Hochlast).
- **`known_networks`-Split ist eigenständiges Feature**: pro Param wird zusätzlich zum Default-Wert (`value`, gilt für externe Quellen) optional ein `value_internal` für interne Quellen geführt. signature-engine wählt zur Auswertung anhand `flow.src_ip ∈ known_networks` den passenden Wert. UI macht den Split sichtbar.
- **Manueller Lock**: jeder Param hat `source: "manual" | "ml"`. Sobald User manuell editiert → `source=manual`, rule-tuner fasst diesen Param nicht mehr an, bis User in der UI explizit "ML wieder übernehmen" klickt.
- **Continuous-Loop-Cadence**: alle 6h, max ±20 % Threshold-Bewegung pro Cycle.
- **Architektur**: rule-tuner läuft **nur am Master**, schreibt Overrides via `PUT /api/sig-rules/overrides` (nicht direkt am File — sonst race mit GUI). Verteilung an Taps läuft über existierenden Reverse-Channel.

### Override-Schema (erweitert, abwärtskompatibel)

Loader und API-Serializer akzeptieren beide Formen:

```jsonc
// Alte Form (manuell, weiter unterstützt)
"SCAN_001": { "parameters": { "port_count": 200 }, "enabled": true }

// Neue strukturierte Form (ML oder manuell mit Provenance)
"SCAN_001": {
  "parameters": {
    "port_count": {
      "value": 35,             // gilt für externe Quellen (oder global, wenn split aus)
      "value_internal": 187,   // optional, nur wenn known_networks-Split aktiv
      "source": "ml",          // "ml" | "manual"
      "ml": {
        "trained_at": "2026-05-02T08:00:00Z",
        "p995_external": 28, "p995_internal": 152,
        "sample_count": 42130,
        "fp_seen": 0, "tp_seen": 0,
        "last_update": "2026-05-08T14:00:00Z"
      }
    },
    "window_s": { "value": 60, "source": "manual" }
  },
  "enabled": true, "severity": null
}
```

### Phasenplan

**Phase 1 — Schema-Erweiterung (signature-engine + api) — ✅ erledigt 2026-04-29**
- ✅ Override-Loader (`signature-engine/src/loader.py`): Param-Wert kann jetzt Objekt mit `value`/`value_internal`/`source`/`ml` sein, Skalar-Form bleibt vollständig akzeptiert. Neuer Helper `is_internal(ip)` mit CIDR-Cache aus `_known_networks.json` (vorgeparst als `ipaddress.ip_network`).
- ✅ Engine (`signature-engine/src/engine.py`): `_FlowParams`-Resolver pro Flow — wählt `value_internal`, wenn `flow.src_ip` in `known_networks` und `value_internal` im Override gesetzt ist; sonst Fallback auf `value`. `flat["src_internal"]` wird in den Flow gemerged für Phase-2-Telemetrie.
- ✅ Rules-Schema: optionales `metric:`-Feld pro Parameter im YAML wird vom Loader gelesen und in `parameters_schema` durchgereicht. Bisher noch nicht in `*.yml` deklariert — kommt mit Phase 2 (Shadow-Pipeline) rein. Rules ohne `metric:` bleiben nicht ML-tunbar.
- ✅ API (`api/src/routers/sig_rules.py`): neue Pydantic-Modelle `SigRuleParamOverride` (Object-Form) + Erweiterung von `SigRuleEntry.parameters_full`. GET liefert Skalar wo trivial, Object sonst — beide nebeneinander. PUT akzeptiert pro Param `float | SigRuleParamOverride`. Persistenz: kompakter Skalar wenn keine Provenance, sonst Object-Form.
- ✅ known_networks-Sync (`api/src/sig_sync.py`, `api/src/main.py`, `api/src/routers/networks.py`, `api/src/routers/itop.py`): CIDR-Liste wird beim Startup + nach jedem Network-CRUD + nach iTop-Subnet-Import als `_known_networks.json` ins sig-rules-Volume geschrieben (atomic write, content-identity-skip). signature-engine zieht via mtime-Watch nach.
- ✅ Reverse-Channel (`master-uplink/src/main.py`, `tap-uplink/src/main.py`): Bundle (Schema-Version "1") trägt jetzt zusätzlich `known_networks`. Tap-uplink schreibt es als `_known_networks.json` ins lokale custom/-Subdir.
- ✅ Smoketest verifiziert: Skalar-Override, Object-Override mit `value_internal` + Provenance, CIDR-Match (v4 + cross-family), Resolver-Fallback wenn `value_internal` fehlt, Clamping gegen Schema-min/max, defektes Override wird ignoriert (Default bleibt).

**Deploy nach Phase 1**: alle vier Services rebuilden — `api`, `signature-engine`, `master-uplink`, `tap-uplink` (`docker compose --profile prod build api signature-engine master-uplink && up -d`; auf dem Tap `docker compose -f docker-compose.tap.yml build signature-engine tap-uplink && up -d`).

**Beobachten**: `_overrides.json` wird beim ersten PUT nach Phase 1 neu geschrieben — Skalare bleiben kompakt, neue Object-Form-Einträge erscheinen nur wenn rule-tuner (Phase 4) oder UI mit Provenance/internal_value einen Wert setzt.

**Phase 2 — Shadow-Metrik-Pipeline — ✅ erledigt 2026-04-29**
- ✅ YAML-Rules: `metric:`-Feld pro tunbarem Param hinzugefügt (`scan.yml`, `dos.yml`, `recon.yml`). Mapping: `port_count → unique_dst_ports`, `ip_count → unique_dst_ips`, `flow_count → flow_rate`, `syn_count → syn_count`, `pps → pps`. `window_s` bleibt absichtlich ohne `metric:` (manuell-only).
- ✅ Engine (`signature-engine/src/engine.py`): `METRIC_FUNCS`-Registry (symbolischer Name → Callable(ctx, flow, params)) + neue Methode `compute_metrics(flow)`. Berechnet pro `(rule, param)` mit Metric-Deklaration einen Telemetrie-Eintrag — scope-aware via `_FlowParams` (interne Quelle nutzt `value_internal`/`window_s` falls gesetzt). Wird *nach* `evaluate()` gerufen, damit der Sliding-Window-Stand aktuell ist; emittiert auch wenn die Condition nicht gefeuert hat (sonst Bias).
- ✅ Sampling (`signature-engine/src/main.py` + `config.py`): per-Flow Bernoulli-Sample mit `METRICS_SAMPLING_RATE` (default 0.01). Bei Treffer wird das ganze Metric-Bündel (1 Record pro Param) auf Topic `METRICS_TOPIC` (default `rule-metrics`) produziert. `METRICS_ENABLED=false` deaktiviert komplett. Kafka-Key `<rule_id>|<param_name>` hält pro Stream Ordering, falls das Topic später partitioniert wird.
- ✅ Kafka-Topic-Init: `infra/kafka/init-topics.sh` (Master, 1p, 7d) + `infra/kafka/init-topics-tap.sh` (Tap, 1p, 24d über das KAFKA_LOG_RETENTION_HOURS-Default).
- ✅ Tap-Uplink (`tap-uplink/src/main.py`): Consumer subscribed jetzt auf `alerts-raw` *und* `rule-metrics`; Frame-Type wird anhand des Quell-Topics gesetzt (`alert` vs. `metric`). Beide Streams teilen sich die DiskQueue (1 GB Outage-Cap) — Metriken können bei langem Outage ältere Records verdrängen, bewusst so (Alert-Backfill nicht kritisch fürs Tuning).
- ✅ Master-Uplink (`master-uplink/src/main.py`): `handle_tap()` akzeptiert Frame-Type `metric` und produziert auf `METRICS_TOPIC` mit `tap_id`-Tag — Tuner kann später Master- vs. Tap-Beiträge auseinanderhalten. `pong`/`alert`-Pfade unverändert.
- ✅ Compose: `METRICS_*`-Env-Vars in `signature-engine` (Master + Tap), `METRICS_TOPIC` zusätzlich in `master-uplink` und `tap-uplink`. Sampling-Rate via `.env` (`METRICS_SAMPLING_RATE`) zentral steuerbar — in der Trainingsphase auf 0.05–0.1 anheben für schnelleres Reservoir.
- ✅ Smoketest verifiziert: Records erscheinen nur für metric-deklarierte Params (window_s nicht), `scope` korrekt anhand `known_networks`, `value_internal`-Override wirkt im Resolver, alle YAML-deklarierten Metric-Namen sind in `METRIC_FUNCS` registriert, Record-Schema vollständig (rule_id, param_name, metric_value, src_ip, scope, ts).

**Deploy nach Phase 2**: dieselben vier Services wie Phase 1 rebuilden — `api` braucht es nicht, ist unverändert. `kafka-init` läuft beim nächsten Stack-Start automatisch und legt `rule-metrics` an; bei einem rolling-Update muss das Topic ggf. einmalig manuell erzeugt werden (`docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --create --topic rule-metrics --partitions 1 --replication-factor 1`).

**Beobachten**: `docker compose logs signature-engine` sollte beim Start `Shadow-Metrik aktiv: topic=rule-metrics sampling=0.0100` zeigen. Topic füllt sich erst nachdem Flows reinlaufen. Mit Kafka-UI auf `http://master:8080` kann man `rule-metrics` browsen, um die Verteilung visuell zu prüfen.

**Phase 3 — DB-Schema + Trainings-State — ✅ erledigt 2026-04-29**
- ✅ Migration `012_rule_tuner_baselines.sql`: `rule_baselines (rule_id, param_name, scope, p50, p99, p995, p999, sample_count, updated_at)` — keine Hypertable, PK `(rule_id, param_name, scope)`. `scope` kann `internal | external | global` sein (`global` für Params ohne value_internal-Slot oder wenn known_networks-Split aus ist).
- ✅ Migration: `system_config`-Defaults für `ml_tuning_state` (`{state: idle|training|tuning|paused, started_at, training_until, last_tuning_at, paused_from}`) und `ml_tuning_config` (`{window_s: 36000, target_alert_rate_per_hour: 0.5, scope_split_enabled: true, quantile: 0.995, max_change_per_cycle: 0.20, blacklist: []}`). Beide Inserts sind `ON CONFLICT (key) DO NOTHING` — re-runs sind idempotent.
- ✅ API-Endpoints unter `/api/sig-rules/ml/` (in `api/src/routers/sig_rules.py`):
  - `GET /status` → `{state, config, total_samples}` (sample_count über alle Baselines).
  - `POST /start-training` mit optionalem Body (`window_s`, `target_alert_rate_per_hour`, `scope_split_enabled`, `quantile`, `max_change_per_cycle`, `blacklist`) — merged in bestehende Config, setzt `state=training`, `started_at=now`, `training_until=now+window_s`, löscht `paused_from`. Kann aus jedem State aufgerufen werden (Restart erlaubt).
  - `POST /pause` — idempotent, merkt sich `paused_from=<vorheriger State>`.
  - `POST /resume` — restored `paused_from`. Wenn dort `training` stand und `training_until` schon abgelaufen ist, springt direkt nach `tuning`.
  - `GET /baselines?rule_id=<optional>` — Liste der Baseline-Einträge für UI-Sparklines.
- ✅ Alle Endpoints `Depends(require_admin)`. State-Transitions in einer DB-Transaction, damit zwei parallele PUT/POST nicht zu inkonsistentem `paused_from` führen.

**Deploy nach Phase 3**: nur `api`-Service rebuilden — Migration läuft beim FastAPI-Startup automatisch (`migrate.run()` im startup-Hook). signature-engine + master-uplink unverändert.

**Beobachten**: nach Deploy `curl -H "Authorization: Bearer <token>" http://master/api/sig-rules/ml/status` → liefert `{state: "idle", config: {...defaults...}, total_samples: 0}`. baselines-Endpoint ist erstmal leer (rule-tuner-Service kommt erst in Phase 4). Trainings-Steuerung kann manuell getestet werden:

```bash
TOKEN=...  # JWT aus /api/auth/login
H="Authorization: Bearer $TOKEN"
curl -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"window_s": 7200, "blacklist": ["DOS_SYN_001"]}' \
  http://master/api/sig-rules/ml/start-training
curl -X POST -H "$H" http://master/api/sig-rules/ml/pause
curl -X POST -H "$H" http://master/api/sig-rules/ml/resume
```

**Phase 4 — rule-tuner Service — ✅ erledigt 2026-04-29**
- ✅ Neuer Python-Service in `rule-tuner/` (`Dockerfile`, `requirements.txt`, `src/{config,reservoir,api_client,tuner,main}.py`). Master-only via Compose-Profil `prod`. Depends-on: kafka healthy, timescaledb healthy, api healthy.
- ✅ Reservoir-Sampling (Algorithm R, default 10k Samples pro `(rule, param, scope)`). Kafka-Consumer läuft im Daemon-Thread, Reservoir-Updates unter `threading.Lock` — async-Persistierung greift den Snapshot, ohne den Consumer zu blockieren.
- ✅ Persistierungs-Loop alle 60s (`PERSIST_INTERVAL_S`): UPSERT `rule_baselines` mit P50/P99/P995/P999 + sample_count.
- ✅ State-Loop alle 30s (`STATE_POLL_INTERVAL_S`): pollt `/api/sig-rules/ml/status`. Übergänge:
  - `idle`/`paused` → nur Sampling, keine Schreiboperation
  - `training` → wenn `training_until <= now`: erster Override-Write (`first_apply=True`, ohne max_change_per_cycle-Klemme), dann state → `tuning` + `last_tuning_at = now`
  - `tuning` → wenn `now - last_tuning_at >= TUNING_CYCLE_S` (default 6h): erneuter Override-Write mit Klemme auf `±max_change_per_cycle` ggü. altem ml-Wert, `last_tuning_at` aktualisiert
- ✅ Override-Write-Algorithmus:
  - `GET /api/sig-rules/list` → Schemata + aktuelle Overrides
  - Für jeden Param mit `metric:`-Deklaration und `rule.id ∉ blacklist`:
    - Wenn `existing.parameters[pname].source == "manual"` oder Skalar (= impliziter manual-Lock von vor Phase 1): überspringen.
    - `scope_split_enabled=true`: `value` aus external-Reservoir, `value_internal` aus internal-Reservoir, beide mindestens `MIN_SAMPLES` (default 100).
    - `scope_split_enabled=false`: `value` aus combined-Reservoir, `value_internal=null`.
    - Quantile × `SAFETY_MARGIN` (1.05) → schema min/max-Clamp → optional Klemme auf `±max_change_per_cycle` × alter ml-Wert.
    - Eintrag mit `source: "ml"` + `ml`-Metadaten (trained_at, quantile, p995_external/internal, sample_count_external/internal, scope_split).
  - `PUT /api/sig-rules/overrides` mit gemergedem Stand (existierende `enabled`/`severity`/manual-Params bleiben erhalten).
- ✅ Service-JWT: tuner mintet selbst ein langlebiges Token mit `role=admin` aus `API_SECRET_KEY` — kein User-DB-Eintrag nötig, da `get_current_user` nur die Signatur validiert.
- ✅ FP/TP-Constraints sind im Code-Path **nicht** implementiert (V1) — CLAUDE.md hatte das als optional markiert ("kein Verlass darauf"). Alert-Wert beim Firing ist nicht persistiert; ein robuster Korrelationspfad würde Phase 4.5 brauchen (z.B. metric_value im Alert-Frame mitschreiben).
- ✅ State-Maschinen-Übergänge `training → tuning` und `last_tuning_at`-Updates schreiben direkt in `system_config` (DB-Codec sorgt für korrektes JSONB-Encoding); User-getriebene Übergänge (start/pause/resume) bleiben Sache der API-Endpoints — keine Konkurrenz, weil unterschiedliche Subfields.

**Deploy nach Phase 4**: `docker compose --profile prod build rule-tuner && up -d` am Master. Kein Tap-Deploy nötig — Tap-Beiträge laufen via master-uplink ins Master-Kafka. Beim Boot pollt der tuner `/ml/status` mit Retry, bis api healthy ist.

**Beobachten**:
- `docker compose logs rule-tuner` zeigt beim Start: `Kafka-Consumer subscribed: rule-metrics`, `API erreichbar — starte Hauptschleifen`.
- Im State `idle` (Default) füllen sich Reservoirs unsichtbar; nach 60s erscheinen Zeilen in `rule_baselines` (`SELECT rule_id, param_name, scope, p995, sample_count FROM rule_baselines ORDER BY rule_id;`).
- Trainingslauf: `POST /api/sig-rules/ml/start-training {window_s: 300}` (5 min) — beim Ablauf log-line `Training abgeschlossen — schalte auf tuning + erster Override-Write`. `_overrides.json` enthält danach Einträge mit `source: "ml"`.
- Cycle-Test mit kürzerem TUNING_CYCLE_S (z.B. `TUNER_TUNING_CYCLE_S=300` in `.env` für 5-min-Cycles statt 6h) — Tuner schreibt dann alle 5 min statt alle 6 h.

**Phase 5 — Frontend-UI (Settings → Rule Adjustments)**
- Neuer Tab "ML-Tuning":
  - Status-Card (state, Restzeit, globaler Sample-Count)
  - Trainings-Konfiguration: Dauer (2h/10d/custom), `target_alert_rate` (default 0,5/h pro Rule), `scope_split_enabled`-Toggle, Blacklist-Multiselect
  - Start/Pause/Resume
  - Verteilungs-Sparklines pro Rule aus `rule_baselines`
- Bestehende Rule-Cards: Provenance-Badge "ML-tuned 187 (intern) / 35 (extern)", Tooltip mit ml-Metadaten, Buttons "Manuell sperren" und "ML wieder übernehmen".
- Bei manueller Number-Input-Editierung automatisch `source=manual` setzen.

**Phase 6 — Reverse-Channel + Verteilung**
- Existierender Master-uplink `/config`-Endpoint serviert die erweiterte `_overrides.json` ohne Änderung — Tap-side signature-engine versteht das neue Schema bereits aus Phase 1.
- WebSocket-Push nach Override-Update (`feedback_updated` analog) → Frontend re-fetcht.

**Phase 7 — Validierung + Re-Evaluierung anderer ML-Modelle**
- 24h Shadow-Run auf Dev (192.168.1.230) ohne Override-Write, Verteilungen visuell prüfen.
- 2h-Test-Training auf Master mit Synthetic Traffic.
- Alert-Rate vorher/nachher messen.
- Danach separat: Verhältnis zu IsolationForest (`ml-engine`) + `training-loop` neu bewerten — der neue Tuner ist deterministisch+statistisch (ergänzt, ersetzt nicht zwingend).

### Was explizit NICHT zum Scope gehört

- Lernen für Rules ohne `parameters:`-Block (Xmas-Scan, NULL-Scan etc. — pure Pattern, nicht tunbar).
- Zeitabhängige Schwellwerte (Tag/Nacht-Profile) — kann Phase 8 sein, jetzt nicht.
- Übergreifende Korrelationen über mehrere Rules — der Tuner pflegt jeden `(rule, param, scope)` unabhängig.
