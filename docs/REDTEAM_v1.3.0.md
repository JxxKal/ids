# CYJAN Auto-RedTeam + Pattern-Federation

**Status:** Plan v0.2 (konsolidiert) · **Owner:** Architecture
**Target Release:** v2.5.0 (Cyjan-Versionierung, Minor-Bump nach v2.4.3)
**Repo:** `github.com/JxxKal/ids`
**Vorgänger-Diskussion:** Chat-Session 2026-05-08/09/10
**Aktivierungs-Modell:** opt-in via Compose-Profil + Feature-Flag, **Default: aus**

Dieses Dokument konsolidiert vier eigenständige aber zusammenhängende Stränge:

1. **`redteam-orchestrator`** — Scenario-Runner + REST-API + MCP-Server (Lab-only)
2. **`kali-shell`** — minimal hardened Kali-Container für reale Tool-Fingerprints (Lab-only)
3. **Pattern-Federation** — signiertes Bundle-Format zum Transfer von Detection-Improvements
   vom Lab- zum Customer-System (Customer importiert, Lab exportiert)
4. **Feature-Flag-System** — alles unter einem Schalter, der pro Cyjan-Installation
   bewusst aktiviert werden muss

Alles unter Compose-Profil `redteam`, `system_config['features']`-gated, an Customer-
Installationen physisch nicht installiert.

-----

## 1. Motivation

Ein Auto-RedTeam-System mit KI/MCP-Steuerung produziert vor allem **Library-
Improvements** an den Detection-Rules — neue Rules, geschärfte Logik, bessere
Default-Parameter, MITRE-Coverage-Beleg. Diese Improvements sind zum großen
Teil **topologie-unabhängig** (Rule-Logik gilt überall, wo das Protokoll
gesprochen wird) und damit zwischen Cyjan-Installationen transferierbar.

Lab-spezifische Werte (rule-tuner ml-Tunings, IsolationForest-Modelle,
P99,5-Baselines) sind dagegen **nicht** transferierbar — der Customer-rule-
tuner aus Phase 4 lernt das lokal sowieso besser.

Daraus folgt das Design:

* **Lab-Modus** (full stack inkl. RedTeam): aggressives Pen-Testing,
  KI-getriebene Adversarial-Search, automatische Rule-Verbesserungen
* **Customer-Modus** (kein RedTeam): minimaler Stack, importiert nur signierte
  Bundles, lokaler rule-tuner verfeinert die importierten Defaults am eigenen Netz
* **Bundle-Format**: Rule-YAMLs + Default-Recalibrations (human-curated) +
  Regression-Test-Suite + MITRE-Coverage. **Keine** trainierten Modelle,
  **keine** lab-spezifischen Schwellwerte.

-----

## 2. Architektur

```
                                          PATTERN-BUNDLE (signiert)
                                          ├── manifest.json + .sig
                                          ├── rules/custom/*.yml
                                          ├── rules/suricata/*.rules
                                          ├── defaults/parameter_recalibration.yml
                                          ├── tests/regression/*.yml
                                          └── evidence/mitre-coverage-matrix.json
                                                  │
                                                  ▼

  ┌─────────────────────────────────────┐         ┌─────────────────────────────────┐
  │ LAB-MASTER                          │ Bundle  │ CUSTOMER-MASTER                 │
  │ (REDTEAM_ENABLED=true)              ├────────►│ (REDTEAM_ENABLED=false)         │
  │                                     │ Export  │                                 │
  │  ┌──────────────────────────────┐   │ Import  │  ┌──────────────────────────┐  │
  │  │ redteam-orchestrator         │   │         │  │ pattern-import (api)     │  │
  │  │  ├ Scenario-Runner           │   │         │  │  ├ Sig-verify gg Trust   │  │
  │  │  ├ MCP-Server (write tools)  │   │         │  │  ├ Diff vs current state │  │
  │  │  └ docker exec → kali-shell  │   │         │  │  ├ Selective apply       │  │
  │  └──────────────────────────────┘   │         │  │  └ Audit-Log             │  │
  │  ┌──────────────────────────────┐   │         │  └──────────────────────────┘  │
  │  │ kali-shell (network=none)    │   │         │  ┌──────────────────────────┐  │
  │  │  └ nmap, hydra, modbus, ncat │   │         │  │ rule-tuner (Phase 4)     │  │
  │  └──────────────────────────────┘   │         │  │  └ tunt importierte      │  │
  │  ┌──────────────────────────────┐   │         │  │    Defaults am Customer- │  │
  │  │ pattern-export (api)         │   │         │  │    Netz lokal weiter     │  │
  │  │  └ signiertes Bundle-Build   │   │         │  └──────────────────────────┘  │
  │  └──────────────────────────────┘   │         │                                 │
  │                                     │         │                                 │
  │  voller Cyjan-Stack +               │         │  voller Cyjan-Stack ohne        │
  │  RedTeam-Profile                    │         │  RedTeam-Profile                │
  └─────────────────────────────────────┘         └─────────────────────────────────┘
```

-----

## 3. Komponenten

### 3.1 redteam-orchestrator (Lab-only)

Python-Service, lebt unter `redteam-orchestrator/`. Hostet:
* REST-API auf 8002 (Health, Scenario-CRUD, Run-Trigger)
* MCP-Server (write-scope: `create_scenario_v1`, `run_kali_tool_v1`)
* Scheduler-Loop für geplante Runs
* `docker exec` Bridge zu kali-shell (Lock-serialisiert)

Reads `cyjankali/scenarios/*.yml` als Scenario-Library, schreibt nach
`redteam_scenarios` + `redteam_results` + `redteam_audit_log`.

**Abhängigkeiten:** `kafka` (für test_runs-Pipeline-Reuse), `api` (für
fixture-pusher), `kali-shell`.

**Compose-Profile:** `redteam`. Nicht im Default-Stack.

### 3.2 kali-shell (Lab-only)

Minimal Kali-Container mit fest verdrahteter Tool-Whitelist:
* `nmap`, `hydra`, `modbus-cli`, `ncat`, `ping`
* `network_mode: none` — veth wird on-demand pro Run reingeklappt
* `cap_drop: [ALL]`, danach `cap_add: [NET_RAW]`
* `read_only: true` Rootfs, tmpfs für scratch
* `seccomp:./kali-shell/seccomp.json` mit Hard-Denies
  (`ptrace`, `mount`, `bpf`, `kexec_load`, `init_module`, …)
* Default-CMD: `sleep infinity` — keine Listener, keine Auto-Actions

Reagiert nur auf `docker exec ... kali_runner.py` mit JSON auf stdin.
Validiert Tool + Args + Target gegen Whitelist (RFC 5737 TEST-NETs).

### 3.3 Pattern-Federation

#### Bundle-Format

```
cyjan-pattern-<lab-id>-<run-id>.zip
├── manifest.json              # schema_version, lab_id, components, sha256-Map
├── manifest.json.sig          # detached PGP-Signature (optional)
├── rules/
│   ├── custom/*.yml           # Heuristik-Rule-YAMLs
│   └── suricata/*.rules       # Suricata Custom-Rules
├── defaults/
│   └── parameter_recalibration.yml  # human-curated Default-Empfehlungen
├── tests/
│   └── regression/*.yml       # validierte Test-Scenarios
├── evidence/
│   └── mitre-coverage-matrix.json   # MITRE-Belege (informativ, nicht apply-bar)
└── README.md
```

#### Trust-Modell

* Lab signiert mit eigenem PGP-Key (registriert in `pattern_signing_keys`)
* Customer trustet explizit Lab-Pubkeys via `pattern_trust_keys`
* Default-Apply nur bei valider Signatur; sonst `force_unverified=true` nötig
* Customer-Import-API verwendet existierende `/api/sig-rules/`-Endpoints
  zum Schreiben — kein Direkt-File-Write, damit Reverse-Channel zu Taps
  und manual-Lock-Respect (rule-tuner Phase 4) automatisch greifen

#### Was im Bundle ist (und was nicht)

| Komponente | Im Bundle? | Begründung |
|---|---|---|
| Custom-Heuristik-Rules (`*.yml`) | ✅ | Rule-Logik ist topologie-unabhängig |
| Suricata Custom-Rules | ✅ | direkt portierbar |
| Default-Recalibrations (human-curated) | ✅ | als Startwerte, Customer tunt lokal nach |
| Regression-Test-Scenarios | ✅ | Customer kann selbst nachfahren |
| MITRE-Coverage-Matrix | ✅ | informativ, wird nicht angewendet |
| rule-tuner ml-Overrides | ❌ | Lab-Topologie-spezifisch |
| IsolationForest-Modelle | ❌ | Lab-Verteilung ≠ Customer-Verteilung |
| `rule_baselines`-DB | ❌ | reine Lab-Statistik |
| Known-Networks/Hosts/Users | ❌ | rein kontextbezogen |
| Alerts, Audit-Log | ❌ | Lab-only |

### 3.4 Feature-Flag-System

Alles ist gated über zwei Schalter:

1. **Compose-Profil `redteam`** — physische Container-Aktivierung
2. **`system_config['features']`** — runtime-Feature-Flag, von der UI gesetzt:
   ```json
   {
     "redteam_enabled": false,           // Lab-only — orchestrator + kali-shell
     "pattern_export_enabled": false,    // Lab-only — Export-API + UI
     "pattern_import_enabled": true      // immer an (auch Customer)
   }
   ```

`/api/system/feature-flags` GET liefert alle Flags an die Frontend, das
Sections konditional rendert. Feature-Flags + Compose-Profil müssen für
Lab-Funktionalität BEIDE aktiv sein — Defense in Depth.

-----

## 4. Datenbank-Schema

Neue Migrations:

| Migration | Zweck |
|---|---|
| `020_redteam_role.sql` | `users.role` um `'redteam'` erweitern |
| `021_redteam_scenarios.sql` | `redteam_scenarios` + `redteam_results` (Hypertable) |
| `022_redteam_audit.sql` | `redteam_audit_log` (Hypertable, append-only) |
| `023_pattern_bundles.sql` | `pattern_trust_keys`, `pattern_bundle_imports` |
| `024_pattern_signing_keys.sql` | `pattern_signing_keys`, `pattern_export_log` (Lab-only) |
| `025_system_features.sql` | Default-Init für `system_config['features']`-Block |

Alle additive — keine Schema-Changes an Bestand, kein Risiko bei Apply auf
v1.2.x-Installationen.

-----

## 5. API-Endpoints

### Customer-Side (immer aktiv)

| Methode | Pfad | Auth | Zweck |
|---|---|---|---|
| `GET` | `/api/system/feature-flags` | admin/viewer | aktuelle Flags |
| `POST` | `/api/system/feature-flags` | admin | Flag setzen |
| `POST` | `/api/pattern/upload` | admin | Bundle hochladen, validieren, staged |
| `POST` | `/api/pattern/apply/{id}` | admin | Komponenten anwenden |
| `GET` | `/api/pattern/imports` | admin | Audit-Listing |
| `GET` | `/api/pattern/trust-keys` | admin | Lab-Trust-Keys lesen |
| `POST` | `/api/pattern/trust-keys` | admin | Lab-Trust-Key registrieren |
| `DELETE` | `/api/pattern/trust-keys/{id}` | admin | Lab-Trust-Key entfernen |

### Lab-Side (nur registriert wenn `REDTEAM_ENABLED=true`)

| Methode | Pfad | Auth | Zweck |
|---|---|---|---|
| `GET` | `/api/pattern/signing-keys` | admin | Signing-Keys auflisten |
| `POST` | `/api/pattern/signing-keys` | admin | Signing-Key registrieren |
| `POST` | `/api/pattern/export` | admin | Bundle bauen + signieren + Stream |
| `GET` | `/api/pattern/exports` | admin | Export-Audit |
| `POST` | `/api/redteam/scenarios` | admin/redteam | Scenario erzeugen |
| `POST` | `/api/redteam/run` | admin/redteam | Scenario abspielen |
| `GET` | `/api/redteam/results` | admin/redteam | Run-Ergebnisse |

MCP-Server (Lab-only) lebt ebenfalls unter `redteam-orchestrator` und
exposed `create_scenario_v1`, `run_kali_tool_v1`, `delete_scenario_v1`
mit eigener Token-Auth (durchgereicht via FastMCP).

-----

## 6. Frontend (Settings)

Section-Layout in `Settings → Integrations`:

* **`pattern-import`** — immer sichtbar (jede Cyjan-Installation kann importieren)
* **`pattern-export`** — sichtbar wenn `feature_flags.pattern_export_enabled=true`

Section in `Settings → System`:

* **`features`** — Toggle-Schalter pro Feature mit Erklär-Text + Warnungs-Modal
  beim Aktivieren von redteam-Features

UI-Patterns siehe Chat-Session-Mockups (DiffSection-Component, TrustKeyForm,
sigBadge), exemplarisch in `frontend/src/components/SettingsPage.tsx` als
`PatternImportSettings` und `PatternExportSettings` umzusetzen.

-----

## 7. Sicherheits-Modell

Fünf-Schichten-Defense für RedTeam-Container:

| # | Layer | Prüfung |
|---|---|---|
| 1 | Compose-Profil | `--profile redteam` muss explizit gesetzt sein |
| 2 | Feature-Flag | `system_config.features.redteam_enabled=true` |
| 3 | MCP-Schema | Pydantic-Validierung Tool/Args/Target |
| 4 | Orchestrator | `target_ip ∈ ALLOWED_SRC_CIDRS`, Audit-Pre-Log |
| 5 | kali-shell-Runner | Tool-Whitelist, forbidden-flags, Shell-Metachar-Scan, IP-Recheck |
| 6 | Kernel | `network_mode: none` + RFC 5737 nicht routbar |

Drei-Schichten-Defense für Pattern-Federation:

| # | Layer | Prüfung |
|---|---|---|
| 1 | Schema-Version | Hard-Fail bei Major-Mismatch |
| 2 | Signature | PGP gegen `pattern_trust_keys`, sonst `force_unverified` |
| 3 | Apply-Path | Geht durch existierende `/api/sig-rules/`-Endpoints, manual-Lock wird respektiert |

`docker.sock`-Bind im Orchestrator wird **ehrlich dokumentiert** als
Root-Equivalent — `:ro`-Flag ist kosmetisch. V2: dedizierter Sidecar mit
nsenter-CAP statt Docker-Socket.

-----

## 8. Phasen-Plan (4 Tage Implementation)

| Phase | Scope | Aufwand | PR-Titel |
|---|---|---|---|
| 0 | Foundation: Migrations 020–025, Feature-Flags-Endpoint | 0.5 d | `feat(redteam): foundation` |
| 1 | Pattern-Import + Trust-Keys (Backend) | 0.5 d | `feat(pattern): import + trust keys` |
| 2 | Pattern-Export + Signing-Keys + PGP-Signing (Backend, Lab-only) | 0.5 d | `feat(pattern): export + signing` |
| 3 | Pattern-Federation Frontend (beide UIs) | 0.5 d | `feat(frontend): pattern federation` |
| 4 | kali-shell Container + Runner + seccomp | 0.5 d | `feat(redteam): kali-shell` |
| 5 | redteam-orchestrator + veth-Handover + Lock | 1 d | `feat(redteam): orchestrator` |
| 6 | MCP-Tools + Audit + Alert-Match-Polling | 0.5 d | `feat(redteam): mcp tools` |
| 7 | CI-Workflow-Update (CUSTOM_MASTER) + Doku | 0.5 d | `chore(ci): redteam in bundle` |

Phasen 0–3 sind **standalone wertvoll**: Pattern-Federation funktioniert
auch ohne RedTeam-Container, falls Lab-Improvements aus anderen Quellen
kommen (manuell, externe Pen-Tester, …).

Phasen 4–7 ergänzen den automatisierten Loop, sind aber keine Voraussetzung.

-----

## 9. Aktivierungs-Workflow für Customer

1. Cyjan v1.3.0 installiert via normalem Update-ZIP
2. Customer-Default: `feature_flags.pattern_import_enabled=true` (kein Toggle nötig)
3. Customer kann Lab-Pubkey via `Settings → Integrations → Pattern-Import → Trust-Keys`
   eintragen
4. Customer kann Lab-Bundle via Drag-Drop hochladen, Diff reviewen, selektiv apply'n
5. **Weder `redteam`-Profile noch Lab-Container** existieren am Customer-System

## 10. Aktivierungs-Workflow für Lab

1. Cyjan v1.3.0 installiert
2. Lab-Engineer setzt in `.env`:
   ```bash
   REDTEAM_ENABLED=true
   CYJAN_LAB_ID=cyjan-lab-jxxk
   ```
3. **Lab-only Images selbst bauen** (Customer-Update-ZIP enthält sie aus
   Sicherheitsgründen NICHT):
   ```bash
   sudo docker compose --profile redteam build kali-shell redteam-orchestrator
   ```
4. `sudo docker compose --profile prod --profile redteam up -d`
5. UI: `Settings → System → Features → RedTeam-Tooling aktivieren` (Modal-Warning bestätigen)
6. UI: `Settings → System → Features → Pattern-Export aktivieren`
7. Lab-Engineer registriert Signing-Key:
   ```bash
   sudo cp lab-signing.pem /etc/cyjan/signing-keys/prod-2026Q2.pem
   # via UI: Settings → Integrations → Pattern-Export → Signing-Keys → Hinzufügen
   ```
8. RedTeam-Loop läuft (Auto, KI-getrieben oder manuell via MCP-Client)
9. Engineer pflegt `_defaults_recalibration.yml` mit reviewten Erkenntnissen
10. UI: `Pattern-Export → Bundle erstellen` → ZIP-Download
11. Bundle an Customer-Site übergeben (USB/Mail/HTTPS-Drop)

**Wichtig: nach jedem Cyjan-System-Update den `redteam`-Build wiederholen**,
weil Customer-Update-ZIPs die RedTeam-Images bewusst nicht enthalten:

```bash
cd /opt/ids && git pull
sudo docker compose --profile redteam build kali-shell redteam-orchestrator
sudo docker compose --profile prod --profile redteam up -d --force-recreate
```

### veth-Setup für `attach_iface=true`-Tool-Runs

kali-shell läuft mit `network_mode: none` und bekommt sein Netz erst, wenn
der Orchestrator beim Tool-Run ein **frisches veth-Pair on-demand**
anlegt + nach dem Run wieder löscht. Kein manueller Lab-Setup-Schritt nötig.

Convention beim Auto-Setup:
* Host-Peer `cy-inj-peer` = `192.0.2.254/24`
* kali-Seite `cyjan-inject` = `192.0.2.1/24`
* User-Tools können beliebige `192.0.2.x` als `target_ip` nutzen.
  `192.0.2.254` trifft den Host-Peer (pingbar = echtes Target).

Voraussetzungen am Host:
* `redteam-orchestrator` läuft mit `network_mode: host`, `pid: host`,
  `cap_add: NET_ADMIN + SYS_PTRACE + SYS_ADMIN` und Docker-Socket-Mount
  (sind in `docker-compose.yml` Profil `redteam` bereits gesetzt).
* `redteam`-Profil aktiv: `sudo docker compose --profile prod --profile redteam up -d`
* Feature-Flag `redteam_enabled=true` in der UI (Settings → Features).

`attach_iface=false` als Alternative führt den Tool-Run ohne Netz-
Konnektivität durch — sinnvoll für Smoketests der Validation-Pipeline,
nicht für echte Detection-Tests.

-----

## 11. V2-Backlog (nicht in v1.3.0)

* **Pattern-Federation Pull-Modus**: Customer kann via mTLS-WSS direkt vom Lab pullen (analog Tap-Pairing)
* **Sigstore/Cosign-Signing**: HSM/Yubikey-Backed-Keys via Cosign-Subprocess
* **Auto-Curated `_defaults_recalibration.yml`**: aus rule-tuner-Sweeps mit Engineer-Review-Workflow
* **MCP-Read-Tools für Customer**: `get_redteam_results_v1` (read-only) — falls Customer eigene Bundles auswerten will
* **Dedizierter nsenter-Sidecar**: ersetzt Docker-Socket-Mount im Orchestrator
* **Bundle-Diff-Visualisierung**: Side-by-Side YAML-Diff im Frontend für modifizierte Rules

-----

## 12. Änderungshistorie

| Datum | Version | Änderung |
|---|---|---|
| 2026-05-09 | 0.1 | Initialer Plan: kali-shell + redteam-orchestrator |
| 2026-05-10 | 0.2 | Konsolidiert mit Pattern-Federation (Export/Import), Feature-Flag-System, Lab/Customer-Trennung; Bundle-Inhalt eingegrenzt auf Library-Improvements (keine Lab-Tunings/Modelle); UI-Mockups beigelegt |
