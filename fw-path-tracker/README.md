# fw-path-tracker

Firewall Policy Path Tracker für verteilte FortiGate-Umgebungen (Full-Mesh-SD-WAN,
mehrere VDOMs/Standorte, zentral verwaltet über einen FortiManager).

Für einen Flow (Quelle, Ziel, Protokoll, Port) zeigt das Dashboard den kompletten
Pfad über alle beteiligten Firewalls/VDOMs — mit **Live-Verdict pro Hop**
(FortiOS `monitor/firewall/policy-lookup`, per FortiManager `/sys/proxy/json`
durchgereicht), den Kandidaten-Regeln aus der gecachten FMG-DB und
**Regel-Vorschlägen bei Deny** (nur Anzeige — der Tracker hat **keinen
Schreibzugriff** auf den FortiManager).

> **Hinweis**: Dieses Verzeichnis ist als eigenständiges Repo konzipiert
> (eigener Compose-Stack, keine Abhängigkeit zum ids-Stack). Es folgt den
> ids-Patterns (FastAPI + asyncpg, system_config-JSONB, JWT HS256,
> Compose-Idiome), teilt aber keinen Code zur Laufzeit.

## Quickstart

```bash
cp .env.example .env        # POSTGRES_PASSWORD + JWT_SECRET setzen!
docker compose up -d --build
# → http://<host>/  Login: admin / $ADMIN_PASSWORD (Default: admin)
```

Danach unter **Einstellungen → FortiManager** Host + API-Token eintragen,
**Verbindung testen** (zeigt Version + ADOMs), ADOMs auswählen, **Speichern**,
**Sync starten**. Sobald der Sync durch ist, funktionieren Trace, Autocomplete
und Regel-Vorschläge.

Demo ohne FMG: `http://<host>/?demo=1` (Login `demo`/`demo`) — spielt die
Testmatrix-Fixtures ab.

## Architektur

```
TraceForm ──POST /api/trace──► engine/path.py (Hop-Loop)
                                 │  pro Hop 2 Live-Lookups:
                                 │  router/lookup + firewall/policy-lookup
                                 ▼
                               fmg/proxy.py ──exec /sys/proxy/json──► FortiManager ──► FortiGate
                                 │
   inventory/sync.py ──pm/config get──► fmg_snapshot (PostgreSQL)
                                 │
                               Read-Models: PrefixTable · ZoneIndex ·
                               PolicyIndex · ObjectIndex  (In-Memory)
```

- **Live-first**: Verdict pro Hop kommt von der echten FortiGate (nur sie kennt
  den Routing-Echtzeitzustand). Die FMG-DB wird nur gecacht für Kandidaten-
  Regeln, Namensauflösung und Vorschläge.
- **Hop-Kette**: aus Live-Route-Lookups + PrefixTable (connected Networks +
  statische Routen aller Geräte/VDOMs), nicht statisch konfiguriert.
  Egress-Klassen: `LOCAL` · `VDOM_LINK` · `OVERLAY` · `DEFAULT`.
- **Degraded Mode**: Gerät offline → Route aus dem Cache, Verdict `UNKNOWN`,
  Hop amber markiert.
- **Resolver-Kette**: FMG-Objekte → iTop (TeemIP `managementip_id_friendlyname`)
  → DNS, mit Provenance-Anzeige in beide Richtungen.
- **IPv6**: out of scope in V1 (sauberer 400).

## No-Write-Garantie

Der Tracker schreibt **nie** in den FortiManager. Die Garantie liegt zentral in
`FmgClient.rpc()` (`api/src/fmg/client.py`): erlaubt sind nur `get` und `exec`,
`exec` nur für `/sys/login/user`, `/sys/logout`, `/sys/proxy/json`, und im
Proxy-Payload nur `action: "get"`. Abgesichert durch `tests/test_write_guard.py`.

### Empfohlenes FMG-Admin-Profil (read-only)

1. **System Settings → Admin → Profile**: neues Profil, alles `None` außer
   `Device Manager` = Read-Only und `Policy & Objects` = Read-Only.
2. **REST-API-Admin** anlegen (FMG ≥ 7.2.2): Profil zuweisen,
   `rpc-permit read`, Trusted Host = IP des Tracker-Hosts, API-Token erzeugen.
3. **ASSUMPTION (im Lab verifizieren)**: ob `exec /sys/proxy/json` mit
   `rpc-permit read` läuft. Falls die FMG-Version `read-write` verlangt:
   `rpc-permit read-write` setzen — das restriktive Profil (read-only) und der
   Code-Write-Guard tragen die Garantie dann gemeinsam.
4. Fallback FMG < 7.2.2: Auth-Modus „User/Passwort (Session)" im FMG-Panel.

## Entwicklung

```bash
# Backend-Tests (offline, deterministisch via FixtureTransport)
cd api && pip install -r requirements.txt pytest pytest-asyncio && pytest

# Frontend-Dev-Server (proxied /api → localhost:8000)
cd frontend && npm install && npm run dev
```

**Fixtures aufzeichnen** (Lab): `FMG_RECORD_FIXTURES=1` in `.env` — jede echte
FMG-Antwort landet als `{request, response}`-JSON im `fmg-fixtures`-Volume.
Diese Files nach `api/tests/fixtures/fmg/` kopieren macht sie zu pytest-/Demo-
Fixtures (Key = Hash über das normalisierte Request-Payload, session/id
werden gestrippt).

### Offene Lab-Validierungen (ASSUMPTIONS)

- Exaktes Erfolgs-Payload von `firewall/policy-lookup` (Parser in
  `engine/path.py::_live_policy_lookup` ist tolerant, aber unverifiziert).
- Feldnamen der `router/lookup`-Antwort (`interface`/`oif`/`gateway`).
- `rpc-permit read` vs. `read-write` für `/sys/proxy/json` (s.o.).
- vdom-link-Erkennung: Namenskonvention `<base>0/<base>1` + Typ
  (`inventory/store.py::vdom_link_peer`) gegen `system/vdom-link` prüfen.

## Sicherheit

- SSRF-Guard (`netguard.py`, portiert aus ids) auf allen admin-konfigurierbaren
  Zielen: FMG-Host, iTop-URL, DNS-Resolver (blockt loopback/link-local inkl.
  Cloud-Metadata; private LAN-Ranges bleiben erlaubt).
- Secrets: FMG-Token/iTop-Passwort liegen in `system_config` (DB); `GET
  /api/config/*` maskiert sie (`•••`), `PATCH` merged den Sentinel zurück auf
  den gespeicherten Wert. In Env liegen nur `JWT_SECRET`/`POSTGRES_PASSWORD`
  (fail-closed `${VAR:?}`).
- TLS-Verify gegen FMG/iTop ist default **an** (Opt-out pro Verbindung).
- Rollen: `admin` (Config/Sync/Users) und `viewer` (Trace/Suche/Verlauf).
