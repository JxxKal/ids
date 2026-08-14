# app-connect — CYJAN-Tunnel-Agent für die iOS-App

Hält vom Master aus eine **ausgehende** WSS-Verbindung zu `proxy.cyjan.dev`,
pusht gefilterte Alarme und Threat-Level dorthin und beantwortet eingehende
RPCs gegen die lokale `ids-api`. Damit erreicht die CYJAN-App ein IDS in einem
OT-Netz, ohne dass dort ein einziger Port nach außen geöffnet wird.

Verbindlicher Vertrag: **`cyjan-mobile/docs/architecture/protocol.md` (v1)**.
Alles hier Beschriebene ist Umsetzung dieser Spezifikation — bei Widerspruch
gilt das Protokoll.

```
OT-Netz (kein Ingress)                              Internet            Gerät
──────────────────────────────                      ──────────          ─────

  kafka:9092 ──alerts-enriched──►┐
                                 │
                          app-connect ──ausgehend :443──► proxy.cyjan.dev ◄── iOS-App
                                 │      (WSS, optional         /tunnel
  ids-api:8000 ◄─────────────────┘       via HTTP-CONNECT)     /api/v1/*
   (RPC-Relay, Service-JWT role=viewer)                        /ws/events
```

---

## Was der Dienst tut

| Aufgabe | Umsetzung |
|---|---|
| Persistenter Tunnel | `wss://…/tunnel` mit `Authorization: Bearer <device_token>`, Reconnect 1 s → 60 s exponentiell mit ±20 % Jitter, Reset erst nach `hello_ack` |
| Heartbeat | Proxy pingt alle 30 s; bleibt es > 75 s still, reconnecten wir (§1.4) |
| Alert-Push | Kafka `alerts-enriched` → Severity-Filter → Feld-Whitelist (§4) → `event`-Frame `kind=alert` |
| Threat-Level | Poll `/api/stats/threat-level` (Default 60 s) → `event`-Frame `kind=threat_level` |
| Status | `event`-Frame `kind=status` direkt nach `hello_ack` (§1.5) und danach alle 5 min |
| RPC-Relay | `rpc`-Frame → Allowlist (§2.3) → `http://api:8000` → `rpc_result` / `rpc_error` |
| PCAP | `rpc` mit `stream: true` auf dem PCAP-Pfad → Folge von `rpc_chunk`-Frames (§2.5) |
| Enrollment | `cyjan-app pair` holt einen Einmal-Code vom Proxy und zeigt ihn als Text + ASCII-QR (§6) |

---

## Bewusste Entscheidungen

### Kein Disk-Buffer (protocol.md §1.5)

Anders als `tap-uplink` (SQLite-Outage-Buffer, 1 GB) puffert app-connect
**nichts** auf Platte. Der Kafka-Consumer läuft mit `auto.offset.reset=latest`
und ohne manuellen Commit — dem Muster von `mqtt-bridge`.

Begründung: der Tunnel transportiert *Benachrichtigungen und On-Demand-
Abfragen*, keine Ereignis-Persistenz. Die kanonische Kopie jedes Alarms liegt
ohnehin in TimescaleDB am Master und wird beim nächsten App-Refresh
nachgeladen. Ein Push von vor zwei Stunden ist für einen Operator wertlos —
schlimmer noch, ein Backlog-Sturm nach einer langen Outage würde das Gerät
unbenutzbar machen und die echten aktuellen Alarme verdecken.

Konkret heißt das:

* Fällt der Tunnel aus, laufen Events ins Leere.
* Die In-Memory-Queue zwischen Kafka-Thread und Tunnel ist bounded
  (`APP_CONNECT_EVENT_QUEUE_MAX`, Default 1000) und wirft bei Überlauf den
  **ältesten** Eintrag weg.
* Beim Reconnect wird die Queue **verworfen**, nicht nachgereicht.
* Stattdessen geht direkt nach `hello_ack` ein `status`-Event mit den
  aktuellen Zählern raus, damit die App den Sprung sieht.

### Heartbeat ist vom Tunnel entkoppelt

`/tmp/heartbeat` wird von einem eigenen asyncio-Task getouched, der nichts über
den Zustand der Cloud-Verbindung weiß. Ein unerreichbarer Proxy (kein Internet
im OT-Netz, Wartungsfenster beim Betreiber, Dienst gar nicht konfiguriert) macht
den Container **nicht** unhealthy.

Das ist kein Schludrigkeits-Kompromiss, sondern Absicht: `cyjan-stack-health`
wartet beim Boot auf gesunde Container. Ein an die Cloud gekoppelter Healthcheck
würde den Start des gesamten Stacks von fremder Infrastruktur abhängig machen.
Gleiche Begründung wie bei `mqtt-bridge`.

### Service-JWT mit `role=viewer`

app-connect mintet sich sein Token selbst aus `API_SECRET_KEY` (Muster:
`rule-tuner/src/api_client.py`) — aber mit **`viewer`**, nicht `admin`. Damit
sind alle `require_admin`-Router (sig-rules, maintenance, users, notifications,
taps, config) serverseitig unerreichbar, unabhängig von der Allowlist. Wer das
auf `admin` hochdreht, hebelt die zweite Verteidigungslinie aus.

### Fail-closed Allowlist

Jede eingehende `rpc` wird gegen eine feste Liste `(Methode, Pfad-Regex)`
geprüft (`src/allowlist.py`, protocol.md §2.3). Kein Wildcard-Zweig, keine
Env-Variable, die die Liste erweitern könnte. Abgelehnte Requests werden **mit
dem Pfad** geloggt:

```
WARNING [app-connect] RPC abgelehnt (not_allowed): method=GET path='/api/users' — kein Allowlist-Eintrag
WARNING [app-connect] RPC abgelehnt (read_only): method=PATCH path='/api/alerts/…/feedback' — Triage deaktiviert (APP_CONNECT_ALLOW_TRIAGE=false)
```

Zusätzlich abgewiesen: Pfade ohne führenden Slash, mit Traversal (`..`,
`%2e%2e`, `%2f`), Fragment, Whitespace oder Steuerzeichen.

### Triage steht aus

`APP_CONNECT_ALLOW_TRIAGE=false` ist der Auslieferzustand. Der Pfad ist
vollständig implementiert und getestet — es ist ein Flag, kein Umbau. Der
Zustand wird im `hello`-Frame gemeldet (`read_only: true`,
`capabilities: ["pcap","flows","ml"]`); die App fragt nicht „darf ich?", sie
liest die Capability und blendet die TP/FP-Buttons entsprechend ein oder aus.

---

## Egress über einen HTTP-Proxy

**Das kann sonst nichts in diesem Stack.** `tap-uplink` und `master-uplink`
verbinden direkt, `cyjan-update` benutzt curl mit dem System-Proxy. app-connect
ist der erste Dienst, der aus dem OT-Netz ins Internet muss — und dort führt in
aller Regel genau ein Weg hinaus.

Ablauf (`src/proxy_egress.py`):

1. `APP_CONNECT_HTTPS_PROXY` → `HTTPS_PROXY` → `https_proxy` (erste gesetzte
   gewinnt), Schema/Host/Port/`user:pass` werden geparst. Ein schemaloser Wert
   (`fw.corp:3128`) wird als `http://` interpretiert.
2. `NO_PROXY`/`no_proxy` wird geprüft — **Hostname-Suffixe und CIDRs**.
3. TCP zum Proxy, `CONNECT proxy.cyjan.dev:443 HTTP/1.1` (+ ggf.
   `Proxy-Authorization: Basic …`), warten auf 2xx.
4. Der rohe Socket geht an `websockets.connect(uri, sock=…, ssl=…)`; der
   TLS-Handshake läuft danach Ende-zu-Ende gegen den echten Proxy-Endpunkt,
   nicht gegen den Forward-Proxy.

### Warum `no_proxy` hier selbst gebaut ist

Der `ids-setup`-Wizard schreibt **CIDRs** nach `/etc/environment`
(`192.168.0.0/16,10.0.0.0/8`). curl versteht das nicht und schickt solche Ziele
trotzdem durch den Proxy. Hier werden CIDR-Einträge als Netz geparst und gegen
die Ziel-IP geprüft:

| Eintrag | Wirkung |
|---|---|
| `192.168.0.0/16` | jede IP im Netz (IPv4 und IPv6 getrennt, kein Cross-Family-Match) |
| `203.0.113.7` | genau dieser Host |
| `.intern.example` / `intern.example` | `intern.example` und alle Subdomains |
| `example.com:8080` | nur dieser Host auf diesem Port |
| `*` | alles direkt |

Hostnamen werden für die CIDR-Prüfung bewusst **nicht** per DNS aufgelöst — ein
Lookup nur für die Proxy-Entscheidung wäre ein zusätzlicher Fehlerpfad und im
OT-Netz oft gar nicht möglich.

Der Weg zur lokalen `ids-api` läuft **nie** über den Proxy
(`trust_env=False` im httpx-Client), auch wenn `HTTPS_PROXY` gesetzt ist.

---

## Betrieb

### Aktivieren

In der `.env` am Master:

```bash
APP_CONNECT_PROXY_URL=wss://proxy.cyjan.dev/tunnel
APP_CONNECT_DEVICE_TOKEN=<vom Proxy-Betreiber vergeben>
APP_CONNECT_SENTRY_NAME=master-hq
# optional, wenn das OT-Netz nur über einen Forward-Proxy rauskommt:
HTTPS_PROXY=http://fw.corp:3128
NO_PROXY=192.168.0.0/16,10.0.0.0/8,.intern.example
```

Dann:

```bash
docker compose --profile prod build app-connect
docker compose --profile prod up -d app-connect
docker compose logs -f app-connect
```

Solange `APP_CONNECT_PROXY_URL` **oder** das Device-Token leer ist, schläft der
Dienst (eine Log-Zeile, danach Ruhe) und bleibt dabei absichtlich *healthy*. Er
prüft die Konfiguration alle 60 s neu — ein per Bind-Mount nachgereichtes
Token-File (`APP_CONNECT_DEVICE_TOKEN_FILE`) wird also ohne Container-Neustart
aufgegriffen.

### Gerät koppeln

```bash
docker compose exec app-connect cyjan-app pair --label "iPhone Jan"
```

Zeigt den 8-stelligen Einmal-Code, die Gültigkeit und einen ASCII-QR-Code.
In der App scannen oder abtippen. Der Code ist einmalig und läuft nach der TTL
des Proxy (Default 10 min) ab.

```bash
docker compose exec app-connect cyjan-app devices          # enrollte Geräte
docker compose exec app-connect cyjan-app revoke <id>      # Gerät sperren
docker compose exec app-connect cyjan-app status           # Tunnel-Zustand
```

`status` liest ausschließlich das lokale State-File
(`/run/cyjan/app-connect.state.json`) und funktioniert deshalb gerade dann,
wenn der Tunnel unten ist. Die übrigen Kommandos sprechen mit dem Proxy und
respektieren dabei `HTTPS_PROXY`/`no_proxy` inklusive CIDR-Einträgen.

### Konfiguration

Alle Variablen sind in `.env.example` dokumentiert. Die wichtigsten:

| Variable | Default | Wirkung |
|---|---|---|
| `APP_CONNECT_ENABLED` | `true` | harter Aus-Schalter |
| `APP_CONNECT_PROXY_URL` | – | Tunnel-Endpunkt; leer = dormant |
| `APP_CONNECT_DEVICE_TOKEN` / `…_FILE` | – | Bearer-Token des Sentry; leer = dormant |
| `APP_CONNECT_ALLOW_TRIAGE` | `false` | Feedback-Endpoints freischalten |
| `APP_CONNECT_SEVERITY_MIN` | `medium` | Untergrenze für gepushte Alarme |
| `APP_CONNECT_THREAT_INTERVAL_S` | `60` | Poll-Takt für `threat_level` |
| `APP_CONNECT_RPC_TIMEOUT_S` | `20` | Timeout gegen die lokale api |
| `APP_CONNECT_CA_FILE` | – | eigene CA für TLS-inspizierende Proxies |
| `APP_CONNECT_TLS_INSECURE` | `false` | **nur Lab** — Zertifikatsprüfung aus |

Der Proxy kann `event_severity_min` und `push_detail` per `config`-Frame live
nachschärfen; das wirkt ohne Reconnect und überschreibt die env-Vorgabe für die
Laufzeit der Verbindung.

---

## Troubleshooting

| Symptom | Ursache / Vorgehen |
|---|---|
| `app-connect ist nicht konfiguriert (…) — Dienst bleibt im Leerlauf` | Erwartetes Verhalten ohne Konfiguration. `APP_CONNECT_PROXY_URL` + Token setzen. |
| `HTTP 401` beim Connect-Versuch | Device-Token falsch oder am Proxy widerrufen. Neues Token vom Betreiber. |
| Close-Code `4400` | Schema-Mismatch — der Proxy erwartet `hello.schema = "1"`. Versionen abgleichen. |
| Close-Code `4409 replaced` | Zweiter Sentry mit demselben `sentry_id` hat die Verbindung verdrängt. Läuft app-connect doppelt (z.B. alter Container)? |
| `Egress-Proxy: Proxy lehnte CONNECT ab: HTTP 407` | Proxy verlangt Auth — Credentials in `HTTPS_PROXY` aufnehmen (`http://user:pass@fw:3128`). |
| `Egress-Proxy: Timeout … beim CONNECT` | Proxy-Host/Port falsch oder Firewall blockt. `HTTPS_PROXY` prüfen. |
| Tunnel geht direkt raus, obwohl `HTTPS_PROXY` gesetzt ist | `NO_PROXY` greift. `cyjan-app status` zeigt in der Zeile `Egress`, welche Entscheidung getroffen wurde. |
| `certificate verify failed` | TLS-inspizierender Corporate-Proxy. Dessen CA per `APP_CONNECT_CA_FILE` einhängen (PEM), **nicht** `APP_CONNECT_TLS_INSECURE` in Produktion. |
| `RPC abgelehnt (not_allowed)` | Die App fragt einen Pfad an, der nicht in der Allowlist steht. Erwartetes Verhalten — bei Bedarf `protocol.md §2.3` erweitern, nicht die Prüfung lockern. |
| `RPC abgelehnt (read_only)` | Triage ist aus. `APP_CONNECT_ALLOW_TRIAGE=true` setzen, wenn gewollt. |
| RPCs kommen mit `401` von der lokalen api zurück | `API_SECRET_KEY` weicht vom `SECRET_KEY` der api ab. |
| App zeigt „Antwort zu groß" | 4-MiB-Deckel (§2.4). Betrifft praktisch nur PCAP — das läuft über den Streaming-Pfad, prüfen ob die App `stream: true` setzt. |
| Container `unhealthy` | Der Healthcheck hängt **nicht** am Tunnel. Unhealthy heißt: der Prozess selbst steht. Logs ansehen. |
| Keine Alerts in der App, Tunnel steht | `APP_CONNECT_SEVERITY_MIN` bzw. das vom Proxy gesetzte `event_severity_min` prüfen (`cyjan-app status`). |
| Events-Zähler `verworfen` steigt | Tunnel war unten oder Alert-Sturm; by design (§1.5, kein Disk-Buffer). |

Logs immer über `docker compose logs -f app-connect`. Nach `hello_ack` sollte
dort stehen:

```
INFO [app-connect] WSS verbunden mit wss://proxy.cyjan.dev/tunnel (sentry=master-hq read_only=True)
INFO [app-connect] hello_ack: proxy_version=… push_enabled=True
```

---

## Entwicklung

```
app-connect/
├── src/
│   ├── main.py           Supervisor: Heartbeat, Dormanz, Neustart-Schleife
│   ├── tunnel.py         WSS-Session: hello/ping/rpc/config, Sende-Loops
│   ├── allowlist.py      Fail-closed Allowlist + Pfad-Normalisierung (§2.3)
│   ├── api_client.py     Service-JWT (role=viewer) + Body-Deckel (§2.2/§2.4)
│   ├── events.py         Kafka-Consumer, bounded Queue, Drop-Oldest (§1.5)
│   ├── fields.py         Alert-Feld-Whitelist (§4)
│   ├── proxy_egress.py   HTTP-CONNECT + no_proxy inkl. CIDR (§1.1)
│   ├── backoff.py        1 s → 60 s, ±20 % Jitter (§1.4)
│   ├── config.py         env-Config + RuntimeConfig aus dem config-Frame
│   ├── state.py          State-File für `cyjan-app status`
│   └── cli.py            `cyjan-app` (pair / devices / revoke / status)
└── tests/                pytest, kein Netzwerk, kein Kafka nötig
```

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest pytest-asyncio
.venv/bin/python -m pytest        # aus app-connect/ heraus
```

Die Tests decken die sicherheitsrelevanten Teile ab: Allowlist (Annahme,
Ablehnung, Triage-Flag, Traversal), Feld-Whitelist, `no_proxy`-Matching
(CIDR + Suffix + Port), Backoff-Sequenz und -Jitter, Body-Deckel und
Truncation-Flag sowie die Frames, die daraus in den Tunnel gehen. Sie brauchen
weder Kafka noch einen Proxy — `confluent_kafka` wird nur von `events.py`
importiert, das in den Tests bewusst außen vor bleibt.
