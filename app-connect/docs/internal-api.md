# app-connect — interne HTTP-API (v1)

Verbindlicher Vertrag zwischen `api` und `app-connect`. Wer hier abweicht,
bricht die Gegenseite.

## Warum es diese Schnittstelle gibt

Kopplungscodes und Gerätelisten liegen beim Cloud-Proxy, nicht lokal. Nur
`app-connect` hat den Tunnel dorthin und kennt den Egress-Weg (Firmen-Proxy,
Firmen-CA). Die `api` hat beides nicht und soll es auch nicht bekommen —
sie fragt stattdessen `app-connect`.

Muster: `api/src/routers/redteam_proxy.py` → redteam-orchestrator.

## Erreichbarkeit

`http://app-connect:8090`, **nur im `ids-net`**. Kein Host-Port veröffentlicht.

Jede Anfrage trägt `Authorization: Bearer <API_SECRET_KEY>`. Das Netz ist
bereits die eigentliche Schranke; das Token verhindert, dass ein anderer
Container auf demselben Netz versehentlich Geräte widerruft.

Fehlerform durchgehend `{"detail": "<deutscher Text>"}`, wie in der ids-API.

## Endpunkte

### `GET /status`

```json
{
  "configured": true,            // proxy_url + device_token vorhanden
  "enabled": true,
  "connection": "connected",     // connected | reconnecting | down | starting | dormant
  "connected_since": 1755172800.0,
  "proxy_url": "wss://proxy.cyjan.dev/tunnel",
  "sentry_name": "cyjan-master",
  "proxy_version": "1.0.0",
  "push_enabled": true,
  "read_only": true,
  "allow_triage": false,
  "event_severity_min": "medium",
  "egress": "http://proxy.kunde.local:3128",   // null = direkt; NIE mit Credentials
  "egress_source": "db",          // db | env | none
  "ca_file": "/etc/cyjan/certs/corp-ca.pem",
  "events_sent": 1234, "events_dropped": 0,
  "rpc_ok": 42, "rpc_rejected": 1, "rpc_failed": 0,
  "last_error": null,
  "config_source": "db"           // db | env  — woher die aktive Konfig stammt
}
```

Antwortet auch im Ruhezustand mit `200` und `connection: "dormant"`. Ein
nicht eingerichtetes App-Connect ist kein Fehler.

### `POST /pair`

```json
// Anfrage
{"label": "iPhone Jan", "ttl_s": 600}

// Antwort 200
{
  "code": "K7MНQ2XR",
  "expires_at": "2026-08-14T15:40:00Z",
  "deep_link": "cyjan://enroll?proxy=https%3A%2F%2Fproxy.cyjan.dev&code=K7MHQ2XR",
  "qr_svg": "<svg …>"
}
```

`qr_svg` kodiert den **deep_link**, nicht den nackten Code — die App bekommt
so Proxy-Adresse und Code in einem Scan.

**Achtung, zwei verschiedene URLs.** `proxy_url` in der Konfiguration ist der
*Tunnel*-Endpunkt, den app-connect selbst benutzt. Die App spricht dagegen die
REST-Basis an. Der `proxy`-Parameter im deep_link muss daraus abgeleitet
werden:

```
wss://proxy.cyjan.dev/tunnel   →   https://proxy.cyjan.dev
ws://10.0.0.5:8000/tunnel      →   http://10.0.0.5:8000
```

Also: Schema `wss→https` bzw. `ws→http`, Pfad abschneiden, Host und Port
behalten. Wer hier die Tunnel-URL durchreicht, erzeugt einen QR-Code, an dem
sich jedes Gerät die Zähne ausbeißt — die App würde `POST /tunnel/api/v1/enroll`
aufrufen.

Der Scheme-Präfix `cyjan://` entspricht `scheme: "cyjan"` in
`cyjan-mobile/apps/mobile/app.json`; die App akzeptiert zusätzlich eine nackte
`https://…?proxy=…&code=…`-Form und einen bloßen 8-Zeichen-Code.

Das Frontend rendert das SVG **nicht** über `dangerouslySetInnerHTML`, sondern
als `<img src="data:image/svg+xml;base64,…">`. Der Inhalt kommt zwar aus dem
eigenen Backend, aber ein QR-Bild rechtfertigt keinen DOM-Injektionspfad.

Fehler: `409` wenn nicht eingerichtet, `502` wenn der Cloud-Proxy nicht
erreichbar ist (Text nennt die Ursache).

### `GET /devices`

```json
[{"id": "…", "label": "iPhone Jan", "platform": "ios",
  "created_at": "…", "last_seen": "…", "push_registered": true,
  "push_severity_min": "high", "include_test": false}]
```

### `DELETE /devices/{device_id}` → `204`

Der Cloud-Proxy trennt daraufhin sofort alle Streams dieses Geräts (`4403`).

### `POST /test-egress`

Prüft denselben Pfad wie `cyjan-app test-proxy`, aber gegen die **übergebene**
Konfiguration — damit ein Admin einen Proxy testen kann, *bevor* er ihn
speichert.

```json
// Anfrage — alle Felder optional, fehlende kommen aus der aktiven Konfig
{"proxy_url": "wss://proxy.cyjan.dev/tunnel",
 "https_proxy": "http://user:pass@proxy.kunde.local:3128",
 "no_proxy": "10.0.0.0/8,.intern.example",
 "ca_file": "/etc/cyjan/certs/corp-ca.pem"}

// Antwort 200 — auch bei Fehlschlag; `ok` trägt das Ergebnis
{
  "ok": false,
  "stage": "connect",             // dns | connect | tls | cert | ok
  "detail": "Der Proxy verlangt Anmeldedaten (407).",
  "hint": "Benutzer und Passwort gehören in die URL: http://user:pass@proxy:3128",
  "steps": [
    {"name": "dns",     "ok": true,  "detail": "proxy.kunde.local → 10.1.2.3"},
    {"name": "connect", "ok": false, "detail": "407 Proxy Authentication Required"}
  ]
}
```

**In der Antwort dürfen niemals Credentials auftauchen** — weder in `detail`
noch in `steps`. `ProxyTarget.__str__` redigiert bereits, das muss so bleiben.

## Konfiguration: DB schlägt ENV

Gespeichert in `system_config` unter dem Schlüssel `app_connect`:

```json
{
  "enabled": true,
  "proxy_url": "wss://proxy.cyjan.dev/tunnel",
  "device_token": "…",
  "sentry_name": "",
  "https_proxy": "",
  "no_proxy": "",
  "ca_file": "",
  "allow_triage": false,
  "severity_min": "medium"
}
```

Auflösung wie bei `mqtt-bridge`: ENV ist Bootstrap (Erstinstallation,
Air-Gap, ISO), die DB überlagert Feld für Feld. Ein **leerer** Wert in der DB
bedeutet „nicht gesetzt" und fällt auf ENV zurück — sonst könnte man einen
per ENV gesetzten Proxy in der GUI nie wieder loswerden, ohne die Datei zu
editieren. Zum expliziten Abschalten dient `enabled: false`.

Poll-Intervall 30 s. Diese Felder erzwingen einen Reconnect, alle anderen
werden im Betrieb übernommen:

```
proxy_url · device_token · https_proxy · no_proxy · ca_file · tls_insecure
```

`allow_triage` wirkt ohne Reconnect: es geht als `read_only`/`capabilities`
im nächsten `hello` mit — bis dahin greift weiterhin die Allowlist, die den
Schreibpfad ohnehin fail-closed abriegelt.

## Was NICHT über diese API geht

Das `device_token` wird **nie zurückgeliefert**. `GET /status` meldet nur, ob
eines vorhanden ist. Ein Token, das man in der GUI wieder auslesen kann, ist
ein Token, das im Browser-Cache und im Screenshot landet.
