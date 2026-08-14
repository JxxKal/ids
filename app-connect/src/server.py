"""Interne HTTP-API für die ids-api (docs/internal-api.md).

    ids-api ──Bearer API_SECRET_KEY──► app-connect:8090 ──► Cloud-Proxy

Warum es das gibt: Kopplungscodes und Gerätelisten liegen beim Cloud-Proxy.
Nur app-connect hat den Tunnel dorthin und kennt den Egress-Weg. Die api hat
beides nicht und soll es auch nicht bekommen — sie fragt stattdessen hier.

Drei Eigenschaften, die dieser Server einhalten muss:

1. **Er läuft immer.** Auch wenn app-connect dormant ist (kein Proxy, kein
   Token) antwortet `GET /status` mit 200 und `connection: "dormant"` —
   sonst könnte die GUI die Einrichtung nie vornehmen. Ein nicht
   eingerichtetes App-Connect ist kein Fehlerzustand.
2. **Er blockiert den Tunnel nicht.** Alles I/O ist async; der einzige
   blockierende Teil (TLS-Handshake im Egress-Test) läuft im Thread-Pool.
3. **Er gibt keine Geheimnisse heraus.** Das Device-Token wird nie
   zurückgeliefert (nur „vorhanden ja/nein"), Proxy-Credentials weder in
   `/status` noch in `/test-egress`.

Server-Muster: `master-uplink/src/main.py` (aiohttp).
"""
from __future__ import annotations

import datetime as dt
import hmac
import logging
from typing import Any, Optional

from aiohttp import web

from config import Config
from egress_check import check_egress
from proxy_api import (
    CloudProxyError,
    build_deep_link,
    create_enroll_code,
    list_devices,
    qr_svg,
    rest_base_url,
    revoke_device,
)
from proxy_egress import parse_proxy_url, proxy_for_url
from state import StateWriter

log = logging.getLogger(__name__)

# Zustände laut Vertrag. Der Tunnel schreibt intern feinere Namen ins
# State-File; hier wird auf das Vokabular der API abgebildet.
# `dormant`/`disabled` stehen bewusst NICHT drin: ob der Dienst schläft,
# entscheidet die aktuelle Konfiguration, nicht ein womöglich veralteter
# Eintrag im State-File. Alles Unbekannte gilt als „fährt gerade hoch".
_CONNECTION_MAP = {
    "connected": "connected",
    "down": "down",
    "crashed": "down",
}

MIN_TTL_S = 60
MAX_TTL_S = 24 * 3600


class ServiceRuntime:
    """Was der Server über den laufenden Dienst wissen muss. Der Supervisor
    in main.py aktualisiert `cfg` bei jeder Konfigurationsänderung; der
    Tunnel-Zustand kommt über den StateWriter."""

    def __init__(self, cfg: Config, state: StateWriter) -> None:
        self.cfg = cfg
        self.state = state


# Typisierter Schlüssel statt String — aiohttp warnt seit 3.9 vor
# String-Keys in `app[...]`.
RUNTIME = web.AppKey("runtime", ServiceRuntime)


# ── Antwort-Helfer ───────────────────────────────────────────────────────────


def _error(status: int, detail: str) -> web.Response:
    """Fehlerform der ids-API: {"detail": "<deutscher Text>"}."""
    return web.json_response({"detail": detail}, status=status)


def _iso_z(value: Any) -> Optional[str]:
    """Zeitstempel des Proxys normalisieren. Strings werden durchgereicht,
    Epoch-Sekunden nach ISO-8601-Z übersetzt."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return (
            dt.datetime.fromtimestamp(float(value), dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return str(value)


def effective_egress(cfg: Config) -> Optional[str]:
    """Egress-Proxy als redigierte URL (nie mit Credentials). None = direkt."""
    if not cfg.https_proxy:
        return None
    target = None
    if cfg.proxy_url:
        target = proxy_for_url(cfg.proxy_url, cfg.https_proxy, cfg.no_proxy)
    else:
        target = parse_proxy_url(cfg.https_proxy)
    return str(target) if target else None


def map_connection(cfg: Config, st: dict, ever_connected: bool) -> str:
    """State-File-Zustand → Vertrags-Vokabular."""
    if not cfg.enabled or not cfg.has_credentials:
        return "dormant"
    raw = str(st.get("connection") or "")
    if raw == "connecting":
        return "reconnecting" if ever_connected else "starting"
    return _CONNECTION_MAP.get(raw, "starting")


def status_payload(runtime: ServiceRuntime) -> dict:
    cfg = runtime.cfg
    st = runtime.state.last or {}
    egress = effective_egress(cfg)
    return {
        "configured": cfg.has_credentials,
        "enabled": cfg.enabled,
        "connection": map_connection(cfg, st, runtime.state.ever_connected),
        "connected_since": st.get("connected_since"),
        "proxy_url": cfg.proxy_url or None,
        "sentry_name": cfg.sentry_name,
        "version": cfg.version,
        "proxy_version": st.get("proxy_version"),
        "push_enabled": st.get("push_enabled"),
        "read_only": not cfg.allow_triage,
        "allow_triage": cfg.allow_triage,
        "event_severity_min": st.get("event_severity_min") or cfg.severity_min,
        "egress": egress,
        "egress_source": "none" if egress is None else cfg.egress_source,
        "ca_file": cfg.ca_file or None,
        "events_sent": int(st.get("events_sent") or 0),
        "events_dropped": int(st.get("events_dropped") or 0),
        "rpc_ok": int(st.get("rpc_ok") or 0),
        "rpc_rejected": int(st.get("rpc_rejected") or 0),
        "rpc_failed": int(st.get("rpc_failed") or 0),
        "last_error": st.get("last_error"),
        "config_source": cfg.config_source,
    }


# ── Auth ─────────────────────────────────────────────────────────────────────


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Bearer gegen API_SECRET_KEY. Das Netz (`ids-net`, kein Host-Port) ist
    die eigentliche Schranke; das Token verhindert, dass ein anderer
    Container auf demselben Netz versehentlich Geräte widerruft."""
    cfg: Config = request.app[RUNTIME].cfg
    key = cfg.api_secret_key
    if not key:
        return _error(503, "API_SECRET_KEY ist im app-connect-Container nicht "
                           "gesetzt — die interne API ist deaktiviert.")
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), key):
        return _error(401, "Fehlendes oder ungültiges Bearer-Token.")
    return await handler(request)


def _require_configured(cfg: Config) -> Optional[web.Response]:
    if not cfg.has_credentials:
        return _error(409, "app-connect ist nicht eingerichtet ("
                           + ", ".join(cfg.missing())
                           + " fehlt) — erst Proxy-URL und Device-Token "
                             "hinterlegen.")
    return None


async def _json_body(request: web.Request) -> dict:
    if not request.can_read_body:
        return {}
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(
            text='{"detail": "Anfrage-Body ist kein gültiges JSON."}',
            content_type="application/json",
        )
    return body if isinstance(body, dict) else {}


# ── Endpunkte ────────────────────────────────────────────────────────────────


async def handle_status(request: web.Request) -> web.Response:
    return web.json_response(status_payload(request.app[RUNTIME]))


async def handle_pair(request: web.Request) -> web.Response:
    cfg: Config = request.app[RUNTIME].cfg
    denied = _require_configured(cfg)
    if denied is not None:
        return denied

    body = await _json_body(request)
    label = str(body.get("label") or "").strip()
    if not label:
        return _error(400, "Ein Anzeigename (label) für das Gerät ist erforderlich.")
    ttl_raw = body.get("ttl_s")
    ttl_s: Optional[int] = None
    if ttl_raw not in (None, ""):
        try:
            ttl_s = max(MIN_TTL_S, min(MAX_TTL_S, int(ttl_raw)))
        except (TypeError, ValueError):
            return _error(400, "ttl_s muss eine Zahl in Sekunden sein.")

    try:
        data = await create_enroll_code(cfg, label, ttl_s)
    except CloudProxyError as exc:
        return _error(502, exc.detail)

    code = str(data.get("code") or "").strip()
    if not code:
        return _error(502, "Der Cloud-Proxy lieferte keinen Kopplungscode.")

    # Die REST-Basis, NICHT die Tunnel-URL — sonst ruft die App
    # POST /tunnel/api/v1/enroll auf und jede Kopplung scheitert.
    deep_link = str(data.get("deep_link") or "").strip() or build_deep_link(
        rest_base_url(cfg.proxy_url), code
    )
    log.info("Kopplungscode für %r erzeugt (gültig bis %s)",
             label, data.get("expires_at"))
    return web.json_response({
        "code": code,
        "expires_at": _iso_z(data.get("expires_at")),
        "deep_link": deep_link,
        "qr_svg": qr_svg(deep_link),
    })


async def handle_devices(request: web.Request) -> web.Response:
    cfg: Config = request.app[RUNTIME].cfg
    denied = _require_configured(cfg)
    if denied is not None:
        return denied
    try:
        devices = await list_devices(cfg)
    except CloudProxyError as exc:
        return _error(502, exc.detail)
    return web.json_response(devices)


async def handle_revoke(request: web.Request) -> web.Response:
    cfg: Config = request.app[RUNTIME].cfg
    denied = _require_configured(cfg)
    if denied is not None:
        return denied
    device_id = request.match_info.get("device_id", "")
    try:
        await revoke_device(cfg, device_id)
    except CloudProxyError as exc:
        if exc.status == 404:
            return _error(404, exc.detail)
        return _error(502, exc.detail)
    log.info("Gerät %s widerrufen — der Cloud-Proxy trennt offene Streams "
             "sofort (4403).", device_id)
    return web.Response(status=204)


async def handle_test_egress(request: web.Request) -> web.Response:
    """Prüft den Egress gegen die ÜBERGEBENE Konfiguration — damit ein Admin
    einen Proxy testen kann, bevor er ihn speichert. Fehlende Felder kommen
    aus der aktiven Konfiguration."""
    cfg: Config = request.app[RUNTIME].cfg
    body = await _json_body(request)

    def pick(key: str, fallback: str) -> str:
        value = body.get(key)
        return value.strip() if isinstance(value, str) and value.strip() else fallback

    url = pick("proxy_url", cfg.proxy_url)
    if not url:
        return _error(400, "Keine Ziel-URL: weder proxy_url übergeben noch "
                           "konfiguriert.")
    tls_insecure = body.get("tls_insecure")
    result = await check_egress(
        url=url,
        https_proxy=pick("https_proxy", cfg.https_proxy),
        no_proxy=pick("no_proxy", cfg.no_proxy),
        ca_file=pick("ca_file", cfg.ca_file),
        tls_insecure=(bool(tls_insecure) if isinstance(tls_insecure, bool)
                      else cfg.tls_insecure),
        timeout=15.0,
    )
    # Immer 200 — das Ergebnis steht in `ok`, ein fehlgeschlagener Test ist
    # kein Fehler der API.
    return web.json_response(result.to_dict())


# ── Server ───────────────────────────────────────────────────────────────────


def create_app(runtime: ServiceRuntime) -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app[RUNTIME] = runtime
    app.router.add_get("/status", handle_status)
    app.router.add_post("/pair", handle_pair)
    app.router.add_get("/devices", handle_devices)
    app.router.add_delete("/devices/{device_id}", handle_revoke)
    app.router.add_post("/test-egress", handle_test_egress)
    return app


class InternalServer:
    """Läuft unabhängig vom Tunnel-Zustand über die gesamte Prozesslaufzeit."""

    def __init__(self, runtime: ServiceRuntime) -> None:
        self._runtime = runtime
        self._runner: Optional[web.AppRunner] = None

    async def start(self) -> None:
        cfg = self._runtime.cfg
        app = create_app(self._runtime)
        # handle_signals=False: die Signalbehandlung macht main.py.
        self._runner = web.AppRunner(app, handle_signals=False, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host=cfg.internal_host,
                           port=cfg.internal_port)
        await site.start()
        log.info("Interne API lauscht auf http://%s:%d (Bearer-Auth, nur ids-net)",
                 cfg.internal_host, cfg.internal_port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
