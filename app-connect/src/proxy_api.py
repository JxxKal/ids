"""Zugriff auf die Verwaltungs-Endpoints des Cloud-Proxys.

Enrollment-Codes und Gerätelisten liegen beim Cloud-Proxy, nicht lokal.
Nur app-connect kennt den Weg dorthin (Device-Token, Firmen-Proxy,
Firmen-CA) — deshalb laufen sowohl `cyjan-app pair|devices|revoke` als
auch die interne HTTP-API über dieses Modul.

Wichtig, und die häufigste Fehlerquelle beim Kopplen: `proxy_url` ist der
**Tunnel**-Endpunkt (`wss://proxy.cyjan.dev/tunnel`), den app-connect
selbst benutzt. Die App spricht dagegen die **REST-Basis**
(`https://proxy.cyjan.dev`) an. `rest_base_url()` leitet das eine aus dem
anderen ab; wer stattdessen die Tunnel-URL in den QR-Code schreibt, erzeugt
einen Code, an dem sich jedes Gerät die Zähne ausbeißt.
"""
from __future__ import annotations

import io
import logging
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from config import Config

log = logging.getLogger(__name__)

# Der proxy-seitige Enrollment-Pfad steht in protocol.md §6. Die
# Verwaltungs-Endpoints (Liste/Revoke) sind dort nur als CLI-Verhalten
# beschrieben, nicht als HTTP-Pfad — wir spiegeln sie unter /internal/,
# analog zu /internal/enroll-codes.
ENROLL_PATH = "/internal/enroll-codes"
DEVICES_PATH = "/internal/devices"

# Deep-Link-Schema der App (`scheme: "cyjan"` in app.json).
DEEP_LINK_SCHEME = "cyjan"
DEEP_LINK_HOST = "enroll"

_SCHEME_MAP = {"wss": "https", "ws": "http", "https": "https", "http": "http"}


class CloudProxyError(Exception):
    """Der Cloud-Proxy war nicht erreichbar oder hat abgelehnt."""

    def __init__(self, detail: str, status: Optional[int] = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status


# ── URL-Ableitung ────────────────────────────────────────────────────────────


def rest_base_url(proxy_url: str) -> str:
    """Tunnel-URL → REST-Basis.

        wss://proxy.cyjan.dev/tunnel   →  https://proxy.cyjan.dev
        ws://10.0.0.5:8000/tunnel      →  http://10.0.0.5:8000

    Schema wird abgebildet (wss→https, ws→http), der Pfad fällt weg, Host
    und Port bleiben erhalten.
    """
    raw = (proxy_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "wss://" + raw
    p = urlparse(raw)
    if not p.netloc:
        return ""
    scheme = _SCHEME_MAP.get((p.scheme or "").lower(), "https")
    return urlunparse((scheme, p.netloc, "", "", "", ""))


def build_deep_link(rest_base: str, code: str) -> str:
    """`cyjan://enroll?proxy=<rest-basis>&code=<code>`"""
    query = urlencode({"proxy": rest_base, "code": code})
    return f"{DEEP_LINK_SCHEME}://{DEEP_LINK_HOST}?{query}"


def qr_svg(data: str) -> str:
    """QR-Code als SVG-Markup (kodiert wird der deep_link).

    Bewusst die SVG-Factory von `qrcode` und nicht die PNG-Variante: die
    bräuchte Pillow, und ein zusätzliches Bild-Toolkit für einen
    Schwarz-Weiß-Raster wäre schlecht investierte Angriffsfläche.
    """
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(
        data,
        image_factory=qrcode.image.svg.SvgPathImage,
        border=2,
    )
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode("utf-8")
    # Die Factory schreibt eine XML-Deklaration voran; die GUI bettet das
    # Markup als data:-URI ein und braucht nur das <svg>-Element.
    idx = svg.find("<svg")
    return svg[idx:] if idx > 0 else svg


# ── HTTP-Client ──────────────────────────────────────────────────────────────


def client_kwargs(cfg: Config) -> dict[str, Any]:
    """Gemeinsame httpx-Argumente für CLI (sync) und Server (async).

    `trust_env=False` ist Absicht: httpx kann keine CIDR-Einträge in
    no_proxy, wir schon (`proxy_egress`) — die Proxy-Entscheidung wird
    deshalb hier getroffen und httpx nur noch das Ergebnis mitgeteilt.
    """
    from proxy_egress import proxy_for_url

    base = rest_base_url(cfg.proxy_url)
    proxy = proxy_for_url(base, cfg.https_proxy, cfg.no_proxy) if base else None
    return {
        "base_url": base,
        "timeout": httpx.Timeout(30.0, connect=10.0),
        "headers": {"Authorization": f"Bearer {cfg.device_token}"},
        "verify": (cfg.ca_file or not cfg.tls_insecure),
        "proxy": (proxy.as_url() if proxy else None),
        "trust_env": False,
    }


def _fail(exc: httpx.HTTPError) -> CloudProxyError:
    # Der Text von httpx kann die Proxy-URL inklusive Credentials
    # enthalten — deshalb nur den Exception-Typ und eine eigene Erklärung.
    return CloudProxyError(
        f"Cloud-Proxy nicht erreichbar ({type(exc).__name__}). Egress-Test "
        "unter Einstellungen ausführen, um die Ursache einzugrenzen.",
    )


def _reject(resp: httpx.Response) -> CloudProxyError:
    return CloudProxyError(
        f"Cloud-Proxy lehnte ab: HTTP {resp.status_code}. "
        + (
            "Das Device-Token ist ungültig oder wurde widerrufen."
            if resp.status_code in (401, 403)
            else "Antwort siehe app-connect-Log."
        ),
        status=resp.status_code,
    )


async def create_enroll_code(cfg: Config, label: str, ttl_s: Optional[int]) -> dict:
    """Enrollment-Code beim Proxy anlegen. Liefert das rohe Proxy-JSON."""
    body: dict[str, Any] = {"label": label}
    if ttl_s:
        body["ttl_s"] = int(ttl_s)
    async with httpx.AsyncClient(**client_kwargs(cfg)) as client:
        try:
            resp = await client.post(ENROLL_PATH, json=body)
        except httpx.HTTPError as exc:
            log.warning("Enrollment-Request fehlgeschlagen: %s", type(exc).__name__)
            raise _fail(exc) from exc
    if resp.status_code >= 400:
        log.warning("Proxy lehnte Enrollment ab: HTTP %d %s",
                    resp.status_code, resp.text[:200])
        raise _reject(resp)
    data = resp.json()
    return data if isinstance(data, dict) else {}


async def list_devices(cfg: Config) -> list[dict]:
    async with httpx.AsyncClient(**client_kwargs(cfg)) as client:
        try:
            resp = await client.get(DEVICES_PATH)
        except httpx.HTTPError as exc:
            log.warning("Geräteliste fehlgeschlagen: %s", type(exc).__name__)
            raise _fail(exc) from exc
    if resp.status_code >= 400:
        raise _reject(resp)
    data = resp.json()
    devices = data.get("devices") if isinstance(data, dict) else data
    return [d for d in (devices or []) if isinstance(d, dict)]


async def revoke_device(cfg: Config, device_id: str) -> None:
    async with httpx.AsyncClient(**client_kwargs(cfg)) as client:
        try:
            resp = await client.delete(f"{DEVICES_PATH}/{device_id}")
        except httpx.HTTPError as exc:
            log.warning("Revoke fehlgeschlagen: %s", type(exc).__name__)
            raise _fail(exc) from exc
    if resp.status_code == 404:
        raise CloudProxyError(f"Gerät {device_id} ist dem Cloud-Proxy unbekannt.",
                              status=404)
    if resp.status_code >= 400:
        raise _reject(resp)
