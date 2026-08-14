"""Stufenweiser Egress-Test: DNS → CONNECT/TCP → TLS → Zertifikat.

Eine Implementierung, zwei Aufrufer:

  * `cyjan-app test-proxy` (cli.py) — druckt das Ergebnis als Klartext.
  * `POST /test-egress` (server.py) — liefert es als JSON an die GUI, und
    zwar gegen eine *übergebene* Konfiguration, damit ein Admin einen Proxy
    prüfen kann, bevor er ihn speichert.

Der Wert steckt in der Stufe: „Proxy-Passwort falsch" und „Firewall lässt
CONNECT nicht durch" sehen von außen identisch aus (Tunnel kommt nicht
zustande), brauchen aber völlig verschiedene Leute zur Behebung.

**Credentials tauchen in keinem Rückgabewert auf.** `ProxyTarget.__str__`
redigiert bereits; `_redact()` ist die zweite Linie für Texte, die aus
fremden Exceptions kommen.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl as ssl_mod
from dataclasses import asdict, dataclass, field
from typing import Optional

from proxy_egress import (
    ProxyError,
    ProxyTarget,
    open_proxied_socket,
    proxy_for_url,
    target_from_url,
)

log = logging.getLogger(__name__)

# Stufen in der Reihenfolge, in der sie durchlaufen werden.
STAGES = ("dns", "connect", "tls", "cert")

_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]*@")


def _redact(text: str, *secrets: str) -> str:
    """`http://user:pass@proxy:3128` → `http://proxy:3128`, zusätzlich
    werden explizit übergebene Geheimnisse ersetzt."""
    out = _USERINFO.sub(r"\1", str(text or ""))
    for secret in secrets:
        if secret and len(secret) >= 3:
            out = out.replace(secret, "***")
    return out


@dataclass
class Step:
    name: str
    ok: bool
    detail: str


@dataclass
class EgressResult:
    ok: bool
    stage: str
    detail: str = ""
    hint: str = ""
    steps: list[Step] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "detail": self.detail,
            "hint": self.hint,
            "steps": [asdict(s) for s in self.steps],
        }


def _fail(result: EgressResult, stage: str, detail: str, hint: str = "") -> EgressResult:
    result.ok = False
    result.stage = stage
    result.detail = detail
    result.hint = hint
    result.steps.append(Step(stage, False, detail))
    return result


def classify_connect_error(text: str, proxy: Optional[ProxyTarget]) -> tuple[str, str]:
    """(detail, hint) für einen gescheiterten CONNECT/TCP-Aufbau.

    Der Text ist bereits redigiert; die Klassifikation entspricht 1:1 der
    Logik von `cyjan-app test-proxy`.
    """
    if proxy is None:
        return (
            text,
            "Der direkte Ausgang ist blockiert. Falls ein Proxy nötig ist, "
            "Egress-Proxy in den Einstellungen setzen (HTTPS_PROXY-Form: "
            "http://proxy:3128).",
        )
    if "407" in text:
        return (
            "Der Proxy verlangt Anmeldedaten (407).",
            "Benutzer und Passwort gehören in die URL: "
            "http://user:pass@proxy:3128",
        )
    if "403" in text or "405" in text:
        return (
            text,
            "Der Proxy verweigert CONNECT. Viele Unternehmens-Proxies erlauben "
            "es nur für Port 443 und nur für freigegebene Ziele — der "
            "Cloud-Proxy muss auf die Freigabeliste.",
        )
    if "nicht auflösbar" in text:
        return (
            text,
            "Der Proxy-Hostname ist nicht auflösbar. Im OT-Netz oft Absicht — "
            "dann den Proxy per IP-Adresse eintragen.",
        )
    if "Errno" in text or "timeout" in text.lower() or "timed out" in text.lower():
        return (
            text,
            f"Der Proxy {proxy} war nicht erreichbar — die Verbindung kam nicht "
            "zustande. Adresse und Port prüfen, danach die Firewall zwischen "
            "Master und Proxy.",
        )
    return (text, "Der Proxy hat den Tunnel abgelehnt.")


def _tls_handshake(
    sock: socket.socket, host: str, ca_file: str, tls_insecure: bool
) -> tuple[str, str]:
    """Blockierender Handshake — gehört in einen Thread, nie in den
    Event-Loop (der interne Server darf den Tunnel nicht anhalten).

    Liefert (protokoll, aussteller-organisation).
    """
    ctx = ssl_mod.create_default_context(ssl_mod.Purpose.SERVER_AUTH)
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if tls_insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE

    sock.setblocking(True)
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        cert = tls.getpeercert()
        proto = tls.version() or "?"
    issuer = "?"
    if cert:
        for part in cert.get("issuer", ()):  # type: ignore[union-attr]
            for key, value in part:
                if key == "organizationName":
                    issuer = value
    return proto, issuer


async def check_egress(
    url: str,
    https_proxy: str = "",
    no_proxy: str = "",
    ca_file: str = "",
    tls_insecure: bool = False,
    timeout: float = 15.0,
) -> EgressResult:
    """Prüft den Egress-Pfad zu `url` Stufe für Stufe. Wirft nicht — das
    Ergebnis steht in `ok`/`stage`."""
    result = EgressResult(ok=False, stage="dns")
    proxy = proxy_for_url(url, https_proxy, no_proxy)
    secrets = (proxy.password, proxy.username) if proxy else ("", "")

    host, port = target_from_url(url)
    if not host:
        return _fail(result, "dns", f"Ziel-URL ohne Host: {url!r}",
                     "Erwartet wird eine vollständige URL, z.B. "
                     "wss://proxy.cyjan.dev/tunnel")

    loop = asyncio.get_running_loop()
    resolve_host = proxy.host if proxy else host
    resolve_port = proxy.port if proxy else port

    # ── 1. Namensauflösung ───────────────────────────────────────────────
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(resolve_host, resolve_port, type=socket.SOCK_STREAM),
            timeout,
        )
    except asyncio.TimeoutError:
        return _fail(
            result, "dns", f"Namensauflösung für {resolve_host} hat "
                           f"{timeout:.0f}s überschritten.",
            "Kein DNS-Server erreichbar. Im OT-Netz oft Absicht — dann muss "
            "der Proxy per IP statt per Name eingetragen werden.",
        )
    except socket.gaierror as exc:
        return _fail(
            result, "dns", f"{resolve_host} ist nicht auflösbar ({exc}).",
            "Namen prüfen, oder im OT-Netz die IP-Adresse direkt eintragen.",
        )
    if not infos:
        return _fail(result, "dns", f"{resolve_host} lieferte keine Adresse.", "")

    addrs = sorted({i[4][0] for i in infos})
    result.steps.append(
        Step("dns", True, f"{resolve_host} → {', '.join(addrs)}")
    )

    # ── 2. TCP bzw. CONNECT-Tunnel ───────────────────────────────────────
    sock: socket.socket | None = None
    try:
        if proxy is not None:
            sock = await open_proxied_socket(host, port, proxy, timeout=timeout)
            connect_detail = f"CONNECT-Tunnel über {proxy} zu {host}:{port} steht"
        else:
            family, socktype, protocol, _canon, sockaddr = infos[0]
            sock = socket.socket(family, socktype, protocol)
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout)
            connect_detail = f"direkt verbunden mit {sockaddr[0]}:{port}"
    except ProxyError as exc:
        detail, hint = classify_connect_error(_redact(exc, *secrets), proxy)
        return _fail(result, "connect", detail, hint)
    except asyncio.TimeoutError:
        detail, hint = classify_connect_error(
            f"Timeout ({timeout:.0f}s) beim Verbindungsaufbau.", proxy
        )
        return _fail(result, "connect", detail, hint)
    except OSError as exc:
        detail, hint = classify_connect_error(_redact(exc, *secrets), proxy)
        return _fail(result, "connect", detail, hint)

    result.steps.append(Step("connect", True, connect_detail))

    # Klartext-Ziel (ws:// bzw. http://) — Lab- und Bring-up-Betrieb. Dahinter
    # liegt kein TLS, also gibt es auch nichts zu prüfen. Täten wir es doch,
    # meldete der Test einen funktionierenden Tunnel als rot, und zwar mit
    # einem Hinweis, der zum Nachbessern an der falschen Stelle einlädt.
    if url.lower().startswith(("ws://", "http://")):
        for name in ("tls", "cert"):
            result.steps.append(
                Step(name, True, "übersprungen — Klartext-Verbindung (ws://)")
            )
        if sock is not None:
            sock.close()
        result.ok = True
        result.stage = "ok"
        result.detail = (
            "Egress-Pfad ist frei. Achtung: unverschlüsselte Verbindung — "
            "für den Produktivbetrieb wss:// verwenden."
        )
        return result

    # ── 3./4. TLS + Zertifikat ───────────────────────────────────────────
    try:
        proto, issuer = await asyncio.wait_for(
            asyncio.to_thread(_tls_handshake, sock, host, ca_file, tls_insecure),
            timeout,
        )
        sock = None  # gehört ab jetzt dem TLS-Wrapper und ist geschlossen
    except ssl_mod.SSLCertVerificationError as exc:
        return _fail(
            result, "cert",
            f"Zertifikat abgelehnt: {_redact(exc.verify_message or exc, *secrets)}",
            "Typischer Fall: der Proxy bricht TLS auf und ersetzt das "
            "Zertifikat durch ein eigenes. Firmen-CA nach /etc/cyjan/certs/ "
            "legen und den CA-Pfad auf die Datei im Container zeigen lassen, "
            "z.B. /etc/cyjan/certs/corp-ca.pem",
        )
    except (ssl_mod.SSLError, OSError) as exc:
        return _fail(result, "tls", f"TLS-Handshake fehlgeschlagen: "
                                    f"{_redact(exc, *secrets)}",
                     "Zielport erreichbar, aber kein TLS dahinter? Schema und "
                     "Port der Proxy-URL prüfen.")
    except asyncio.TimeoutError:
        return _fail(result, "tls", f"TLS-Handshake hat {timeout:.0f}s "
                                    "überschritten.", "")
    finally:
        if sock is not None:
            sock.close()

    result.steps.append(Step("tls", True, f"{proto}, Aussteller: {issuer}"))
    result.steps.append(Step("cert", True, f"gültig für {host}"))
    result.ok = True
    result.stage = "ok"
    result.detail = f"Egress-Pfad zu {host}:{port} ist frei."
    if ca_file and issuer != "?":
        result.hint = (
            f"Verifikation lief gegen {ca_file} (Aussteller: {issuer}). Sieht "
            "der Aussteller nach einer Firmen-CA aus, inspiziert der Proxy "
            "TLS — dann ist genau das richtig so."
        )
    elif tls_insecure:
        result.hint = ("TLS-Prüfung ist abgeschaltet — das Ergebnis sagt "
                       "nichts über die Echtheit des Gegenübers aus.")
    return result
