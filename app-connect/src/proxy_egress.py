"""HTTP-CONNECT-Egress für den ausgehenden WSS-Tunnel (protocol.md §1.1).

Der bestehende Cyjan-Stack spricht *nirgends* über einen HTTP-Proxy —
tap-uplink und master-uplink reden direkt, und `cyjan-update` benutzt den
System-Proxy nur indirekt über curl. app-connect ist der erste Dienst, der
aus einem OT-Netz heraus ins Internet muss, und OT-Netze haben in aller
Regel genau einen Weg dorthin: einen expliziten Forward-Proxy.

Ablauf:

    1. `HTTPS_PROXY` parsen (Schema, Host, Port, optional user:pass)
    2. `no_proxy` prüfen — Hostname-Suffixe UND CIDRs
    3. TCP zum Proxy, `CONNECT host:443 HTTP/1.1` senden, auf 2xx warten
    4. den rohen, jetzt getunnelten Socket an websockets übergeben
       (`websockets.connect(uri, sock=..., ssl=ctx)` — die Lib setzt
       `server_hostname` automatisch aus der URI, der TLS-Handshake läuft
       also Ende-zu-Ende gegen den echten Proxy-Endpunkt, nicht gegen den
       Forward-Proxy).

Zu no_proxy im Besonderen: der `ids-setup`-Wizard schreibt CIDRs
(`192.168.0.0/16`) in `/etc/environment`. curl versteht das nicht und
schickt solche Ziele trotzdem durch den Proxy. Hier wird es richtig
gemacht — CIDR-Einträge werden als Netz geparst und gegen die Ziel-IP
geprüft, Suffix-Einträge wie gewohnt gegen den Hostnamen.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

log = logging.getLogger(__name__)

_DEFAULT_PORTS = {"ws": 80, "wss": 443, "http": 80, "https": 443}


class ProxyError(Exception):
    """CONNECT ist fehlgeschlagen — der Tunnel kann nicht aufgebaut werden."""


@dataclass(frozen=True)
class ProxyTarget:
    host: str
    port: int
    scheme: str = "http"
    username: str = ""
    password: str = ""

    def auth_header(self) -> str | None:
        if not self.username and not self.password:
            return None
        raw = f"{self.username}:{self.password}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def as_url(self) -> str:
        """Für httpx (`proxy=`). Credentials bleiben drin, weil httpx sie
        selbst in den Proxy-Authorization-Header übersetzt."""
        auth = ""
        if self.username or self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def __str__(self) -> str:  # niemals Credentials ins Log
        return f"{self.scheme}://{self.host}:{self.port}"


# ── Parsing ──────────────────────────────────────────────────────────────────


def parse_proxy_url(url: str) -> ProxyTarget | None:
    """`http://user:pass@proxy:3128` → ProxyTarget. Leer/ungültig → None.

    Ein schemaloser Wert (`proxy:3128`) wird als http:// interpretiert —
    das tun curl und requests auch, und in /etc/environment steht es oft so.
    """
    raw = (url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlparse(raw)
    except ValueError:
        log.warning("HTTPS_PROXY=%r nicht parsebar — ignoriert", url)
        return None
    if not p.hostname:
        log.warning("HTTPS_PROXY=%r ohne Host — ignoriert", url)
        return None

    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        log.warning("HTTPS_PROXY=%r mit Schema %r nicht unterstützt — ignoriert",
                    url, scheme)
        return None
    if scheme == "https":
        # TLS-zum-Proxy (selten; meist eine Fehlkonfiguration). Wir bauen
        # den CONNECT-Hop trotzdem als Klartext auf, warnen aber deutlich —
        # ein doppelt-TLS-Setup ist in v1 nicht implementiert.
        log.warning("HTTPS_PROXY nutzt https:// — der CONNECT-Hop wird "
                    "unverschlüsselt aufgebaut (TLS-zum-Proxy ist nicht "
                    "implementiert). Der WSS-Tunnel darin bleibt TLS-geschützt.")

    try:
        port = p.port or (443 if scheme == "https" else 3128)
    except ValueError:
        log.warning("HTTPS_PROXY=%r mit ungültigem Port — ignoriert", url)
        return None

    return ProxyTarget(
        host=p.hostname,
        port=int(port),
        scheme=scheme,
        username=unquote(p.username or ""),
        password=unquote(p.password or ""),
    )


def split_no_proxy(no_proxy: str) -> list[str]:
    """Komma- und/oder whitespace-separierte Liste, leere Einträge raus."""
    out: list[str] = []
    for chunk in (no_proxy or "").replace(";", ",").split(","):
        for item in chunk.split():
            item = item.strip()
            if item:
                out.append(item)
    return out


def _entry_matches(entry: str, host: str, port: int | None) -> bool:
    entry = entry.strip().lower()
    if not entry:
        return False
    if entry == "*":
        return True

    # Optionaler Port am Eintrag: "example.com:8080" gilt nur für 8080.
    # Achtung: eine IPv6-Literal-Notation (`::1`, `fe80::/10`) darf davon
    # nicht zerschnitten werden — deshalb nur splitten, wenn genau EIN
    # Doppelpunkt drin ist und der Rest numerisch ist.
    entry_port: int | None = None
    if entry.count(":") == 1:
        left, _, right = entry.partition(":")
        if right.isdigit():
            entry, entry_port = left, int(right)
    if entry_port is not None and port is not None and entry_port != port:
        return False

    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    # IPv6-Literale kommen aus URLs in eckigen Klammern.
    host_clean = host.strip("[]")

    # 1) CIDR / nackte IP — nur sinnvoll, wenn das Ziel selbst eine IP ist.
    #    Hostnamen werden hier bewusst NICHT aufgelöst: ein DNS-Lookup nur
    #    für die Proxy-Entscheidung wäre ein zusätzlicher Fehlerpfad, und
    #    im OT-Netz oft gar nicht möglich.
    try:
        network = ipaddress.ip_network(entry.strip("[]"), strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            addr = ipaddress.ip_address(host_clean)
        except ValueError:
            return False
        return addr.version == network.version and addr in network

    # 2) Hostname-Suffix. ".example.com" und "example.com" sind laut der
    #    (uneinheitlichen) Konvention beide Suffix-Matches; ein exakter
    #    Treffer zählt ebenfalls.
    suffix = entry.lstrip(".")
    return host_clean == suffix or host_clean.endswith("." + suffix)


def bypass_proxy(host: str, port: int | None, no_proxy: str) -> bool:
    """True ⇒ direkt verbinden, Proxy überspringen."""
    for entry in split_no_proxy(no_proxy):
        if _entry_matches(entry, host, port):
            return True
    return False


def target_from_url(url: str) -> tuple[str, int]:
    """(host, port) aus einer ws/wss/http/https-URL, mit Schema-Default."""
    p = urlparse(url)
    host = p.hostname or ""
    port = p.port or _DEFAULT_PORTS.get((p.scheme or "").lower(), 443)
    return host, int(port)


def proxy_for_url(url: str, https_proxy: str, no_proxy: str) -> ProxyTarget | None:
    """Effektiver Proxy für `url` — None heißt Direktverbindung."""
    proxy = parse_proxy_url(https_proxy)
    if proxy is None:
        return None
    host, port = target_from_url(url)
    if bypass_proxy(host, port, no_proxy):
        log.debug("no_proxy greift für %s:%d — Direktverbindung", host, port)
        return None
    return proxy


# ── CONNECT ──────────────────────────────────────────────────────────────────


_MAX_HEADER_BYTES = 32 * 1024


def build_connect_request(host: str, port: int, proxy: ProxyTarget) -> bytes:
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: keep-alive",
        "User-Agent: cyjan-app-connect/1",
    ]
    auth = proxy.auth_header()
    if auth:
        lines.append(f"Proxy-Authorization: {auth}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def parse_connect_response(head: bytes) -> int:
    """Statuscode aus der ersten Zeile. Wirft ProxyError bei Müll."""
    first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise ProxyError(f"Keine HTTP-Antwort vom Proxy: {first!r}")
    try:
        return int(parts[1])
    except ValueError:
        raise ProxyError(f"Ungültiger Statuscode vom Proxy: {first!r}") from None


async def open_proxied_socket(
    host: str,
    port: int,
    proxy: ProxyTarget,
    timeout: float = 15.0,
) -> socket.socket:
    """Baut den CONNECT-Tunnel auf und gibt den rohen, non-blocking Socket
    zurück. Aufrufer übergibt ihn an `websockets.connect(sock=...)`, das
    darauf den TLS-Handshake gegen `host` fährt.

    Bei jedem Fehler wird der Socket geschlossen und ProxyError geworfen —
    ein halb aufgebauter Tunnel darf nie an die WS-Lib gehen.
    """
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(
        proxy.host, proxy.port, type=socket.SOCK_STREAM
    )
    if not infos:
        raise ProxyError(f"Proxy {proxy} nicht auflösbar")

    family, socktype, protocol, _canon, sockaddr = infos[0]
    sock = socket.socket(family, socktype, protocol)
    try:
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout)
        await asyncio.wait_for(
            loop.sock_sendall(sock, build_connect_request(host, port, proxy)),
            timeout,
        )

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout)
            if not chunk:
                raise ProxyError("Proxy hat die Verbindung während CONNECT geschlossen")
            buf += chunk
            if len(buf) > _MAX_HEADER_BYTES:
                raise ProxyError("Proxy-Antwort auf CONNECT zu groß")

        head, _, rest = buf.partition(b"\r\n\r\n")
        status = parse_connect_response(head)
        if not 200 <= status < 300:
            # Header/Body bewusst nicht loggen — dort stehen ggf.
            # Auth-Challenges und interne Hostnamen.
            raise ProxyError(f"Proxy lehnte CONNECT ab: HTTP {status}")
        if rest:
            # Nach 200 gehört der Bytestrom dem TLS-Handshake. Sendet der
            # Proxy hier schon etwas, ist das entweder ein kaputter Proxy
            # oder ein Smuggling-Versuch — beides ein Abbruchgrund, weil
            # wir diese Bytes an websockets nicht nachreichen können.
            raise ProxyError("Proxy sendete unerwartete Daten nach CONNECT")

        log.info("CONNECT-Tunnel über %s zu %s:%d steht", proxy, host, port)
        return sock
    except asyncio.TimeoutError:
        sock.close()
        raise ProxyError(f"Timeout ({timeout:.0f}s) beim CONNECT über {proxy}") from None
    except ProxyError:
        sock.close()
        raise
    except OSError as exc:
        sock.close()
        raise ProxyError(f"CONNECT über {proxy} fehlgeschlagen: {exc}") from exc
