"""HTTP-Client für die lokale ids-api (protocol.md §2.2).

Auth-Muster ist 1:1 von `rule-tuner/src/api_client.py` übernommen: der
Service mintet sich sein JWT selbst aus dem geteilten `API_SECRET_KEY`.
Kein User-DB-Eintrag nötig, weil `get_current_user` nur die Signatur
validiert.

**Unterschied zum rule-tuner: `role="viewer"`, nicht `admin`.** Damit sind
sämtliche `require_admin`-Router (sig-rules, maintenance, users,
notifications, taps, config) serverseitig unerreichbar — das zweite Netz
unter der Allowlist. Wer hier auf admin hochdreht, hebelt die halbe
Sicherheitsarchitektur des Tunnels aus.

`trust_env=False` ist ebenfalls Absicht: der Weg zur lokalen api darf
NIEMALS durch den Egress-Proxy laufen, auch wenn HTTPS_PROXY gesetzt ist.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import httpx
from jose import jwt as jose_jwt

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
# protocol.md §2.2: exp = now + 3600, alle 30 min erneuert.
TOKEN_TTL_S = 3600
TOKEN_REFRESH_S = 1800

# Welche Response-Header wir zurück in den Tunnel geben. Alles andere
# (Set-Cookie, Server, interne Tracing-Header) bleibt im OT-Netz.
_RESPONSE_HEADER_WHITELIST = frozenset({
    "content-type", "content-length", "content-disposition",
})


@dataclass
class RpcResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False


def _mint_service_token(secret: str) -> str:
    payload = {
        "sub": "app-connect",
        "username": "app-connect",
        "role": "viewer",
        "exp": int(time.time()) + TOKEN_TTL_S,
    }
    return jose_jwt.encode(payload, secret, algorithm=ALGORITHM)


def filter_response_headers(headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in dict(headers).items():
        if k.lower() in _RESPONSE_HEADER_WHITELIST:
            out[k.lower()] = v
    return out


class ApiClient:
    """Async-Client gegen `http://api:8000`. Token wird gecacht und alle
    30 min neu gemintet (Signieren ist billig, aber ein Token pro RPC wäre
    bei einem Alert-Sturm trotzdem sinnlose Arbeit)."""

    def __init__(
        self,
        base_url: str,
        secret_key: str,
        timeout_s: float = 20.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url
        self._secret = secret_key
        self._timeout_s = timeout_s
        # Nur für Tests (httpx.MockTransport). In Produktion None.
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._token: str = ""
        self._token_minted_at: float = 0.0

    async def __aenter__(self) -> "ApiClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout_s, connect=5.0),
            follow_redirects=False,
            trust_env=False,   # niemals über den Egress-Proxy
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        assert self._client is not None, "ApiClient nicht betreten"
        return self._client

    def _auth(self) -> dict[str, str]:
        now = time.monotonic()
        if not self._token or now - self._token_minted_at > TOKEN_REFRESH_S:
            self._token = _mint_service_token(self._secret)
            self._token_minted_at = now
        return {"Authorization": f"Bearer {self._token}"}

    # ── RPC-Ausführung ───────────────────────────────────────────────────

    async def execute(
        self,
        method: str,
        path: str,
        query: dict[str, str] | None = None,
        body: bytes | None = None,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> RpcResponse:
        """Führt einen Allowlist-geprüften Request aus und deckelt den
        Body auf `max_bytes` (protocol.md §2.4). Bei Überschreitung:
        leerer Body + truncated=True — wir schicken bewusst NICHT die
        ersten 4 MiB, weil ein halbes JSON die App nur zum Parse-Fehler
        führt."""
        headers = self._auth()
        if body:
            headers.setdefault("content-type", "application/json")

        req = self.client.build_request(
            method.upper(), path, params=query or None,
            content=body or None, headers=headers,
        )
        resp = await self.client.send(req, stream=True)
        chunks = resp.aiter_bytes(65536)
        try:
            buf = bytearray()
            truncated = False
            async for chunk in chunks:
                buf += chunk
                if len(buf) > max_bytes:
                    truncated = True
                    break
            # Generator explizit schließen — sonst räumt erst der GC auf
            # und wirft dabei "coroutine ... never awaited"-Warnungen.
            await chunks.aclose()
            return RpcResponse(
                status=resp.status_code,
                headers=filter_response_headers(resp.headers),
                body=b"" if truncated else bytes(buf),
                truncated=truncated,
            )
        finally:
            await resp.aclose()

    async def stream(
        self,
        method: str,
        path: str,
        query: dict[str, str] | None = None,
        chunk_bytes: int = 192 * 1024,
        max_bytes: int = 32 * 1024 * 1024,
    ) -> AsyncIterator[tuple[int, dict[str, str], bytes, bool]]:
        """Streaming-Variante für PCAP (protocol.md §2.5).

        Yielded Tupel: (status, headers, chunk, truncated). Das erste Tupel
        trägt Status + Header (Chunk kann leer sein), danach nur noch
        Daten. `truncated=True` im letzten Tupel heißt: `max_bytes`
        erreicht, der Rest wurde verworfen.
        """
        req = self.client.build_request(
            method.upper(), path, params=query or None, headers=self._auth()
        )
        resp = await self.client.send(req, stream=True)
        chunks = resp.aiter_bytes(chunk_bytes)
        try:
            status = resp.status_code
            headers = filter_response_headers(resp.headers)
            sent_header = False
            total = 0
            buf = bytearray()
            truncated = False

            async for chunk in chunks:
                buf += chunk
                total += len(chunk)
                if total > max_bytes:
                    truncated = True
                while len(buf) >= chunk_bytes:
                    piece = bytes(buf[:chunk_bytes])
                    del buf[:chunk_bytes]
                    yield (status, headers if not sent_header else {}, piece, False)
                    sent_header = True
                if truncated:
                    break

            if buf and not truncated:
                yield (status, headers if not sent_header else {}, bytes(buf), False)
                sent_header = True
            if not sent_header:
                # Leerer Body (z.B. 404) — Header trotzdem ausliefern.
                yield (status, headers, b"", truncated)
            elif truncated:
                yield (status, {}, b"", True)
        finally:
            await chunks.aclose()
            await resp.aclose()

    # ── Convenience ──────────────────────────────────────────────────────

    async def get_threat_level(self) -> dict | None:
        """`GET /api/stats/threat-level` → {level, label, alert_counts,
        window_min}. None bei Fehler (die api kann während eines Restarts
        kurz weg sein — das ist kein Grund, den Tunnel zu reißen)."""
        try:
            r = await self.client.get("/api/stats/threat-level", headers=self._auth())
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, dict) else None
        except Exception as exc:
            log.debug("threat-level-Poll fehlgeschlagen: %s", exc)
            return None
