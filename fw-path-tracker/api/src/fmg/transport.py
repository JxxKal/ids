"""Transport-Schicht für den FortiManager-JSON-RPC-Client.

HttpTransport spricht den echten FMG; FixtureTransport spielt aufgezeichnete
Antworten deterministisch ab (pytest + Demo-Mode ohne Lab). RecordingTransport
wrappt den HttpTransport und schneidet Antworten als Fixture-Files mit
(FMG_RECORD_FIXTURES=1).

Fixture-Key: Hash über das normalisierte Payload (ohne session/id; resource-
Querystrings werden in sortierte Param-Listen zerlegt, damit die Reihenfolge
der Querystring-Parameter egal ist).
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit

import httpx

log = logging.getLogger("fmg.transport")


class Transport(Protocol):
    async def send(self, payload: dict) -> dict: ...
    async def close(self) -> None: ...


def _normalize(obj: Any) -> Any:
    """Payload für Fixture-Keying normalisieren (rekursiv)."""
    if isinstance(obj, dict):
        return {
            k: _normalize_resource(v) if k == "resource" else _normalize(v)
            for k, v in sorted(obj.items())
            if k not in ("session", "id")
        }
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def _normalize_resource(resource: Any) -> Any:
    if not isinstance(resource, str):
        return resource
    parts = urlsplit(resource)
    params = sorted(parse_qsl(parts.query))
    return {"path": parts.path, "params": params}


def fixture_key(payload: dict) -> str:
    canonical = json.dumps(_normalize(payload), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()[:24]


class HttpTransport:
    def __init__(self, base_url: str, *, ssl_verify: bool = True,
                 timeout: float = 60.0, bearer_token: str | None = None):
        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), verify=ssl_verify,
            timeout=timeout, headers=headers,
        )

    async def send(self, payload: dict) -> dict:
        r = await self._client.post("/jsonrpc", json=payload)
        r.raise_for_status()
        return r.json()

    async def close(self) -> None:
        await self._client.aclose()


class FixtureMissing(Exception):
    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__(
            f"Keine Fixture für Request (key={fixture_key(payload)}): "
            f"{json.dumps(_normalize(payload), ensure_ascii=False)[:400]}"
        )


class FixtureTransport:
    """Antworten aus Verzeichnis (JSON-Files {request, response}) und/oder
    programmatisch registrierten Paaren (Tests)."""

    def __init__(self, fixture_dir: str | Path | None = None):
        self._fixtures: dict[str, dict] = {}
        if fixture_dir:
            self.load_dir(fixture_dir)

    def load_dir(self, fixture_dir: str | Path) -> None:
        d = Path(fixture_dir)
        if not d.is_dir():
            return
        for f in sorted(d.glob("*.json")):
            try:
                doc = json.loads(f.read_text())
                self._fixtures[fixture_key(doc["request"])] = doc["response"]
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("Fixture %s ungültig: %s", f.name, exc)

    def add(self, request: dict, response: dict) -> None:
        self._fixtures[fixture_key(request)] = response

    async def send(self, payload: dict) -> dict:
        key = fixture_key(payload)
        if key not in self._fixtures:
            raise FixtureMissing(payload)
        return copy.deepcopy(self._fixtures[key])

    async def close(self) -> None:
        pass


class RecordingTransport:
    """Wrappt einen echten Transport und schreibt jede Antwort als Fixture."""

    def __init__(self, inner: Transport, fixture_dir: str | Path):
        self._inner = inner
        self._dir = Path(fixture_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    async def send(self, payload: dict) -> dict:
        response = await self._inner.send(payload)
        key = fixture_key(payload)
        path = self._dir / f"{key}.json"
        redacted = _normalize(payload)  # session/id sind schon raus
        path.write_text(json.dumps(
            {"request": redacted, "response": response},
            indent=2, ensure_ascii=False,
        ))
        log.info("Fixture aufgezeichnet: %s", path.name)
        return response

    async def close(self) -> None:
        await self._inner.close()
