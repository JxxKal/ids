"""HTTP-Client für die api: GET /api/sig-rules/list, GET /ml/status,
PUT /api/sig-rules/overrides.

Auth: wir minten ein langlebiges JWT mit role='admin' aus dem geteilten
SECRET_KEY. Kein User-DB-Eintrag nötig — get_current_user validiert nur
die Signatur, nicht die Existenz des Users.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from jose import jwt as jose_jwt

from config import Config

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 365 * 24 * 3600


def _mint_service_token(secret: str) -> str:
    """Erstellt ein langlebiges JWT für Service-zu-Service-Aufrufe.

    `sub`/`username` sind keine echten User-IDs, sondern Identifier zur
    Diagnose im Log. role='admin' ist nötig, weil require_admin auf den
    sig_rules-Endpoints prüft.
    """
    import time
    payload = {
        "sub":      "rule-tuner",
        "username": "rule-tuner-service",
        "role":     "admin",
        "exp":      int(time.time()) + TOKEN_TTL_SECONDS,
    }
    return jose_jwt.encode(payload, secret, algorithm=ALGORITHM)


class ApiClient:
    """Async-Client mit cached httpx.AsyncClient + Service-Token."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ApiClient":
        self._token = _mint_service_token(self._cfg.api_secret_key)
        self._client = httpx.AsyncClient(
            base_url=self._cfg.api_base_url,
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={"Authorization": f"Bearer {self._token}"},
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        assert self._client is not None, "ApiClient not entered"
        return self._client

    # ── Reads ─────────────────────────────────────────────────────────────

    async def get_ml_status(self) -> dict:
        r = await self.client.get("/api/sig-rules/ml/status")
        r.raise_for_status()
        return r.json()

    async def list_rules(self) -> list[dict]:
        """Alle YAML-Regeln + aktuelle Override-Effective-Werte + Schema."""
        r = await self.client.get("/api/sig-rules/list")
        r.raise_for_status()
        return r.json()

    async def get_overrides(self) -> dict[str, dict]:
        """Roher Inhalt von _overrides.json (decoded)."""
        r = await self.client.get("/api/sig-rules/overrides")
        r.raise_for_status()
        body = r.json()
        return body.get("overrides", {}) if isinstance(body, dict) else {}

    # ── Writes ────────────────────────────────────────────────────────────

    async def put_overrides(self, payload: dict[str, dict]) -> None:
        """Setzt Overrides komplett — die api ersetzt den Inhalt von
        _overrides.json. signature-engine und tap-uplink picken das via
        mtime-Watch + Reverse-Channel selbst auf."""
        r = await self.client.put(
            "/api/sig-rules/overrides", json={"overrides": payload}
        )
        r.raise_for_status()
