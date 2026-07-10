"""FortiManager-JSON-RPC-Client mit zentraler No-Write-Garantie.

Der Write-Guard sitzt in ``rpc()`` selbst, nicht in den Aufrufern: erlaubt
sind nur ``get`` und ``exec``; ``exec`` nur für Login/Logout und
``/sys/proxy/json``, und im Proxy-Payload nur ``action: "get"``. Jeder
andere Aufruf raist ``FmgWriteBlocked`` — egal woher er kommt.

Auth-Modi:
  - token:   FMG >= 7.2.2, Bearer-Header (REST-API-Admin mit rpc-permit)
  - session: Fallback für ältere FMG, exec /sys/login/user + session-Feld
"""
from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Any

import httpx

from fmg.transport import Transport

log = logging.getLogger("fmg.client")

ALLOWED_EXEC_URLS = frozenset({"/sys/login/user", "/sys/logout", "/sys/proxy/json"})


class FmgError(Exception):
    """Basisklasse für FMG-Fehler."""
    def __init__(self, message: str, code: int | None = None):
        self.code = code
        super().__init__(message)


class FmgAuthError(FmgError):
    """Login fehlgeschlagen / Session abgelaufen / Token ungültig."""


class FmgPermissionError(FmgError):
    """Admin-Profil erlaubt die Operation nicht (rpc-permit / Profil prüfen)."""


class FmgTargetOffline(FmgError):
    """Ziel-FortiGate über den Proxy nicht erreichbar."""


class FmgWriteBlocked(FmgError):
    """Vom Code-Write-Guard geblockt — dieser Client schreibt nie."""


# FMG-Statuscodes (result[0].status.code)
_CODE_NO_PERMISSION = -11
_CODE_LOGIN_FAIL = -22
_CODE_SESSION_INVALID = -1  # "Invalid session" / abgelaufene Session


def _assert_readonly(method: str, url: str, data: Any) -> None:
    m = (method or "").lower()
    if m not in ("get", "exec"):
        raise FmgWriteBlocked(f"Methode '{method}' ist geblockt (No-Write-Garantie).")
    if m == "exec":
        if url not in ALLOWED_EXEC_URLS:
            raise FmgWriteBlocked(f"exec auf '{url}' ist geblockt (No-Write-Garantie).")
        if url == "/sys/proxy/json":
            action = (data or {}).get("action")
            if action != "get":
                raise FmgWriteBlocked(
                    f"Proxy-Action '{action}' ist geblockt — nur action='get' erlaubt."
                )


class FmgClient:
    def __init__(self, transport: Transport, *, auth_mode: str = "token",
                 username: str | None = None, password: str | None = None):
        self._transport = transport
        self._auth_mode = auth_mode  # "token" | "session"
        self._username = username
        self._password = password
        self._session: str | None = None
        self._ids = itertools.count(1)
        self._login_lock = asyncio.Lock()

    # ── Auth ────────────────────────────────────────────────────────────────

    async def _login(self) -> None:
        if self._auth_mode != "session":
            return
        async with self._login_lock:
            payload = {
                "id": next(self._ids),
                "method": "exec",
                "params": [{
                    "url": "/sys/login/user",
                    "data": {"user": self._username, "passwd": self._password},
                }],
            }
            body = await self._transport.send(payload)
            status = ((body.get("result") or [{}])[0].get("status") or {})
            if status.get("code", 0) != 0:
                raise FmgAuthError(f"FMG-Login fehlgeschlagen: {status.get('message')}",
                                   status.get("code"))
            self._session = body.get("session")
            if not self._session:
                raise FmgAuthError("FMG-Login ohne Session in der Antwort.")

    async def logout(self) -> None:
        if self._session:
            try:
                await self._raw_rpc("exec", "/sys/logout", None)
            except FmgError:
                pass
            self._session = None

    async def close(self) -> None:
        await self.logout()
        await self._transport.close()

    # ── RPC ─────────────────────────────────────────────────────────────────

    async def rpc(self, method: str, url: str, data: Any = None) -> Any:
        """Einziger Weg zum FMG. Write-Guard, Retry auf Netzfehler,
        transparentes Relogin bei abgelaufener Session."""
        _assert_readonly(method, url, data)

        if self._auth_mode == "session" and self._session is None and url != "/sys/login/user":
            await self._login()

        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                return await self._raw_rpc(method, url, data)
            except FmgAuthError:
                if self._auth_mode == "session" and attempt == 0:
                    self._session = None
                    await self._login()
                    continue
                raise
            except httpx.TransportError as exc:
                last_exc = exc
                await asyncio.sleep(0.5 * (attempt + 1))
        raise FmgError(f"FMG nicht erreichbar: {last_exc}")

    async def _raw_rpc(self, method: str, url: str, data: Any) -> Any:
        params: dict[str, Any] = {"url": url}
        if data is not None:
            params["data"] = data
        payload: dict[str, Any] = {
            "id": next(self._ids),
            "method": method.lower(),
            "params": [params],
        }
        if self._session:
            payload["session"] = self._session

        body = await self._transport.send(payload)
        result = (body.get("result") or [{}])[0]
        status = result.get("status") or {}
        code = status.get("code", 0)
        if code == 0:
            return result.get("data")
        message = status.get("message", "unbekannter Fehler")
        if code in (_CODE_LOGIN_FAIL, _CODE_SESSION_INVALID) or "session" in message.lower():
            raise FmgAuthError(f"FMG-Auth: {message}", code)
        if code == _CODE_NO_PERMISSION or "permission" in message.lower():
            raise FmgPermissionError(
                f"FMG verweigert '{method} {url}': {message} — "
                "Admin-Profil/rpc-permit prüfen.", code)
        raise FmgError(f"FMG-Fehler bei '{method} {url}': {message}", code)
