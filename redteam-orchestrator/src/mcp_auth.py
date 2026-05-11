"""MCP-Auth-Middleware — validiert eingehende Bearer-JWTs auf /mcp/-Pfaden.

Wenn settings.mcp_auth_required = True (env `MCP_AUTH_REQUIRED=true`),
muss jeder Request gegen /mcp/* einen `Authorization: Bearer <jwt>`-Header
tragen, der gegen das geteilte API_SECRET_KEY signiert ist + im exp-Fenster
liegt + role='api' Claim hat. Sonst 401.

Default: deaktiviert (MCP_AUTH_REQUIRED=false oder fehlend) — abwärts-
kompatibel mit existierender Lab-Konfig wo MCP offen läuft. Customer-
Deployments sollten das explizit auf true setzen.
"""
from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt as jose_jwt
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

log = logging.getLogger(__name__)

ALGORITHM = "HS256"


class MCPAuthMiddleware(BaseHTTPMiddleware):
    """Prüft Bearer-JWT auf allen /mcp/-Pfaden wenn settings.mcp_auth_required.

    Validation-Schritte:
      1. Path startet mit /mcp → check, sonst pass-through
      2. Authorization-Header vorhanden und beginnt mit "Bearer "?
      3. JWT signiert mit API_SECRET_KEY (HS256)?
      4. exp noch in der Zukunft?
      5. role-Claim ist 'api' oder 'admin'?

    Auf Fehler: 401 mit klarer Fehlermeldung im Body — der MCP-Client
    (Claude Desktop etc.) zeigt das dem User direkt an."""

    async def dispatch(self, request: Request, call_next: Callable):
        if not settings.mcp_auth_required:
            return await call_next(request)
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return _err(401, "missing_bearer",
                        "MCP-Endpoint requires Authorization: Bearer <token>")
        token = auth[7:].strip()

        secret = settings.api_secret_key
        if not secret:
            log.error("MCP_AUTH_REQUIRED=true but API_SECRET_KEY ist leer — alle Requests werden geblockt")
            return _err(503, "auth_misconfigured",
                        "Server has MCP_AUTH_REQUIRED but no API_SECRET_KEY configured")

        try:
            claims = jose_jwt.decode(token, secret, algorithms=[ALGORITHM])
        except JWTError as exc:
            return _err(401, "invalid_jwt", f"JWT validation failed: {exc}")

        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and exp < time.time():
            return _err(401, "token_expired", "Token expired")

        role = claims.get("role")
        if role not in ("api", "admin"):
            return _err(403, "wrong_role",
                        f"Token role '{role}' not allowed for MCP (need 'api' or 'admin')")

        # Forwarding-Info für Audit (orchestrator kann das ins
        # redteam_audit_log packen via Request-Header).
        request.state.mcp_token_jti  = claims.get("jti") or claims.get("sub", "")
        request.state.mcp_token_desc = claims.get("desc") or claims.get("username", "")

        return await call_next(request)


def _err(status: int, code: str, msg: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": code, "message": msg},
    )
