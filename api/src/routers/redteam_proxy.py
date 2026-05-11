"""api/src/routers/redteam_proxy.py — HTTP-Proxy zum redteam-orchestrator.

Der redteam-orchestrator läuft auf network_mode=host:8002 und ist vom
Frontend (nginx im ids-net) nicht direkt erreichbar. Statt CORS + Cross-
Origin nutzen wir die cyjan-api als Proxy — selbe Auth-Boundary, selbes
Logging.

Endpoints:
  GET  /api/redteam/health           — Orchestrator-Health (200 wenn Lab-Mode)
  POST /api/redteam/run              — Pen-Test-Tool ausführen
  GET  /api/redteam/scenarios        — Scenario-Liste
  POST /api/redteam/scenarios/run    — Scenario-Payload abspielen
  GET  /api/redteam/audit-log        — letzte Audit-Einträge
  POST /api/redteam/mcp-token        — langlebiges Bearer-JWT für MCP-Clients

Aktivierung: nur registriert wenn REDTEAM_ENABLED=true (selbe env-Var wie
beim pattern_export-Router-Mount). Customer-Master kennt den Endpoint
physisch nicht.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException
from jose import jwt as jose_jwt
from pydantic import BaseModel, Field

from config import Config
from deps import require_admin
from jwt_utils import ALGORITHM


def _cfg() -> Config:
    from main import cfg
    return cfg

router = APIRouter(prefix="/api/redteam", tags=["redteam"])
log = logging.getLogger(__name__)

ORCHESTRATOR_URL = os.environ.get(
    "REDTEAM_ORCHESTRATOR_URL", "http://host.docker.internal:8002"
).rstrip("/")
TIMEOUT = httpx.Timeout(180.0, connect=5.0)


class RunRequest(BaseModel):
    tool: str
    target_ip: str
    args: list[str] = Field(default_factory=list)
    timeout_sec: int = 30
    expected_alert_rule_id: str | None = None
    attach_iface: bool = True


class RunScenarioRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=64)
    target_ip:   str = Field(min_length=7, max_length=45)
    timeout_sec: int = Field(default=10, ge=1, le=60)


class McpTokenRequest(BaseModel):
    description: str = Field(default="", max_length=120,
                             description="Frei-Text für eigene Notiz (z.B. 'Claude Desktop Jan')")
    expires_days: int = Field(default=365, ge=1, le=3650)


class McpTokenResponse(BaseModel):
    token:           str
    token_id:        str
    description:     str
    expires_at:      str
    expires_in_days: int


@router.get("/health", dependencies=[Depends(require_admin)])
async def health() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as cli:
            r = await cli.get(f"{ORCHESTRATOR_URL}/health")
            r.raise_for_status()
            return {"reachable": True, **r.json()}
    except httpx.HTTPError as exc:
        return {"reachable": False, "error": str(exc)}


@router.post("/run", dependencies=[Depends(require_admin)])
async def run_tool(req: RunRequest) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as cli:
            r = await cli.post(
                f"{ORCHESTRATOR_URL}/redteam/run_kali_tool",
                json=req.model_dump(),
            )
            if r.status_code >= 400:
                # Orchestrator-Fehler durchreichen
                raise HTTPException(r.status_code, r.text)
            return r.json()
    except httpx.HTTPError as exc:
        log.warning("orchestrator unreachable: %s", exc)
        raise HTTPException(503, f"orchestrator nicht erreichbar: {exc}")


@router.get("/scenarios", dependencies=[Depends(require_admin)])
async def scenarios() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as cli:
            r = await cli.get(f"{ORCHESTRATOR_URL}/redteam/scenarios")
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as exc:
        return {"scenarios": [], "error": str(exc)}


@router.post("/scenarios/run", dependencies=[Depends(require_admin)])
async def run_scenario(req: RunScenarioRequest) -> dict[str, Any]:
    """Spielt ein Payload-Scenario ab. Body: scenario_id + target_ip
    (+ optional timeout_sec). Orchestrator lädt das YAML aus templates/
    | generated/ | imported/ und feuert es via ncat aus der kali-shell."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as cli:
            r = await cli.post(
                f"{ORCHESTRATOR_URL}/redteam/scenarios/run",
                json=req.model_dump(),
            )
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text)
            return r.json()
    except httpx.HTTPError as exc:
        log.warning("orchestrator unreachable: %s", exc)
        raise HTTPException(503, f"orchestrator nicht erreichbar: {exc}")


@router.post("/mcp-token",
             response_model=McpTokenResponse,
             dependencies=[Depends(require_admin)])
async def generate_mcp_token(
    req: McpTokenRequest,
    cfg: Config = Depends(_cfg),
) -> McpTokenResponse:
    """Mintet ein langlebiges JWT für MCP-Clients (Claude Desktop, KI-
    Skripte etc.). Token ist self-contained (stateless), Validation läuft
    über die HS256-Signatur mit dem geteilten API_SECRET_KEY — der
    orchestrator hat das selbe Secret und prüft jedes incoming Bearer
    gegen die Signatur + exp + role-Claim.

    Token-Lifetime default 365 Tage. KEIN persistenter Storage — Revocation
    aktuell nur global via Rotation des API_SECRET_KEY (invalidatet alle
    Tokens). V2: pro-Token-Revocation-Liste.

    Audit-Spur: token_id (UUID) wird ins JWT als `jti`-Claim eingebettet —
    landet im orchestrator-Audit-Log bei jeder Aktion, so dass man im
    Nachhinein sehen kann WELCHER Token welche MCP-Aktion ausgelöst hat.
    """
    token_id = str(uuid4())
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=req.expires_days)

    desc_label = (req.description or "").strip()[:120] or "mcp-client"
    username   = f"mcp:{desc_label}"

    payload = {
        "sub":      token_id,
        "username": username,
        "role":     "api",        # API-Role: get_current_user akzeptiert das ohne DB-Lookup
        "exp":      exp,
        "iat":      now,
        "jti":      token_id,
        "mcp":      True,         # Marker für Forensik
        "desc":     desc_label,
    }
    token = jose_jwt.encode(payload, cfg.secret_key, algorithm=ALGORITHM)

    return McpTokenResponse(
        token=token,
        token_id=token_id,
        description=desc_label,
        expires_at=exp.isoformat(),
        expires_in_days=req.expires_days,
    )


@router.get("/audit-log", dependencies=[Depends(require_admin)])
async def audit_log_proxy(limit: int = 50, pool=Depends(__import__("database").get_pool)) -> dict[str, Any]:
    """Liest direkt aus redteam_audit_log — kein Roundtrip zum orchestrator
    nötig, da die Tabelle in der gemeinsamen TimescaleDB liegt."""
    limit = max(1, min(500, limit))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, ts::text AS ts, mcp_tool, target_ip::text AS target_ip,
                   decision, reject_reason, duration_ms, result_summary,
                   args_excerpt
            FROM redteam_audit_log
            ORDER BY ts DESC
            LIMIT $1
            """,
            limit,
        )
    return {"entries": [dict(r) for r in rows], "total": len(rows)}
