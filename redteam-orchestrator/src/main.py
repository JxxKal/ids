"""redteam-orchestrator — FastAPI-Entry-Point.

REST-Endpoints (alle benötigen X-Cyjan-Token wenn CYJAN_API_TOKEN gesetzt):
  GET  /health                       — liveness + kali-shell-PID
  POST /redteam/run_kali_tool        — direkter Tool-Aufruf gegen TEST-NET
  GET  /redteam/scenarios            — Scenario-Library
  POST /redteam/scenarios/run        — Scenario abspielen (V2: kommt mit MCP)

Bewusst KEIN MCP-Server in V1.3.0 — Phase 6 ergänzt das.
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from config import settings
from kali_executor import KaliExecutionError, KaliExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("redteam-orchestrator")

app = FastAPI(
    title="Cyjan RedTeam-Orchestrator",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

executor = KaliExecutor()


# ─── Auth ────────────────────────────────────────────────────────────────

async def verify_token(x_cyjan_token: str = Header(default="")) -> None:
    """Optional pre-shared Token. Wenn CYJAN_API_TOKEN env gesetzt ist,
    muss Header X-Cyjan-Token matchen. Sonst offen (Lab-only-Service,
    auf localhost gebunden).

    V2: JWT vom Master API verifizieren via shared secret."""
    if not settings.api_token:
        return
    if x_cyjan_token != settings.api_token:
        raise HTTPException(401, "X-Cyjan-Token missing or invalid")


# ─── Models ──────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    kali_container: str
    allowed_src_cidrs: list[str]


class RunKaliToolRequest(BaseModel):
    tool:       Literal["nmap", "hydra", "modbus-cli", "ncat", "ping"]
    target_ip:  str = Field(min_length=7, max_length=45)
    args:       list[str] = Field(default_factory=list, max_length=30)
    timeout_sec: int = Field(default=30, ge=5, le=120)
    attach_iface: bool = Field(default=True,
                               description="false = direkter exec ohne veth-Handover")


class RunKaliToolResponse(BaseModel):
    run_id: str
    tool:   str
    target_ip: str
    args:   list[str]
    exit_code: int
    duration_ms: int
    timed_out:   bool
    stdout_excerpt: str = Field(max_length=2000)
    stderr_excerpt: str = Field(max_length=1000)


# ─── Endpoints ───────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        kali_container=settings.kali_container,
        allowed_src_cidrs=list(settings.allowed_src_cidrs),
    )


@app.post("/redteam/run_kali_tool",
          response_model=RunKaliToolResponse,
          dependencies=[Depends(verify_token)])
async def run_kali_tool(req: RunKaliToolRequest) -> RunKaliToolResponse:
    """Führt ein Pen-Test-Tool aus kali-shell aus. Target MUSS in
    ALLOWED_SRC_CIDRS (RFC 5737 TEST-NETs). Args werden serverseitig
    durch den kali_runner gegen die Tool-Whitelist validiert."""
    run_id = str(uuid.uuid4())
    log.info("run_kali_tool: id=%s tool=%s target=%s args=%s",
             run_id, req.tool, req.target_ip, req.args)

    try:
        result = await executor.run_with_iface(
            tool=req.tool, target_ip=req.target_ip,
            args=req.args, timeout_sec=req.timeout_sec,
            attach_iface=req.attach_iface,
        )
    except KaliExecutionError as exc:
        log.warning("run_kali_tool rejected: %s", exc)
        raise HTTPException(400, str(exc))

    return RunKaliToolResponse(
        run_id=run_id,
        tool=req.tool,
        target_ip=req.target_ip,
        args=req.args,
        exit_code=result["exit_code"],
        duration_ms=result["duration_ms"],
        timed_out=result["timed_out"],
        stdout_excerpt=result.get("stdout", "")[:2000],
        stderr_excerpt=result.get("stderr", "")[:1000],
    )


@app.on_event("startup")
async def _startup() -> None:
    log.info("RedTeam-Orchestrator startup. kali_container=%s, allowed_cidrs=%s",
             settings.kali_container, ",".join(settings.allowed_src_cidrs))
