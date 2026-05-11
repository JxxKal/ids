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
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from alert_match import poll_alerts_for_rule
from config import settings
from db import audit_log, close_pool, init_pool
from kali_executor import KaliExecutionError, KaliExecutor
from mcp_server import mcp
from scenario_store import (
    ScenarioValidationError,
    load_scenario,
    seed_builtin_templates,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("redteam-orchestrator")

executor = KaliExecutor()

# FastMCP 3.x StreamableHTTPSessionManager braucht den lifespan-Context der
# MCP-App, kombiniert mit unserem eigenen DB-Pool-Setup. Lifespan-Context-
# Manager der MCP-App umwickeln und unsere init_pool/close_pool drin laufen
# lassen. Sonst RuntimeError beim ersten /mcp-Call: "task group is not
# initialized".
# path="/" damit der Mount-Endpoint nicht /mcp/mcp wird sondern /mcp.
# Default-Path in FastMCP 3.x ist /mcp — kombiniert mit unserem Sub-Mount
# unter /mcp gäbe das den doppelten Pfad.
_mcp_app = mcp.http_app(path="/")


@asynccontextmanager
async def lifespan(_app: "FastAPI"):  # noqa: F821
    await init_pool(settings.postgres_dsn)
    log.info("RedTeam-Orchestrator startup. kali_container=%s, allowed_cidrs=%s",
             settings.kali_container, ",".join(settings.allowed_src_cidrs))
    # veth-Pair persistent einrichten — wird vom Sniffer kontinuierlich
    # capture'd. Tool-Runs verschieben das veth nicht mehr, das spart
    # Race-Conditions zwischen attach/detach und Sniffer-Reopen.
    try:
        await executor.setup_veth_pair_once()
    except Exception as exc:
        log.warning("setup_veth_pair_once failed (Lab-Setup-Check): %s", exc)
    # Builtin-Templates (Siemens S7/WinCC, GE iFix, Kerberos, SMB, NTLM)
    # aus dem Image ins Volume seeden — synchron, sehr billig.
    try:
        seed_builtin_templates()
    except Exception as exc:
        log.warning("seed_builtin_templates failed: %s", exc)
    # Verschachteln des MCP-Lifespan damit FastMCP intern initialisiert wird
    async with _mcp_app.lifespan(_app):
        yield
    await close_pool()


app = FastAPI(
    title="Cyjan RedTeam-Orchestrator",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


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
    tool:       Literal["nmap", "hydra", "hping3", "ncat", "ping"]
    target_ip:  str = Field(min_length=7, max_length=45)
    args:       list[str] = Field(default_factory=list, max_length=30)
    timeout_sec: int = Field(default=30, ge=5, le=120)
    attach_iface: bool = Field(default=True,
                               description="false = direkter exec ohne veth-Handover")
    expected_alert_rule_id: str | None = Field(
        default=None,
        description=(
            "Wenn gesetzt: nach Tool-Exit für 10s an Cyjan-API pollen, "
            "ob ein Alert mit diesem rule_id-Prefix erschienen ist. "
            "Result wird im matched_alerts-Feld zurückgegeben."
        ),
    )


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
    matched_alerts: list[dict] = Field(default_factory=list)


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
    durch den kali_runner gegen die Tool-Whitelist validiert.

    Audit-Log-Eintrag wird IMMER geschrieben (allowed/rejected_validation/error).
    Wenn expected_alert_rule_id gesetzt: pollt Cyjan-API 10s nach Tool-Exit
    auf einen Match — Result im matched_alerts-Feld."""
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
        await audit_log(
            mcp_tool="run_kali_tool_v1", target_ip=req.target_ip, args=req.args,
            decision="rejected_validation", reject_reason=str(exc),
        )
        log.warning("run_kali_tool rejected: %s", exc)
        raise HTTPException(400, str(exc))

    matched: list[dict] = []
    if req.expected_alert_rule_id:
        matched = await poll_alerts_for_rule(
            rule_id_prefix=req.expected_alert_rule_id,
            window_sec=10,
        )

    await audit_log(
        mcp_tool="run_kali_tool_v1", target_ip=req.target_ip, args=req.args,
        decision="allowed",
        duration_ms=result.get("duration_ms"),
        result_summary={
            "exit_code":     result["exit_code"],
            "timed_out":     result["timed_out"],
            "matched_alerts": len(matched),
            "expected_rule": req.expected_alert_rule_id,
        },
    )

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
        matched_alerts=matched,
    )


# ─── Scenario-Loader (V1 minimal) ───────────────────────────────────────

class ScenarioInfo(BaseModel):
    scenario_id: str
    file: str
    rule_id: str | None
    description: str | None


@app.get("/redteam/scenarios", dependencies=[Depends(verify_token)])
async def list_scenarios() -> dict:
    """Listet Scenario-YAMLs aus /scenarios/templates/, /scenarios/generated/
    und /scenarios/imported/. Pattern-Federation-Imports landen unter
    imported/, builtin-Templates aus dem Image unter templates/, KI-via-MCP
    unter generated/."""
    import yaml
    from pathlib import Path
    scenarios = []
    base = Path("/scenarios")
    if not base.exists():
        return {"scenarios": []}
    for f in sorted(base.rglob("*.yml")):
        try:
            doc = yaml.safe_load(f.read_text())
            if isinstance(doc, dict) and doc.get("id"):
                scenarios.append({
                    "scenario_id":            doc["id"],
                    "file":                   str(f.relative_to(base)),
                    "rule_id":                doc.get("rule_id"),
                    "expected_alert_rule_id": doc.get("expected_alert_rule_id"),
                    "description":            doc.get("description"),
                    "protocol":               doc.get("protocol"),
                    "target_port":            doc.get("target_port"),
                    "tags":                   doc.get("tags", []),
                    "mitre":                  doc.get("mitre", []),
                })
        except Exception as exc:
            log.debug("scenario %s unparseable: %s", f, exc)
    return {"scenarios": scenarios}


# ─── Scenario-Run-Endpoint (Phase-A: UI-Friendly Run-Button) ────────────

class RunScenarioRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=64)
    target_ip:   str = Field(min_length=7, max_length=45)
    timeout_sec: int = Field(default=10, ge=1, le=60)


class RunScenarioResponse(BaseModel):
    run_id:            str
    scenario_id:       str
    target_ip:         str
    target_port:       int
    protocol:          str
    sent_bytes:        int | None
    exit_code:         int
    duration_ms:       int | None
    stderr_excerpt:    str = Field(default="", max_length=500)
    matched_alerts:    list[dict] = Field(default_factory=list)
    detection_success: bool | None
    expected_rule:     str | None


@app.post("/redteam/scenarios/run",
          response_model=RunScenarioResponse,
          dependencies=[Depends(verify_token)])
async def run_scenario_rest(req: RunScenarioRequest) -> RunScenarioResponse:
    """Spielt ein Payload-Scenario gegen target_ip ab. Lädt YAML aus
    /scenarios/{generated|templates|imported}, sendet den base64-encoded
    Payload via ncat aus der kali-shell und pollt 10s für expected_alert
    falls im YAML gesetzt. Audit-Log wird IMMER geschrieben.

    Dieselbe Semantik wie MCP-Tool `run_payload_scenario_v1` — nur als
    REST für das UI."""
    run_id = str(uuid.uuid4())
    log.info("run_scenario_rest: id=%s scenario=%s target=%s",
             run_id, req.scenario_id, req.target_ip)

    try:
        scenario = load_scenario(req.scenario_id)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ScenarioValidationError as exc:
        raise HTTPException(400, str(exc))

    try:
        result = await executor.run_payload_with_iface(
            target_ip=req.target_ip,
            target_port=int(scenario["target_port"]),
            protocol=scenario["protocol"],
            payload_b64=scenario["payload_b64"],
            timeout_sec=req.timeout_sec,
        )
    except KaliExecutionError as exc:
        await audit_log(
            mcp_tool="run_payload_scenario_v1", target_ip=req.target_ip,
            decision="rejected_validation", reject_reason=str(exc),
            result_summary={"scenario_id": req.scenario_id, "via": "rest"},
        )
        raise HTTPException(400, str(exc))

    matched: list[dict] = []
    expected = scenario.get("expected_alert_rule_id")
    if expected:
        matched = await poll_alerts_for_rule(rule_id_prefix=expected, window_sec=10)

    await audit_log(
        mcp_tool="run_payload_scenario_v1", target_ip=req.target_ip,
        decision="allowed", duration_ms=result.get("duration_ms"),
        result_summary={
            "scenario_id":    req.scenario_id,
            "via":            "rest",
            "sent_bytes":     result.get("sent_bytes"),
            "exit_code":      result.get("exit_code"),
            "matched_alerts": len(matched),
            "expected_rule":  expected,
        },
    )

    return RunScenarioResponse(
        run_id=run_id,
        scenario_id=req.scenario_id,
        target_ip=req.target_ip,
        target_port=int(result.get("target_port", scenario["target_port"])),
        protocol=str(result.get("protocol", scenario["protocol"])),
        sent_bytes=result.get("sent_bytes"),
        exit_code=int(result.get("exit_code", -1)),
        duration_ms=result.get("duration_ms"),
        stderr_excerpt=str(result.get("stderr", ""))[:500],
        matched_alerts=matched,
        detection_success=(len(matched) > 0 if expected else None),
        expected_rule=expected,
    )


# ─── MCP-Server-Mount ────────────────────────────────────────────────────
# Endpoint: http://master:8002/mcp/  (Streamable-HTTP Transport)
# Claude/MCP-Clients verbinden POST /mcp/ mit JSON-RPC-Payload.
# Es ist die SELBE _mcp_app die oben in lifespan reingeht.
app.mount("/mcp", _mcp_app)
