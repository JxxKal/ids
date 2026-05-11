"""MCP-Server für RedTeam-Tooling. Wird als SSE-Endpoint unter
`/mcp` der FastAPI-App gemountet — Claude/AI-Clients verbinden über
http://master:8002/mcp/sse.

Exposed Tools (alle write-scope, Token-protected):
  - run_kali_tool_v1     — Pen-Test-Tool aus kali-shell ausführen
  - list_scenarios_v1    — Verfügbare Scenarios listen
  - get_audit_log_v1     — Letzte Audit-Einträge lesen (read scope)

Bewusst MINIMAL — die KI hat über diese 3 Tools alles was sie für den
Auto-Loop "run → check alerts → suggest rule → re-run" braucht. Mehr
Tools würden den Tool-Surface vergrößern ohne neuen Wert.

Auth: der MCP-Server lebt im selben Process wie die HTTP-API; der
Token-Check für MCP läuft über denselben CYJAN_API_TOKEN env-var.
FastMCP unterstützt das via Lifespan-Context."""
from __future__ import annotations

import logging
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import Field

from alert_match import poll_alerts_for_rule
from config import settings
from db import audit_log, get_pool
from kali_executor import KaliExecutionError, KaliExecutor

log = logging.getLogger(__name__)

mcp = FastMCP("cyjan-redteam")
_executor = KaliExecutor()


@mcp.tool()
async def run_kali_tool_v1(
    tool: Literal["nmap", "hydra", "hping3", "ncat", "ping"],
    target_ip: str = Field(
        description=(
            "Ziel-IP. MUSS in RFC 5737 TEST-NET liegen: 192.0.2.0/24, "
            "198.51.100.0/24 oder 203.0.113.0/24. Customer-Netze werden "
            "garantiert nie erreicht — der Tool-Runner ist network_mode=none "
            "und kann nur über einen dedicated veth in TEST-NET-Range senden."
        ),
    ),
    args: list[str] = Field(
        default_factory=list, max_length=30,
        description=(
            "Tool-Argumente als Liste (NIE Shell-String). Per-Tool-Whitelist "
            "blockiert: nmap --script/-iL/-oN, hydra -R/-o, ncat -e/-l, etc. "
            "Shell-Metacharacters (;|&$`<>) werden geblockt. IP-Smuggling: "
            "jeder Token der wie IP/CIDR aussieht wird gegen TEST-NET geprüft."
        ),
    ),
    timeout_sec: int = Field(default=30, ge=5, le=120),
    expected_alert_rule_id: str | None = Field(
        default=None,
        description=(
            "Optional: nach Tool-Exit für 10s an Cyjan-API pollen, ob ein "
            "Alert mit rule_id-Prefix erschienen ist. Result im matched_alerts-"
            "Feld. Für Detection-Validation-Loops: KI proposed eine Rule, "
            "ruft sie + run_kali_tool ab, prüft ob detection greift."
        ),
    ),
) -> dict[str, Any]:
    """Führt ein Pen-Test-Tool aus dem kali-shell-Container gegen eine
    TEST-NET-IP aus. Args werden serverseitig durch den kali_runner gegen
    eine Tool-Whitelist validiert. Audit-Log wird IMMER geschrieben.

    Für KI-Auto-RedTeam: Setze expected_alert_rule_id wenn du eine
    Detection prüfen willst — der Tool-Run + Alert-Match wird in einem
    Call abgewickelt.

    Returns dict mit run_id, exit_code, duration_ms, timed_out,
    stdout_excerpt, stderr_excerpt, matched_alerts."""
    import uuid
    run_id = str(uuid.uuid4())
    log.info("MCP run_kali_tool_v1: id=%s tool=%s target=%s",
             run_id, tool, target_ip)

    try:
        result = await _executor.run_with_iface(
            tool=tool, target_ip=target_ip, args=args,
            timeout_sec=timeout_sec, attach_iface=True,
        )
    except KaliExecutionError as exc:
        await audit_log(
            mcp_tool="run_kali_tool_v1", target_ip=target_ip, args=args,
            decision="rejected_validation", reject_reason=str(exc),
        )
        return {
            "ok": False, "run_id": run_id, "error": "validation_failed",
            "message": str(exc),
        }

    matched = []
    if expected_alert_rule_id:
        matched = await poll_alerts_for_rule(
            rule_id_prefix=expected_alert_rule_id, window_sec=10,
        )

    await audit_log(
        mcp_tool="run_kali_tool_v1", target_ip=target_ip, args=args,
        decision="allowed", duration_ms=result.get("duration_ms"),
        result_summary={
            "exit_code": result["exit_code"], "timed_out": result["timed_out"],
            "matched_alerts": len(matched),
            "expected_rule": expected_alert_rule_id,
        },
    )

    return {
        "ok": True, "run_id": run_id,
        "tool": tool, "target_ip": target_ip, "args": args,
        "exit_code": result["exit_code"], "duration_ms": result["duration_ms"],
        "timed_out": result["timed_out"],
        "stdout_excerpt": result.get("stdout", "")[:2000],
        "stderr_excerpt": result.get("stderr", "")[:1000],
        "matched_alerts": matched,
        "detection_success": (
            len(matched) > 0 if expected_alert_rule_id else None
        ),
    }


@mcp.tool()
async def list_scenarios_v1() -> dict[str, Any]:
    """Listet verfügbare RedTeam-Scenarios. Enthält imported-Scenarios
    aus Pattern-Federation-Bundles."""
    import yaml
    from pathlib import Path
    scenarios = []
    base = Path("/scenarios")
    if not base.exists():
        return {"scenarios": [], "note": "Volume /scenarios nicht gemountet"}
    for f in sorted(base.rglob("*.yml")):
        try:
            doc = yaml.safe_load(f.read_text())
            if isinstance(doc, dict) and doc.get("id"):
                scenarios.append({
                    "scenario_id": doc["id"],
                    "file": str(f.relative_to(base)),
                    "rule_id": doc.get("rule_id"),
                    "description": doc.get("description"),
                    "tags": doc.get("tags", []),
                })
        except Exception as exc:
            log.debug("scenario %s unparseable: %s", f, exc)
    return {"scenarios": scenarios, "total": len(scenarios)}


@mcp.tool()
async def get_audit_log_v1(limit: int = 50) -> dict[str, Any]:
    """Liest die letzten N Einträge aus redteam_audit_log.
    Hilft der KI ihre eigenen vorigen Aktionen zu sehen und Loops
    nicht doppelt zu fahren."""
    pool = get_pool()
    if pool is None:
        return {"entries": [], "note": "DB nicht verfügbar"}
    limit = max(1, min(500, limit))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT ts::text AS ts, mcp_tool, target_ip::text AS target_ip,
                   decision, reject_reason, duration_ms, result_summary,
                   args_excerpt
            FROM redteam_audit_log
            ORDER BY ts DESC
            LIMIT $1
            """,
            limit,
        )
    return {"entries": [dict(r) for r in rows], "total": len(rows)}
