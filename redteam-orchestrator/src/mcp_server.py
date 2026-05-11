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
from run_logger import (
    log_scenario_run,
    log_tool_run,
    mark_scenario_disabled,
    register_scenario,
)
from scenario_store import (
    ScenarioValidationError,
    delete_scenario,
    load_scenario,
    save_scenario,
)
from suricata_rules import (
    SuricataRuleError,
    delete_rule as suricata_delete_rule,
    list_rules as suricata_list_rules,
    upsert_rule as suricata_upsert_rule,
)

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
    await log_tool_run(
        tool=tool, target_ip=target_ip, args=args,
        exit_code=result["exit_code"], duration_ms=result.get("duration_ms"),
        matched_count=len(matched), expected_rule_id=expected_alert_rule_id,
        timed_out=result["timed_out"],
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
async def create_payload_scenario_v1(
    scenario_id: str = Field(
        description=(
            "Eindeutige ID, Pattern ^[A-Z][A-Z0-9_]{2,63}$. "
            "Convention: <PROTOCOL>_<INTENT>_<VARIANT>, z.B. "
            "'MODBUS_PROBE_FC_01', 'HTTP_AUTH_BYPASS_001', 'DNS_TUNNEL_BASE32'."
        ),
    ),
    protocol: Literal["tcp", "udp"] = Field(
        description="Transport-Protokoll. udp z.B. für DNS, tcp für HTTP/Modbus.",
    ),
    target_port: int = Field(ge=1, le=65535),
    payload_b64: str = Field(
        max_length=5500,
        description=(
            "Base64-encoded raw bytes. Max 4 KB decoded. Wird via "
            "`ncat --send-only` an target_ip:target_port geschickt. "
            "Für L7-Signatur-Detection: Modbus-PDU, HTTP-Request-Header-"
            "Pattern, DNS-Query mit Custom-Subdomain, OPC-UA-Frame etc."
        ),
    ),
    description: str = Field(
        default="",
        max_length=500,
        description="Kurze Beschreibung was der Payload signaturmäßig auslöst.",
    ),
    expected_alert_rule_id: str | None = Field(
        default=None, max_length=128,
        description=(
            "Optional: rule_id-Prefix für Detection-Validation beim "
            "späteren run_payload_scenario_v1-Aufruf. Z.B. 'SURICATA:1:2018927' "
            "für ET-Suricata-Modbus-Probe oder 'MODBUS_UNAUTH_502' für Custom-"
            "Cyjan-Rule."
        ),
    ),
    tags: list[str] = Field(default_factory=list, max_length=16),
    mitre: list[str] = Field(default_factory=list, max_length=16),
) -> dict[str, Any]:
    """Persistiert ein KI-generiertes Payload-Scenario als YAML im
    /scenarios/generated/-Volume. Scenario kann danach wiederholt via
    run_payload_scenario_v1 abgespielt werden (Regression-Detection-Tests).

    Sicherheits-Validator:
    - id-Pattern (kein Filesystem-Smuggling)
    - protocol in (tcp, udp)
    - target_port 1-65535
    - payload_b64 max 4 KB decoded
    - tags/mitre max 16 string-entries

    Pattern-Federation-Export sammelt diese Scenarios später ein, wenn das
    Bundle 'tests.regression' enthält — Lab-Curated-Detection-Patterns
    fließen damit an Customer-Sites.
    """
    try:
        path = save_scenario({
            "id": scenario_id,
            "description": description,
            "protocol": protocol,
            "target_port": target_port,
            "payload_b64": payload_b64,
            "expected_alert_rule_id": expected_alert_rule_id,
            "tags": tags,
            "mitre": mitre,
        })
    except ScenarioValidationError as exc:
        await audit_log(
            mcp_tool="create_payload_scenario_v1",
            decision="rejected_validation", reject_reason=str(exc),
        )
        return {"ok": False, "error": "validation_failed", "message": str(exc)}

    await audit_log(
        mcp_tool="create_payload_scenario_v1",
        decision="allowed",
        result_summary={"scenario_id": scenario_id, "path": str(path)},
    )
    # In DB-Registry aufnehmen — sonst taucht KI-Scenario nicht in
    # MITRE-Coverage-Aggregaten auf.
    await register_scenario({
        "id":                     scenario_id,
        "description":            description,
        "protocol":               protocol,
        "target_port":            target_port,
        "payload_b64":            payload_b64,
        "expected_alert_rule_id": expected_alert_rule_id,
        "tags":                   tags,
        "mitre":                  mitre,
    })
    return {
        "ok": True, "scenario_id": scenario_id, "path": str(path),
        "next_step": (
            "run_payload_scenario_v1(scenario_id, target_ip) — schickt das "
            "Scenario an target_ip:target_port und pollt für expected_alert"
        ),
    }


@mcp.tool()
async def run_payload_scenario_v1(
    scenario_id: str,
    target_ip: str = Field(
        description="TEST-NET-IP (192.0.2.x / 198.51.100.x / 203.0.113.x). 192.0.2.254 trifft den Host-Peer.",
    ),
    timeout_sec: int = Field(default=10, ge=1, le=60),
) -> dict[str, Any]:
    """Lädt das Scenario aus dem Storage und sendet seinen Payload an
    target_ip:target_port. Wenn expected_alert_rule_id im Scenario gesetzt
    ist, wird die Cyjan-API 10 s nach Send für matching Alerts gepollt.

    Returns dict mit exit_code, sent_bytes, duration_ms, matched_alerts."""
    import uuid
    run_id = str(uuid.uuid4())
    try:
        scenario = load_scenario(scenario_id)
    except FileNotFoundError as exc:
        return {"ok": False, "error": "scenario_not_found", "message": str(exc)}
    except ScenarioValidationError as exc:
        return {"ok": False, "error": "scenario_invalid", "message": str(exc)}

    try:
        result = await _executor.run_payload_with_iface(
            target_ip=target_ip,
            target_port=int(scenario["target_port"]),
            protocol=scenario["protocol"],
            payload_b64=scenario["payload_b64"],
            timeout_sec=timeout_sec,
        )
    except KaliExecutionError as exc:
        await audit_log(
            mcp_tool="run_payload_scenario_v1", target_ip=target_ip,
            decision="rejected_validation", reject_reason=str(exc),
            result_summary={"scenario_id": scenario_id},
        )
        return {"ok": False, "run_id": run_id, "error": "execution_failed",
                "message": str(exc)}

    matched: list[dict] = []
    expected = scenario.get("expected_alert_rule_id")
    if expected:
        matched = await poll_alerts_for_rule(rule_id_prefix=expected, window_sec=10)

    await audit_log(
        mcp_tool="run_payload_scenario_v1", target_ip=target_ip,
        decision="allowed", duration_ms=result.get("duration_ms"),
        result_summary={
            "scenario_id": scenario_id,
            "sent_bytes": result.get("sent_bytes"),
            "exit_code": result.get("exit_code"),
            "matched_alerts": len(matched),
            "expected_rule": expected,
        },
    )
    await log_scenario_run(
        scenario_id=scenario_id,
        target_ip=target_ip,
        exit_code=int(result.get("exit_code", -1)),
        duration_ms=result.get("duration_ms"),
        matched_count=len(matched),
        expected_rule_id=expected,
        matched_rule_ids=[a.get("rule_id", "") for a in matched if a.get("rule_id")],
    )
    return {
        "ok": True, "run_id": run_id,
        "scenario_id": scenario_id,
        "target_ip": target_ip,
        "target_port": result.get("target_port"),
        "protocol": result.get("protocol"),
        "sent_bytes": result.get("sent_bytes"),
        "exit_code": result.get("exit_code"),
        "duration_ms": result.get("duration_ms"),
        "stderr_excerpt": result.get("stderr", "")[:500],
        "matched_alerts": matched,
        "detection_success": (len(matched) > 0 if expected else None),
    }


@mcp.tool()
async def delete_payload_scenario_v1(scenario_id: str) -> dict[str, Any]:
    """Löscht ein KI-generiertes Payload-Scenario. Imported-Scenarios (aus
    Pattern-Federation-Bundles) bleiben unangetastet — die kommen aus
    versendeter Lab-Quelle und sollen nicht über MCP gelöscht werden können."""
    removed = delete_scenario(scenario_id)
    await audit_log(
        mcp_tool="delete_payload_scenario_v1",
        decision="allowed",
        result_summary={"scenario_id": scenario_id, "removed": removed},
    )
    if removed:
        # Registry-Row markieren als enabled=false (Historie bleibt für
        # MITRE-Coverage-Look-Backs erhalten).
        await mark_scenario_disabled(scenario_id)
    return {"ok": True, "scenario_id": scenario_id, "removed": removed}


# ────────────────────────────────────────────────────────────────────────
# Phase B — Feedback-Loop-Tools für KI-Auto-RedTeam
# ────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def recent_alerts_for_target_v1(
    target_ip:     str = Field(description="Ziel-IP (z.B. 192.0.2.254) — wird gegen alerts.dst_ip gematcht"),
    dst_port:      int | None = Field(default=None, ge=1, le=65535),
    since_seconds: int = Field(default=30, ge=1, le=3600,
                               description="Wie weit zurück die Suche geht. Default 30s."),
    limit:         int = Field(default=50, ge=1, le=500),
) -> dict[str, Any]:
    """Liefert alerts der letzten N Sekunden gegen target_ip (+ optional
    dst_port). Für KI-Validierung nach einem run_payload_scenario_v1:
    "hat irgendeine Rule auf das Scenario reagiert, mit welcher Severity?"

    Returns Liste mit ts, rule_id, severity, description, source (suricata/
    signature/ml), src_ip, src_port — dieselben Felder wie das /api/alerts-
    REST aber direkt aus der DB (kein API-Roundtrip).
    """
    pool = get_pool()
    if pool is None:
        return {"alerts": [], "note": "DB nicht verfügbar"}

    sql = """
        SELECT ts::text AS ts, rule_id, severity, source, description,
               src_ip::text AS src_ip, src_port,
               dst_ip::text AS dst_ip, dst_port, proto, tags
          FROM alerts
         WHERE dst_ip = $1::inet
           AND ts > NOW() - ($2::int || ' seconds')::interval
    """
    args: list = [target_ip, since_seconds]
    if dst_port is not None:
        sql += " AND dst_port = $3"
        args.append(dst_port)
    sql += " ORDER BY ts DESC LIMIT $%d" % (len(args) + 1)
    args.append(limit)

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
    except Exception as exc:
        log.warning("recent_alerts_for_target_v1 query failed: %s", exc)
        return {"alerts": [], "error": str(exc)}

    return {
        "alerts":         [dict(r) for r in rows],
        "total":          len(rows),
        "window_seconds": since_seconds,
        "target_ip":      target_ip,
        "dst_port":       dst_port,
    }


@mcp.tool()
async def recent_flow_summary_v1(
    target_ip:     str = Field(description="Ziel-IP — wird gegen flows.dst_ip gematcht"),
    dst_port:      int | None = Field(default=None, ge=1, le=65535),
    since_seconds: int = Field(default=60, ge=1, le=3600),
    limit:         int = Field(default=20, ge=1, le=200),
) -> dict[str, Any]:
    """Liefert Flow-Summary aus den letzten N Sekunden — pkt_count,
    byte_count, proto + (wenn Suricata den Flow als App-Layer-Protokoll
    erkannt hat) app_proto aus eve.json.

    Für KI-Feedback: wenn matched_alerts leer aber app_proto = 'smb' / 'krb5'
    erscheint → Detection-Gap auf dem ERKANNTEN Protokoll, sprich
    "Suricata parsed das, hat aber keine passende Rule".
    """
    import json
    import time
    pool = get_pool()
    flows: list[dict] = []
    if pool:
        sql = """
            SELECT to_char(start_ts, 'HH24:MI:SS.MS') AS start_ts,
                   src_ip::text AS src_ip, src_port,
                   dst_ip::text AS dst_ip, dst_port,
                   proto, pkt_count, byte_count
              FROM flows
             WHERE dst_ip = $1::inet
               AND start_ts > NOW() - ($2::int || ' seconds')::interval
        """
        args: list = [target_ip, since_seconds]
        if dst_port is not None:
            sql += " AND dst_port = $3"
            args.append(dst_port)
        sql += " ORDER BY start_ts DESC LIMIT $%d" % (len(args) + 1)
        args.append(limit)
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(sql, *args)
                flows = [dict(r) for r in rows]
        except Exception as exc:
            log.warning("recent_flow_summary_v1 flow-query failed: %s", exc)

    # Suricata-App-Proto-Klassifikation aus eve.json — tail die letzten
    # 5000 Zeilen, filtere auf event_type=flow + dst_ip-Match. Schwerere
    # Loglines stehen am Ende; cutoff via ts_from.
    cutoff = time.time() - since_seconds
    app_protos: list[dict[str, Any]] = []
    eve = "/var/log/suricata/eve.json"
    try:
        with open(eve, "r", encoding="utf-8", errors="ignore") as fh:
            # Naives Tail-by-Read — eve.json kann sehr groß sein; wir
            # lesen die letzten ~1 MB und parsen rückwärts.
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 1_000_000))
            for line in fh:
                if not line.startswith("{"):
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("event_type") != "flow":
                    continue
                if e.get("dest_ip") != target_ip:
                    continue
                if dst_port is not None and e.get("dest_port") != dst_port:
                    continue
                ts_str = e.get("timestamp", "")
                # Quick-cutoff per Char-Vergleich (ISO-8601 ist sortable)
                app_protos.append({
                    "ts":        ts_str[:23],
                    "src_ip":    e.get("src_ip"),
                    "dst_port":  e.get("dest_port"),
                    "proto":     e.get("proto"),
                    "app_proto": e.get("app_proto", "-"),
                    "in_iface":  e.get("in_iface"),
                    "pkts":      e.get("flow", {}).get("pkts_toserver", 0)
                                  + e.get("flow", {}).get("pkts_toclient", 0),
                })
                if len(app_protos) >= limit:
                    break
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.warning("recent_flow_summary_v1 eve-parse failed: %s", exc)

    return {
        "flows":           flows,
        "suricata_flows":  app_protos[-limit:],
        "target_ip":       target_ip,
        "dst_port":        dst_port,
        "window_seconds":  since_seconds,
    }


@mcp.tool()
async def create_suricata_rule_v1(
    sid: int = Field(
        ge=9_000_000, le=9_999_999,
        description=(
            "SID muss in der AI-Reserve-Range [9000000, 9999999] liegen. "
            "ET-Open nutzt 2.xxx.xxx, Suricata-Builtin 1.xxx.xxx — "
            "Kollision damit ausgeschlossen."
        ),
    ),
    msg: str = Field(
        max_length=200,
        description='Alarm-Text, kein " ; oder Newline. Wird mit "Cyjan-AI: "-Prefix gespeichert.',
    ),
    proto: Literal["tcp", "udp"] = Field(description="Transport-Protokoll"),
    dst_port: int = Field(ge=1, le=65535),
    content_hex: str = Field(
        max_length=600,
        description=(
            "Byte-Pattern als hex (z.B. '4e 54 4c 4d 53 53 50 00' für 'NTLMSSP\\0'). "
            "Whitespace + 0x-Präfix + |bars| werden toleriert. Max 256 bytes decoded."
        ),
    ),
    classtype: str = Field(default="misc-attack", max_length=64),
) -> dict[str, Any]:
    """Schreibt eine Suricata-Detection-Rule für AI-erkannte Byte-Patterns
    nach /rules/cyjan-ai.rules + triggert Suricata-Reload via update.trigger.

    Generierte Form:
      alert <proto> any any -> $HOME_NET <port> (msg:"Cyjan-AI: <msg>";
          [flow:to_server,established;] content:"|<hex>|"; offset:0;
          classtype:<classtype>; sid:<sid>; rev:1; metadata:author cyjan-ai;)

    Reload-Latenz: ~30s (snort-entrypoint pollt update.trigger).
    Idempotent gegen gleiche SID: überschreibt existierenden Eintrag.
    """
    try:
        result = suricata_upsert_rule(
            sid=sid, msg=msg, proto=proto, dst_port=dst_port,
            content_hex=content_hex, classtype=classtype,
        )
    except SuricataRuleError as exc:
        await audit_log(
            mcp_tool="create_suricata_rule_v1",
            decision="rejected_validation", reject_reason=str(exc),
            result_summary={"sid": sid},
        )
        return {"ok": False, "error": "validation_failed", "message": str(exc)}

    await audit_log(
        mcp_tool="create_suricata_rule_v1", decision="allowed",
        result_summary={
            "sid":               sid,
            "msg":               msg[:80],
            "proto":             proto,
            "dst_port":          dst_port,
            "replaced_existing": result["replaced_existing"],
        },
    )
    return {
        "ok":                True,
        "sid":               sid,
        "msg":               msg,
        "raw":               result["raw"],
        "path":              result["path"],
        "replaced_existing": result["replaced_existing"],
        "next_step":         (
            "Suricata reload braucht ~30s (entrypoint pollt). Re-run das "
            "Scenario per run_payload_scenario_v1 und check via "
            "recent_alerts_for_target_v1 ob die neue Rule trifft."
        ),
    }


@mcp.tool()
async def list_suricata_custom_rules_v1() -> dict[str, Any]:
    """Liefert alle AI-authored Suricata-Rules aus /rules/cyjan-ai.rules.
    Enthält sid, msg, classtype, raw — keine ET-Open- oder Suricata-Builtin-
    Rules (die liegen in anderen *.rules-Files und sind nicht editierbar)."""
    rules = suricata_list_rules()
    return {"rules": rules, "total": len(rules)}


@mcp.tool()
async def delete_suricata_rule_v1(
    sid: int = Field(ge=9_000_000, le=9_999_999),
) -> dict[str, Any]:
    """Entfernt eine AI-authored Rule. Nur AI-Range-SIDs erlaubt — auf
    ET-Open- oder Suricata-Builtin-Rules kein Zugriff (die kommen aus
    rules-Tarball, nicht aus dem AI-File)."""
    try:
        removed = suricata_delete_rule(sid)
    except SuricataRuleError as exc:
        await audit_log(
            mcp_tool="delete_suricata_rule_v1",
            decision="rejected_validation", reject_reason=str(exc),
        )
        return {"ok": False, "error": "validation_failed", "message": str(exc)}

    await audit_log(
        mcp_tool="delete_suricata_rule_v1", decision="allowed",
        result_summary={"sid": sid, "removed": removed},
    )
    return {"ok": True, "sid": sid, "removed": removed}


# ────────────────────────────────────────────────────────────────────────
# Audit-Log (read-scope)
# ────────────────────────────────────────────────────────────────────────

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
