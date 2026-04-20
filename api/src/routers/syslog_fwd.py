"""Syslog-Forwarding: Konfiguration, Testeindpunkt und Forwarder-Loop."""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from database import get_pool

log = logging.getLogger("syslog-fwd")
router = APIRouter(prefix="/api/syslog", tags=["syslog"])

# ── Modelle ───────────────────────────────────────────────────────────────────

class SyslogConfig(BaseModel):
    enabled:   bool        = False
    host:      str         = ""
    port:      int         = 514
    protocol:  str         = "udp"       # udp | tcp
    format:    str         = "rfc5424"   # rfc5424 | cef | leef
    min_severity: str      = "low"       # low | medium | high | critical


class SyslogTestRequest(BaseModel):
    host:     str
    port:     int = 514
    protocol: str = "udp"
    format:   str = "rfc5424"


# ── Syslog-Formatierung ───────────────────────────────────────────────────────

_SEV_MAP = {"critical": 2, "high": 3, "medium": 4, "low": 5}
_SEV_ORDER = ["low", "medium", "high", "critical"]


def _rfc5424(alert: dict[str, Any]) -> str:
    pri = 8 + _SEV_MAP.get(alert.get("severity", "low"), 5)  # facility 1 (user)
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = socket.gethostname()
    msg = (f'<{pri}>1 {ts} {hostname} cyjan-ids - {alert.get("id","")[:8]} - '
           f'rule="{alert.get("rule_id","")}" '
           f'severity="{alert.get("severity","")}" '
           f'src="{alert.get("src_ip","")}" '
           f'dst="{alert.get("dst_ip","")}" '
           f'msg="{alert.get("description","")}"')
    return msg


def _cef(alert: dict[str, Any]) -> str:
    sev_num = {"low": 3, "medium": 5, "high": 7, "critical": 10}.get(alert.get("severity","low"), 3)
    ts = int(time.time() * 1000)
    msg = (f"CEF:0|Cyjan|IDS|1.0|{alert.get('rule_id','')}|"
           f"{alert.get('description','')}|{sev_num}|"
           f"src={alert.get('src_ip','')} dst={alert.get('dst_ip','')} "
           f"rt={ts} cs1={alert.get('severity','')} cs1Label=severity")
    return msg


def _leef(alert: dict[str, Any]) -> str:
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    msg = (f"LEEF:2.0|Cyjan|IDS|1.0|{alert.get('rule_id','')}|"
           f"src={alert.get('src_ip','')}\\tdst={alert.get('dst_ip','')}\\t"
           f"severity={alert.get('severity','')}\\t"
           f"msg={alert.get('description','')}")
    return f"{ts} {msg}"


def _format(alert: dict[str, Any], fmt: str) -> bytes:
    if fmt == "cef":
        return (_cef(alert) + "\n").encode()
    if fmt == "leef":
        return (_leef(alert) + "\n").encode()
    return (_rfc5424(alert) + "\n").encode()


def _send(host: str, port: int, protocol: str, data: bytes) -> None:
    if protocol == "tcp":
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(data)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data, (host, port))


# ── Endpunkte ─────────────────────────────────────────────────────────────────

@router.get("/config", response_model=SyslogConfig)
async def get_syslog_config(pool: asyncpg.Pool = Depends(get_pool)) -> SyslogConfig:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = 'syslog'")
    if not row:
        return SyslogConfig()
    return SyslogConfig(**dict(row["value"]))


@router.patch("/config", response_model=SyslogConfig)
async def save_syslog_config(
    body: SyslogConfig,
    pool: asyncpg.Pool = Depends(get_pool),
) -> SyslogConfig:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO system_config (key, value) VALUES ('syslog', $1)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            dict(body.model_dump()),
        )
    return body


@router.post("/test")
async def test_syslog(body: SyslogTestRequest) -> dict:
    test_alert = {
        "id": "test-0000",
        "rule_id": "TEST_SYSLOG_001",
        "severity": "low",
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "description": "Cyjan IDS Syslog-Verbindungstest",
    }
    try:
        data = _format(test_alert, body.format)
        _send(body.host, body.port, body.protocol, data)
        return {"status": "ok", "message": f"Test-Nachricht gesendet an {body.host}:{body.port}"}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Syslog-Test fehlgeschlagen: {e}")


# ── Forwarder-Loop (wird von main.py als Background-Task gestartet) ───────────

_last_forwarded: datetime | None = None


async def syslog_forwarder_loop(pool_getter) -> None:
    global _last_forwarded
    _last_forwarded = datetime.now(timezone.utc)
    _SEV_IDX = {s: i for i, s in enumerate(_SEV_ORDER)}

    while True:
        await asyncio.sleep(30)
        try:
            pool = pool_getter()
            async with pool.acquire() as conn:
                row = await conn.fetchrow("SELECT value FROM system_config WHERE key = 'syslog'")
            if not row:
                continue
            cfg = SyslogConfig(**dict(row["value"]))
            if not cfg.enabled or not cfg.host:
                continue

            min_idx = _SEV_IDX.get(cfg.min_severity, 0)

            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, rule_id, severity, src_ip, dst_ip, description, ts
                    FROM alerts
                    WHERE ts > $1 AND is_test = false
                    ORDER BY ts ASC
                    LIMIT 500
                    """,
                    _last_forwarded,
                )

            sent = 0
            for r in rows:
                if _SEV_IDX.get(r["severity"], 0) < min_idx:
                    continue
                alert = dict(r)
                alert["id"] = str(alert["id"])
                try:
                    data = _format(alert, cfg.format)
                    _send(cfg.host, cfg.port, cfg.protocol, data)
                    sent += 1
                except Exception as e:
                    log.warning("Syslog send error: %s", e)
                    break

            if rows:
                _last_forwarded = rows[-1]["ts"]
            if sent:
                log.info("Syslog: %d Alerts weitergeleitet an %s:%d", sent, cfg.host, cfg.port)

        except Exception as e:
            log.debug("Syslog forwarder loop error: %s", e)
