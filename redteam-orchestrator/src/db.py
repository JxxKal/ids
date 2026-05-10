"""asyncpg-Pool + Audit-Log-Writer für den Orchestrator.

Schreibt in redteam_audit_log (Migration 022). Append-only — UPDATE/DELETE
am Schema-Level revoked, daher hier nur INSERT.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None


async def _init_conn(conn: asyncpg.Connection) -> None:
    """JSONB-Codec damit asyncpg dict→jsonb automatisch encodet."""
    for pg_type in ("json", "jsonb"):
        await conn.set_type_codec(
            pg_type, encoder=json.dumps, decoder=json.loads, schema="pg_catalog",
        )


async def init_pool(dsn: str) -> None:
    global _pool
    dsn = dsn.replace("postgres://", "postgresql://")
    try:
        _pool = await asyncpg.create_pool(
            dsn, min_size=1, max_size=3, init=_init_conn,
        )
        log.info("DB-Pool init OK")
    except Exception as exc:
        log.warning("DB-Pool init failed (audit-log disabled): %s", exc)
        _pool = None


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool | None:
    return _pool


async def audit_log(
    *,
    mcp_tool:       str,
    actor_token_id: str | None = None,
    target_ip:      str | None = None,
    args:           list[str] | None = None,
    decision:       str,
    reject_reason:  str | None = None,
    duration_ms:    int | None = None,
    result_summary: dict[str, Any] | None = None,
) -> None:
    """Schreibt einen Eintrag ins redteam_audit_log. Best-effort:
    fail-silent wenn DB nicht verfügbar — Orchestrator-Funktion soll
    nicht crashen wenn DB-Pool noch nicht initialisiert ist (z.B. beim
    Startup-Smoketest)."""
    if _pool is None:
        log.debug("audit_log skip (no DB pool): tool=%s decision=%s", mcp_tool, decision)
        return

    args_str = json.dumps(args) if args else "[]"
    args_hash = hashlib.sha256(args_str.encode()).hexdigest()
    excerpt = args_str[:500]

    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO redteam_audit_log
                    (actor_token_id, mcp_tool, target_ip, args_hash, args_excerpt,
                     decision, reject_reason, duration_ms, result_summary)
                VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9)
                """,
                actor_token_id, mcp_tool, target_ip, args_hash, excerpt,
                decision, reject_reason, duration_ms, result_summary,
            )
    except Exception as exc:
        log.warning("audit_log INSERT failed: %s", exc)
