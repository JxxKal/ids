"""Retention-/Disk-Monitor.

Hintergrund: flows/alerts sind Hypertables OHNE Retention-Policy (nur
redteam_audit_log hat Compression). Im 24/7-Betrieb wachsen sie also bis die
Disk voll ist — und falls doch eine Policy gesetzt ist, kann der TimescaleDB-
Background-Worker still scheitern (last_run_status='Failed'), ohne dass es
jemand merkt. Beides endet im selben Totalausfall.

Dieser Monitor läuft als asyncio-Task im api-Container und prüft alle
RETENTION_CHECK_INTERVAL_S (Default 6h) drei Signale:

  1. Disk-Auslastung (Container-`/` ist der Docker-Overlay auf dem Host-FS →
     brauchbarer Proxy für die Host-Disk). >= RETENTION_DISK_WARN_PCT → DISK_SPACE_001 (critical).
  2. DB-Größe (pg_database_size). >= RETENTION_DB_SIZE_WARN_GB → RETENTION_001
     (high) — Catch-all, greift auch wenn GAR keine Policy existiert.
  3. TimescaleDB-Job-Health (policy_retention/policy_compression): failed oder
     seit > 2× schedule_interval kein Erfolg → RETENTION_001 (high).

Alarmierung: Insert direkt in die alerts-Tabelle (gleiches Muster wie
BOOT_HEALTH_001/UNKNOWN_HOST_001 — erscheint im Web-UI-Feed; live-Push via WS
kommt erst beim nächsten Refresh, für eine 6h-Kadenz unkritisch). Dedup: pro
rule_id max. 1 Alert je 24h, damit es nicht bei jedem Cycle neu feuert.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime, timezone
from typing import Any, Callable

import asyncpg

from config import Config

log = logging.getLogger("retention-monitor")
cfg = Config.from_env()

_RETENTION_PROCS = ["policy_retention", "policy_compression"]
_DEDUP_WINDOW = "24 hours"


async def gather_health(pool: asyncpg.Pool) -> dict[str, Any]:
    """Liest Disk-, DB- und Job-Status. Reine Lesefunktion (Loop + Endpoint).

    `problems` ist die abgeleitete Liste (rule_id/severity/message) — leer = ok.
    """
    du = shutil.disk_usage("/")
    disk_pct = round(du.used / du.total * 100, 1)

    db_size = 0
    jobs: list[dict[str, Any]] = []
    hypertables_without_retention: list[str] = []

    async with pool.acquire() as conn:
        db_size = int(await conn.fetchval("SELECT pg_database_size(current_database())"))

        try:
            rows = await conn.fetch(
                """
                SELECT j.job_id, j.proc_name, j.hypertable_name, j.schedule_interval,
                       s.last_run_status, s.last_successful_finish, s.total_failures
                FROM timescaledb_information.jobs j
                LEFT JOIN timescaledb_information.job_stats s USING (job_id)
                WHERE j.proc_name = ANY($1::text[])
                """,
                _RETENTION_PROCS,
            )
            now = datetime.now(timezone.utc)
            for r in rows:
                finish = r["last_successful_finish"]
                interval = r["schedule_interval"]
                stale = bool(
                    finish is not None and interval is not None
                    and (now - finish) > (interval * 2)
                )
                jobs.append({
                    "job_id":          r["job_id"],
                    "proc":            r["proc_name"],
                    "hypertable":      r["hypertable_name"],
                    "last_run_status": r["last_run_status"],
                    "last_success":    finish.isoformat() if finish else None,
                    "total_failures":  r["total_failures"],
                    "stale":           stale,
                })
        except Exception as exc:
            # job_stats fehlt bei sehr alten TimescaleDB-Versionen — nicht fatal.
            log.warning("TimescaleDB job_stats nicht abfragbar: %s", exc)

        # Welche Hypertables haben KEINE Retention-Policy? (Catch-all-Kontext)
        try:
            ht_rows = await conn.fetch(
                "SELECT hypertable_name FROM timescaledb_information.hypertables"
            )
            with_retention = {
                j["hypertable"] for j in jobs if j["proc"] == "policy_retention"
            }
            hypertables_without_retention = [
                r["hypertable_name"] for r in ht_rows
                if r["hypertable_name"] not in with_retention
            ]
        except Exception as exc:
            log.debug("hypertables-Liste nicht abfragbar: %s", exc)

    # ── Probleme ableiten ────────────────────────────────────────────────────
    problems: list[dict[str, Any]] = []

    if disk_pct >= cfg.retention_disk_warn_pct:
        problems.append({
            "rule_id":  "DISK_SPACE_001",
            "severity": "critical",
            "score":    0.9,
            "message":  f"Disk zu {disk_pct}% voll (Schwelle {cfg.retention_disk_warn_pct}%). "
                        f"DB-Größe {db_size // 1024**3} GB. "
                        f"Hypertables ohne Retention: {', '.join(hypertables_without_retention) or '–'}.",
        })

    db_gb = db_size / 1024**3
    if db_gb >= cfg.retention_db_size_warn_gb:
        problems.append({
            "rule_id":  "RETENTION_001",
            "severity": "high",
            "score":    0.7,
            "message":  f"DB-Größe {db_gb:.1f} GB ≥ Schwelle {cfg.retention_db_size_warn_gb} GB. "
                        f"Hypertables ohne Retention-Policy: {', '.join(hypertables_without_retention) or '–'} "
                        f"— Retention unter Einstellungen → Wartung setzen.",
        })

    bad_jobs = [j for j in jobs if j["last_run_status"] == "Failed" or j["stale"]]
    if bad_jobs:
        names = ", ".join(f"{j['hypertable']}({j['proc'].replace('policy_', '')})" for j in bad_jobs)
        problems.append({
            "rule_id":  "RETENTION_001",
            "severity": "high",
            "score":    0.7,
            "message":  f"TimescaleDB-Policy-Jobs gestört: {names}. "
                        f"last_run_status=Failed oder seit > 2× Intervall kein Erfolg.",
        })

    return {
        "disk_pct":      disk_pct,
        "disk_warn_pct": cfg.retention_disk_warn_pct,
        "db_size_bytes": db_size,
        "db_size_gb":    round(db_gb, 1),
        "jobs":          jobs,
        "hypertables_without_retention": hypertables_without_retention,
        "problems":      problems,
        "checked_at":    datetime.now(timezone.utc).isoformat(),
    }


async def _emit_alert(conn: asyncpg.Connection, rule_id: str, severity: str,
                      score: float, message: str) -> bool:
    """Dedup'd Alert-Insert. Gibt True zurück, wenn neu eingefügt."""
    recent = await conn.fetchval(
        f"SELECT 1 FROM alerts WHERE rule_id = $1 AND ts > now() - interval '{_DEDUP_WINDOW}' LIMIT 1",
        rule_id,
    )
    if recent:
        return False
    await conn.execute(
        """
        INSERT INTO alerts (ts, source, rule_id, severity, score, description, is_test)
        VALUES (now(), 'correlation', $1, $2, $3, $4, false)
        """,
        rule_id, severity, score, message,
    )
    return True


async def run_check(pool: asyncpg.Pool) -> dict[str, Any]:
    health = await gather_health(pool)
    problems = health["problems"]
    if not problems:
        log.info("Retention-Check ok: Disk %.1f%%, DB %.1f GB",
                 health["disk_pct"], health["db_size_gb"])
        return health

    # Pro rule_id nur einmal alarmieren (mehrere Probleme können dieselbe ID
    # tragen — die erste Message gewinnt, die anderen stehen im Log).
    async with pool.acquire() as conn:
        seen: set[str] = set()
        for p in problems:
            log.error("Retention-Problem [%s/%s]: %s", p["rule_id"], p["severity"], p["message"])
            if p["rule_id"] in seen:
                continue
            seen.add(p["rule_id"])
            inserted = await _emit_alert(conn, p["rule_id"], p["severity"], p["score"], p["message"])
            if inserted:
                log.warning("Alert %s in DB geschrieben (sichtbar im Web-UI).", p["rule_id"])
    return health


async def retention_monitor_loop(get_pool: Callable[[], asyncpg.Pool]) -> None:
    if not cfg.retention_check_enabled:
        log.info("Retention-Monitor deaktiviert (RETENTION_CHECK_ENABLED=false).")
        return
    log.info("Retention-Monitor aktiv: Intervall %ds, Disk-Warn %d%%, DB-Warn %d GB.",
             cfg.retention_check_interval_s, cfg.retention_disk_warn_pct,
             cfg.retention_db_size_warn_gb)
    # Kurzer initialer Delay, damit Migration/Startup durch ist.
    await asyncio.sleep(60)
    while True:
        try:
            await run_check(get_pool())
        except Exception as exc:
            log.warning("Retention-Check fehlgeschlagen: %s", exc)
        await asyncio.sleep(cfg.retention_check_interval_s)
