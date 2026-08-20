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

Alarmierung: Insert in die alerts-Tabelle **und** Publikation auf
'alerts-enriched' — dieselbe Doppelung wie im alert-manager. Der reine Insert
reichte nicht: alles, was auf dem Topic hört, sah diese Alarme sonst nie.
Betroffen waren die App-Push-Benachrichtigung (app-connect), der
notification-dispatcher (E-Mail/Webhook/Syslog) und die mqtt-bridge.

Ausgerechnet „die Platte läuft voll" — ein Zustand, der das IDS blind macht —
erreichte damit kein Telefon. Aufgefallen am 2026-08-20, als ein
DISK_SPACE_001 um 00:47 im Web-UI stand, aber nirgends sonst ankam.

Der Insert bleibt trotzdem zuerst: er ist die Dedup-Instanz, und wenn Kafka
klemmt, soll der Alarm wenigstens im Feed stehen. Umgekehrt wäre er bei einem
Kafka-Ausfall ganz verloren.

Dedup: pro rule_id max. 1 Alert je 24h, damit es nicht bei jedem Cycle neu
feuert — das begrenzt zugleich, wie oft die Kanäle davon hören.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import asyncpg
import orjson
from confluent_kafka import Producer

from config import Config

log = logging.getLogger("retention-monitor")
cfg = Config.from_env()

ALERTS_TOPIC = "alerts-enriched"

# Wird von main.py nach dem Start gesetzt — gleiches Muster wie
# set_feedback_producer/set_notifications_producer in den Routern.
_producer: Producer | None = None


def set_retention_producer(producer: Producer) -> None:
    global _producer
    _producer = producer

_RETENTION_PROCS = ["policy_retention", "policy_compression"]
_DEDUP_WINDOW = "24 hours"

# Notfall-Cleanup: evictable Hypertables in Prioritätsreihenfolge (zuerst die
# voluminöse, am wenigsten wertvolle) mit Schutz-Floor in Tagen — Daten jünger
# als der Floor werden NIE gelöscht. flows = rohe Flow-Records (hohes Volumen,
# regenerierbar), test_runs = Test-Artefakte, alerts NUR als letztes Mittel mit
# großzügigem Floor (Kernprodukt). redteam_*/notification_deliveries bewusst
# nicht evictable.
_EVICTABLE = [("flows", 2), ("test_runs", 1), ("alerts", 30)]
_MAX_DROP_ITERATIONS = 300  # harte Obergrenze gegen Runaway


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


def _disk_pct() -> float:
    du = shutil.disk_usage("/")
    return round(du.used / du.total * 100, 1)


async def _emit_alert(conn: asyncpg.Connection, rule_id: str, severity: str,
                      score: float, message: str, dedup_window: str = _DEDUP_WINDOW) -> bool:
    """Dedup'd Alert-Insert plus Publikation auf `alerts-enriched`.

    Gibt True zurück, wenn neu eingefügt.

    `alert_id` und `ts` entstehen hier in Python statt in der Datenbank, damit
    der Datensatz in der Tabelle und die Nachricht auf dem Topic **dieselbe**
    Kennung und denselben Zeitstempel tragen. Sonst zeigte die App eine andere
    ID als das Web-UI, und ein Tipp auf die Push-Nachricht liefe ins Leere.
    """
    recent = await conn.fetchval(
        f"SELECT 1 FROM alerts WHERE rule_id = $1 AND ts > now() - interval '{dedup_window}' LIMIT 1",
        rule_id,
    )
    if recent:
        return False

    alert_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc)
    await conn.execute(
        """
        INSERT INTO alerts (alert_id, ts, source, rule_id, severity, score, description, is_test)
        VALUES ($1, $2, 'correlation', $3, $4, $5, $6, false)
        """,
        alert_id, ts, rule_id, severity, score, message,
    )

    _publish(alert_id, ts, rule_id, severity, score, message)
    return True


def _publish(alert_id: str, ts: datetime, rule_id: str, severity: str,
             score: float, message: str) -> None:
    """Best effort: der Alarm steht bereits in der Tabelle.

    Schlägt die Publikation fehl, fehlt er nur den Topic-Konsumenten und nicht
    dem Web-UI. Deshalb wird hier geloggt statt geworfen — ein klemmender
    Broker darf den Monitor-Cycle nicht abbrechen.
    """
    if _producer is None:
        log.debug("Kein Kafka-Producer gesetzt — %s nur in der Tabelle.", rule_id)
        return
    try:
        _producer.produce(
            ALERTS_TOPIC,
            value=orjson.dumps({
                "alert_id":    alert_id,
                "ts":          ts.isoformat(),
                "source":      "correlation",
                "rule_id":     rule_id,
                "severity":    severity,
                "score":       score,
                "description": message,
                "is_test":     False,
            }),
        )
        _producer.poll(0)
    except Exception as exc:
        log.warning("Publikation von %s auf %s fehlgeschlagen: %s",
                    rule_id, ALERTS_TOPIC, exc)


async def emergency_cleanup(pool: asyncpg.Pool) -> dict[str, Any]:
    """Letzte Instanz, wenn die Disk trotz Retention volläuft: löscht die
    ältesten Chunks der evictable Hypertables (drop_chunks, ältester zuerst)
    bis Disk < target_pct oder alle Chunks im Schutz-Floor liegen.

    drop_chunks droppt ganze Chunk-Tabellen → Platz wird sofort frei (kein
    VACUUM-Bloat wie bei DELETE). Bounded durch Floors + _MAX_DROP_ITERATIONS.
    """
    target = cfg.retention_emergency_target_pct
    dropped: dict[str, int] = {}
    start_pct = _disk_pct()
    async with pool.acquire() as conn:
        now = await conn.fetchval("SELECT now()")
        iters = 0
        for table, floor_days in _EVICTABLE:
            floor_cut = now - timedelta(days=floor_days)
            while _disk_pct() >= target and iters < _MAX_DROP_ITERATIONS:
                iters += 1
                oldest_end = await conn.fetchval(
                    """
                    SELECT range_end FROM timescaledb_information.chunks
                    WHERE hypertable_name = $1 AND range_end IS NOT NULL
                    ORDER BY range_end ASC LIMIT 1
                    """,
                    table,
                )
                if oldest_end is None or oldest_end > floor_cut:
                    break  # keine Chunks mehr ODER ältester liegt im Schutz-Floor
                try:
                    await conn.execute(
                        "SELECT drop_chunks($1, older_than => $2::timestamptz)",
                        table, oldest_end,
                    )
                    dropped[table] = dropped.get(table, 0) + 1
                except Exception as exc:
                    log.warning("drop_chunks(%s) fehlgeschlagen: %s", table, exc)
                    break
            if _disk_pct() < target:
                break

    end_pct = _disk_pct()
    total = sum(dropped.values())
    detail = ", ".join(f"{t}:{n}" for t, n in dropped.items()) or "nichts"
    if total and end_pct < cfg.retention_emergency_pct:
        msg = (f"Notfall-Cleanup: {total} Chunks gelöscht ({detail}); "
               f"Disk {start_pct}% → {end_pct}% (Ziel {target}%).")
    elif total:
        msg = (f"Notfall-Cleanup: {total} Chunks gelöscht ({detail}), Disk aber WEITERHIN "
               f"{end_pct}% (≥ {cfg.retention_emergency_pct}%). Platz liegt evtl. außerhalb der "
               f"DB (PCAP/MinIO) oder in den Schutz-Floors — MANUELLER EINGRIFF NÖTIG.")
    else:
        msg = (f"Notfall-Cleanup konnte NICHTS löschen (alle Chunks innerhalb der Schutz-Floors "
               f"oder keine Chunks). Disk {end_pct}% — MANUELLER EINGRIFF NÖTIG.")
    log.error(msg)
    async with pool.acquire() as conn:
        # Kurzes Dedup-Fenster: bei anhaltender Krise soll der adaptive 30-min-
        # Takt erneut alarmieren, aber Doppelläufe nicht spammen.
        await _emit_alert(conn, "DISK_EMERGENCY_001", "critical", 0.95, msg,
                          dedup_window="25 minutes")
    return {"dropped": dropped, "start_pct": start_pct, "end_pct": end_pct, "message": msg}


async def run_check(pool: asyncpg.Pool) -> dict[str, Any]:
    health = await gather_health(pool)
    problems = health["problems"]

    if problems:
        # Pro rule_id nur einmal alarmieren (mehrere Probleme können dieselbe
        # ID tragen — die erste Message gewinnt, die anderen stehen im Log).
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
    else:
        log.info("Retention-Check ok: Disk %.1f%%, DB %.1f GB",
                 health["disk_pct"], health["db_size_gb"])

    # Notfall-Cleanup, wenn die Disk trotz allem kritisch voll ist.
    if cfg.retention_emergency_enabled and health["disk_pct"] >= cfg.retention_emergency_pct:
        log.error("Disk %.1f%% ≥ Notfall-Schwelle %d%% — starte Notfall-Cleanup.",
                  health["disk_pct"], cfg.retention_emergency_pct)
        await emergency_cleanup(pool)

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
        high = False
        try:
            health = await run_check(get_pool())
            high = health["disk_pct"] >= cfg.retention_disk_warn_pct
        except Exception as exc:
            log.warning("Retention-Check fehlgeschlagen: %s", exc)
        # Adaptive Kadenz: nähert sich die Disk dem Limit, schneller nachschauen
        # (max. alle 30 min) statt erst nach dem vollen Intervall.
        sleep_s = min(cfg.retention_check_interval_s, 1800) if high else cfg.retention_check_interval_s
        await asyncio.sleep(sleep_s)
