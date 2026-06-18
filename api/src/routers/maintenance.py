"""
Datenbank-Wartung und Administration.

Alle Endpoints sind admin-only. Destructive Actions (Cleanup, Factory-Reset,
Restore) erfordern zusätzlich die Re-Auth des Passworts im Request-Body.
Jede Aktion wird im `maintenance_audit`-Log protokolliert.

Sektionen:
  1. Stats      — GET  /api/maintenance/stats
  2. Cleanup    — POST /api/maintenance/cleanup       (re-auth)
  3. Vacuum     — POST /api/maintenance/vacuum        (re-auth)
  4. Retention  — GET  /api/maintenance/retention
                  PATCH /api/maintenance/retention
  5. Backup     — GET  /api/maintenance/backup        (streamt pg_dump)
  6. Restore    — POST /api/maintenance/restore       (re-auth, multipart)
  7. Audit      — GET  /api/maintenance/audit
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Literal

import asyncpg
import orjson
from bcrypt import checkpw
from fastapi import APIRouter, Body, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin

log = logging.getLogger("maintenance")

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])

# ── Tabellen die im Cleanup/Stats-Scope sind ─────────────────────────────────
TABLES_WITH_TS = {
    "alerts":            "ts",
    "flows":             "end_ts",
    "training_samples":  "created_at",
    "test_runs":         "started_at",
    "maintenance_audit": "ts",
}
TABLES_NO_TS = ["host_info", "known_networks", "users", "system_config"]

# Hypertables: COUNT(*) ist ein Full-Scan und kann bei Millionen Rows minutenlang
# laufen → 504-Timeout im nginx-Proxy. Für die Übersicht reicht der TimescaleDB-
# Approximator (basiert auf reltuples/Chunk-Statistik, ±1 % genau).
HYPERTABLES = {"alerts", "flows", "test_runs"}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

async def _verify_password(pool: asyncpg.Pool, user_payload: dict, password: str) -> None:
    """Re-Auth: überprüft das Passwort des eingeloggten Users. Raised 403
    bei Nicht-Übereinstimmung.

    JWT-Payload trägt "sub"=user_id(UUID) und "username"=<name> separat.
    Früher las dieser Code zuerst "sub", was die UUID als Username gegen die
    Datenbank prüfte und immer 403 'Re-Auth fehlgeschlagen' lieferte.
    """
    username = user_payload.get("username") or user_payload.get("sub")
    if not username:
        raise HTTPException(401, "Ungültiger Token")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role FROM users WHERE username = $1",
            username,
        )
    if not row or not row["password_hash"]:
        raise HTTPException(403, "Re-Auth fehlgeschlagen")
    if not checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(403, "Passwort falsch")
    if row["role"] != "admin":
        raise HTTPException(403, "Nur Admins dürfen Wartungsaktionen ausführen")


async def _audit(
    pool: asyncpg.Pool,
    user_payload: dict,
    action: str,
    params: dict | None,
    result: dict | None,
    success: bool,
    error_msg: str | None,
    duration_ms: int,
) -> None:
    """Schreibt einen Eintrag ins maintenance_audit-Log."""
    import orjson
    username = user_payload.get("sub") or user_payload.get("username") or "?"
    user_id  = user_payload.get("user_id")
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO maintenance_audit
                    (user_id, username, action, params, result, success, error_msg, duration_ms)
                VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)
                """,
                user_id, username, action,
                orjson.dumps(params).decode() if params else None,
                orjson.dumps(result).decode() if result else None,
                success, error_msg, duration_ms,
            )
    except Exception:
        pass  # Audit-Fehler dürfen Action nicht blockieren


# ═══════════════════════════════════════════════════════════════════════════
# 1. STATS
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/retention/policies", dependencies=[Depends(require_admin)])
async def retention_policies(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    """Pro Hypertable: Größe + aktuelle Retention-Frist (Tage, null = keine).

    Für die Settings-UI (Liste mit Set/Remove). retention_days wird aus der
    `drop_after`-Config des policy_retention-Jobs abgeleitet.
    """
    out: list[dict] = []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT h.hypertable_name AS name,
                   hypertable_size(format('%I.%I', h.hypertable_schema, h.hypertable_name)::regclass) AS size_bytes,
                   (SELECT round(extract(epoch FROM (j.config->>'drop_after')::interval) / 86400)::int
                      FROM timescaledb_information.jobs j
                     WHERE j.proc_name = 'policy_retention'
                       AND j.hypertable_name = h.hypertable_name
                     LIMIT 1) AS retention_days
              FROM timescaledb_information.hypertables h
             ORDER BY size_bytes DESC NULLS LAST
            """
        )
        for r in rows:
            out.append({
                "hypertable":     r["name"],
                "size_bytes":     int(r["size_bytes"]) if r["size_bytes"] is not None else 0,
                "retention_days": r["retention_days"],
            })
    import shutil
    from retention_monitor import cfg as _rcfg, _EVICTABLE
    du = shutil.disk_usage("/")
    return {
        "policies": out,
        "disk_pct": round(du.used / du.total * 100, 1),
        "emergency": {
            "enabled":    _rcfg.retention_emergency_enabled,
            "trigger_pct": _rcfg.retention_emergency_pct,
            "target_pct":  _rcfg.retention_emergency_target_pct,
            # Welche Tabellen der Notfall-Cleanup räumt (+ Schutz-Floor in Tagen)
            "evictable":  [{"hypertable": t, "floor_days": d} for t, d in _EVICTABLE],
        },
    }


@router.get("/retention/health", dependencies=[Depends(require_admin)])
async def retention_health(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    """Aktueller Disk-/DB-/Policy-Job-Status des Retention-Monitors.

    Liest live (kein Cache): Disk-Auslastung, DB-Größe, TimescaleDB-Policy-
    Jobs und die abgeleitete Problemliste. `problems` leer = alles ok.
    """
    from retention_monitor import gather_health
    return await gather_health(pool)


@router.get("/stats", dependencies=[Depends(require_admin)])
async def db_stats(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    """Liefert Zeilen/Größe pro Tabelle + Hypertable-Infos + DB-Gesamtgröße."""
    async with pool.acquire() as conn:
        # DB Gesamtgröße
        db_size = await conn.fetchval(
            "SELECT pg_database_size(current_database())"
        )

        # Pro Tabelle: Zeilen + Bytes
        tables = []
        for name in list(TABLES_WITH_TS.keys()) + TABLES_NO_TS:
            try:
                if name in HYPERTABLES:
                    cnt = await conn.fetchval(
                        "SELECT approximate_row_count($1::regclass)", name,
                    )
                    # Fallback wenn approximate_row_count fehlt (alte TS-Version)
                    # oder die Tabelle (noch) keine Statistik hat
                    if cnt is None:
                        cnt = await conn.fetchval(
                            "SELECT reltuples::bigint FROM pg_class WHERE oid = $1::regclass",
                            name,
                        )
                else:
                    cnt = await conn.fetchval(f"SELECT COUNT(*) FROM {name}")
            except Exception:
                continue
            try:
                size = await conn.fetchval(
                    "SELECT pg_total_relation_size($1)", name,
                )
            except Exception:
                size = 0
            oldest = None
            newest = None
            if name in TABLES_WITH_TS:
                col = TABLES_WITH_TS[name]
                try:
                    row = await conn.fetchrow(
                        f"SELECT MIN({col}) AS o, MAX({col}) AS n FROM {name}",
                    )
                    oldest = row["o"].isoformat() if row and row["o"] else None
                    newest = row["n"].isoformat() if row and row["n"] else None
                except Exception:
                    pass
            tables.append({
                "name":     name,
                "rows":     int(cnt or 0),
                "size_bytes": int(size or 0),
                "oldest":   oldest,
                "newest":   newest,
            })

        # TimescaleDB Hypertable-Infos
        hypertables = []
        try:
            rows = await conn.fetch(
                """
                SELECT hypertable_name,
                       hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass) AS total_bytes,
                       (SELECT COUNT(*) FROM timescaledb_information.chunks c
                          WHERE c.hypertable_name = h.hypertable_name)                                AS chunks
                FROM timescaledb_information.hypertables h
                """
            )
            for r in rows:
                hypertables.append({
                    "name":        r["hypertable_name"],
                    "size_bytes":  int(r["total_bytes"] or 0),
                    "chunks":      int(r["chunks"] or 0),
                })
        except Exception:
            pass

        # Retention Policies
        policies = []
        try:
            rows = await conn.fetch(
                """
                SELECT hypertable_name, config
                FROM timescaledb_information.jobs
                WHERE proc_name = 'policy_retention'
                """
            )
            for r in rows:
                policies.append({
                    "hypertable": r["hypertable_name"],
                    "config":     dict(r["config"]) if r["config"] else {},
                })
        except Exception:
            pass

    return {
        "db_size_bytes": int(db_size or 0),
        "tables":        tables,
        "hypertables":   hypertables,
        "retention":     policies,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 2. CLEANUP
# ═══════════════════════════════════════════════════════════════════════════

class CleanupRequest(BaseModel):
    password:         str
    target:           Literal["alerts", "flows", "training_samples", "test_runs", "all"]
    older_than_days:  int | None = Field(default=None, ge=0, le=36500)
    only_test:        bool = False  # nur is_test=true löschen


@router.post("/cleanup", dependencies=[Depends(require_admin)])
async def cleanup(
    body:  CleanupRequest,
    user:  dict           = Depends(require_admin),
    pool:  asyncpg.Pool   = Depends(get_pool),
) -> dict:
    """Löscht Daten nach Kriterien. Re-Auth über Passwort erforderlich."""
    await _verify_password(pool, user, body.password)

    start = time.monotonic()
    try:
        deleted_total = 0
        details: dict = {}
        async with pool.acquire() as conn:
            if body.target == "all":
                # Factory-Reset: alle Daten außer Config/User
                for tbl, col in TABLES_WITH_TS.items():
                    if tbl == "maintenance_audit":
                        continue  # Audit bleibt!
                    r = await conn.execute(f"TRUNCATE TABLE {tbl} CASCADE")
                    details[tbl] = "truncated"
            else:
                tbl = body.target
                col = TABLES_WITH_TS.get(tbl)
                if not col:
                    raise HTTPException(400, f"Tabelle {tbl} unbekannt")
                conditions = []
                params: list = []
                if body.only_test and tbl == "alerts":
                    conditions.append("is_test = true")
                if body.older_than_days is not None:
                    conditions.append(f"{col} < NOW() - ($1 * INTERVAL '1 day')")
                    params.append(body.older_than_days)
                where = "WHERE " + " AND ".join(conditions) if conditions else ""
                sql = f"DELETE FROM {tbl} {where}"
                if params:
                    tag = await conn.execute(sql, *params)
                else:
                    tag = await conn.execute(sql)
                # tag format: "DELETE N"
                deleted_total = int(tag.split()[-1]) if tag.split() else 0
                details[tbl] = deleted_total

        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(
            pool, user, "cleanup",
            body.model_dump(exclude={"password"}),
            {"deleted": deleted_total, "details": details},
            True, None, duration_ms,
        )
        return {"success": True, "deleted": deleted_total, "details": details, "duration_ms": duration_ms}
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(
            pool, user, "cleanup",
            body.model_dump(exclude={"password"}),
            None, False, str(exc), duration_ms,
        )
        raise HTTPException(500, f"Cleanup fehlgeschlagen: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# 3. VACUUM / ANALYZE
# ═══════════════════════════════════════════════════════════════════════════

class VacuumRequest(BaseModel):
    password: str
    full:     bool = False        # VACUUM FULL sperrt Tabelle lange!
    analyze:  bool = True
    table:    str | None = None   # None = alle


@router.post("/vacuum", dependencies=[Depends(require_admin)])
async def vacuum(
    body:  VacuumRequest,
    user:  dict           = Depends(require_admin),
    pool:  asyncpg.Pool   = Depends(get_pool),
) -> dict:
    await _verify_password(pool, user, body.password)
    start = time.monotonic()

    opts = []
    if body.full:    opts.append("FULL")
    if body.analyze: opts.append("ANALYZE")
    opts_str = f"({', '.join(opts)})" if opts else ""

    target = body.table or ""
    if target:
        # nur alphanumerische Tabellennamen und Underscore erlauben (SQL Injection Schutz)
        if not target.replace("_", "").isalnum():
            raise HTTPException(400, "Ungültiger Tabellenname")

    try:
        # VACUUM kann nicht in Transaction, deshalb neue Connection mit autocommit
        conn = await asyncpg.connect(os.environ["POSTGRES_DSN"])
        try:
            sql = f"VACUUM {opts_str} {target}".strip()
            await conn.execute(sql)
        finally:
            await conn.close()

        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "vacuum", body.model_dump(exclude={"password"}),
                     {"sql": sql}, True, None, duration_ms)
        return {"success": True, "sql": sql, "duration_ms": duration_ms}
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "vacuum", body.model_dump(exclude={"password"}),
                     None, False, str(exc), duration_ms)
        raise HTTPException(500, f"VACUUM fehlgeschlagen: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# 4. RETENTION POLICIES (TimescaleDB)
# ═══════════════════════════════════════════════════════════════════════════

class RetentionUpdate(BaseModel):
    password:   str
    hypertable: str
    days:       int | None = Field(default=None, ge=0, le=36500)  # None = entfernen


@router.patch("/retention", dependencies=[Depends(require_admin)])
async def set_retention(
    body:  RetentionUpdate,
    user:  dict         = Depends(require_admin),
    pool:  asyncpg.Pool = Depends(get_pool),
) -> dict:
    await _verify_password(pool, user, body.password)
    if not body.hypertable.replace("_", "").isalnum():
        raise HTTPException(400, "Ungültiger Hypertable-Name")

    start = time.monotonic()
    try:
        async with pool.acquire() as conn:
            # Existierende Policy entfernen (idempotent)
            try:
                await conn.execute(
                    "SELECT remove_retention_policy($1, if_exists => TRUE)",
                    body.hypertable,
                )
            except Exception:
                pass

            if body.days is not None and body.days > 0:
                await conn.execute(
                    "SELECT add_retention_policy($1, INTERVAL '1 day' * $2)",
                    body.hypertable, body.days,
                )
                msg = f"Retention {body.hypertable}: {body.days} Tage"
            else:
                msg = f"Retention {body.hypertable}: entfernt"

        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "retention", body.model_dump(exclude={"password"}),
                     {"message": msg}, True, None, duration_ms)
        return {"success": True, "message": msg}
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "retention", body.model_dump(exclude={"password"}),
                     None, False, str(exc), duration_ms)
        raise HTTPException(500, str(exc))


# ═══════════════════════════════════════════════════════════════════════════
# 5. BACKUP (pg_dump streamen)
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/backup", dependencies=[Depends(require_admin)])
async def backup(user: dict = Depends(require_admin), pool: asyncpg.Pool = Depends(get_pool)) -> StreamingResponse:
    """Streamt pg_dump als .sql.gz. Kein Re-Auth — nur Lesen.
    Protokolliert aber im Audit-Log."""
    dsn = os.environ.get("POSTGRES_DSN", "")
    # DSN → pg-env Variablen parsen (einfache Implementation)
    import urllib.parse as up
    parsed = up.urlparse(dsn)
    env = {
        **os.environ,
        "PGHOST":     parsed.hostname or "timescaledb",
        "PGPORT":     str(parsed.port or 5432),
        "PGUSER":     parsed.username or "ids",
        "PGPASSWORD": parsed.password or "",
        "PGDATABASE": parsed.path.lstrip("/") or "ids",
    }

    start = time.monotonic()
    ts = time.strftime("%Y%m%d-%H%M%S")
    filename = f"cyjan-db-{ts}.sql.gz"

    await _audit(pool, user, "backup", None, {"filename": filename}, True, None, 0)

    proc = subprocess.Popen(
        ["sh", "-c", "pg_dump --no-owner --no-acl --clean --if-exists | gzip -9"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    def stream():
        assert proc.stdout is not None
        try:
            while True:
                chunk = proc.stdout.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.wait()

    return StreamingResponse(
        stream(),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ═══════════════════════════════════════════════════════════════════════════
# 6. RESTORE (psql < dump.sql.gz)
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/restore", dependencies=[Depends(require_admin)])
async def restore(
    password: str             = Body(..., embed=True),
    dump:     UploadFile      = File(...),
    user:     dict            = Depends(require_admin),
    pool:     asyncpg.Pool    = Depends(get_pool),
) -> dict:
    await _verify_password(pool, user, password)

    dsn = os.environ.get("POSTGRES_DSN", "")
    import urllib.parse as up
    parsed = up.urlparse(dsn)
    env = {
        **os.environ,
        "PGHOST":     parsed.hostname or "timescaledb",
        "PGPORT":     str(parsed.port or 5432),
        "PGUSER":     parsed.username or "ids",
        "PGPASSWORD": parsed.password or "",
        "PGDATABASE": parsed.path.lstrip("/") or "ids",
    }
    start = time.monotonic()
    try:
        # gzip-Detektion anhand der Magic-Bytes
        content = await dump.read()
        is_gz   = content.startswith(b"\x1f\x8b")
        shell_cmd = "gunzip -c | psql --set ON_ERROR_STOP=on" if is_gz else "psql --set ON_ERROR_STOP=on"

        proc = subprocess.run(
            ["sh", "-c", shell_cmd],
            input=content, env=env,
            capture_output=True, timeout=600,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        if proc.returncode != 0:
            err = proc.stderr.decode(errors="replace")[:1000]
            await _audit(pool, user, "restore", {"filename": dump.filename},
                         None, False, err, duration_ms)
            raise HTTPException(500, f"Restore fehlgeschlagen: {err}")

        await _audit(pool, user, "restore", {"filename": dump.filename, "bytes": len(content)},
                     {"duration_ms": duration_ms}, True, None, duration_ms)
        return {"success": True, "duration_ms": duration_ms, "bytes": len(content)}
    except HTTPException:
        raise
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "restore", {"filename": dump.filename},
                     None, False, str(exc), duration_ms)
        raise HTTPException(500, f"Restore fehlgeschlagen: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# 7. AUDIT-LOG
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/audit", dependencies=[Depends(require_admin)])
async def audit_log(
    limit: int            = 100,
    pool:  asyncpg.Pool   = Depends(get_pool),
) -> list[dict]:
    limit = max(1, min(limit, 1000))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, ts, username, action, params, result, success, error_msg, duration_ms
            FROM maintenance_audit
            ORDER BY ts DESC
            LIMIT $1
            """,
            limit,
        )
    return [
        {
            "id":          r["id"],
            "ts":          r["ts"].isoformat(),
            "username":    r["username"],
            "action":      r["action"],
            "params":      dict(r["params"]) if r["params"] else None,
            "result":      dict(r["result"]) if r["result"] else None,
            "success":     r["success"],
            "error_msg":   r["error_msg"],
            "duration_ms": r["duration_ms"],
        }
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════
# 8. PCAP-Retention (MinIO Lifecycle)
# ═══════════════════════════════════════════════════════════════════════════
#
# Aktuelle Default-Retention für ids-pcaps Bucket. minio-init setzt das beim
# Stack-Start aus PCAP_RETENTION_DAYS env-Var (Default 7). Über die UI kann
# der Wert zur Laufzeit geändert werden — wird in system_config persistiert
# und beim API-Startup gegen MinIO gesynct (siehe ensure_pcap_lifecycle()).

PCAP_BUCKET   = "ids-pcaps"
PCAP_RULE_ID  = "ids-pcap-expiry-managed"
SETTINGS_KEY  = "pcap_retention_days"


def _build_lifecycle(days: int):
    """LifecycleConfig-Objekt für den ids-pcaps-Bucket. Eine Rule, die
    auf den ganzen Bucket-Inhalt wirkt und nach N Tagen löscht."""
    from minio.lifecycleconfig import LifecycleConfig, Rule, Expiration, Filter
    return LifecycleConfig([
        Rule(
            rule_id=PCAP_RULE_ID,
            rule_filter=Filter(prefix=""),
            status="Enabled",
            expiration=Expiration(days=days),
        ),
    ])


async def _read_pcap_setting(pool: asyncpg.Pool) -> int | None:
    """Liest pcap_retention_days aus system_config. None wenn nicht
    gesetzt (= UI hat noch nie was geändert, env-Var-Default greift)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM system_config WHERE key = $1",
            SETTINGS_KEY,
        )
    if not row:
        return None
    val = row["value"]
    if isinstance(val, dict):
        days = val.get("days")
    else:
        days = val
    try:
        return int(days)
    except (TypeError, ValueError):
        return None


async def _write_pcap_setting(pool: asyncpg.Pool, days: int) -> None:
    # asyncpg hat einen jsonb-Codec konfiguriert (siehe database.py /
    # andere routers wie syslog_fwd) — wir übergeben das dict direkt,
    # kein orjson.dumps + ::jsonb-Cast (sonst wird der String doppelt
    # JSON-enkodiert und das Read-Pattern findet den dict nicht mehr).
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO system_config (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            SETTINGS_KEY, {"days": days},
        )


def _pcap_bucket_stats(minio_client) -> dict:
    """Bucket-Größe + Object-Count + Alter des ältesten Objekts. Robust
    gegen leeren Bucket. Zählt bis 50k Objects, danach summiert weiter
    aber kein Detail-Sample mehr (sonst dauert's bei Massendaten)."""
    import datetime as _dt
    total_bytes = 0
    count = 0
    oldest_ts: _dt.datetime | None = None
    try:
        for obj in minio_client.list_objects(PCAP_BUCKET, recursive=True):
            count += 1
            if obj.size:
                total_bytes += obj.size
            ts = obj.last_modified
            if ts and (oldest_ts is None or ts < oldest_ts):
                oldest_ts = ts
            if count >= 50000:
                break
    except Exception as exc:
        log.warning("pcap-bucket-stats: %s", exc)
    return {
        "object_count":  count,
        "total_bytes":   total_bytes,
        "total_gb":      round(total_bytes / 1024 / 1024 / 1024, 2),
        "oldest_iso":    oldest_ts.isoformat() if oldest_ts else None,
        "oldest_age_days": (
            (_dt.datetime.now(_dt.timezone.utc) - oldest_ts).days
            if oldest_ts else None
        ),
    }


def _read_active_lifecycle_days(minio_client) -> int | None:
    """Liest die aktuell aktive Lifecycle-Rule am Bucket aus. None wenn
    keine Rule gesetzt ist (Edge-Case nach Volume-Reset)."""
    try:
        cfg = minio_client.get_bucket_lifecycle(PCAP_BUCKET)
    except Exception as exc:
        log.debug("get_bucket_lifecycle %s: %s", PCAP_BUCKET, exc)
        return None
    if not cfg or not getattr(cfg, "rules", None):
        return None
    for r in cfg.rules:
        exp = getattr(r, "expiration", None)
        if exp is None:
            continue
        days = getattr(exp, "days", None)
        if days:
            return int(days)
    return None


async def ensure_pcap_lifecycle(pool: asyncpg.Pool, minio_client) -> None:
    """Wird vom api-Startup-Hook aufgerufen. Wenn system_config einen
    Wert hat, wird die MinIO-Lifecycle-Rule darauf gesetzt — robust
    gegen einen minio-init-Run mit alter env-Var. Wenn system_config
    nichts hat, no-op (env-Var-Default vom minio-init wirkt weiter)."""
    desired = await _read_pcap_setting(pool)
    if desired is None:
        return
    current = _read_active_lifecycle_days(minio_client)
    if current == desired:
        return
    try:
        minio_client.set_bucket_lifecycle(PCAP_BUCKET, _build_lifecycle(desired))
        log.info("PCAP-Lifecycle gesynct: %s → %s Tage", current, desired)
    except Exception as exc:
        log.error("PCAP-Lifecycle-Sync gescheitert: %s", exc)


@router.get("/pcap-retention", dependencies=[Depends(require_admin)])
async def get_pcap_retention(
    pool:  asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Aktuelle Konfiguration + Bucket-Stats für die UI."""
    from main import minio_client
    persisted = await _read_pcap_setting(pool)
    active    = _read_active_lifecycle_days(minio_client)
    stats     = _pcap_bucket_stats(minio_client)
    return {
        "persisted_days": persisted,    # aus system_config (UI-Override)
        "active_days":    active,       # aus MinIO-Bucket (real)
        "default_days":   int(os.environ.get("PCAP_RETENTION_DAYS", "7")),
        "bucket": {
            "name":            PCAP_BUCKET,
            "object_count":    stats["object_count"],
            "total_gb":        stats["total_gb"],
            "oldest_iso":      stats["oldest_iso"],
            "oldest_age_days": stats["oldest_age_days"],
        },
    }


class PcapRetentionUpdate(BaseModel):
    days: int = Field(..., ge=1, le=365)


@router.patch("/pcap-retention", dependencies=[Depends(require_admin)])
async def set_pcap_retention(
    body:  PcapRetentionUpdate,
    user:  dict         = Depends(require_admin),
    pool:  asyncpg.Pool = Depends(get_pool),
) -> dict:
    from main import minio_client
    start = time.monotonic()
    try:
        minio_client.set_bucket_lifecycle(PCAP_BUCKET, _build_lifecycle(body.days))
        await _write_pcap_setting(pool, body.days)
        active = _read_active_lifecycle_days(minio_client)
        msg = f"PCAP-Retention auf {body.days} Tage gesetzt (aktiv: {active})."
        await _audit(pool, user, "pcap_retention",
                     {"days": body.days}, {"active_days": active},
                     True, None, int((time.monotonic() - start) * 1000))
        return {"success": True, "days": body.days, "active_days": active, "message": msg}
    except Exception as exc:
        await _audit(pool, user, "pcap_retention",
                     {"days": body.days}, None, False, str(exc),
                     int((time.monotonic() - start) * 1000))
        raise HTTPException(500, f"Lifecycle-Update gescheitert: {exc}")


class PcapForceCleanup(BaseModel):
    days: int = Field(..., ge=1, le=365)


@router.post("/pcap-cleanup", dependencies=[Depends(require_admin)])
async def pcap_force_cleanup(
    body:  PcapForceCleanup,
    user:  dict         = Depends(require_admin),
    pool:  asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Force-Trigger: löscht alle PCAPs > body.days Tage SOFORT, statt
    auf den nächsten MinIO-Scanner-Pass zu warten. Iteriert per minio-
    py-Client statt mc-subprocess — kein zusätzliches Container-Spawn
    nötig.
    """
    import datetime as _dt
    from main import minio_client
    start    = time.monotonic()
    cutoff   = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=body.days)
    deleted  = 0
    bytes_freed = 0
    try:
        # list_objects ist generator — wir sammeln zuerst Keys, dann
        # remove_objects in Batches (S3-Limit ~1000 pro Call).
        to_delete = []
        for obj in minio_client.list_objects(PCAP_BUCKET, recursive=True):
            if obj.last_modified and obj.last_modified < cutoff:
                to_delete.append(obj.object_name)
                if obj.size:
                    bytes_freed += obj.size

        from minio.deleteobjects import DeleteObject
        # remove_objects ist iterator — wir consumen ihn um Errors zu
        # erfassen.
        chunk = 1000
        for i in range(0, len(to_delete), chunk):
            batch = [DeleteObject(k) for k in to_delete[i:i+chunk]]
            for err in minio_client.remove_objects(PCAP_BUCKET, batch):
                log.warning("pcap-cleanup remove error: %s", err)
            deleted += len(to_delete[i:i+chunk])

        msg = f"{deleted} Objects entfernt, ~{round(bytes_freed/1024/1024/1024, 2)} GB."
        await _audit(pool, user, "pcap_cleanup",
                     {"days": body.days},
                     {"deleted": deleted, "bytes_freed": bytes_freed},
                     True, None, int((time.monotonic() - start) * 1000))
        return {"success": True, "deleted": deleted, "bytes_freed": bytes_freed,
                "message": msg}
    except Exception as exc:
        await _audit(pool, user, "pcap_cleanup",
                     {"days": body.days}, None, False, str(exc),
                     int((time.monotonic() - start) * 1000))
        raise HTTPException(500, f"PCAP-Cleanup gescheitert: {exc}")
