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

import os
import subprocess
import time
from typing import Literal

import asyncpg
from bcrypt import checkpw
from fastapi import APIRouter, Body, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin

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


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

async def _verify_password(pool: asyncpg.Pool, user_payload: dict, password: str) -> None:
    """Re-Auth: überprüft das Passwort des eingeloggten Users. Raised 403
    bei Nicht-Übereinstimmung."""
    username = user_payload.get("sub") or user_payload.get("username")
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
