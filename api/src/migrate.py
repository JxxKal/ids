"""Auto-Migration Runner.

Läuft beim API-Startup und bringt die DB auf den aktuellen Stand.
Verwaltet eine schema_migrations-Tabelle als angewendete Migrations-Liste.
Jede Migration läuft in einer eigenen Transaktion; schlägt eine fehl, bricht
der Startup ab statt still vorbeizugehen.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import asyncpg

log = logging.getLogger("migrate")

_DEFAULT_DIR = Path(os.environ.get("MIGRATIONS_DIR", "/migrations"))


async def _is_already_applied(conn: asyncpg.Connection, name: str) -> bool:
    """Prüft ob eine Migration bereits im DB-Schema widergespiegelt ist.

    Wird beim Seeding genutzt: alte Installs haben migrations via initdb.d
    eingespielt, aber nur bis zu einem bestimmten Stand. Neue Migrations
    die gleichzeitig mit dem Migration-Runner eingeführt wurden, müssen ggf.
    noch ausgeführt werden.
    """
    if name == "008_itop_cmdb.sql":
        return await _cmdb_constraint_exists(conn)
    return True


async def _cmdb_constraint_exists(conn: asyncpg.Connection) -> bool:
    count = await conn.fetchval(
        "SELECT COUNT(*) FROM pg_constraint "
        "WHERE conrelid = 'host_info'::regclass "
        "AND pg_get_constraintdef(oid) LIKE '%cmdb%'"
    )
    return count > 0


async def _repair_if_needed(conn: asyncpg.Connection, sql_files: list[Path]) -> None:
    """Repariert Migrations die als angewendet markiert sind, aber nicht aktiv sind.

    Hintergrund: v1.0.9/v1.0.10 hat den Seeding-Pfad zu früh ausgeführt und
    008_itop_cmdb.sql als angewendet markiert ohne es auszuführen. Dadurch fehlte
    'cmdb' in der trust_source-Constraint und jeder iTop-Sync schlug fehl.
    """
    for sql_file in sql_files:
        if sql_file.name != "008_itop_cmdb.sql":
            continue
        if not await _cmdb_constraint_exists(conn):
            log.warning(
                "008_itop_cmdb.sql ist in schema_migrations markiert, "
                "aber 'cmdb' fehlt in der Constraint – führe Reparatur durch."
            )
            async with conn.transaction():
                await conn.execute(sql_file.read_text())
            log.info("Reparatur von 008_itop_cmdb.sql erfolgreich.")


async def run(pool: asyncpg.Pool, migrations_dir: Path = _DEFAULT_DIR) -> None:
    if not migrations_dir.is_dir():
        log.warning("Migrations-Verzeichnis %s nicht gefunden – übersprungen.", migrations_dir)
        return

    sql_files = sorted(migrations_dir.glob("*.sql"))
    if not sql_files:
        log.info("Keine Migrations-Dateien in %s.", migrations_dir)
        return

    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id          TEXT        PRIMARY KEY,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        applied = {row["id"] for row in await conn.fetch("SELECT id FROM schema_migrations")}

        if not applied:
            # schema_migrations is empty: either fresh install or upgrade from
            # pre-runner state. Check whether user tables already exist to tell them apart.
            has_tables = await conn.fetchval("""
                SELECT count(*) FROM pg_tables
                WHERE schemaname = 'public' AND tablename != 'schema_migrations'
            """)
            if has_tables:
                log.info("Bestehende DB erkannt – prüfe Migrations-Status.")
                for sql_file in sql_files:
                    name = sql_file.name
                    if await _is_already_applied(conn, name):
                        await conn.execute(
                            "INSERT INTO schema_migrations (id) VALUES ($1) ON CONFLICT DO NOTHING",
                            name,
                        )
                        log.debug("Migration %s als angewendet markiert.", name)
                    else:
                        log.info("Migration %s noch nicht angewendet – führe aus.", name)
                        sql = sql_file.read_text()
                        async with conn.transaction():
                            await conn.execute(sql)
                            await conn.execute(
                                "INSERT INTO schema_migrations (id) VALUES ($1) ON CONFLICT DO NOTHING",
                                name,
                            )
                        log.info("Migration %s erfolgreich.", name)
                log.info("Seeding/Upgrade abgeschlossen.")
                return

        # Neue Migrations ausführen
        for sql_file in sql_files:
            name = sql_file.name
            if name in applied:
                log.debug("Migration %s bereits angewendet.", name)
                continue

            log.info("Wende Migration an: %s", name)
            sql = sql_file.read_text()
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (id) VALUES ($1)", name
                )
            log.info("Migration %s erfolgreich.", name)

        # Reparaturlauf: prüft ob als "applied" markierte Migrations wirklich aktiv sind.
        # Behebt Fehler aus v1.0.9/v1.0.10 wo Seeding zu früh ausgeführt wurde.
        await _repair_if_needed(conn, sql_files)

    log.info("DB-Migrations abgeschlossen.")
