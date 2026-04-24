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

    log.info("DB-Migrations abgeschlossen.")
