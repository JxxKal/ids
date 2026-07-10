"""Auto-Migration Runner (portiert aus ids api/src/migrate.py).

Läuft beim API-Startup und bringt die DB auf den aktuellen Stand.
Verwaltet eine schema_migrations-Tabelle als angewendete Migrations-Liste.
Jede Migration läuft in einer eigenen Transaktion; schlägt eine fehl, bricht
der Startup ab statt still vorbeizugehen.
"""
from __future__ import annotations

import logging
from pathlib import Path

import asyncpg

log = logging.getLogger("migrate")


async def run(pool: asyncpg.Pool, migrations_dir: Path) -> None:
    if not migrations_dir.is_dir():
        log.warning("Migrations-Verzeichnis %s nicht gefunden – übersprungen.", migrations_dir)
        return

    sql_files = sorted(migrations_dir.glob("*.sql"))
    if not sql_files:
        log.info("Keine Migrations-Dateien in %s.", migrations_dir)
        return

    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename   TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        applied = {
            r["filename"]
            for r in await conn.fetch("SELECT filename FROM schema_migrations")
        }
        for sql_file in sql_files:
            if sql_file.name in applied:
                continue
            log.info("Wende Migration %s an ...", sql_file.name)
            async with conn.transaction():
                await conn.execute(sql_file.read_text())
                await conn.execute(
                    "INSERT INTO schema_migrations (filename) VALUES ($1)",
                    sql_file.name,
                )
            log.info("Migration %s angewendet.", sql_file.name)
