"""
asyncpg Connection Pool.
Wird beim App-Start initialisiert und über FastAPI-Dependency injiziert.
"""
from __future__ import annotations

import json
import asyncpg


_pool: asyncpg.Pool | None = None


async def _init_conn(conn: asyncpg.Connection) -> None:
    for pg_type in ("json", "jsonb"):
        await conn.set_type_codec(
            pg_type,
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )


async def init_pool(dsn: str) -> None:
    global _pool
    # asyncpg erwartet postgresql:// statt postgres://
    dsn = dsn.replace("postgres://", "postgresql://")
    _pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, init=_init_conn)


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool:
    assert _pool is not None, "DB pool not initialised"
    return _pool
