"""fw-path-tracker API — FastAPI-App + Lifespan-Wiring.

app.state hält:
  cfg          – Env-Config
  inventory    – Inventory (immutable, per set_inventory atomar getauscht)
  prefixes     – PrefixTable (wird zusammen mit inventory neu gebaut)
  resolver     – ResolverChain (FMG → iTop → DNS)
  sync_manager – SyncManager (_state für /api/fmg/sync/status)
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

import database
import migrate
from config import Config
from inventory.store import Inventory
from inventory.sync import SyncManager, load_inventory
from resolver.chain import ResolverChain
from routers import auth as auth_router
from routers import config as config_router
from routers import fmg_admin, itop_admin, search, trace, users
from routers.auth import hash_password
from routers.config import read_config

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("main")


async def _seed_admin(pool, cfg: Config) -> None:
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM users")
        if count == 0:
            pw_hash = await asyncio.to_thread(hash_password, cfg.admin_bootstrap_password)
            await conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES ('admin', $1, 'admin')",
                pw_hash,
            )
            log.info("Initialer admin-User angelegt (Passwort aus ADMIN_PASSWORD).")


async def _rebuild_state(app: FastAPI, inv: Inventory) -> None:
    sites_cfg = await read_config("sites")
    app.state.inventory = inv
    app.state.prefixes = inv.build_prefix_table(sites_cfg.get("overrides"))
    log.info("Inventory geladen: %d Geräte, %d Prefix-Einträge.",
             len(inv.devices), len(app.state.prefixes.entries))


async def _periodic_sync(app: FastAPI) -> None:
    """Automatischer Re-Sync (Intervall aus system_config['tracker'])."""
    from fmg.factory import build_fmg_client
    while True:
        tracker_cfg = await read_config("tracker")
        interval = int(tracker_cfg.get("sync_interval_s", 1800))
        await asyncio.sleep(max(interval, 60))
        fmg_cfg = await read_config("fmg")
        adoms = fmg_cfg.get("adoms") or []
        if not fmg_cfg.get("host") or not adoms:
            continue
        if app.state.sync_manager.state["phase"] == "running":
            continue
        try:
            client = build_fmg_client(fmg_cfg, app.state.cfg)
        except Exception as exc:
            log.warning("Periodischer Sync: FMG-Client nicht baubar: %s", exc)
            continue
        try:
            await app.state.sync_manager.run(
                database.get_pool(), client, adoms, on_done=app.state.set_inventory
            )
        finally:
            await client.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = Config()
    app.state.cfg = cfg
    pool = await database.create_pool(cfg.dsn)
    await migrate.run(pool, Path(cfg.migrations_dir))
    await _seed_admin(pool, cfg)

    app.state.sync_manager = SyncManager()
    app.state.resolver = ResolverChain()
    app.state.set_inventory = lambda inv: _rebuild_state(app, inv)
    await _rebuild_state(app, await load_inventory(pool))

    sync_task = asyncio.create_task(_periodic_sync(app))
    try:
        yield
    finally:
        sync_task.cancel()
        await database.close_pool()


app = FastAPI(title="fw-path-tracker", lifespan=lifespan)

app.include_router(auth_router.router)
app.include_router(config_router.router)
app.include_router(users.router)
app.include_router(fmg_admin.router)
app.include_router(itop_admin.router)
app.include_router(search.router)
app.include_router(trace.router)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}
