"""FMG-Inventory-Sync (Background-Task, ids-itop-Muster: _state + Log-Ring).

Zieht pro ADOM Geräte/VDOMs, Packages+Scope, Policies (Reihenfolge bleibt
erhalten), Objekte, Zonen, Interfaces und statische Routen in fmg_snapshot
und baut danach die In-Memory-Read-Models (Inventory + PrefixTable) neu.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable

import asyncpg

from fmg.client import FmgClient, FmgError
from inventory.store import Inventory

log = logging.getLogger("inventory.sync")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


class SyncManager:
    def __init__(self) -> None:
        self.state: dict[str, Any] = {
            "phase": "idle",   # idle | running | done | error
            "log": [],
            "stats": {},
            "started_at": None,
            "finished_at": None,
        }

    def _log(self, msg: str) -> None:
        self.state["log"].append(f"[{_ts()}] {msg}")
        if len(self.state["log"]) > 300:
            self.state["log"] = self.state["log"][-150:]
        log.info(msg)

    async def run(self, pool: asyncpg.Pool, client: FmgClient, adoms: list[str],
                  on_done: Callable[[Inventory], Any] | None = None) -> None:
        if self.state["phase"] == "running":
            return
        self.state.update({
            "phase": "running", "log": [], "stats": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        })
        try:
            counts: dict[str, int] = {}
            for adom in adoms:
                await self._sync_adom(pool, client, adom, counts)
            self.state["stats"] = counts
            inv = await load_inventory(pool)
            if on_done:
                res = on_done(inv)
                if asyncio.iscoroutine(res):
                    await res
            self._log(f"Sync abgeschlossen: {counts}")
            self.state["phase"] = "done"
        except Exception as exc:
            self.state["phase"] = "error"
            self._log(f"FEHLER: {exc}")
        finally:
            self.state["finished_at"] = datetime.now(timezone.utc).isoformat()

    async def _sync_adom(self, pool: asyncpg.Pool, client: FmgClient, adom: str,
                         counts: dict[str, int]) -> None:
        self._log(f"ADOM '{adom}': Geräte laden ...")
        devices = await client.rpc("get", f"/dvmdb/adom/{adom}/device") or []
        await self._store(pool, adom, "device",
                          [(d.get("name"), d) for d in devices if d.get("name")])
        counts[f"{adom}:devices"] = len(devices)

        self._log(f"ADOM '{adom}': Policy-Packages laden ...")
        pkgs_raw = await client.rpc("get", f"/pm/pkg/adom/{adom}") or []
        packages = _flatten_packages(pkgs_raw)
        await self._store(pool, adom, "package",
                          [(p["_path"], p) for p in packages])

        for pkg in packages:
            path = pkg["_path"]
            self._log(f"  Package '{path}': Policies laden ...")
            policies = await client.rpc(
                "get", f"/pm/config/adom/{adom}/pkg/{path}/firewall/policy"
            ) or []
            await self._store(pool, adom, "policy", [(path, policies)])
            counts[f"{adom}:policies"] = counts.get(f"{adom}:policies", 0) + len(policies)

        obj_paths = [
            ("address", "obj/firewall/address"),
            ("addrgrp", "obj/firewall/addrgrp"),
            ("service", "obj/firewall/service/custom"),
            ("servicegrp", "obj/firewall/service/group"),
            ("vip", "obj/firewall/vip"),
            ("zone", "obj/dynamic/interface"),
        ]
        for kind, path in obj_paths:
            self._log(f"ADOM '{adom}': {kind} laden ...")
            objs = await client.rpc("get", f"/pm/config/adom/{adom}/{path}") or []
            await self._store(pool, adom, kind,
                              [(o.get("name"), o) for o in objs if o.get("name")])
            counts[f"{adom}:{kind}"] = len(objs)

        for dev in devices:
            name = dev.get("name")
            if not name:
                continue
            self._log(f"  Gerät '{name}': Interfaces laden ...")
            try:
                intfs = await client.rpc(
                    "get", f"/pm/config/device/{name}/global/system/interface"
                ) or []
                await self._store(pool, adom, "interface", [(name, intfs)])
            except FmgError as exc:
                self._log(f"  Gerät '{name}': Interfaces fehlgeschlagen ({exc}) – übersprungen.")
                continue
            vdoms = [v.get("name") for v in (dev.get("vdom") or []) if v.get("name")] or ["root"]
            for vdom in vdoms:
                try:
                    routes = await client.rpc(
                        "get", f"/pm/config/device/{name}/vdom/{vdom}/router/static"
                    ) or []
                    await self._store(pool, adom, "route", [(f"{name}|{vdom}", routes)])
                except FmgError as exc:
                    self._log(f"  {name}/{vdom}: Routen fehlgeschlagen ({exc}) – übersprungen.")

    async def _store(self, pool: asyncpg.Pool, adom: str, kind: str,
                     items: list[tuple[str, Any]]) -> None:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Alte Einträge dieser Art ersetzen (Objekte können gelöscht worden sein)
                await conn.execute(
                    "DELETE FROM fmg_snapshot WHERE adom = $1 AND kind = $2", adom, kind
                )
                for key, data in items:
                    await conn.execute(
                        """
                        INSERT INTO fmg_snapshot (adom, kind, key, data, synced_at)
                        VALUES ($1, $2, $3, $4, now())
                        """,
                        adom, kind, str(key), data,
                    )


def _flatten_packages(pkgs: list[dict], prefix: str = "") -> list[dict]:
    """Nested Package-Folder ('subobj') zu flachen Pfaden auflösen."""
    out = []
    for p in pkgs or []:
        name = p.get("name")
        if not name:
            continue
        path = f"{prefix}{name}"
        if p.get("type") == "folder" or p.get("subobj"):
            out.extend(_flatten_packages(p.get("subobj") or [], prefix=f"{path}/"))
        else:
            out.append({**p, "_path": path})
    return out


async def load_inventory(pool: asyncpg.Pool) -> Inventory:
    """Read-Models aus dem Snapshot bauen (Startup + nach Sync)."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT adom, kind, key, data, synced_at FROM fmg_snapshot")
        synced = await conn.fetchval("SELECT max(synced_at) FROM fmg_snapshot")
    return Inventory.build(
        [dict(r) for r in rows],
        synced_at=synced.isoformat() if synced else None,
    )
