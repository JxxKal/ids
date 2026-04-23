"""iTop CMDB-Synchronisation.

Liest Subnets → known_networks und Server/NetworkDevice/PC → host_info.
Konfiguration wird in system_config['itop'] gespeichert (via /api/config/itop).

Endpunkte:
  POST /api/itop/sync          – Sync starten (Background-Task)
  GET  /api/itop/sync/status   – letzter Sync-Status + Log
  POST /api/itop/test          – Verbindungstest (gibt iTop-Version zurück)
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException

from database import get_pool

router = APIRouter(prefix="/api/itop", tags=["itop"])

_CI_CLASSES = ["Server", "NetworkDevice", "PC", "ApplicationServer"]

# iTop-Klassennamen für Subnets variieren je nach installierten Extensions.
# TeemIP verwendet IPv4Subnet, ältere/andere Instanzen ggf. NetworkSubnet oder Subnet.
_SUBNET_CLASSES = ["IPv4Subnet", "NetworkSubnet", "Subnet"]

_state: dict[str, Any] = {
    "phase": "idle",   # idle | running | done | error
    "log":   [],
    "stats": {},
    "started_at":  None,
    "finished_at": None,
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(msg: str) -> None:
    _state["log"].append(f"[{_ts()}] {msg}")
    if len(_state["log"]) > 300:
        _state["log"] = _state["log"][-150:]


def _mask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return None


async def _get_cfg(pool: asyncpg.Pool) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM system_config WHERE key = 'itop'"
        )
    if not row:
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    return dict(row["value"])


def _build_client(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=cfg.get("ssl_verify", False),
        timeout=30,
    )


async def _core_get(client: httpx.AsyncClient, base_url: str, user: str, pwd: str,
                    cls: str, fields: str, oql: str | None = None) -> list[dict]:
    query = oql or f"SELECT {cls}"
    payload = json.dumps({
        "operation":     "core/get",
        "class":         cls,
        "key":           query,
        "output_fields": fields,
    })
    r = await client.post(
        f"{base_url.rstrip('/')}/webservices/rest.php",
        data={"version": "1.3", "auth_user": user, "auth_pwd": pwd, "json_data": payload},
    )
    r.raise_for_status()
    body = r.json()
    if body.get("code", 0) != 0:
        raise RuntimeError(f"iTop-Fehler ({cls}): {body.get('message', body)}")
    return [obj["fields"] for obj in (body.get("objects") or {}).values()
            if obj.get("code", 0) == 0]


async def _sync(pool: asyncpg.Pool) -> None:
    _state.update({
        "phase": "running",
        "log":   [],
        "stats": {},
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    })
    try:
        cfg = await _get_cfg(pool)
        if not cfg.get("enabled", True):
            _log("iTop-Sync ist deaktiviert.")
            _state["phase"] = "done"
            return

        base_url = cfg["base_url"]
        user     = cfg["user"]
        pwd      = cfg["password"]
        org      = (cfg.get("org_filter") or "").strip()

        _log(f"Verbinde mit {base_url} ...")

        nets_ok = hosts_ok = nets_err = hosts_err = 0

        async with _build_client(cfg) as client:
            # ── Subnets → known_networks ──────────────────────────────────────
            _log("Lade Subnets ...")
            subnets: list[dict] = []
            subnet_cls_used = None
            for subnet_cls in _SUBNET_CLASSES:
                try:
                    subnet_oql = (
                        f"SELECT {subnet_cls} WHERE org_name = '{org}'" if org else None
                    )
                    subnets = await _core_get(
                        client, base_url, user, pwd,
                        subnet_cls, "name,ip,mask,comment,block_name", subnet_oql,
                    )
                    subnet_cls_used = subnet_cls
                    _log(f"  Klasse '{subnet_cls}' gefunden – {len(subnets)} Subnets.")
                    break
                except RuntimeError as exc:
                    if "not a valid class" in str(exc).lower() or "is not a valid class" in str(exc):
                        _log(f"  Klasse '{subnet_cls}' nicht vorhanden – versuche nächste …")
                        continue
                    raise
            if subnet_cls_used is None:
                _log("  Keine bekannte Subnet-Klasse gefunden – Netzwerk-Import übersprungen.")

            async with pool.acquire() as conn:  # noqa: SIM117
                for s in subnets:
                    ip   = (s.get("ip")   or "").strip()
                    mask = (s.get("mask") or "").strip()
                    # name kann leer sein → block_name als Fallback, dann IP
                    name = (s.get("name") or s.get("block_name") or ip or "unbekannt").strip()
                    desc = (s.get("comment") or "").strip() or None

                    if not ip or not mask:
                        nets_err += 1
                        continue
                    prefix = _mask_to_prefix(mask)
                    if prefix is None:
                        _log(f"  Ungültige Maske '{mask}' für {name} – übersprungen.")
                        nets_err += 1
                        continue
                    cidr = f"{ip}/{prefix}"
                    try:
                        await conn.execute(
                            """
                            INSERT INTO known_networks (cidr, name, description)
                            VALUES ($1::cidr, $2, $3)
                            ON CONFLICT (cidr) DO UPDATE SET
                              name        = EXCLUDED.name,
                              description = COALESCE(EXCLUDED.description, known_networks.description),
                              updated_at  = now()
                            """,
                            cidr, name, desc,
                        )
                        nets_ok += 1
                    except Exception as exc:
                        _log(f"  Netzwerk {cidr} Fehler: {exc}")
                        nets_err += 1

            _log(f"  Netzwerke: {nets_ok} upserted, {nets_err} Fehler.")

            # ── CI-Klassen → host_info ────────────────────────────────────────
            for cls in _CI_CLASSES:
                _log(f"Lade {cls} ...")
                oql = f"SELECT {cls} WHERE org_name = '{org}'" if org else None
                try:
                    cis = await _core_get(client, base_url, user, pwd,
                                          cls, "name,managementip,description", oql)
                except Exception as exc:
                    _log(f"  {cls}: {exc} – übersprungen.")
                    continue

                _log(f"  {len(cis)} Objekte gefunden.")
                async with pool.acquire() as conn:
                    for ci in cis:
                        # TeemIP speichert Management-IP als IPv4Address-Objekt;
                        # die aufgelöste IP steht in managementip_id_friendlyname
                        ip_raw = (
                            ci.get("managementip_id_friendlyname") or
                            ci.get("managementip") or ""
                        ).strip()
                        name = (ci.get("name") or "").strip() or None
                        if not ip_raw or ip_raw in ("0.0.0.0", "::/0", ""):
                            continue
                        ip = ip_raw.split("/")[0]
                        try:
                            await conn.execute(
                                """
                                INSERT INTO host_info
                                  (ip, display_name, trusted, trust_source, updated_at)
                                VALUES ($1::inet, $2, true, 'cmdb', now())
                                ON CONFLICT (ip) DO UPDATE SET
                                  display_name = COALESCE(
                                    EXCLUDED.display_name,
                                    host_info.display_name
                                  ),
                                  trusted      = true,
                                  trust_source = CASE
                                    WHEN host_info.trust_source = 'manual' THEN 'manual'
                                    ELSE 'cmdb'
                                  END,
                                  updated_at   = now()
                                """,
                                ip, name,
                            )
                            hosts_ok += 1
                        except Exception as exc:
                            _log(f"  {cls} {ip}: {exc}")
                            hosts_err += 1

                _log(f"  {cls}: fertig.")

        _state["stats"] = {
            "networks_upserted": nets_ok,
            "networks_errors":   nets_err,
            "hosts_upserted":    hosts_ok,
            "hosts_errors":      hosts_err,
        }
        _log(f"Sync abgeschlossen – {nets_ok} Netzwerke, {hosts_ok} Hosts importiert.")
        _state["phase"] = "done"

    except Exception as exc:
        _state["phase"] = "error"
        _log(f"FEHLER: {exc}")
    finally:
        _state["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/sync", summary="iTop-Sync starten")
async def start_sync(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    if _state["phase"] == "running":
        raise HTTPException(409, "Sync läuft bereits.")
    asyncio.create_task(_sync(pool))
    return {"status": "started"}


@router.get("/sync/status", summary="Sync-Status abfragen")
async def sync_status() -> dict:
    return _state


@router.post("/test", summary="Verbindungstest")
async def test_connection(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    cfg = await _get_cfg(pool)
    base_url = cfg["base_url"]
    user     = cfg["user"]
    pwd      = cfg["password"]

    payload = json.dumps({"operation": "core/get", "class": "Organization",
                          "key": "SELECT Organization", "output_fields": "name"})
    try:
        async with _build_client(cfg) as client:
            r = await client.post(
                f"{base_url.rstrip('/')}/webservices/rest.php",
                data={"version": "1.3", "auth_user": user,
                      "auth_pwd": pwd, "json_data": payload},
            )
        r.raise_for_status()
        body = r.json()
        if body.get("code", 0) != 0:
            raise ValueError(body.get("message", "Unbekannter Fehler"))
        orgs = [o["fields"]["name"] for o in (body.get("objects") or {}).values()]
        return {"ok": True, "organisations": orgs}
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc
