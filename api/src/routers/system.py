"""Stats, System-Config und Threat-Level."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from database import get_pool
from models import ConfigResponse, ConfigUpdate, ThreatLevelResponse

_SYS_NET  = Path("/host/sys/class/net")
_IDS_DIR  = Path("/opt/ids")
_ENV_FILE = _IDS_DIR / ".env"


class InterfaceConfigRequest(BaseModel):
    role:  Literal["sniffer", "management"]
    iface: str

router = APIRouter(prefix="/api", tags=["system"])


def _ip_addr_via_docker() -> list[dict] | None:
    """ip -j addr vom Sniffer-Container (network_mode: host)."""
    try:
        r = subprocess.run(
            ["docker", "exec", "ids-sniffer", "ip", "-j", "addr"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return json.loads(r.stdout)
    except Exception:
        pass
    return None


_VIRTUAL_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "tun", "tap",
    "dummy", "ovs", "cali", "flannel", "cilium", "cni", "lxc",
)


def _is_physical(name: str) -> bool:
    """True wenn das Interface ein physisches (oder konfiguriertes VM-)Interface ist.

    Auf Bare-Metal: sysfs-Symlink zeigt auf /devices/pci.../usb.../platform...
    → kein "virtual" im Pfad → echte NIC.
    Auf VMs: alle Links zeigen auf /devices/virtual/net/... → Namens-Präfix-Filter
    entscheidet (eth0/ens3 wird angezeigt, docker0/veth* nicht).
    """
    iface_link = _SYS_NET / name
    if iface_link.is_symlink():
        try:
            target = os.readlink(str(iface_link))
            if "/devices/virtual/" not in target:
                return True  # physische PCI/USB-NIC
        except OSError:
            pass
    # VM oder kein sysfs: Name-basierter Filter
    return not any(name.startswith(p) for p in _VIRTUAL_PREFIXES)


def _ip_addr_via_sysfs() -> list[dict]:
    """Fallback: nur Name + operstate aus /host/sys/class/net."""
    result = []
    if not _SYS_NET.is_dir():
        return result
    for iface_dir in sorted(_SYS_NET.iterdir()):
        try:
            operstate = (iface_dir / "operstate").read_text().strip()
            mac = (iface_dir / "address").read_text().strip()
        except OSError:
            operstate, mac = "unknown", ""
        result.append({"ifname": iface_dir.name, "operstate": operstate,
                        "address": mac, "addr_info": []})
    return result


@router.get("/system/interfaces", summary="Netzwerk-Interface-Status")
async def get_interfaces() -> list[dict]:
    mirror_iface = os.environ.get("MIRROR_IFACE", "")
    mgmt_iface   = os.environ.get("MANAGEMENT_IFACE", "")

    raw = _ip_addr_via_docker() or _ip_addr_via_sysfs()

    result = []
    for iface in raw:
        name = iface.get("ifname", "")
        if not _is_physical(name):
            continue
        role = None
        if mirror_iface and name == mirror_iface:
            role = "sniffer"
        elif mgmt_iface and name == mgmt_iface:
            role = "management"

        addresses = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") in ("inet", "inet6")
               and a.get("scope") in ("global", "host")
        ]
        result.append({
            "name":      name,
            "role":      role,
            "operstate": iface.get("operstate", "unknown").lower(),
            "addresses": addresses,
            "mac":       iface.get("address", ""),
        })
    return result


def _env_set(key: str, value: str) -> None:
    """Setzt einen Key in /opt/ids/.env, fügt ihn an wenn nicht vorhanden."""
    if not _ENV_FILE.exists():
        raise FileNotFoundError(f"{_ENV_FILE} nicht gefunden")
    text = _ENV_FILE.read_text()
    pattern = re.compile(rf"^{re.escape(key)}\s*=.*$", re.MULTILINE)
    replacement = f"{key}={value}"
    if pattern.search(text):
        text = pattern.sub(replacement, text)
    else:
        text = text.rstrip("\n") + f"\n{replacement}\n"
    _ENV_FILE.write_text(text)


def _spawn_sniffer_reconfig(ids_dir: Path, profile: str) -> None:
    """Startet docker compose up -d sniffer in einem unabhängigen Container."""
    compose_cmd = (
        f"docker compose --project-directory {ids_dir} --profile {profile} up -d sniffer"
    )
    subprocess.Popen(
        [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{ids_dir}:{ids_dir}",
            "-w", str(ids_dir),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-sniffer-reconfig",
            "ids-api:latest",
            "sh", "-c", f"sleep 2 && {compose_cmd}",
        ],
        start_new_session=True, close_fds=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ},
    )


@router.post("/system/interfaces/config", summary="Sniffer-/Management-Interface setzen")
async def set_interface_config(body: InterfaceConfigRequest) -> dict:
    iface = body.iface.strip()
    if not iface or "/" in iface or " " in iface:
        raise HTTPException(400, "Ungültiger Interface-Name")

    profile_file = Path("/etc/cyjan/profile")
    profile = profile_file.read_text().strip() if profile_file.exists() else "prod"

    if body.role == "sniffer":
        _env_set("MIRROR_IFACE", iface)
        os.environ["MIRROR_IFACE"] = iface
        _spawn_sniffer_reconfig(_IDS_DIR, profile)
        return {"status": "restarting", "role": "sniffer", "iface": iface}

    # management: .env schreiben, kein Auto-Restart (Port-Rebind nötig)
    _env_set("MANAGEMENT_IFACE", iface)
    os.environ["MANAGEMENT_IFACE"] = iface
    return {"status": "saved", "role": "management", "iface": iface,
            "note": "Stack-Neustart erforderlich damit Port-Binding greift"}


_THREAT_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
_THREAT_WINDOW_MIN = 15


@router.get("/stats/threat-level", response_model=ThreatLevelResponse)
async def get_threat_level(pool: asyncpg.Pool = Depends(get_pool)) -> ThreatLevelResponse:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM alerts
            WHERE ts > now() - INTERVAL '15 minutes'
              AND is_test = false
            GROUP BY severity
            """
        )

    counts = {r["severity"]: int(r["cnt"]) for r in rows}
    raw_score = sum(_THREAT_WEIGHTS.get(sev, 0) * cnt for sev, cnt in counts.items())

    # Normierung: 0–100 (cap bei 200 Rohpunkten → 100%)
    level = min(100, int(raw_score * 100 / 200))

    if level >= 75:
        label = "red"
    elif level >= 50:
        label = "orange"
    elif level >= 25:
        label = "yellow"
    else:
        label = "green"

    return ThreatLevelResponse(
        level=level,
        label=label,
        alert_counts=counts,
        window_min=_THREAT_WINDOW_MIN,
    )


@router.get("/config", response_model=list[ConfigResponse])
async def list_config(pool: asyncpg.Pool = Depends(get_pool)) -> list[ConfigResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key, value FROM system_config ORDER BY key")
    return [ConfigResponse(key=r["key"], value=dict(r["value"])) for r in rows]


@router.get("/config/{key}", response_model=ConfigResponse)
async def get_config(key: str, pool: asyncpg.Pool = Depends(get_pool)) -> ConfigResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT key, value FROM system_config WHERE key = $1", key)
    if not row:
        raise HTTPException(status_code=404, detail="Config key not found")
    return ConfigResponse(key=row["key"], value=dict(row["value"]))


@router.patch("/config/{key}", response_model=ConfigResponse)
async def update_config(
    key:  str,
    body: ConfigUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> ConfigResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO system_config (key, value) VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            RETURNING key, value
            """,
            key, dict(body.value),
        )
    return ConfigResponse(key=row["key"], value=dict(row["value"]))
