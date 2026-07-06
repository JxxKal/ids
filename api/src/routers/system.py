"""Stats, System-Config und Threat-Level."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from database import get_pool
from deps import require_admin
from env_safe import valid_iface_name
from models import ConfigResponse, ConfigUpdate, ThreatLevelResponse

_SYS_NET  = Path("/host/sys/class/net")
_PROC     = Path("/host/proc")
_IDS_DIR  = Path("/opt/ids")
_ENV_FILE = _IDS_DIR / ".env"

# ── Zustandsspeicher für Delta-basierte Raten ────────────────────────────────
_cpu_prev: list[int] = []
_cpu_prev_t: float = 0.0
_net_prev: dict[str, tuple[int, int, int, int, float]] = {}  # iface→(rx_b,tx_b,rx_p,tx_p,t)


def _cpu_pct() -> float | None:
    global _cpu_prev, _cpu_prev_t
    try:
        line = (_PROC / "stat").read_text().splitlines()[0]
        vals = list(map(int, line.split()[1:8]))  # user nice sys idle iowait irq softirq
        now = time.monotonic()
        result: float | None = None
        if _cpu_prev and now - _cpu_prev_t > 0.1:
            delta = [v2 - v1 for v1, v2 in zip(_cpu_prev, vals)]
            total = sum(delta)
            idle = delta[3] + delta[4]
            result = round((total - idle) / total * 100, 1) if total > 0 else 0.0
        _cpu_prev = vals
        _cpu_prev_t = now
        return result
    except Exception:
        return None


def _mem() -> dict:
    try:
        info: dict[str, int] = {}
        for line in (_PROC / "meminfo").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                info[parts[0].rstrip(":")] = int(parts[1])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        used = total - avail
        return {
            "total_mb": total // 1024,
            "used_mb": used // 1024,
            "pct": round(used / total * 100, 1) if total else 0.0,
        }
    except Exception:
        return {"total_mb": 0, "used_mb": 0, "pct": None}


def _disk() -> dict:
    try:
        path = "/opt/ids" if Path("/opt/ids").exists() else "/"
        st = os.statvfs(path)
        total = st.f_frsize * st.f_blocks
        free  = st.f_frsize * st.f_bfree
        used  = total - free
        return {
            "total_gb": round(total / 1e9, 1),
            "used_gb":  round(used  / 1e9, 1),
            "pct":      round(used / total * 100, 1) if total else 0.0,
        }
    except Exception:
        return {"total_gb": 0.0, "used_gb": 0.0, "pct": None}


def _net_rates(iface: str) -> dict | None:
    global _net_prev
    if not iface:
        return None
    stats_dir = _SYS_NET / iface / "statistics"
    if not stats_dir.is_dir():
        return None
    try:
        def rd(f: str) -> int:
            return int((stats_dir / f).read_text())
        rx_b = rd("rx_bytes"); tx_b = rd("tx_bytes")
        rx_p = rd("rx_packets"); tx_p = rd("tx_packets")
        rx_d = rd("rx_dropped")
        now = time.monotonic()
        prev = _net_prev.get(iface)
        _net_prev[iface] = (rx_b, tx_b, rx_p, tx_p, now)
        if prev is None:
            return {"rx_bps": None, "tx_bps": None, "rx_pps": None, "tx_pps": None, "rx_dropped": rx_d}
        p_rx_b, p_tx_b, p_rx_p, p_tx_p, p_t = prev
        dt = now - p_t
        if dt < 0.1:
            return {"rx_bps": None, "tx_bps": None, "rx_pps": None, "tx_pps": None, "rx_dropped": rx_d}
        return {
            "rx_bps": round((rx_b - p_rx_b) / dt),
            "tx_bps": round((tx_b - p_tx_b) / dt),
            "rx_pps": round((rx_p - p_rx_p) / dt),
            "tx_pps": round((tx_p - p_tx_p) / dt),
            "rx_dropped": rx_d,
        }
    except Exception:
        return None


# tracing-subscriber im Sniffer rendert ANSI-Escape-Sequenzen (Farben +
# Stile) selbst dann, wenn stdout kein TTY ist – der Pretty-Output landet
# 1:1 in `docker logs`. Die `pps="…"`-Regex matcht damit nicht, weil
# zwischen `pps` und `=` plötzlich `\e[3mpps\e[0m\e[2m=\e[0m"11"` steht.
# Vor dem Regex-Pass also alle ANSI-Sequenzen wegputzen, damit das Frontend
# wieder echte Werte zu sehen bekommt statt "…".
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _sniffer_stats() -> dict:
    try:
        r = subprocess.run(
            ["docker", "logs", "--tail", "30", "ids-sniffer"],
            capture_output=True, text=True, timeout=3,
        )
        text = _ANSI_RE.sub("", r.stdout + r.stderr)
        for line in reversed(text.splitlines()):
            if "sniffer stats" not in line:
                continue
            def _f(pattern: str, default: float = 0.0) -> float:
                m = re.search(pattern, line)
                return float(m.group(1)) if m else default
            def _i(pattern: str) -> int:
                m = re.search(pattern, line)
                return int(m.group(1)) if m else 0
            return {
                "pps":            _f(r'pps="([^"]+)"'),
                "drop_pct":       _f(r'drop_pct="([^%"]+)%?"'),
                "total_captured": _i(r'total_cap=(\d+)'),
                "total_dropped":  _i(r'total_drop=(\d+)'),
                "kafka_errors":   _i(r'kafka_errors=(\d+)'),
            }
    except Exception:
        pass
    return {"pps": None, "drop_pct": None, "total_captured": 0, "total_dropped": 0, "kafka_errors": 0}


class InterfaceConfigRequest(BaseModel):
    role:  Literal["sniffer", "management"]
    iface: str


router = APIRouter(prefix="/api", tags=["system"])


def _ip_addr_via_docker() -> list[dict] | None:
    """ip -j addr aus einem Container mit network_mode: host.

    Probiert mehrere Kandidaten – wenn der Sniffer crashloopt (z.B. weil das
    Mirror-Interface noch keine Carrier hat), liefert snort/snort-bridge u.U.
    trotzdem; sonst fällt der Endpoint auf den sysfs-Pfad zurück und zeigt
    operstate + MAC ohne IPs.
    """
    for name in ("ids-sniffer", "ids-snort"):
        try:
            r = subprocess.run(
                ["docker", "exec", name, "ip", "-j", "addr"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return json.loads(r.stdout)
        except Exception:
            continue
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

        # Mehrere Rollen pro Interface erlauben – im Single-NIC-Setup ist die
        # Management-NIC gleichzeitig der Sniffer (promiscuous). Das alte
        # `if/elif` hat in dem Fall die Management-Markierung still überschrieben,
        # sodass die GUI für beide Interfaces "als Management setzen" anbot
        # und der User die Bind-Adresse seines eigenen Frontends nicht mehr
        # erkennen konnte.
        roles: list[str] = []
        if mgmt_iface and name == mgmt_iface:
            roles.append("management")
        if mirror_iface and name == mirror_iface:
            roles.append("sniffer")

        addresses = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") in ("inet", "inet6")
               and a.get("scope") in ("global", "host")
        ]
        result.append({
            "name":      name,
            # `role` für Rückwärtskompatibilität – ältere Frontend-Builds lesen
            # weiter den ersten Eintrag; neuere greifen `roles` direkt.
            "role":      roles[0] if roles else None,
            "roles":     roles,
            "operstate": iface.get("operstate", "unknown").lower(),
            "addresses": addresses,
            "mac":       iface.get("address", ""),
        })
    return result


@router.get("/system/stats", summary="System-Ressourcen und Sniffer-Health")
async def get_system_stats() -> dict:
    iface = os.environ.get("MIRROR_IFACE", "")
    return {
        "cpu_pct":  _cpu_pct(),
        "mem":      _mem(),
        "disk":     _disk(),
        "net":      _net_rates(iface),
        "sniffer":  _sniffer_stats(),
        "iface":    iface,
    }


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
    """Startet docker compose up -d sniffer in einem unabhängigen Container.

    `profile` kann eine kommaseparierte Liste sein (z.B. "prod,snort"). Compose
    interpretiert `--profile "a,b"` als EINEN Profilnamen, der nichts matcht;
    deshalb pro Eintrag ein eigenes --profile-Flag.
    """
    profile_args = " ".join(
        f"--profile {p.strip()}"
        for p in profile.split(",")
        if p.strip()
    )
    compose_cmd = (
        f"docker compose --project-directory {ids_dir} {profile_args} up -d sniffer"
    )

    # Vorhergehenden Reconfig-Container weg, falls er noch da ist – wir nutzen
    # absichtlich KEIN --rm, damit `docker logs ids-sniffer-reconfig` nach
    # einem Fehlschlag noch was zeigt. Ohne diese Präventivabräumung würde
    # `docker run --name ids-sniffer-reconfig` mit "name already in use"
    # scheitern.
    subprocess.run(
        ["docker", "rm", "-f", "ids-sniffer-reconfig"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )

    # Output zusätzlich in /opt/ids/.cyjan-sniffer-reconfig.log spiegeln,
    # damit auch nach einem späteren `docker rm` die Diagnose erhalten bleibt.
    log_path = ids_dir / ".cyjan-sniffer-reconfig.log"
    full_cmd = (
        f"set -ex; sleep 2; "
        f"{{ {compose_cmd}; echo 'Sniffer-Reconfig fertig'; }} "
        f"2>&1 | tee {log_path}"
    )
    subprocess.Popen(
        [
            "docker", "run", "-d",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{ids_dir}:{ids_dir}",
            "-w", str(ids_dir),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-sniffer-reconfig",
            "ids-api:latest",
            "sh", "-c", full_cmd,
        ],
        start_new_session=True, close_fds=True,
        env={**os.environ},
    )


@router.post("/system/interfaces/config", summary="Sniffer-/Management-Interface setzen")
async def set_interface_config(
    body: InterfaceConfigRequest,
    _admin: dict = Depends(require_admin),
) -> dict:
    iface = body.iface.strip()
    # Strikte Whitelist: der Name landet via _env_set() in /opt/ids/.env — ein
    # Newline oder Steuerzeichen im Namen würde sonst beliebige .env-Zeilen
    # injizieren (z.B. POSTGRES_PASSWORD=…). Nur echte Linux-Interface-Namen
    # zulassen: [a-zA-Z0-9_.:-], 1–32 Zeichen (deckt VLAN/Alias wie eth0.100:1).
    if not valid_iface_name(iface):
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
async def list_config(
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> list[ConfigResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key, value FROM system_config ORDER BY key")
    return [ConfigResponse(key=r["key"], value=dict(r["value"])) for r in rows]


@router.get("/config/{key}", response_model=ConfigResponse)
async def get_config(
    key: str,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> ConfigResponse:
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
    _admin: dict = Depends(require_admin),
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


# ── Feature-Flags ───────────────────────────────────────────────────────────
# Cyjan-weite Feature-Toggles (RedTeam, Pattern-Federation etc). Frontend
# pollt /system/feature-flags beim Start und entscheidet welche Settings-
# Sections gerendert werden. Gates AUSSCHLIESSLICH UI/Endpoint-Sichtbarkeit
# — die echte Aktivierung passiert über Compose-Profile (Container-Existenz)
# UND die Flag-Werte hier (Defense in Depth).

# Whitelist der erlaubten Flag-Namen — verhindert dass User über die API
# beliebige neue Felder anlegt. Ergänzen wenn neue Features dazukommen.
KNOWN_FEATURE_FLAGS = {
    "redteam_enabled",
    "pattern_export_enabled",
    "pattern_import_enabled",
}


class FeatureFlags(BaseModel):
    redteam_enabled:        bool = False
    pattern_export_enabled: bool = False
    pattern_import_enabled: bool = True


class FeatureFlagsUpdate(BaseModel):
    redteam_enabled:        bool | None = None
    pattern_export_enabled: bool | None = None
    pattern_import_enabled: bool | None = None


@router.get("/system/feature-flags", response_model=FeatureFlags,
            summary="Cyjan-Feature-Flags lesen (RedTeam, Pattern-Federation, …)")
async def get_feature_flags(pool: asyncpg.Pool = Depends(get_pool)) -> FeatureFlags:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = 'features'")
    raw = dict(row["value"]) if row and row["value"] else {}
    # Defaults: nur pattern_import ist standardmäßig an
    return FeatureFlags(
        redteam_enabled=bool(raw.get("redteam_enabled", False)),
        pattern_export_enabled=bool(raw.get("pattern_export_enabled", False)),
        pattern_import_enabled=bool(raw.get("pattern_import_enabled", True)),
    )


@router.patch("/system/feature-flags", response_model=FeatureFlags,
              summary="Feature-Flags partiell aktualisieren (admin only)")
async def update_feature_flags(
    body: FeatureFlagsUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> FeatureFlags:
    """Patch-Semantik: nur Felder die in der Request !=None sind werden
    geschrieben. Nicht erkannte Keys werden ignoriert."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = 'features'")
        current = dict(row["value"]) if row and row["value"] else {}

        patch = body.model_dump(exclude_unset=True, exclude_none=True)
        for k, v in patch.items():
            if k in KNOWN_FEATURE_FLAGS:
                current[k] = bool(v)

        # asyncpg jsonb-codec encoded dict→JSON selbst — kein json.dumps
        # davor, sonst wird die Spalte als doppelt-encodierter String
        # geschrieben und der nächste GET wirft beim dict(str)-Cast.
        await conn.execute(
            """
            INSERT INTO system_config (key, value) VALUES ('features', $1)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            current,
        )
    return await get_feature_flags(pool)


# ── Docker-Container-Status (profilbewusst) ──────────────────────────────────
# Zeigt im „System Details"-Tab auf einen Blick, welche Container des aktiven
# Compose-Profils laufen — und welche fehlen/abgestürzt sind. Soll-Set =
# Services des Profils aus /etc/cyjan/profile (z.B. "prod,snort"); Lab/RedTeam
# als separate Gruppe, wenn redteam_enabled ODER RedTeam-Container existieren.
# Der api-Container hat dafür /var/run/docker.sock + /opt/ids gemountet.
_PROFILE_FILE = Path("/etc/cyjan/profile")
_LAB_PROFILES = ["redteam"]

# Kleiner TTL-Cache, damit das 5-s-Polling des Frontends nicht pro Tick mehrere
# (langsame) `docker compose`-Aufrufe auslöst.
_containers_cache: tuple[float, dict] | None = None
_CONTAINERS_TTL = 3.0


def _profiles_from_file() -> list[str]:
    raw = _PROFILE_FILE.read_text().strip() if _PROFILE_FILE.exists() else "prod"
    return [p.strip() for p in raw.split(",") if p.strip()] or ["prod"]


def _profile_flags(profiles: list[str]) -> list[str]:
    # compose interpretiert `--profile "a,b"` als EINEN Namen → pro Eintrag ein Flag.
    flags: list[str] = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def _compose(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess | None:
    """docker compose im Projektverzeichnis; None bei Fehler/Timeout (failsoft)."""
    try:
        return subprocess.run(
            ["docker", "compose", "--project-directory", str(_IDS_DIR), *args],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None


def _compose_services(profiles: list[str]) -> list[str]:
    """Soll-Services eines Profil-Sets (`config --services`). Failsoft []."""
    r = _compose([*_profile_flags(profiles), "config", "--services"])
    if not r or r.returncode != 0 or not r.stdout:
        return []
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _compose_ps(profiles: list[str]) -> dict[str, dict]:
    """Ist-Zustand (`ps -a --format json`), gemappt Service→info. Parst JSON-Array
    UND ein-Objekt-pro-Zeile (compose-Versions-Drift)."""
    r = _compose([*_profile_flags(profiles), "ps", "-a", "--format", "json"])
    if not r or r.returncode != 0 or not r.stdout:
        return {}
    raw = r.stdout.strip()
    records: list[dict] = []
    try:
        parsed = json.loads(raw)
        records = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    out: dict[str, dict] = {}
    for rec in records:
        svc = rec.get("Service") or ""
        if not svc:
            continue
        out[svc] = {
            "name":      rec.get("Name") or None,
            "state":     (rec.get("State") or "unknown").lower(),
            "status":    rec.get("Status") or None,
            "health":    (rec.get("Health") or "").lower() or None,
            "exit_code": rec.get("ExitCode"),
        }
    return out


class ContainerInfo(BaseModel):
    service:   str
    name:      str | None = None
    state:     str                 # running|exited|restarting|created|paused|missing
    status:    str | None = None
    health:    str | None = None
    exit_code: int | None = None


class ContainerGroup(BaseModel):
    key:        str                # "active" | "lab"
    profiles:   list[str]
    running:    int
    total:      int
    containers: list[ContainerInfo]


class ContainerStatusResponse(BaseModel):
    deployment:      str           # "prod" | "lab"
    active_profiles: list[str]
    groups:          list[ContainerGroup]


def _is_oneshot(svc: str) -> bool:
    """One-Shot-Init-Jobs per Namenskonvention (kafka-init, minio-init).

    Gleiche Klassifikation wie cyjan-stack-health am Host: exited 0 heißt
    "erledigt", nicht "down" — und ein fehlender Init-Container ist normal,
    weil das wöchentliche `docker system prune` exited Container wegräumt.
    """
    return svc.endswith("-init")


def _build_group(key: str, profiles: list[str], services: list[str],
                 ps: dict[str, dict]) -> ContainerGroup:
    containers: list[ContainerInfo] = []
    running = 0
    total = 0
    for svc in sorted(services):
        info = ps.get(svc)
        if info is None:
            if _is_oneshot(svc):
                continue  # weggeprunter Init-Job — nicht listen, nicht zählen
            total += 1
            containers.append(ContainerInfo(service=svc, state="missing"))
            continue
        total += 1
        if info["state"] == "running":
            running += 1
        elif (_is_oneshot(svc) and info["state"] == "exited"
              and info.get("exit_code") == 0):
            running += 1  # sauber durchgelaufener One-Shot zählt als gesund
        containers.append(ContainerInfo(service=svc, **info))
    return ContainerGroup(key=key, profiles=profiles,
                          running=running, total=total,
                          containers=containers)


@router.get("/system/containers", response_model=ContainerStatusResponse,
            summary="Docker-Container-Status (profilbewusst)")
async def get_container_status(
    pool: asyncpg.Pool = Depends(get_pool),
) -> ContainerStatusResponse:
    global _containers_cache
    now = time.time()
    if _containers_cache and now - _containers_cache[0] < _CONTAINERS_TTL:
        return ContainerStatusResponse(**_containers_cache[1])

    active = _profiles_from_file()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = 'features'")
    feats  = dict(row["value"]) if row and row["value"] else {}
    lab_on = bool(feats.get("redteam_enabled", False))

    active_services = _compose_services(active)
    # `config --services --profile redteam` liefert profillose Services
    # (kafka, api, …) IMMER mit — Compose-Semantik. Ohne Differenz zur
    # Active-Gruppe würde die Lab-Gruppe den kompletten Basis-Stack doppelt
    # listen; übrig bleiben sollen nur die redteam-exklusiven Services.
    lab_services    = [s for s in _compose_services(_LAB_PROFILES)
                       if s not in set(active_services)]
    ps              = _compose_ps(active + _LAB_PROFILES)
    lab_present     = any(svc in ps for svc in lab_services)

    groups = [_build_group("active", active, active_services, ps)]
    if lab_on or lab_present:
        groups.append(_build_group("lab", _LAB_PROFILES, lab_services, ps))

    resp = ContainerStatusResponse(
        deployment="lab" if len(groups) > 1 else "prod",
        active_profiles=active,
        groups=groups,
    )
    _containers_cache = (now, resp.model_dump())
    return resp
