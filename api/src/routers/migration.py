"""
Settings-Migration zwischen Hosts.

Drei Endpoints:

  POST /api/migration/export      → liefert tar.gz mit Settings + Volumes
  POST /api/migration/preview     → parsed Bundle, liefert Diff + Iface-Liste
  POST /api/migration/apply       → schreibt DB/Volumes/.env am Zielsystem

Use-Case: Master-Hardware tauschen. Bundle wird am alten Host gezogen,
Quell-Host danach abgeschaltet, Bundle am neuen Host eingespielt. Tap-
Pairings bleiben gültig, weil die Master-CA Teil des Bundles ist.

Scope:
  - DB-Tabellen: users, system_config, known_networks, host_info,
    notification_channels, egress_whitelist, taps, redteam_scenarios,
    pattern_trust_keys, pattern_signing_keys.
    NICHT operative Daten (flows/alerts/training_samples/etc.) — das
    macht /api/maintenance/backup.
  - signature-rules Volume (custom YAML + _overrides.json)
  - master-ca Volume (Root-CA + .key)
  - /models/ml_config.json (kein Modell selbst)
  - /opt/ids/.env → MIRROR_INTERFACE/MANAGEMENT_INTERFACE (Iface-Mapping)

NICHT im Bundle:
  - JWT_SECRET/SECRET_KEY (würde Login-Tokens auf Ziel ungültig machen)
  - POSTGRES_PASSWORD (Bootstrap-Wert)
  - flows/alerts/training_samples → Backup-Endpoint
  - Trained ML-Modell — passt nicht auf neues Netz, retrained sich

Re-Auth via Passwort wegen CA-Key + User-Hashes.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

import asyncpg
import orjson
from bcrypt import checkpw
from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from database import get_pool
from deps import require_admin

log = logging.getLogger("migration")

router = APIRouter(prefix="/api/migration", tags=["migration"])

# Schema-Version des Bundle-Formats. Bei breaking changes hochzählen,
# Preview verweigert dann den Import mit klarer Fehlermeldung.
BUNDLE_SCHEMA_VERSION = 1

# Tabellen die zum Settings-Scope gehören. Reihenfolge wichtig wegen
# FK-Constraints beim Import (TRUNCATE CASCADE löst sie, aber INSERT-
# Reihenfolge muss sauber sein: users vor notification_channels,
# taps vor pending_taps falls vorhanden).
SETTINGS_TABLES = [
    "users",
    "system_config",
    "known_networks",
    "host_info",
    "egress_whitelist",
    "taps",
    "notification_channels",
    "redteam_scenarios",
    "pattern_trust_keys",
    "pattern_signing_keys",
]

# Volumes, die mit dem Bundle reisen
SIG_RULES_DIR = Path("/sig-rules")          # api-Mount des signature-rules-Volumes
MASTER_CA_DIR = Path(os.environ.get("MASTER_CA_DIR", "/var/lib/cyjan/master-ca"))
ML_CONFIG     = Path("/models/ml_config.json")
HOST_ENV_FILE = Path("/opt/ids/.env")
HOST_IFACES   = Path("/etc/cyjan/host-interfaces.json")

CATEGORIES = ("db", "sig_rules", "master_ca", "ml_config")


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

async def _verify_password(pool: asyncpg.Pool, user_payload: dict, password: str) -> None:
    """Re-Auth (analog maintenance.py).

    JWT-Payload enthält "sub"=user_id(UUID) und "username"="<name>" — separat!
    Frühere Versionen lookupten gegen "sub" was zu 403 'Re-Auth fehlgeschlagen'
    führte, weil 'WHERE username=<UUID>' immer leer war.
    """
    username = user_payload.get("username") or user_payload.get("sub")
    if not username:
        raise HTTPException(401, "Ungültiger Token")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash, role FROM users WHERE username = $1",
            username,
        )
    if not row or not row["password_hash"]:
        raise HTTPException(403, "Re-Auth fehlgeschlagen")
    if not checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(403, "Passwort falsch")
    if row["role"] != "admin":
        raise HTTPException(403, "Nur Admins dürfen Migration ausführen")


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
    """Schreibt ins maintenance_audit-Log (selber Audit-Stream wie /maintenance)."""
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
        log.exception("audit-write failed")


def _json_default(obj: Any) -> Any:
    """asyncpg liefert datetime, UUID, IPv4Network etc. — orjson default-Hook."""
    import datetime as _dt
    import uuid
    import ipaddress
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network,
                        ipaddress.IPv4Address, ipaddress.IPv6Address,
                        ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).decode("utf-8", errors="replace")
    raise TypeError(f"nicht serialisierbar: {type(obj)}")


async def _dump_table(conn: asyncpg.Connection, table: str) -> list[dict]:
    """Liest die ganze Tabelle als list[dict]. Bei nicht-existenter Tabelle: []."""
    try:
        rows = await conn.fetch(f"SELECT * FROM {table}")
    except Exception as exc:
        log.warning("dump skip %s: %s", table, exc)
        return []
    return [dict(r) for r in rows]


def _parse_env(path: Path) -> dict[str, str]:
    """KISS-.env-Parser: nur KEY=VALUE-Lines, keine Quotes/Substitution."""
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _read_host_interfaces() -> dict | None:
    try:
        return json.loads(HOST_IFACES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# 1. EXPORT
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/export")
async def export_bundle(
    password: str  = Body(..., embed=True),
    user:     dict = Depends(require_admin),
    pool:     asyncpg.Pool = Depends(get_pool),
) -> StreamingResponse:
    """Streamt das komplette Settings-Bundle als tar.gz.

    Bundle-Inhalt (siehe Modul-Docstring). Re-Auth via Passwort, weil
    der Master-CA-Privatekey mitgeht.
    """
    await _verify_password(pool, user, password)
    start = time.monotonic()

    env = _parse_env(HOST_ENV_FILE)
    ifaces = _read_host_interfaces()
    hostname = (ifaces or {}).get("hostname") or os.uname().nodename
    version  = (Path("/opt/ids/VERSION").read_text(encoding="utf-8").strip()
                if Path("/opt/ids/VERSION").is_file() else "unknown")

    manifest: dict[str, Any] = {
        "schema_version":   BUNDLE_SCHEMA_VERSION,
        "source_hostname":  hostname,
        "source_version":   version,
        "created_at":       int(time.time()),
        "created_by":       user.get("sub") or user.get("username") or "?",
        "tables":           [],
        "includes": {
            "db":         True,
            "sig_rules":  SIG_RULES_DIR.is_dir(),
            "master_ca":  MASTER_CA_DIR.is_dir(),
            "ml_config":  ML_CONFIG.is_file(),
        },
        "env_snapshot": {
            "MIRROR_INTERFACE":     env.get("MIRROR_INTERFACE") or env.get("MIRROR_IFACE"),
            "MANAGEMENT_INTERFACE": env.get("MANAGEMENT_INTERFACE") or env.get("MGMT_INTERFACE"),
            "MANAGEMENT_IP":        env.get("MANAGEMENT_IP"),
        },
        "host_interfaces": ifaces,
    }

    # tarball im Speicher bauen — Settings-Bundle ist im O(MB), kein Streaming nötig
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        # ── 1) DB-Tabellen als JSON ──────────────────────────────────────
        async with pool.acquire() as conn:
            for tbl in SETTINGS_TABLES:
                rows = await _dump_table(conn, tbl)
                payload = orjson.dumps(
                    rows, default=_json_default,
                    option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS,
                )
                info = tarfile.TarInfo(f"db/{tbl}.json")
                info.size  = len(payload)
                info.mtime = int(time.time())
                info.mode  = 0o644
                tar.addfile(info, io.BytesIO(payload))
                manifest["tables"].append({"name": tbl, "rows": len(rows)})

        # ── 2) signature-rules Volume ───────────────────────────────────
        if SIG_RULES_DIR.is_dir():
            for root, _dirs, files in os.walk(SIG_RULES_DIR):
                for f in files:
                    src = Path(root) / f
                    rel = src.relative_to(SIG_RULES_DIR)
                    # Operative Files weglassen (existieren hier nicht
                    # standardmäßig, aber defensiv)
                    if any(part in (".tmp", "__pycache__") for part in rel.parts):
                        continue
                    arc = f"sig-rules/{rel.as_posix()}"
                    tar.add(str(src), arcname=arc, recursive=False)

        # ── 3) Master-CA Volume ─────────────────────────────────────────
        if MASTER_CA_DIR.is_dir():
            for root, _dirs, files in os.walk(MASTER_CA_DIR):
                for f in files:
                    src = Path(root) / f
                    rel = src.relative_to(MASTER_CA_DIR)
                    arc = f"master-ca/{rel.as_posix()}"
                    tar.add(str(src), arcname=arc, recursive=False)

        # ── 4) ML-Config ────────────────────────────────────────────────
        if ML_CONFIG.is_file():
            tar.add(str(ML_CONFIG), arcname="ml/ml_config.json", recursive=False)

        # ── 5) Manifest ─────────────────────────────────────────────────
        mpayload = orjson.dumps(manifest, default=_json_default,
                                option=orjson.OPT_INDENT_2)
        info = tarfile.TarInfo("manifest.json")
        info.size  = len(mpayload)
        info.mtime = int(time.time())
        info.mode  = 0o644
        tar.addfile(info, io.BytesIO(mpayload))

    duration_ms = int((time.monotonic() - start) * 1000)
    buf.seek(0)
    size = buf.getbuffer().nbytes
    ts_human = time.strftime("%Y%m%d-%H%M%S")
    filename = f"cyjan-settings-{hostname}-{ts_human}.cysb"

    await _audit(
        pool, user, "migration.export",
        {"include_categories": list(CATEGORIES)},
        {"filename": filename, "bytes": size, "tables": manifest["tables"]},
        True, None, duration_ms,
    )

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Bundle-Schema":     str(BUNDLE_SCHEMA_VERSION),
            "X-Bundle-Hostname":   hostname,
            "X-Bundle-Version":    version,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
# 2. PREVIEW
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/preview", dependencies=[Depends(require_admin)])
async def preview_bundle(
    bundle: UploadFile = File(...),
    pool:   asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Parsed das hochgeladene Bundle, gibt Manifest + Iface-Mapping-
    Vorschlag + Konflikte zurück. Schreibt NICHTS — Apply ist separater
    Endpoint.
    """
    content = await bundle.read()
    if len(content) > 500 * 1024 * 1024:
        raise HTTPException(413, "Bundle > 500 MB — nicht plausibel")

    try:
        tar = tarfile.open(fileobj=io.BytesIO(content), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise HTTPException(400, f"Kein gültiges tar.gz: {exc}")

    try:
        try:
            manifest_member = tar.getmember("manifest.json")
            manifest_fd = tar.extractfile(manifest_member)
            if manifest_fd is None:
                raise HTTPException(400, "manifest.json nicht lesbar")
            manifest = json.loads(manifest_fd.read())
        except (KeyError, json.JSONDecodeError) as exc:
            raise HTTPException(400, f"manifest.json fehlt oder kaputt: {exc}")

        bundle_local_admins = _extract_bundle_local_admins(tar)
    finally:
        tar.close()

    # Schema-Version prüfen
    schema = int(manifest.get("schema_version", 0))
    if schema != BUNDLE_SCHEMA_VERSION:
        raise HTTPException(
            400,
            f"Bundle-Schema {schema} inkompatibel — erwartet {BUNDLE_SCHEMA_VERSION}. "
            "Source und Ziel-Host müssen dieselbe Cyjan-Version haben.",
        )

    # Ziel-Iface-Liste laden
    target_ifaces = _read_host_interfaces()

    # Mapping-Vorschlag bauen: gleicher Name = Match, sonst leer
    source_env = manifest.get("env_snapshot") or {}
    target_iface_names = []
    if target_ifaces:
        target_iface_names = [
            i["name"]
            for i in target_ifaces.get("interfaces", [])
            if not i.get("is_virtual")
        ]
    mapping_suggestion = {}
    for role in ("MIRROR_INTERFACE", "MANAGEMENT_INTERFACE"):
        source_name = source_env.get(role) or ""
        if source_name and source_name in target_iface_names:
            mapping_suggestion[role] = source_name
        else:
            mapping_suggestion[role] = ""

    # DB-Diff: aktuelle Row-Counts vs. Source
    db_diff = []
    async with pool.acquire() as conn:
        for tbl_entry in manifest.get("tables", []):
            name = tbl_entry["name"]
            src_rows = int(tbl_entry.get("rows", 0))
            try:
                tgt_rows = int(await conn.fetchval(f"SELECT COUNT(*) FROM {name}") or 0)
            except Exception:
                tgt_rows = -1
            db_diff.append({
                "table":         name,
                "source_rows":   src_rows,
                "target_rows":   tgt_rows,
                "after_import":  src_rows,  # truncate+insert: Source-Wert gewinnt
            })

    # Alle IPs am Ziel sammeln (für IP-Übernahme-Prüfung im UI)
    target_addresses: list[str] = []
    if target_ifaces:
        for i in target_ifaces.get("interfaces", []):
            target_addresses.extend(i.get("addresses", []))

    return {
        "manifest":        manifest,
        "target": {
            # Host-Name aus host-interfaces.json (Container-uname zeigt 'ids-api')
            "hostname":   (target_ifaces or {}).get("hostname") or os.uname().nodename,
            "interfaces": target_ifaces.get("interfaces", []) if target_ifaces else [],
            "mirror_interface": (target_ifaces or {}).get("mirror_interface"),
            "mgmt_interface":   (target_ifaces or {}).get("mgmt_interface"),
            "all_addresses":    target_addresses,
        },
        "mapping_suggestion":  mapping_suggestion,
        "db_diff":             db_diff,
        "bundle_local_admins": bundle_local_admins,
        "warnings":            _build_warnings(manifest, target_ifaces, bundle_local_admins),
    }


def _build_warnings(
    manifest: dict,
    target_ifaces: dict | None,
    bundle_local_admins: list[str],
) -> list[dict]:
    """Liefert eine Liste von Warnings, jede mit `level` (info/warn/critical)
    und `text`. Frontend rendert level-abhängig (gelb/rot)."""
    out: list[dict] = []

    if not target_ifaces:
        out.append({
            "level": "warn",
            "text": "Host-Iface-Liste nicht verfügbar (/etc/cyjan/host-interfaces.json fehlt). "
                    "post-update.sh am Ziel-Host ausführen, dann erneut probieren.",
        })

    # Version-Diff
    src_ver = manifest.get("source_version", "unknown")
    try:
        tgt_ver = Path("/opt/ids/VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        tgt_ver = "unknown"
    if src_ver != "unknown" and tgt_ver != "unknown" and src_ver != tgt_ver:
        # v2.5.7 vs v2.5.9 — Patch-Diff ist additive, OK mit Warn-Level.
        # Major/Minor-Diff (v2.5 vs v2.4 / v3.0 vs v2.x) — strikter, weil
        # Migrations divergieren.
        sm = _parse_semver(src_ver)
        tm = _parse_semver(tgt_ver)
        same_minor = (sm is not None and tm is not None
                      and sm[0] == tm[0] and sm[1] == tm[1])
        out.append({
            "level": "warn" if same_minor else "critical",
            "text": f"Versions-Mismatch: Source={src_ver}, Ziel={tgt_ver}. "
                    + ("Patch-Level-Diff ist meist unkritisch, aber zur Sicherheit beide Hosts auf dieselbe Version ziehen."
                       if same_minor else
                       "Major/Minor-Versionen weichen ab — DB-Schema kann inkompatibel sein. Import wird wahrscheinlich fehlschlagen."),
        })

    # Master-CA-Übernahme + IP-Match
    includes = manifest.get("includes", {})
    if includes.get("master_ca"):
        src_mgmt_ip = (manifest.get("env_snapshot") or {}).get("MANAGEMENT_IP")
        tgt_ip_list: list[str] = []
        if target_ifaces:
            for i in target_ifaces.get("interfaces", []):
                tgt_ip_list.extend(i.get("addresses", []))

        if src_mgmt_ip and src_mgmt_ip in tgt_ip_list:
            out.append({
                "level": "info",
                "text": f"Master-IP {src_mgmt_ip} ist auf dem Ziel-Host konfiguriert — "
                        "Tap-Pairings sollten nach dem Import ohne weitere Aktion weiterlaufen.",
            })
        elif src_mgmt_ip:
            out.append({
                "level": "critical",
                "text": f"Master-IP {src_mgmt_ip} (Quelle) ist auf dem Ziel-Host NICHT konfiguriert "
                        f"(verfügbar: {', '.join(tgt_ip_list) or '–'}). "
                        "Taps haben in ihrer lokalen .env MASTER_URL=wss://<source-ip>:8443 — "
                        "ohne Eingriff bleiben sie offline. Entweder am Ziel-Host die Source-IP "
                        f"({src_mgmt_ip}) übers OS-Netzwerk-Setup (netplan/NetworkManager) zuweisen, "
                        "oder an jedem Tap manuell `cyjan-tap unpair && cyjan-tap pair` gegen die neue IP.",
            })

        out.append({
            "level": "warn",
            "text": "Master-CA + Tap-Pairings werden übernommen. "
                    "Der Quell-Host MUSS nach dem Import abgeschaltet werden, sonst sehen die Taps zwei Master "
                    "und das Reverse-Channel-Pull der Heuristik-Rules race-ed.",
        })

    # Lokaler-Admin-Check (Lockout-Risiko)
    if not bundle_local_admins:
        out.append({
            "level": "critical",
            "text": "Bundle enthält KEINEN lokalen Admin-User (alle source='saml' oder Rolle != 'admin'). "
                    "Nach dem Import gibt es keinen Login-Pfad, bis SAML am Ziel konfiguriert ist. "
                    "Empfehlung: am Quell-Host einen lokalen Admin anlegen und erneut exportieren.",
        })
    else:
        out.append({
            "level": "info",
            "text": f"Lokale Admin-Logins nach Import verfügbar: {', '.join(bundle_local_admins)}.",
        })

    return out


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    """'v2.5.9' → (2, 5, 9). None bei nicht-parsebaren Strings."""
    try:
        s = v.lstrip("v").split("-")[0]
        parts = s.split(".")
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, IndexError):
        return None


def _extract_bundle_local_admins(tar: tarfile.TarFile) -> list[str]:
    """Reads db/users.json from the bundle, returns usernames of
    role=admin AND source=local users. Empty list if file missing/parse error."""
    try:
        fd = tar.extractfile("db/users.json")
        if fd is None:
            return []
        users = json.loads(fd.read())
    except (KeyError, json.JSONDecodeError, OSError):
        return []
    return [
        u.get("username", "?")
        for u in users
        if u.get("role") == "admin" and u.get("source", "local") == "local"
    ]


# ═══════════════════════════════════════════════════════════════════════════
# 3. APPLY
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/apply", dependencies=[Depends(require_admin)])
async def apply_bundle(
    bundle:     UploadFile = File(...),
    password:   str        = Form(...),
    mapping:    str        = Form("{}"),
    categories: str        = Form(""),
    user:       dict       = Depends(require_admin),
    pool:       asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Schreibt das Bundle ins Zielsystem.

    Form-Felder:
      - bundle:     tar.gz-Upload
      - password:   Re-Auth des admin
      - mapping:    JSON-String {"MIRROR_INTERFACE": "enp1s0", ...}
      - categories: CSV "db,sig_rules,master_ca,ml_config" (Default: alle)

    Strategie:
      - DB-Tabellen: TRUNCATE + INSERT in einer Transaction
      - sig-rules-Volume: rsync-Style overwrite (alte custom-Files bleiben,
        wenn im Bundle nicht enthalten — Reverse-Channel zieht sie sonst nach)
      - master-ca: replace
      - ml_config: replace
      - .env: atomic rewrite mit .env.bak
    """
    await _verify_password(pool, user, password)
    start = time.monotonic()

    try:
        mapping_obj = json.loads(mapping) if mapping else {}
    except json.JSONDecodeError:
        raise HTTPException(400, "mapping ist kein valides JSON")
    if not isinstance(mapping_obj, dict):
        raise HTTPException(400, "mapping muss ein Objekt sein")

    selected = {c.strip() for c in (categories or "").split(",") if c.strip()}
    if not selected:
        selected = set(CATEGORIES)
    invalid = selected - set(CATEGORIES)
    if invalid:
        raise HTTPException(400, f"Unbekannte Kategorien: {invalid}")

    content = await bundle.read()
    try:
        tar = tarfile.open(fileobj=io.BytesIO(content), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise HTTPException(400, f"Kein gültiges tar.gz: {exc}")

    audit_params = {
        "categories": sorted(selected),
        "mapping":    mapping_obj,
        "filename":   bundle.filename,
        "bytes":      len(content),
    }
    result_details: dict[str, Any] = {}

    try:
        # ── Manifest lesen ─────────────────────────────────────────────
        try:
            mfd = tar.extractfile("manifest.json")
            if mfd is None:
                raise KeyError("manifest.json")
            manifest = json.loads(mfd.read())
        except (KeyError, json.JSONDecodeError) as exc:
            raise HTTPException(400, f"manifest.json fehlt/defekt: {exc}")

        schema = int(manifest.get("schema_version", 0))
        if schema != BUNDLE_SCHEMA_VERSION:
            raise HTTPException(
                400, f"Bundle-Schema {schema} inkompatibel (erwartet {BUNDLE_SCHEMA_VERSION})",
            )

        # ── 1) DB ───────────────────────────────────────────────────────
        if "db" in selected:
            details = await _apply_db(pool, tar)
            result_details["db"] = details

        # ── 2) sig-rules ────────────────────────────────────────────────
        if "sig_rules" in selected:
            details = _apply_volume(tar, prefix="sig-rules/", dest=SIG_RULES_DIR)
            result_details["sig_rules"] = details

        # ── 3) master-ca ────────────────────────────────────────────────
        if "master_ca" in selected:
            details = _apply_volume(tar, prefix="master-ca/", dest=MASTER_CA_DIR,
                                    preserve_mode=True)
            result_details["master_ca"] = details

        # ── 4) ml-config ────────────────────────────────────────────────
        if "ml_config" in selected:
            try:
                fd = tar.extractfile("ml/ml_config.json")
                if fd is not None:
                    ML_CONFIG.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write_bytes(ML_CONFIG, fd.read())
                    result_details["ml_config"] = "replaced"
            except KeyError:
                result_details["ml_config"] = "not_in_bundle"

        # ── 5) .env (Iface-Mapping) ─────────────────────────────────────
        env_change = _apply_env_mapping(mapping_obj, manifest)
        result_details["env"] = env_change

        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(
            pool, user, "migration.apply", audit_params, result_details,
            True, None, duration_ms,
        )
        # Wenn die users-Tabelle migriert wurde, ist der aktuelle JWT-User
        # nach dem TRUNCATE+INSERT ggf. nicht mehr in der DB. Frontend muss
        # Logout erzwingen, sonst landet der nächste Call auf 401 ohne UX-
        # Erklärung.
        require_relogin = "db" in selected and "users" in (
            result_details.get("db", {}) if isinstance(result_details.get("db"), dict) else {}
        )
        next_steps = [
            "Stack neu starten: 'docker compose --profile prod up -d --force-recreate api master-uplink' (signature-engine reagiert via inotify).",
        ]
        if isinstance(result_details.get("env"), dict) and result_details["env"].get("status") == "updated":
            next_steps.append(
                "Da .env angepasst wurde: zusätzlich sniffer + flow-aggregator restarten "
                "('docker compose --profile prod restart sniffer flow-aggregator')."
            )
        if "master_ca" in selected:
            next_steps.append(
                "Quell-Host runterfahren, BEVOR Taps wieder online gehen — sonst sehen die Taps zwei Master."
            )
        if require_relogin:
            next_steps.insert(
                0,
                "Wichtig: Login-Sitzung wird beendet, weil die User-Tabelle ersetzt wurde. "
                "Mit einem Login aus dem importierten User-Set neu anmelden."
            )
        return {
            "success":         True,
            "duration_ms":     duration_ms,
            "details":         result_details,
            "next_steps":      next_steps,
            "require_relogin": require_relogin,
        }

    except HTTPException:
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "migration.apply", audit_params,
                     result_details, False, "HTTP-Fehler", duration_ms)
        raise
    except Exception as exc:
        log.exception("migration.apply failed")
        duration_ms = int((time.monotonic() - start) * 1000)
        await _audit(pool, user, "migration.apply", audit_params,
                     result_details, False, str(exc), duration_ms)
        raise HTTPException(500, f"Apply fehlgeschlagen: {exc}")
    finally:
        tar.close()


# ─── Apply-Helpers ─────────────────────────────────────────────────────────

async def _apply_db(pool: asyncpg.Pool, tar: tarfile.TarFile) -> dict:
    """TRUNCATE + INSERT für alle Tabellen, die im Bundle vorhanden sind."""
    details: dict[str, Any] = {}
    async with pool.acquire() as conn:
        async with conn.transaction():
            # CASCADE räumt FK-Referenzen mit ab — z.B. notification_channels
            # hängt an users(id). Reihenfolge SETTINGS_TABLES rückwärts:
            # erst die Kinder truncaten, sonst meckert CASCADE-Restrict.
            for tbl in reversed(SETTINGS_TABLES):
                try:
                    await conn.execute(f"TRUNCATE TABLE {tbl} CASCADE")
                except Exception as exc:
                    # Tabelle existiert ggf. nicht (z.B. redteam_scenarios
                    # in einer Lite-Install) — überspringen.
                    log.warning("truncate skip %s: %s", tbl, exc)

            for tbl in SETTINGS_TABLES:
                try:
                    fd = tar.extractfile(f"db/{tbl}.json")
                except KeyError:
                    fd = None
                if fd is None:
                    details[tbl] = {"status": "no_data_in_bundle"}
                    continue
                rows = json.loads(fd.read())
                inserted = await _insert_rows(conn, tbl, rows)
                details[tbl] = {"status": "imported", "rows": inserted}
    return details


async def _insert_rows(conn: asyncpg.Connection, table: str, rows: list[dict]) -> int:
    """Insert beliebige Rows in beliebige Tabelle. JSON-Spalten werden als
    String erkannt und mit ::jsonb gecastet."""
    if not rows:
        return 0

    # Spalten-Typen aus der Ziel-DB lesen (statt aus den Rows zu raten — sicherer)
    col_rows = await conn.fetch(
        """
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = $1 AND table_schema = 'public'
        """,
        table,
    )
    if not col_rows:
        log.warning("insert skip %s: keine Spalten gefunden", table)
        return 0
    col_types = {r["column_name"]: r["data_type"] for r in col_rows}
    valid_cols = set(col_types)

    # Bundle-Rows können Spalten enthalten, die das Ziel nicht (mehr) hat —
    # nur die Schnittmenge nehmen.
    sample_cols = list(rows[0].keys())
    cols = [c for c in sample_cols if c in valid_cols]
    if not cols:
        return 0

    placeholders = []
    for i, col in enumerate(cols, start=1):
        dtype = col_types[col]
        if dtype in ("jsonb", "json"):
            placeholders.append(f"${i}::{dtype}")
        elif dtype in ("inet", "cidr"):
            placeholders.append(f"${i}::{dtype}")
        else:
            placeholders.append(f"${i}")
    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"

    inserted = 0
    for r in rows:
        vals = []
        for col in cols:
            v = r.get(col)
            dtype = col_types[col]
            if dtype in ("jsonb", "json") and v is not None and not isinstance(v, str):
                # asyncpg-jsonb-Codec ist auf dem api-Pool aktiv (siehe
                # database._init_conn), aber ::jsonb-Cast braucht einen
                # String. Wir gehen den String-Pfad, damit Cast-Operator
                # funktioniert.
                v = json.dumps(v)
            vals.append(v)
        try:
            await conn.execute(sql, *vals)
            inserted += 1
        except Exception as exc:
            log.warning("insert row failed (%s): %s", table, exc)
    return inserted


def _apply_volume(
    tar: tarfile.TarFile, prefix: str, dest: Path, preserve_mode: bool = False,
) -> dict:
    """Extrahiert alle Bundle-Member mit gegebenem Pfad-Prefix nach dest/.
    Bestehende Files werden überschrieben. Files die im Bundle fehlen,
    bleiben unangetastet (kein purge)."""
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for member in tar.getmembers():
        if not member.isfile():
            continue
        if not member.name.startswith(prefix):
            continue
        rel = member.name[len(prefix):]
        if not rel:
            continue
        # Pfad-Traversal-Schutz: relpath enthält keine ".." nach normalize
        normalized = os.path.normpath(rel)
        if normalized.startswith("..") or os.path.isabs(normalized):
            log.warning("skip path-traversal: %s", member.name)
            continue
        target = dest / normalized
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = tar.extractfile(member)
        if fd is None:
            continue
        data = fd.read()
        _atomic_write_bytes(target, data)
        if preserve_mode and member.mode:
            try:
                os.chmod(target, member.mode & 0o7777)
            except OSError:
                pass
        count += 1
    return {"status": "imported", "files": count}


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False,
    ) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _apply_env_mapping(mapping: dict[str, str], manifest: dict) -> dict:
    """Schreibt Iface-Mapping (+ optional MANAGEMENT_IP) in /opt/ids/.env,
    atomisch und mit .env.bak-Backup. Andere Keys bleiben unverändert.

    MANAGEMENT_IP wird übernommen, wenn mapping["MANAGEMENT_IP_TAKE"]=="yes" —
    sonst bleibt der Ziel-Host-Wert stehen. Das Frontend setzt das Flag nur,
    wenn die Source-IP auch tatsächlich auf einem Ziel-Iface liegt; sonst
    wäre der API-Port nicht erreichbar.
    """
    if not HOST_ENV_FILE.is_file():
        return {"status": "skipped", "reason": ".env nicht gefunden"}

    target_keys: dict[str, str] = {}
    if mapping.get("MIRROR_INTERFACE"):
        target_keys["MIRROR_INTERFACE"] = mapping["MIRROR_INTERFACE"]
        target_keys["MIRROR_IFACE"]     = mapping["MIRROR_INTERFACE"]  # alter Name, symmetrisch
    if mapping.get("MANAGEMENT_INTERFACE"):
        target_keys["MANAGEMENT_INTERFACE"] = mapping["MANAGEMENT_INTERFACE"]
        target_keys["MGMT_INTERFACE"]       = mapping["MANAGEMENT_INTERFACE"]
    if mapping.get("MANAGEMENT_IP_TAKE") == "yes":
        src_ip = (manifest.get("env_snapshot") or {}).get("MANAGEMENT_IP")
        if src_ip:
            target_keys["MANAGEMENT_IP"] = src_ip

    if not target_keys:
        return {"status": "skipped", "reason": "kein Mapping angegeben"}

    old = HOST_ENV_FILE.read_text(encoding="utf-8", errors="replace")
    # Backup (nur einmal pro Tag, damit wiederholte Imports nicht überschreiben)
    backup = HOST_ENV_FILE.with_suffix(".env.bak")
    try:
        shutil.copy2(HOST_ENV_FILE, backup)
    except OSError:
        pass

    seen = set()
    lines = []
    for line in old.splitlines():
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            k = stripped.split("=", 1)[0].strip()
            if k in target_keys:
                lines.append(f"{k}={target_keys[k]}")
                seen.add(k)
                continue
        lines.append(line)
    # Keys die noch nicht in .env standen → anhängen
    for k, v in target_keys.items():
        if k not in seen:
            lines.append(f"{k}={v}")

    new_content = "\n".join(lines)
    if not new_content.endswith("\n"):
        new_content += "\n"
    _atomic_write_bytes(HOST_ENV_FILE, new_content.encode("utf-8"))
    return {"status": "updated", "keys": sorted(target_keys.keys()), "backup": str(backup)}
