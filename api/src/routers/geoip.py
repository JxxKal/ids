"""
GeoIP-Datenbank-Verwaltung — Status + Upload für die enrichment-service
GeoIP-/ASN-Lookups.

Schreibt die `.mmdb`-Dateien ins Volume-Verzeichnis (Host-Pfad
`/opt/ids/geoip/`, im api-Container als `/opt/ids/geoip` gemountet).
Der enrichment-service mountet dasselbe Verzeichnis read-only als
`/geoip` und lädt beim Start die DBs. Nach Upload wird er via
docker-compose-Runner-Container neu gestartet (gleiches Pattern wie
in update.py — der api-Container darf sich nicht selbst neu starten,
deshalb über einen unabhängigen Einweg-Container).

Akzeptiert sowohl rohe `.mmdb` als auch gzippte `.mmdb.gz` (DB-IP und
MaxMind shippen beide als .gz). MaxMind-Tarballs (.tar.gz mit Ordner
drin) werden bewusst nicht unterstützt — der User soll dann erst lokal
extrahieren.
"""
from __future__ import annotations

import gzip
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from deps import require_admin

log = logging.getLogger("api.geoip")

router = APIRouter(prefix="/api/system/geoip", tags=["geoip"])

# Host-Pfad ins Volume — die api-Container hat /opt/ids:/opt/ids gemountet,
# enrichment-service mountet ./geoip:/geoip:ro (gleiches Verzeichnis,
# anderer Pfad-View).
GEOIP_DIR = Path("/opt/ids/geoip")
CITY_NAME = "GeoLite2-City.mmdb"
ASN_NAME  = "GeoLite2-ASN.mmdb"
IDS_DIR   = Path("/opt/ids")

# Magic-Bytes am Ende eines validen MaxMind-/DB-IP-MMDB-Files.
# Format-Spec: <data-section>\xAB\xCD\xEFMaxMind.com<metadata-bson>
_MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"


def _has_mmdb_marker(path: Path) -> bool:
    """True wenn die Datei am Ende den MaxMind-/DB-IP-Magic-String enthält.
    Wir lesen die letzten 128 KB — Metadata-Block ist immer im hinteren
    Bereich des Files (typisch < 2 KB groß)."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            end = fh.tell()
            head = max(0, end - 131072)
            fh.seek(head)
            return _MMDB_MARKER in fh.read()
    except OSError:
        return False


def _file_meta(path: Path) -> dict:
    if not path.exists():
        return {"present": False, "size": 0, "mtime": None, "valid": False}
    try:
        st = path.stat()
        return {
            "present": True,
            "size":    st.st_size,
            "mtime":   datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "valid":   _has_mmdb_marker(path),
        }
    except OSError:
        return {"present": False, "size": 0, "mtime": None, "valid": False}


@router.get("/status", summary="Status der GeoIP-Datenbanken")
async def status(_: dict = Depends(require_admin)) -> dict:
    """Liefert Präsenz + Größe + mtime + Magic-Validierung pro DB."""
    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "geoip_dir": str(GEOIP_DIR),
        "city":      _file_meta(GEOIP_DIR / CITY_NAME),
        "asn":       _file_meta(GEOIP_DIR / ASN_NAME),
    }


def _maybe_gunzip(body: bytes) -> bytes:
    """gzip-Magic erkennen + transparent dekomprimieren. DB-IP-Lite und
    MaxMind shippen die .mmdb-Files standardmäßig als .gz."""
    if len(body) >= 2 and body[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(body)
        except Exception as exc:                            # noqa: BLE001
            raise HTTPException(400, f"Datei ist gzip-Header-tagged, aber nicht entpackbar: {exc}")
    return body


def _write_atomic(target: Path, content: bytes) -> None:
    """Schreibt nach target.tmp, validiert Magic + rename atomisch.
    Bei Validierungsfehler wird die .tmp wieder gelöscht — die alte
    DB bleibt bestehen, der enrichment-service ist nie ohne Daten."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(content)
        if not _has_mmdb_marker(tmp):
            raise HTTPException(
                400,
                f"{target.name}: Datei enthält keinen MaxMind-/DB-IP-Magic-Marker. "
                f"Bitte die rohe .mmdb (oder .mmdb.gz) hochladen, keinen Tarball oder ZIP.",
            )
        os.replace(tmp, target)
    finally:
        # Sicherheitsnetz: falls nicht durch os.replace verbraucht
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _spawn_enrichment_restart() -> None:
    """Restartet den enrichment-service via unabhängigem Runner-Container.
    Direkter `docker compose restart` aus dem api-Container wäre technisch
    OK (api ≠ enrichment-service), aber wir spiegeln das Pattern aus
    update._spawn_compose_restart_runner für konsistente Logs/Errors."""
    profile_file = Path("/etc/cyjan/profile")
    profile = profile_file.read_text().strip() if profile_file.exists() else "prod"
    compose_cmd = (
        f"docker compose --project-directory {IDS_DIR} --profile {profile} "
        f"restart enrichment-service"
    )
    subprocess.Popen(
        [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{IDS_DIR}:{IDS_DIR}",
            "-w", str(IDS_DIR),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-geoip-reload",
            "ids-api:latest",
            "sh", "-c", f"sleep 2 && {compose_cmd}",
        ],
        start_new_session=True,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ},
    )


@router.post("/upload", summary="GeoIP-Datenbank(en) hochladen")
async def upload(
    city: UploadFile | None = File(default=None),
    asn:  UploadFile | None = File(default=None),
    _:    dict = Depends(require_admin),
) -> dict:
    """Akzeptiert eine oder beide .mmdb-Dateien (raw oder .gz). Mindestens
    eine ist Pflicht. Schreibt atomisch nach /opt/ids/geoip/ und triggert
    einen Restart des enrichment-service über einen unabhängigen
    Runner-Container."""
    if city is None and asn is None:
        raise HTTPException(400, "Mindestens eine Datei (city oder asn) erforderlich")

    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    for upload_file, target_name in ((city, CITY_NAME), (asn, ASN_NAME)):
        if upload_file is None:
            continue
        raw = await upload_file.read()
        if not raw:
            raise HTTPException(400, f"Hochgeladene Datei für {target_name} ist leer")
        body = _maybe_gunzip(raw)
        _write_atomic(GEOIP_DIR / target_name, body)
        log.info("geoip: %s geschrieben (%d bytes raw, %d bytes nach gunzip)",
                 target_name, len(raw), len(body))
        written.append(target_name)

    _spawn_enrichment_restart()
    return {
        "status":  "ok",
        "written": written,
        "message": "enrichment-service wird neu geladen.",
    }
