"""Offline-Update: ZIP-Upload → Extraktion → docker load (images.tar.gz) oder build.

Fix: docker compose up -d läuft im ids-api-Container. Wenn Compose ids-api
rekonstruiert, killt es sich selbst. Lösung: erst alle anderen Custom-Services
neu starten (--no-deps), dann api per fire-and-forget Popen restarten – der
Docker-Daemon hat die Anfrage schon, bevor er uns per SIGTERM beendet.
"""
from __future__ import annotations

import asyncio
import io
import os
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

router = APIRouter(prefix="/api/system", tags=["update"])

IDS_DIR       = Path("/opt/ids")
_PROTECT      = {".env", ".git"}
_IMAGE_FILES  = {"images.tar.gz", "images.tar"}
_VERSION_FILE = IDS_DIR / "VERSION"

# Custom-Services ohne api – diese werden in einem ersten Pass neu gestartet,
# ohne dass der api-Container (= wir selbst) dabei gekillt wird.
_NON_API_SERVICES = [
    "frontend", "flow-aggregator", "signature-engine", "ml-engine",
    "alert-manager", "enrichment-service", "pcap-store",
    "training-loop", "sniffer", "irma-bridge",
]


def _read_version() -> str:
    try:
        return _VERSION_FILE.read_text().strip()
    except OSError:
        return "unbekannt"


_state: dict[str, Any] = {
    "phase":       "idle",   # idle | extracting | loading | building | done | error
    "log":         [],
    "progress":    0,        # 0-100
    "started_at":  None,
    "finished_at": None,
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(msg: str) -> None:
    _state["log"].append(f"[{_ts()}] {msg}")
    if len(_state["log"]) > 500:
        _state["log"] = _state["log"][-200:]


def _extract(zip_bytes: bytes, dest: Path) -> tuple[int, str | None]:
    """Entpackt ZIP nach dest. Überspringt .env, .git und images.tar[.gz]."""
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(zip_bytes)
        tmp_path = Path(tmp.name)
    images_entry: str | None = None
    try:
        with zipfile.ZipFile(tmp_path, "r") as zf:
            members = zf.namelist()
            if not members:
                raise ValueError("ZIP ist leer")
            prefix = members[0].split("/")[0] + "/"
            count = 0
            for member in members:
                rel = member.removeprefix(prefix)
                if not rel:
                    continue
                parts = rel.split("/")
                if parts[0] in _PROTECT:
                    continue
                if parts[-1] in _IMAGE_FILES:
                    images_entry = member
                    continue
                target = dest / rel
                if member.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    count += 1
        return count, images_entry
    finally:
        tmp_path.unlink(missing_ok=True)


def _unpack_images_to_temp(zip_bytes: bytes, member: str) -> Path:
    """Schreibt images.tar[.gz] aus der ZIP in eine Temp-Datei."""
    suffix = ".tar.gz" if member.endswith(".gz") else ".tar"
    tmp = Path(tempfile.mktemp(suffix=suffix))
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        with zf.open(member) as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return tmp


async def _run_subprocess(
    cmd: list[str],
    on_line: Callable[[str], None] | None = None,
) -> None:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(IDS_DIR),
    )
    assert proc.stdout is not None
    async for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        if line:
            _log(line)
            if on_line:
                on_line(line)
    rc = await proc.wait()
    if rc != 0:
        raise RuntimeError(f"'{' '.join(cmd[:3])} …' beendet mit Code {rc}")


def _fire_and_forget_restart(base_args: list[str]) -> None:
    """Startet 'docker compose restart api' als unabhängigen Prozess.

    Der Docker-Daemon empfängt die Anfrage und führt den Neustart durch,
    auch wenn dieser Container (ids-api) anschließend per SIGTERM/SIGKILL
    gestoppt wird. start_new_session=True schützt den Subprocess vor
    versehentlichem SIGHUP beim Parent-Tod.
    """
    subprocess.Popen(
        base_args + ["restart", "api"],
        start_new_session=True,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ},
    )


async def _run_update(zip_bytes: bytes, pull_images: bool) -> None:
    _state.update({
        "phase":       "extracting",
        "log":         [],
        "progress":    0,
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    })
    try:
        # ── 1. ZIP entpacken (0-10%) ──────────────────────────────────────────
        _log(f"Entpacke ZIP ({len(zip_bytes) // 1024} KB) nach {IDS_DIR} ...")
        count, images_entry = await asyncio.to_thread(_extract, zip_bytes, IDS_DIR)
        _log(f"{count} Dateien entpackt. .env und .git bleiben erhalten.")
        _state["progress"] = 10

        profile_file = Path("/etc/cyjan/profile")
        profile = profile_file.read_text().strip() if profile_file.exists() else "prod"
        _log(f"Compose-Profil: {profile}")

        base_args = [
            "docker", "compose",
            "--project-directory", str(IDS_DIR),
            "--profile", profile,
        ]

        if images_entry:
            # ── 2A. Vorgebaute Images laden (10-80%) ──────────────────────────
            _state["phase"] = "loading"
            img_name = images_entry.split("/")[-1]
            _log(f"Vorgebaute Images gefunden ({img_name}) – lade via docker load ...")
            _state["progress"] = 12

            tmp_img = await asyncio.to_thread(_unpack_images_to_temp, zip_bytes, images_entry)
            try:
                loaded = [0]
                def on_load_line(line: str) -> None:
                    if "Loaded image" in line:
                        loaded[0] += 1
                        _state["progress"] = min(78, 15 + loaded[0] * 6)
                await _run_subprocess(["docker", "load", "-i", str(tmp_img)], on_load_line)
            finally:
                await asyncio.to_thread(tmp_img.unlink, True)

            _log("Images geladen.")
            _state["progress"] = 80

            # ── 3A. Alle Services außer api neu starten (80-95%) ─────────────
            _state["phase"] = "restarting"
            _log("Starte Services neu (außer API) ...")
            await _run_subprocess(
                base_args + ["up", "-d", "--no-deps"] + _NON_API_SERVICES
            )
            _state["progress"] = 95

        else:
            # ── 2B. Aus Quellcode bauen (10-80%) ─────────────────────────────
            _state["phase"] = "building"
            build_cmd = base_args + ["build"]
            if pull_images:
                build_cmd.append("--pull")
                _log("Starte: docker compose build --pull ...")
            else:
                _log("Starte: docker compose build (offline) ...")
            _state["progress"] = 15
            await _run_subprocess(build_cmd)
            _state["progress"] = 80

            # ── 3B. Alle Services außer api neu starten (80-95%) ─────────────
            _state["phase"] = "restarting"
            _log("Starte Services neu (außer API) ...")
            await _run_subprocess(
                base_args + ["up", "-d", "--no-deps"] + _NON_API_SERVICES
            )
            _state["progress"] = 95

        # ── 4. API per fire-and-forget neu starten (95-100%) ──────────────────
        _log("Starte API-Container neu – Verbindung kurz unterbrochen (~10 Sek.) ...")
        _state["phase"]       = "done"
        _state["progress"]    = 100
        _state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _log("Update erfolgreich. Seite nach ~15 Sekunden neu laden.")

        _fire_and_forget_restart(base_args)
        return  # finally setzt finished_at nicht nochmal (schon gesetzt)

    except Exception as exc:  # noqa: BLE001
        _state["phase"] = "error"
        _log(f"FEHLER: {exc}")
    finally:
        if not _state["finished_at"]:
            _state["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/update", summary="Offline-Update via ZIP")
async def start_update(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    pull_images: bool = Form(False),
) -> dict:
    if _state["phase"] not in ("idle", "done", "error"):
        raise HTTPException(409, "Ein Update läuft bereits")
    if not (file.filename or "").endswith(".zip"):
        raise HTTPException(400, "Nur ZIP-Dateien erlaubt")
    zip_bytes = await file.read()
    background_tasks.add_task(_run_update, zip_bytes, pull_images)
    return {"status": "started"}


@router.get("/update/status", summary="Update-Status abfragen")
async def get_update_status() -> dict:
    return {**_state, "version": _read_version()}


@router.get("/version", summary="Installierte Version")
async def get_version() -> dict:
    return {"version": _read_version()}
