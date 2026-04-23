"""Offline-Update: ZIP-Upload → Extraktion → docker load → compose up.

Kernproblem: docker compose up -d läuft im ids-api-Container. Wenn Compose
ids-api rekonstruiert, killt es sich selbst.

Lösung: Nach docker load einen UNABHÄNGIGEN Einweg-Container starten, der
docker compose up -d ausführt. Dieser Container heißt NICHT ids-api und wird
daher NICHT gekillt, wenn Compose ids-api neustartet. Funktioniert auch wenn
das geladene Image alten Code enthält – der Runner-Container ist ein anderes
Objekt als der ids-api-Service-Container.
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


def _read_version() -> str:
    try:
        return _VERSION_FILE.read_text().strip()
    except OSError:
        return "unbekannt"


_state: dict[str, Any] = {
    "phase":       "idle",
    "log":         [],
    "progress":    0,
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


def _spawn_compose_up_runner(ids_dir: Path, profile: str) -> None:
    """Startet docker compose up -d in einem UNABHÄNGIGEN Einweg-Container.

    Der Container wird via `docker run` gestartet und ist NICHT der
    ids-api-Service-Container. Wenn Compose den ids-api-Service neu startet,
    ist dieser Runner-Container davon unberührt und läuft bis zum Ende.

    Verwendet ids-api:latest als Basis-Image (hat docker-compose-plugin).
    sleep 5 gibt dem aktuellen API-Container Zeit, den "done"-Status zu schreiben
    bevor compose up startet.
    """
    compose_cmd = (
        f"docker compose --project-directory {ids_dir} --profile {profile} up -d"
    )
    subprocess.Popen(
        [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{ids_dir}:{ids_dir}",
            "-w", str(ids_dir),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-update-runner",
            "ids-api:latest",
            "sh", "-c", f"sleep 5 && {compose_cmd}",
        ],
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

        # ── 3. Unabhängigen Runner-Container starten (80-100%) ────────────────
        _state["phase"]       = "restarting"
        _state["progress"]    = 85
        _log("Starte unabhängigen Update-Runner-Container ...")
        _log("Alle Services werden neu gestartet – API-Verbindung kurz unterbrochen (~20 Sek.).")

        # Status jetzt setzen BEVOR der Runner startet und uns killt
        _state["phase"]       = "done"
        _state["progress"]    = 100
        _state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _log("Update abgeschlossen. Seite nach ~20 Sekunden neu laden.")

        _spawn_compose_up_runner(IDS_DIR, profile)
        return  # finally setzt finished_at nicht nochmal

    except Exception as exc:  # noqa: BLE001
        _state["phase"] = "error"
        _log(f"FEHLER: {exc}")
    finally:
        if not _state.get("finished_at"):
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
