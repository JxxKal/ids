"""Offline-Update: ZIP-Upload → Extraktion → docker load (images.tar.gz) oder build."""
from __future__ import annotations

import asyncio
import io
import shutil
import tempfile
import zipfile
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
    "phase": "idle",   # idle | extracting | building | done | error
    "log": [],
    "started_at": None,
    "finished_at": None,
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(msg: str) -> None:
    _state["log"].append(f"[{_ts()}] {msg}")
    if len(_state["log"]) > 500:
        _state["log"] = _state["log"][-200:]


def _extract(zip_bytes: bytes, dest: Path) -> tuple[int, str | None]:
    """Entpackt ZIP nach dest. Überspringt .env, .git und images.tar[.gz].
    Gibt (Dateianzahl, Member-Name der Image-Datei oder None) zurück."""
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(zip_bytes)
        tmp_path = Path(tmp.name)
    images_entry: str | None = None
    try:
        with zipfile.ZipFile(tmp_path, "r") as zf:
            members = zf.namelist()
            if not members:
                raise ValueError("ZIP ist leer")
            # GitHub-ZIP hat Top-Level-Dir z.B. ids-main/
            prefix = members[0].split("/")[0] + "/"
            count = 0
            for member in members:
                rel = member.removeprefix(prefix)
                if not rel:
                    continue
                parts = rel.split("/")
                if parts[0] in _PROTECT:
                    continue
                # Image-Tar merken, aber nicht auf Disk entpacken
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
    """Schreibt images.tar[.gz] aus der ZIP in eine Temp-Datei. Caller muss unlink."""
    suffix = ".tar.gz" if member.endswith(".gz") else ".tar"
    tmp = Path(tempfile.mktemp(suffix=suffix))
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        with zf.open(member) as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return tmp


async def _run_subprocess(cmd: list[str]) -> None:
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
    rc = await proc.wait()
    if rc != 0:
        raise RuntimeError(f"'{' '.join(cmd[:3])} …' beendet mit Code {rc}")


async def _run_update(zip_bytes: bytes, pull_images: bool) -> None:
    _state.update({
        "phase": "extracting",
        "log": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    })
    try:
        _log(f"Entpacke ZIP ({len(zip_bytes) // 1024} KB) nach {IDS_DIR} ...")
        count, images_entry = await asyncio.to_thread(_extract, zip_bytes, IDS_DIR)
        _log(f"{count} Dateien entpackt. .env und .git bleiben erhalten.")

        profile_file = Path("/etc/cyjan/profile")
        profile = profile_file.read_text().strip() if profile_file.exists() else "prod"
        _log(f"Compose-Profil: {profile}")

        _state["phase"] = "building"
        base_args = [
            "docker", "compose",
            "--project-directory", str(IDS_DIR),
            "--profile", profile,
        ]

        if images_entry:
            # ── Pfad A: vorgebaute Images laden (kein apt/pip/npm, kein Internet) ──
            img_name = images_entry.split("/")[-1]
            _log(f"Vorgebaute Images gefunden ({img_name}) – lade via docker load ...")
            tmp_img = await asyncio.to_thread(_unpack_images_to_temp, zip_bytes, images_entry)
            try:
                await _run_subprocess(["docker", "load", "-i", str(tmp_img)])
            finally:
                await asyncio.to_thread(tmp_img.unlink, True)
            _log("Images geladen. Starte Container neu ...")
            await _run_subprocess(base_args + ["up", "-d"])
        else:
            # ── Pfad B: aus Quellcode bauen (Fallback / Quell-ZIP) ──
            build_cmd = base_args + ["build"]
            if pull_images:
                build_cmd.append("--pull")
                _log("Starte: docker compose build --pull (mit Basis-Image-Update) ...")
            else:
                _log("Starte: docker compose build (offline-sicher, kein --pull) ...")
            await _run_subprocess(build_cmd)
            _log("Starte: docker compose up -d ...")
            await _run_subprocess(base_args + ["up", "-d"])

        _state["phase"] = "done"
        _log("Update erfolgreich abgeschlossen.")

    except Exception as exc:  # noqa: BLE001
        _state["phase"] = "error"
        _log(f"FEHLER: {exc}")
    finally:
        _state["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/update", summary="Offline-Update via ZIP")
async def start_update(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Update-ZIP (mit images.tar.gz) oder Quell-ZIP"),
    pull_images: bool = Form(False, description="Basis-Images pullen – nur für Quell-ZIP mit Internet"),
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
