"""
Tap-Update-Bundle-Verwaltung für die Master-UI.

Endpoints:
  GET  /api/tap-update          – Status: aktuelle Bundle-Version + Größe
  POST /api/tap-update/refresh  – ruft scripts/refresh-tap-update.sh auf

Hintergrund: master-uplink serviert /tap-update/<file> (Manifest, Bundle,
Compose, Scripts) für die Tap-Side-CLI `cyjan-tap update --from-master`.
Diese Files leben in /opt/ids/tap-update/ und werden vom Update-ZIP-Import
oder `cyjan-maintenance --refresh-tap-update` befüllt. Der UI-Endpoint
hier triggert dasselbe Helper-Skript.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from deps import require_admin

router = APIRouter(prefix="/api/tap-update", tags=["tap-update"])

IDS_DIR        = Path("/opt/ids")
TAP_UPDATE_DIR = IDS_DIR / "tap-update"
MANIFEST       = TAP_UPDATE_DIR / "manifest.json"
BUNDLE         = TAP_UPDATE_DIR / "images-tap.tar.zst"
REFRESH_SCRIPT = IDS_DIR / "scripts" / "refresh-tap-update.sh"

# In-Memory Lock + Status. Wir wollen nicht zwei parallel laufende
# Refresh-Aufrufe (docker save + zstd ist CPU-/Disk-intensiv) — der
# zweite kriegt 409. Plus der Status wird live gehalten damit die UI
# einen Lauf-Indikator zeigen kann.
_state: dict = {
    "running":     False,
    "started_at":  0.0,
    "finished_at": 0.0,
    "ok":          None,        # bool | None (None = noch nicht gelaufen)
    "log_tail":    [],
}


class TapUpdateStatus(BaseModel):
    bundle_present:    bool
    bundle_size_bytes: int | None
    bundle_size_mb:    float | None
    manifest_version:  str | None
    manifest_created:  str | None
    manifest_sha256:   str | None
    refresh_running:   bool
    refresh_last_ok:   bool | None
    refresh_started:   float
    refresh_finished:  float
    refresh_log_tail:  list[str]


@router.get("", response_model=TapUpdateStatus, dependencies=[Depends(require_admin)])
async def tap_update_status() -> TapUpdateStatus:
    """Aktueller Stand des Tap-Update-Bundles für die UI-Anzeige."""
    bundle_size = None
    if BUNDLE.exists():
        bundle_size = BUNDLE.stat().st_size

    manifest_version = manifest_created = manifest_sha = None
    if MANIFEST.exists():
        try:
            data = json.loads(MANIFEST.read_text())
            manifest_version = data.get("version")
            manifest_created = data.get("created_at")
            manifest_sha     = (data.get("bundle") or {}).get("sha256")
        except Exception:
            pass

    return TapUpdateStatus(
        bundle_present    = BUNDLE.exists(),
        bundle_size_bytes = bundle_size,
        bundle_size_mb    = round(bundle_size / 1024 / 1024, 1) if bundle_size else None,
        manifest_version  = manifest_version,
        manifest_created  = manifest_created,
        manifest_sha256   = manifest_sha,
        refresh_running   = _state["running"],
        refresh_last_ok   = _state["ok"],
        refresh_started   = _state["started_at"],
        refresh_finished  = _state["finished_at"],
        refresh_log_tail  = list(_state["log_tail"][-40:]),
    )


@router.post("/refresh", dependencies=[Depends(require_admin)])
async def trigger_refresh() -> dict:
    """Triggert das Refresh-Skript im Hintergrund. Returnt sofort, der
    UI-Polling-Loop fragt dann tap-update-Status ab bis running=false."""
    if _state["running"]:
        raise HTTPException(409, "Refresh läuft bereits")
    if not REFRESH_SCRIPT.exists():
        raise HTTPException(500, f"Refresh-Skript fehlt: {REFRESH_SCRIPT}")

    _state["running"]    = True
    _state["started_at"] = time.time()
    _state["finished_at"] = 0.0
    _state["ok"]         = None
    _state["log_tail"]   = []

    asyncio.create_task(_run_refresh())
    return {"started": True, "started_at": _state["started_at"]}


async def _run_refresh() -> None:
    """Subprocess-Runner. Schreibt zeilenweise in den log_tail-Buffer
    damit die UI Live-Output zeigen kann."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", str(REFRESH_SCRIPT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(IDS_DIR),
            env={**os.environ, "CYJAN_DIR": str(IDS_DIR)},
        )
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if line:
                _state["log_tail"].append(line)
                # Buffer-Cap, damit log_tail nicht unbegrenzt wächst
                if len(_state["log_tail"]) > 500:
                    _state["log_tail"] = _state["log_tail"][-200:]
        rc = await proc.wait()
        _state["ok"] = (rc == 0)
        if rc != 0:
            _state["log_tail"].append(f"[exit] rc={rc}")
    except Exception as exc:
        _state["ok"] = False
        _state["log_tail"].append(f"[exception] {exc!r}")
    finally:
        _state["running"]    = False
        _state["finished_at"] = time.time()
