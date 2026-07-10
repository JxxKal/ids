"""iTop-Verbindungstest (Settings-Panel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from routers.config import read_config

router = APIRouter(prefix="/api/itop", tags=["itop"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    try:
        return await request.app.state.resolver.itop.test(cfg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc
