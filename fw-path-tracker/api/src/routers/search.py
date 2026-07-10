"""Autocomplete-Suche + explizite Namensauflösung."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from deps import get_current_user
from routers.config import read_config

router = APIRouter(prefix="/api", tags=["search"])


@router.get("/search")
async def search(
    request: Request,
    q: str = Query(min_length=2, max_length=128),
    _user: dict = Depends(get_current_user),
) -> list[dict]:
    state = request.app.state
    itop_cfg = await read_config("itop")
    return await state.resolver.search(q, state.inventory, itop_cfg)


class ResolveRequest(BaseModel):
    value: str


@router.post("/resolve")
async def resolve(
    body: ResolveRequest, request: Request, _user: dict = Depends(get_current_user)
) -> dict:
    state = request.app.state
    itop_cfg = await read_config("itop")
    dns_cfg = await read_config("dns")
    try:
        return await state.resolver.resolve_endpoint(
            body.value, state.inventory, itop_cfg, dns_cfg
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
