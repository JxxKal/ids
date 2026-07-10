"""Helper für FortiOS-Monitor-Aufrufe via exec /sys/proxy/json.

Die VDOM-Auswahl läuft über den Querystring der resource (verifiziert),
nicht über das target. Antwort-Envelope: result[0].data = Liste von
{target, status{code,message}, response} — response ist das rohe
FortiOS-Envelope ({"results": ..., "status": "success", ...}).
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from fmg.client import FmgClient, FmgError, FmgTargetOffline

log = logging.getLogger("fmg.proxy")

PROXY_TIMEOUT_S = 20


def build_monitor_request(adom: str, device: str, vdom: str, path: str,
                          params: dict[str, Any] | None = None) -> dict:
    qs = urlencode({"vdom": vdom, **(params or {})})
    return {
        "action": "get",
        "resource": f"/api/v2/monitor/{path.lstrip('/')}?{qs}",
        "target": [f"adom/{adom}/device/{device}"],
        "timeout": PROXY_TIMEOUT_S,
    }


def _unwrap(device: str, data: Any) -> Any:
    """result[0].data → FortiOS-response des (einzigen) Targets."""
    entries = data if isinstance(data, list) else [data] if data else []
    if not entries:
        raise FmgTargetOffline(f"Gerät {device}: leere Proxy-Antwort.")
    entry = entries[0] or {}
    status = entry.get("status") or {}
    if status.get("code", 0) != 0:
        message = status.get("message", "")
        low = message.lower()
        if any(w in low for w in ("offline", "unreachable", "timeout", "timed out",
                                  "no route", "connect", "down")):
            raise FmgTargetOffline(f"Gerät {device} nicht erreichbar: {message}")
        raise FmgError(f"Proxy-Fehler an {device}: {message}", status.get("code"))
    return entry.get("response")


async def monitor_get(client: FmgClient, adom: str, device: str, vdom: str,
                      path: str, params: dict[str, Any] | None = None) -> Any:
    req = build_monitor_request(adom, device, vdom, path, params)
    data = await client.rpc("exec", "/sys/proxy/json", req)
    return _unwrap(device, data)


def fortios_results(response: Any) -> Any:
    """FortiOS-Monitor-Envelope tolerant entpacken.

    ASSUMPTION (Lab): Envelope-Form variiert je FortiOS-Version —
    {"results": {...}} ist die dokumentierte Form; einzelne Builds liefern
    das Ergebnis flach. Wir nehmen 'results' wenn vorhanden, sonst das
    Objekt selbst.
    """
    if isinstance(response, dict) and "results" in response:
        return response["results"]
    return response
