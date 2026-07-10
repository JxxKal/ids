"""Helper zum programmatischen Registrieren von FMG-Proxy-Fixtures.

Baut Request-Payloads mit denselben Buildern wie der echte Code
(build_monitor_request), damit die Fixture-Keys deterministisch matchen —
Lab-Mitschnitte (RecordingTransport) landen im selben Format.
"""
from __future__ import annotations

from fmg.proxy import build_monitor_request
from fmg.transport import FixtureTransport

ADOM = "corp"


def proxy_request(device: str, vdom: str, path: str, params: dict) -> dict:
    return {
        "method": "exec",
        "params": [{
            "url": "/sys/proxy/json",
            "data": build_monitor_request(ADOM, device, vdom, path, params),
        }],
    }


def proxy_ok(device: str, results) -> dict:
    """Transport-Level-Antwort: FMG-Envelope → Proxy-Target → FortiOS-Envelope."""
    return {
        "result": [{
            "status": {"code": 0, "message": "OK"},
            "data": [{
                "target": device,
                "status": {"code": 0, "message": "OK"},
                "response": {"status": "success", "results": results},
            }],
        }],
    }


def proxy_offline(device: str) -> dict:
    return {
        "result": [{
            "status": {"code": 0, "message": "OK"},
            "data": [{
                "target": device,
                "status": {"code": -8, "message": "device is offline / unreachable"},
                "response": None,
            }],
        }],
    }


def add_route(t: FixtureTransport, device: str, vdom: str, dst: str,
              interface: str | None, offline: bool = False) -> None:
    req = proxy_request(device, vdom, "router/lookup", {"destination": dst})
    if offline:
        t.add(req, proxy_offline(device))
    elif interface is None:
        t.add(req, proxy_ok(device, {}))
    else:
        t.add(req, proxy_ok(device, {"interface": interface, "gateway": "0.0.0.0"}))


def add_policy_lookup(t: FixtureTransport, device: str, vdom: str, params: dict,
                      policy_id: int | None, offline: bool = False) -> None:
    req = proxy_request(device, vdom, "firewall/policy-lookup", params)
    if offline:
        t.add(req, proxy_offline(device))
    elif policy_id is None:
        t.add(req, proxy_ok(device, {"success": False}))
    else:
        t.add(req, proxy_ok(device, {"success": True, "policy_id": policy_id}))


def tcp_params(srcintf: str, src: str, dst: str, port: int) -> dict:
    return {"srcintf": srcintf, "sourceip": src, "dest": dst,
            "protocol": "tcp", "destport": port}
