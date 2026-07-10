"""Regel-Vorschläge für Deny-Hops — reine Anzeige, kein Schreibzugriff.

Output pro Deny-Hop: strukturierte Karte + FortiOS-CLI-Snippet +
FMG-JSON-RPC-Bodies zum Copy-Paste. Die Installation läuft immer über
den FortiManager (Policy & Objects → Install) — der Tracker schreibt nie.
"""
from __future__ import annotations

import json
import re

from engine.verdict import Hop
from inventory.store import Inventory


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)[:60]


def _address_for(inv: Inventory, adom: str, ip: str, names: list[dict]) -> dict:
    existing = inv.find_address_for_ip(adom, ip)
    if existing:
        return {"name": existing["name"], "existing": True}
    hostname = next((n["name"].split(".")[0] for n in names if n.get("name")), None)
    return {
        "name": _safe_name(f"h-{hostname}" if hostname else f"h-{ip}"),
        "existing": False,
        "subnet": f"{ip}/32",
    }


def _service_for(inv: Inventory, adom: str, protocol: str,
                 dst_port: int | None) -> dict:
    proto = protocol.lower()
    if proto == "icmp":
        return {"name": "ALL_ICMP", "existing": True}
    existing = inv.find_service(adom, proto, dst_port)
    if existing:
        return {"name": existing["name"], "existing": True}
    return {
        "name": _safe_name(f"svc-{proto}-{dst_port}"),
        "existing": False,
        "protocol": proto,
        "port": dst_port,
    }


def _render_cli(src_zone: str, dst_zone: str, src_obj: dict, dst_obj: dict,
                service: dict, policy_name: str) -> str:
    lines: list[str] = []
    for obj in (src_obj, dst_obj):
        if not obj["existing"]:
            lines += [
                "config firewall address",
                f'    edit "{obj["name"]}"',
                f"        set subnet {obj['subnet'].replace('/32', ' 255.255.255.255')}",
                "    next",
                "end",
            ]
    if not service["existing"]:
        lines += [
            "config firewall service custom",
            f'    edit "{service["name"]}"',
            f"        set {service['protocol']}-portrange {service['port']}",
            "    next",
            "end",
        ]
    lines += [
        "config firewall policy",
        "    edit 0",
        f'        set name "{policy_name}"',
        f'        set srcintf "{src_zone}"',
        f'        set dstintf "{dst_zone}"',
        f'        set srcaddr "{src_obj["name"]}"',
        f'        set dstaddr "{dst_obj["name"]}"',
        f'        set service "{service["name"]}"',
        "        set action accept",
        "        set schedule always",
        "        set logtraffic all",
        "    next",
        "end",
    ]
    return "\n".join(lines)


def _render_jsonrpc(adom: str, pkg: str | None, src_zone: str, dst_zone: str,
                    src_obj: dict, dst_obj: dict, service: dict,
                    policy_name: str) -> list[dict]:
    bodies: list[dict] = []
    for obj in (src_obj, dst_obj):
        if not obj["existing"]:
            bodies.append({
                "method": "add",
                "params": [{
                    "url": f"/pm/config/adom/{adom}/obj/firewall/address",
                    "data": {"name": obj["name"], "type": "ipmask",
                             "subnet": obj["subnet"]},
                }],
            })
    if not service["existing"]:
        bodies.append({
            "method": "add",
            "params": [{
                "url": f"/pm/config/adom/{adom}/obj/firewall/service/custom",
                "data": {"name": service["name"],
                         "protocol": "TCP/UDP/SCTP",
                         f"{service['protocol']}-portrange": str(service["port"])},
            }],
        })
    pkg_path = pkg or "<policy-package>"
    bodies.append({
        "method": "add",
        "params": [{
            "url": f"/pm/config/adom/{adom}/pkg/{pkg_path}/firewall/policy",
            "data": {
                "name": policy_name,
                "srcintf": [src_zone], "dstintf": [dst_zone],
                "srcaddr": [src_obj["name"]], "dstaddr": [dst_obj["name"]],
                "service": [service["name"]],
                "action": "accept", "schedule": ["always"],
                "status": "enable", "logtraffic": "all",
            },
        }],
    })
    return bodies


def build_suggestion(inv: Inventory, hop: Hop, *, src_ip: str, dst_ip: str,
                     protocol: str, dst_port: int | None,
                     src_names: list[dict], dst_names: list[dict]) -> dict | None:
    if hop.adom is None or hop.egress is None:
        return None
    adom = hop.adom
    src_zone = hop.src_zone or hop.srcintf
    dst_zone = hop.egress_zone or hop.egress
    src_obj = _address_for(inv, adom, src_ip, src_names)
    dst_obj = _address_for(inv, adom, dst_ip, dst_names)
    service = _service_for(inv, adom, protocol, dst_port)
    policy_name = _safe_name(
        f"allow-{src_obj['name']}-to-{dst_obj['name']}-{service['name']}"
    )
    jsonrpc = _render_jsonrpc(adom, inv.pkg_of.get((hop.device, hop.vdom)),
                              src_zone, dst_zone, src_obj, dst_obj, service,
                              policy_name)
    return {
        "device": hop.device, "vdom": hop.vdom, "adom": adom,
        "package": inv.pkg_of.get((hop.device, hop.vdom)),
        "src_zone": src_zone, "dst_zone": dst_zone,
        "src_obj": src_obj, "dst_obj": dst_obj, "service": service,
        "policy_name": policy_name,
        "cli": _render_cli(src_zone, dst_zone, src_obj, dst_obj, service, policy_name),
        "jsonrpc": [json.dumps(b, indent=2, ensure_ascii=False) for b in jsonrpc],
        "note": "Nur Vorschlag — Installation via FortiManager erforderlich. "
                "Der Tracker hat keinen Schreibzugriff.",
    }
