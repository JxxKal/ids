"""Resolver-Quelle 1: FortiManager-Adress-Objekte (aus dem Inventory-Cache)."""
from __future__ import annotations

from inventory.store import Inventory, parse_subnet


def resolve_name(inv: Inventory, name: str) -> dict | None:
    """Objektname → IP (nur /32-Subnets sind eindeutig)."""
    needle = name.strip().lower()
    for adom, objs in inv.addresses.items():
        for oname, obj in objs.items():
            if oname.lower() != needle:
                continue
            net = parse_subnet(obj.get("subnet"))
            if net and net.prefixlen == 32:
                return {"ip": str(net.network_address), "name": oname,
                        "provenance": "fmg", "adom": adom}
    return None


def resolve_ip(inv: Inventory, ip: str) -> dict | None:
    """IP → Objektname (exaktes /32-Objekt)."""
    for adom, objs in inv.addresses.items():
        for oname, obj in objs.items():
            net = parse_subnet(obj.get("subnet"))
            if net and net.prefixlen == 32 and str(net.network_address) == ip:
                return {"name": oname, "provenance": "fmg", "adom": adom}
    return None


def search(inv: Inventory, q: str, limit: int = 10) -> list[dict]:
    needle = q.strip().lower()
    out = []
    for adom in inv.adoms:
        for entry in inv.object_names(adom):
            if needle in entry["name"].lower():
                out.append({**entry, "provenance": "fmg"})
                if len(out) >= limit:
                    return out
    return out
