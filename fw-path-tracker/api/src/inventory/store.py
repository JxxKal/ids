"""In-Memory-Read-Models aus dem fmg_snapshot (ZoneIndex, PolicyIndex,
ObjectIndex, Interfaces, Routen) + PrefixTable-Builder.

Die FMG-Feldformate variieren je Version (subnet als Liste [ip, maske],
als "ip maske" oder als CIDR; action numerisch oder als String) — alle
Parser hier sind deshalb tolerant.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from typing import Any

from inventory.prefixes import PrefixTable

log = logging.getLogger("inventory.store")


# ── Tolerante Feld-Parser ─────────────────────────────────────────────────────

def parse_subnet(value: Any) -> ipaddress.IPv4Network | None:
    """['10.0.0.0','255.255.255.0'] | '10.0.0.0 255.255.255.0' | '10.0.0.0/24'"""
    try:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return ipaddress.IPv4Network(f"{value[0]}/{value[1]}", strict=False)
        if isinstance(value, str):
            v = value.strip()
            if " " in v:
                ip, mask = v.split()
                return ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            if "/" in v:
                return ipaddress.IPv4Network(v, strict=False)
            return ipaddress.IPv4Network(f"{v}/32")
    except ValueError:
        pass
    return None


def parse_interface_ip(value: Any) -> ipaddress.IPv4Interface | None:
    """['10.1.1.1','255.255.255.0'] | '10.1.1.1 255.255.255.0' | '10.1.1.1/24'"""
    try:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            iface = ipaddress.IPv4Interface(f"{value[0]}/{value[1]}")
        elif isinstance(value, str) and value.strip():
            v = value.strip().replace(" ", "/")
            iface = ipaddress.IPv4Interface(v)
        else:
            return None
        if iface.ip == ipaddress.IPv4Address("0.0.0.0"):
            return None
        return iface
    except ValueError:
        return None


def action_str(value: Any) -> str:
    mapping = {0: "deny", 1: "accept", 2: "ipsec", "0": "deny", "1": "accept"}
    if isinstance(value, str) and value in ("deny", "accept", "ipsec"):
        return value
    return mapping.get(value, "deny")


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first(value: Any) -> Any:
    lst = _as_list(value)
    return lst[0] if lst else None


class Inventory:
    """Read-Models über alle ADOMs. Immutable nach build() — bei Sync wird
    eine neue Instanz gebaut und atomar getauscht (app.state.inventory)."""

    def __init__(self) -> None:
        self.synced_at: str | None = None
        self.adoms: list[str] = []
        # device → {adom, vdoms:[...], data}
        self.devices: dict[str, dict] = {}
        # device → {intf_name: {ip, vdom, type, name}}
        self.interfaces: dict[str, dict[str, dict]] = {}
        # (device, vdom) → [ {policyid, name, action, srcintf, dstintf,
        #                     srcaddr, dstaddr, service, status, comments} ]
        self.policies: dict[tuple[str, str], list[dict]] = {}
        # (device, vdom) → {zone_name: [member-intfs]}
        self.zones: dict[tuple[str, str], dict[str, list[str]]] = {}
        # adom → {name: address-data}
        self.addresses: dict[str, dict[str, dict]] = {}
        self.addrgrps: dict[str, dict[str, dict]] = {}
        self.services: dict[str, dict[str, dict]] = {}
        self.servicegrps: dict[str, dict[str, dict]] = {}
        self.vips: dict[str, dict[str, dict]] = {}
        # (device, vdom) → [ {network, interface, gateway} ]
        self.static_routes: dict[tuple[str, str], list[dict]] = {}
        # (device, vdom) → Package-Pfad (für Regel-Vorschläge)
        self.pkg_of: dict[tuple[str, str], str] = {}

    # ── Aufbau aus Snapshot-Zeilen ────────────────────────────────────────────

    @classmethod
    def build(cls, rows: list[dict], synced_at: str | None = None) -> "Inventory":
        inv = cls()
        inv.synced_at = synced_at
        by_kind: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_kind[r["kind"]].append(r)
        inv.adoms = sorted({r["adom"] for r in rows})

        for r in by_kind.get("device", []):
            data = r["data"]
            name = data.get("name") or r["key"]
            vdoms = [v.get("name") for v in _as_list(data.get("vdom")) if v.get("name")]
            inv.devices[name] = {"adom": r["adom"], "vdoms": vdoms or ["root"], "data": data}

        for r in by_kind.get("interface", []):
            device = r["key"]
            table: dict[str, dict] = {}
            for intf in _as_list(r["data"]):
                iname = intf.get("name")
                if not iname:
                    continue
                table[iname] = {
                    "name": iname,
                    "ip": parse_interface_ip(intf.get("ip")),
                    "vdom": _first(intf.get("vdom")) or "root",
                    "type": intf.get("type"),
                }
            inv.interfaces[device] = table

        # Zonen: obj/dynamic/interface mit per-Device-Mapping
        for r in by_kind.get("zone", []):
            zname = r["data"].get("name") or r["key"]
            for mapping in _as_list(r["data"].get("dynamic_mapping")):
                members = [m for m in _as_list(mapping.get("local-intf")) if m]
                for scope in _as_list(mapping.get("_scope")):
                    dev, vdom = scope.get("name"), scope.get("vdom") or "root"
                    if dev:
                        inv.zones.setdefault((dev, vdom), {})[zname] = members

        # Packages → Scope, Policies → (device, vdom)
        pkg_scope: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for r in by_kind.get("package", []):
            scope = [
                (s.get("name"), s.get("vdom") or "root")
                for s in _as_list(r["data"].get("scope member"))
                if s.get("name")
            ]
            pkg_scope[(r["adom"], r["key"])] = scope
        for r in by_kind.get("policy", []):
            normalized = [inv._normalize_policy(p) for p in _as_list(r["data"])]
            for dev_vdom in pkg_scope.get((r["adom"], r["key"]), []):
                inv.policies[dev_vdom] = normalized
                inv.pkg_of[dev_vdom] = r["key"]

        for kind, target in (("address", inv.addresses), ("addrgrp", inv.addrgrps),
                             ("service", inv.services), ("servicegrp", inv.servicegrps),
                             ("vip", inv.vips)):
            for r in by_kind.get(kind, []):
                name = r["data"].get("name") or r["key"]
                target.setdefault(r["adom"], {})[name] = r["data"]

        for r in by_kind.get("route", []):
            device, _, vdom = r["key"].partition("|")
            routes = []
            for rt in _as_list(r["data"]):
                net = parse_subnet(rt.get("dst"))
                if net is None:
                    net = ipaddress.IPv4Network("0.0.0.0/0")
                routes.append({
                    "network": net,
                    "interface": _first(rt.get("device")),
                    "gateway": rt.get("gateway"),
                })
            inv.static_routes[(device, vdom or "root")] = routes

        return inv

    @staticmethod
    def _normalize_policy(p: dict) -> dict:
        return {
            "policyid": p.get("policyid"),
            "name": p.get("name") or "",
            "action": action_str(p.get("action")),
            "status": "enable" if p.get("status") in (1, "1", "enable", None) else "disable",
            "srcintf": _as_list(p.get("srcintf")),
            "dstintf": _as_list(p.get("dstintf")),
            "srcaddr": _as_list(p.get("srcaddr")),
            "dstaddr": _as_list(p.get("dstaddr")),
            "service": _as_list(p.get("service")),
            "comments": p.get("comments") or "",
        }

    # ── Abfragen ──────────────────────────────────────────────────────────────

    def adom_of(self, device: str) -> str | None:
        d = self.devices.get(device)
        return d["adom"] if d else None

    def connected_networks(self, device: str, vdom: str) -> list[tuple[ipaddress.IPv4Network, str]]:
        out = []
        for intf in (self.interfaces.get(device) or {}).values():
            if intf["vdom"] != vdom or intf["ip"] is None:
                continue
            out.append((intf["ip"].network, intf["name"]))
        return out

    def interface(self, device: str, name: str) -> dict | None:
        return (self.interfaces.get(device) or {}).get(name)

    def zone_of(self, device: str, vdom: str, intf: str) -> str:
        """Zone, die das Interface enthält — sonst das Interface selbst."""
        for zname, members in (self.zones.get((device, vdom)) or {}).items():
            if intf in members:
                return zname
        return intf

    def vdom_link_peer(self, device: str, intf_name: str) -> tuple[str, str] | None:
        """Peer-Interface/VDOM eines vdom-links.

        ASSUMPTION (Lab): Namenskonvention <base>0/<base>1 für die beiden
        Enden; Interface-Typ 'vdom-link' bzw. npu-vlink. Verifizieren gegen
        system/vdom-link in der Device-DB.
        """
        table = self.interfaces.get(device) or {}
        me = table.get(intf_name)
        if not me:
            return None
        m = re.match(r"^(.*?)([01])$", intf_name)
        if not m:
            return None
        base, side = m.group(1), m.group(2)
        peer_name = base + ("1" if side == "0" else "0")
        peer = table.get(peer_name)
        if peer is None or peer["vdom"] == me["vdom"]:
            return None
        return peer_name, peer["vdom"]

    def find_address_for_ip(self, adom: str, ip: str) -> dict | None:
        """Engstes Adress-Objekt (type subnet/ipmask), das die IP enthält."""
        addr = ipaddress.IPv4Address(ip)
        best: tuple[int, dict] | None = None
        for obj in (self.addresses.get(adom) or {}).values():
            net = parse_subnet(obj.get("subnet"))
            if net is None or addr not in net:
                continue
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, obj)
        return best[1] if best else None

    def find_service(self, adom: str, protocol: str, port: int | None) -> dict | None:
        """Service-Objekt für Proto+Port (exakter Einzelport bevorzugt)."""
        proto = protocol.lower()
        field = {"tcp": "tcp-portrange", "udp": "udp-portrange"}.get(proto)
        if field is None or port is None:
            return None
        candidates = []
        for obj in (self.services.get(adom) or {}).values():
            for pr in _as_list(obj.get(field)):
                pr = str(pr).split(":")[0]  # "dst:src" → dst-Teil
                lo, _, hi = pr.partition("-")
                try:
                    lo_i = int(lo)
                    hi_i = int(hi) if hi else lo_i
                except ValueError:
                    continue
                if lo_i <= port <= hi_i:
                    candidates.append((hi_i - lo_i, obj))
        candidates.sort(key=lambda c: c[0])
        return candidates[0][1] if candidates else None

    def vip_for(self, adom: str, ip: str) -> dict | None:
        for obj in (self.vips.get(adom) or {}).values():
            extip = str(obj.get("extip") or "")
            for part in extip.split("-")[:1]:  # Ranges: nur Startadresse prüfen
                if part.strip() == ip:
                    return obj
        return None

    def candidate_policies(self, device: str, vdom: str, srcintf: str, dstintf: str) -> list[dict]:
        """Geordnete Policies, deren srcintf/dstintf-Zonen zum Hop passen."""
        src_zone = self.zone_of(device, vdom, srcintf)
        dst_zone = self.zone_of(device, vdom, dstintf)
        out = []
        for p in self.policies.get((device, vdom), []):
            if p["status"] != "enable":
                continue
            src_ok = any(z in ("any", srcintf, src_zone) for z in p["srcintf"]) or not p["srcintf"]
            dst_ok = any(z in ("any", dstintf, dst_zone) for z in p["dstintf"]) or not p["dstintf"]
            if src_ok and dst_ok:
                out.append(p)
        return out

    def object_names(self, adom: str) -> list[dict]:
        """Namensindex für Autocomplete: Adress-Objekte mit /32-Subnet o. FQDN."""
        out = []
        for name, obj in (self.addresses.get(adom) or {}).items():
            net = parse_subnet(obj.get("subnet"))
            ip = str(net.network_address) if net and net.prefixlen == 32 else None
            fqdn = obj.get("fqdn")
            if ip or fqdn:
                out.append({"name": name, "ip": ip, "fqdn": fqdn, "adom": adom})
        return out

    def build_prefix_table(self, site_overrides: list[dict] | None = None) -> PrefixTable:
        table = PrefixTable()
        for override in site_overrides or []:
            try:
                table.add(override["cidr"], "override", override["device"],
                          override.get("vdom", "root"),
                          site_name=override.get("name"))
            except (KeyError, ValueError) as exc:
                log.warning("Site-Override ungültig (%s): %s", override, exc)
        for device, info in self.devices.items():
            adom = info["adom"]
            for vdom in info["vdoms"]:
                for net, intf in self.connected_networks(device, vdom):
                    table.add(net, "connected", device, vdom, intf, adom)
                for rt in self.static_routes.get((device, vdom), []):
                    table.add(rt["network"], "static", device, vdom,
                              rt["interface"], adom)
        return table

    def summary(self) -> dict:
        return {
            "synced_at": self.synced_at,
            "adoms": self.adoms,
            "devices": {
                name: {"adom": d["adom"], "vdoms": d["vdoms"]}
                for name, d in sorted(self.devices.items())
            },
            "counts": {
                "policies": sum(len(v) for v in self.policies.values()),
                "addresses": sum(len(v) for v in self.addresses.values()),
                "services": sum(len(v) for v in self.services.values()),
                "vips": sum(len(v) for v in self.vips.values()),
                "zones": sum(len(v) for v in self.zones.values()),
            },
        }
