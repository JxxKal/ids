"""Egress-Interface-Klassifikation: LOCAL | VDOM_LINK | OVERLAY | DEFAULT.

Entscheidet, wie es nach einem Hop weitergeht. Reihenfolge der Prüfungen:
  1. LOCAL     – connected Subnet des Egress enthält das Ziel → letzter Hop
  2. VDOM_LINK – Egress ist ein vdom-link → nächster Hop = Peer-VDOM, gleiches Gerät
  3. OVERLAY   – Tunnel-/SD-WAN-Interface (Typ oder Name-Pattern) → nächster Hop =
                 Ziel-Site-Firewall via PrefixTable
  4. DEFAULT   – nichts davon → Default-Route Richtung Internet/unbekannt
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from inventory.prefixes import PrefixTable
from inventory.store import Inventory

_TUNNEL_TYPES = {"tunnel", "ipsec", "vdom-link", "npu-vlink"}


@dataclass
class Classification:
    egress_class: str                       # LOCAL | VDOM_LINK | OVERLAY | DEFAULT
    next_device: str | None = None
    next_vdom: str | None = None
    next_srcintf: str | None = None
    warnings: list[str] = field(default_factory=list)


def _is_overlay(intf_info: dict | None, intf_name: str, overlay_re: re.Pattern) -> bool:
    if intf_info and intf_info.get("type") in ("tunnel", "ipsec"):
        return True
    return bool(overlay_re.search(intf_name))


def _remote_overlay_intf(inv: Inventory, device: str, vdom: str,
                         overlay_re: re.Pattern) -> tuple[str | None, list[str]]:
    """Overlay-Interface der Gegenseite (remote srcintf). Heuristik:
    Tunnel-Interfaces des Ziel-(Device,VDOM); bei Mehrdeutigkeit Warning."""
    candidates = sorted(
        name for name, info in (inv.interfaces.get(device) or {}).items()
        if info.get("vdom") == vdom and _is_overlay(info, name, overlay_re)
    )
    if not candidates:
        return None, [f"Kein Overlay-Interface auf {device}/{vdom} gefunden — "
                      "remote srcintf unbekannt."]
    warnings = []
    if len(candidates) > 1:
        warnings.append(
            f"Mehrere Overlay-Interfaces auf {device}/{vdom} "
            f"({', '.join(candidates)}) — nehme '{candidates[0]}'."
        )
    return candidates[0], warnings


def classify_egress(inv: Inventory, prefixes: PrefixTable, overlay_pattern: str,
                    device: str, vdom: str, egress_intf: str,
                    dst_ip: str) -> Classification:
    overlay_re = re.compile(overlay_pattern)
    dst = ipaddress.IPv4Address(dst_ip)
    intf_info = inv.interface(device, egress_intf)

    # 1. LOCAL: connected Subnet des Egress-Interfaces enthält das Ziel
    if intf_info and intf_info.get("ip") is not None and dst in intf_info["ip"].network:
        return Classification(egress_class="LOCAL")

    # 2. VDOM-LINK
    peer = inv.vdom_link_peer(device, egress_intf)
    if peer is not None and (
        (intf_info or {}).get("type") in ("vdom-link", "npu-vlink")
        or _looks_like_vdom_link(egress_intf)
    ):
        peer_intf, peer_vdom = peer
        return Classification(
            egress_class="VDOM_LINK",
            next_device=device, next_vdom=peer_vdom, next_srcintf=peer_intf,
        )

    # 3. OVERLAY: nächste Site-Firewall über die PrefixTable
    if _is_overlay(intf_info, egress_intf, overlay_re):
        cls = Classification(egress_class="OVERLAY")
        entry = prefixes.lookup(dst_ip)
        if entry is None or (entry.device == device and entry.vdom == vdom):
            cls.warnings.append(
                f"Ziel {dst_ip} hinter Overlay '{egress_intf}', aber keine "
                "Ziel-Site in der PrefixTable — Pfad endet hier."
            )
            cls.egress_class = "DEFAULT"
            return cls
        remote_intf, warns = _remote_overlay_intf(inv, entry.device, entry.vdom, overlay_re)
        cls.warnings.extend(warns)
        cls.next_device, cls.next_vdom = entry.device, entry.vdom
        cls.next_srcintf = remote_intf
        return cls

    # 4. DEFAULT
    return Classification(egress_class="DEFAULT")


def _looks_like_vdom_link(name: str) -> bool:
    """ASSUMPTION (Lab): vdom-link-Enden heißen <base>0/<base>1 und enthalten
    typischerweise 'vlink'/'vdlink'. Gegen system/vdom-link verifizieren."""
    return bool(re.search(r"(?i)(vlink|vd-?link|vdom)", name))
