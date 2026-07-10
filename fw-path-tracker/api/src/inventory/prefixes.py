"""PrefixTable: Longest-Prefix-Match über alle (Device, VDOM).

Quellen: connected Networks + statische Routen aus dem FMG-Snapshot, plus
manuelle Site-Overrides aus system_config['sites']. Kodiert implizit das
Site-/20 → Firewall-Mapping. Default-Routen (/0) gehören NICHT hierher —
sie werden in der Path-Engine als Egress-Klasse DEFAULT behandelt.

Priorität bei gleicher Prefix-Länge: override > connected > static.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

_SOURCE_PRIO = {"override": 0, "connected": 1, "static": 2}


@dataclass(frozen=True)
class PrefixEntry:
    network: ipaddress.IPv4Network
    source: str          # override | connected | static
    device: str
    vdom: str
    interface: str | None
    adom: str | None = None
    site_name: str | None = None


@dataclass
class PrefixTable:
    entries: list[PrefixEntry] = field(default_factory=list)

    def add(self, network: ipaddress.IPv4Network | str, source: str, device: str,
            vdom: str, interface: str | None = None, adom: str | None = None,
            site_name: str | None = None) -> None:
        if source not in _SOURCE_PRIO:
            raise ValueError(f"Unbekannte Quelle: {source}")
        net = ipaddress.IPv4Network(network) if isinstance(network, str) else network
        if net.prefixlen == 0:
            return  # Default-Routen sind Sache der DEFAULT-Klassifikation
        self.entries.append(PrefixEntry(
            network=net, source=source, device=device, vdom=vdom,
            interface=interface, adom=adom, site_name=site_name,
        ))

    def lookup(self, ip: str | ipaddress.IPv4Address) -> PrefixEntry | None:
        addr = ipaddress.IPv4Address(ip) if isinstance(ip, str) else ip
        matches = [e for e in self.entries if addr in e.network]
        if not matches:
            return None
        matches.sort(key=lambda e: (-e.network.prefixlen, _SOURCE_PRIO[e.source]))
        return matches[0]

    def lookup_all(self, ip: str | ipaddress.IPv4Address) -> list[PrefixEntry]:
        addr = ipaddress.IPv4Address(ip) if isinstance(ip, str) else ip
        matches = [e for e in self.entries if addr in e.network]
        matches.sort(key=lambda e: (-e.network.prefixlen, _SOURCE_PRIO[e.source]))
        return matches
