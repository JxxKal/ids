"""Verdichtet die DB-Aggregationen zu einem Per-Host-Profil, das der
matcher direkt gegen den Katalog auswertet.

Pro Host: Set servierter (port, proto)-Paare mit Flow-Count, Mode-MAC (+ OUI-
Präfix) und ob er langlebiger Responder ist (long_lived).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from db import Db

log = logging.getLogger(__name__)


@dataclass
class HostProfile:
    ip: str
    # {(port, proto): flow_count} — proto wie in flows.proto (TCP|UDP|ICMP|…).
    served: dict[tuple[int, str], int] = field(default_factory=dict)
    mode_mac: str | None = None       # Original-Format, z.B. 'aa:bb:cc:dd:ee:ff'
    oui: str | None = None            # erste 3 Oktette, normalisiert 'AABBCC'
    long_lived: bool = False
    total_flows: int = 0


def _norm_oui(mac: str) -> str | None:
    """'aa:bb:cc:dd:ee:ff' → 'AABBCC' (erste 3 Oktette). None bei Müll."""
    hexed = "".join(c for c in mac if c.isalnum()).upper()
    return hexed[:6] if len(hexed) >= 6 else None


async def build_profiles(
    db: "Db", window_days: int, min_flows_per_port: int, long_lived_min_days: float,
) -> dict[str, HostProfile]:
    """Baut die HostProfiles aus den drei DB-Aggregationen. Hosts ohne
    servierte Ports tauchen nicht auf — wir bewerten nur Responder."""
    served = await db.served_ports(window_days, min_flows_per_port)
    macs = await db.mode_macs(window_days)
    first_seen = await db.host_first_seen(window_days)

    now = datetime.now(timezone.utc)
    profiles: dict[str, HostProfile] = {}
    for host, ports in served.items():
        prof = HostProfile(ip=host, served=dict(ports))
        prof.total_flows = sum(ports.values())
        mac = macs.get(host)
        if mac:
            prof.mode_mac = mac
            prof.oui = _norm_oui(mac)
        fs = first_seen.get(host)
        if fs is not None:
            age_days = (now - fs).total_seconds() / 86400.0
            prof.long_lived = age_days >= long_lived_min_days
        profiles[host] = prof

    log.info(
        "Aggregation: %d Hosts mit servierten Ports (Fenster %dd, min_flows≥%d)",
        len(profiles), window_days, min_flows_per_port,
    )
    return profiles
