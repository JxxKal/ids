"""
Self-Traffic-Filter: verwirft Alerts die von der Appliance selbst
stammen (Mgmt-Interface generiert Traffic durch Updates, DNS-Lookups,
SSH, enrichment-Pings, etc. — das ist kein Security-Event).

Konfiguration:
  IDS_SELF_IPS=192.168.1.230,172.28.0.0/16   # kommagetrennt
    - einzelne IPs (werden als /32 behandelt)
    - CIDR-Blöcke (z.B. 172.28.0.0/16 für Docker-Bridge)

Matcht wenn src_ip ODER dst_ip in einer der konfigurierten Ranges liegt.
"""
from __future__ import annotations

import logging
import os
from ipaddress import ip_address, ip_network
from typing import Iterable

log = logging.getLogger(__name__)


def _parse_self_nets(raw: str) -> list:
    """Parst die Komma-Liste in ip_network-Objekte."""
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            # strict=False erlaubt Einzel-IPs ohne /32 sowie ungewöhnliche Hostbits
            nets.append(ip_network(part, strict=False))
        except ValueError as exc:
            log.warning("Self-Filter: ungültige IP/CIDR '%s' ignoriert (%s)", part, exc)
    return nets


class SelfFilter:
    def __init__(self, raw_config: str | None = None) -> None:
        cfg = raw_config if raw_config is not None else os.environ.get("IDS_SELF_IPS", "")
        self._nets = _parse_self_nets(cfg)
        if self._nets:
            log.info(
                "Self-Filter aktiv: %d Range(s) — %s",
                len(self._nets),
                ", ".join(str(n) for n in self._nets),
            )
        else:
            log.info("Self-Filter: keine Ranges konfiguriert (IDS_SELF_IPS leer)")

    def is_self(self, ip_str: str | None) -> bool:
        if not ip_str or not self._nets:
            return False
        try:
            # Einige Alerts liefern "192.168.1.1/32" — defensiv den Suffix abschneiden
            clean = ip_str.split("/")[0]
            ip = ip_address(clean)
            return any(ip in net for net in self._nets)
        except ValueError:
            return False

    def should_drop(self, src_ip: str | None, dst_ip: str | None) -> bool:
        """True wenn Alert verworfen werden soll (Self-Traffic)."""
        return self.is_self(src_ip) or self.is_self(dst_ip)

    @property
    def ranges(self) -> Iterable:
        return tuple(self._nets)
