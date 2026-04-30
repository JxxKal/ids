"""
Self-Traffic-Filter: verwirft Alerts die von der Appliance selbst
stammen (Mgmt-Interface generiert Traffic durch Updates, DNS-Lookups,
SSH, enrichment-Pings, etc. — das ist kein Security-Event).

Drei Kategorien — wichtig bei Single-NIC-Setups (Management = Sniffer
auf demselben Interface):

1. **Loopback + Docker-Bridge** (`IDS_SELF_LOOPBACK_IPS`):
   beide Endpunkte sind per Definition intern. Wir droppen sobald
   src_ip ODER dst_ip in einer dieser Ranges liegt. Default
   `127.0.0.0/8,172.28.0.0/16`.

2. **Management-IP** (`IDS_SELF_OUTBOUND_IPS`):
   Wir droppen NUR wenn die Appliance der *Sender* ist (src_ip in
   dieser Range). Eingehende Verbindungen *zu* der Mgmt-IP kommen
   durch — sonst werden Angriffe gegen die Appliance selbst (z.B.
   nmap auf 192.168.1.230) wegfiltert. Default = `MANAGEMENT_IP`
   aus der .env.

3. **Legacy** (`IDS_SELF_IPS`):
   wird zusätzlich beidseitig gematcht — für Bestandsdeployments,
   die noch die alte symmetrische Semantik benutzen. Neue Installs
   sollten die zwei spezifischeren Variablen oben nutzen.

Beispiel .env (Single-NIC-Master, der Hostname auflöst auf 192.168.1.230):
  IDS_SELF_LOOPBACK_IPS=127.0.0.0/8,172.28.0.0/16
  IDS_SELF_OUTBOUND_IPS=192.168.1.230
  # IDS_SELF_IPS=  (leer/unset — die beiden oberen ersetzen es)
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
    def __init__(
        self,
        raw_loopback: str | None = None,
        raw_outbound: str | None = None,
        raw_legacy: str | None = None,
    ) -> None:
        # Konfig-Reihenfolge: explizite Argumente > Env > Default. Loopback +
        # Docker-Bridge müssen für Master-Setups immer gefiltert werden, sonst
        # rauschen Container-zu-Container-Flows ungebremst durch den Stack.
        if raw_loopback is None:
            raw_loopback = os.environ.get(
                "IDS_SELF_LOOPBACK_IPS",
                "127.0.0.0/8,172.28.0.0/16",
            )
        if raw_outbound is None:
            raw_outbound = os.environ.get("IDS_SELF_OUTBOUND_IPS", "")
        if raw_legacy is None:
            raw_legacy = os.environ.get("IDS_SELF_IPS", "")

        self._loopback_nets = _parse_self_nets(raw_loopback)
        self._outbound_nets = _parse_self_nets(raw_outbound)
        self._legacy_nets   = _parse_self_nets(raw_legacy)

        log.info(
            "Self-Filter aktiv: loopback=%d range(s), outbound-only=%d range(s), legacy=%d range(s)",
            len(self._loopback_nets), len(self._outbound_nets), len(self._legacy_nets),
        )
        if self._loopback_nets:
            log.info("  loopback: %s", ", ".join(str(n) for n in self._loopback_nets))
        if self._outbound_nets:
            log.info("  outbound-only: %s — eingehende Verbindungen kommen durch",
                     ", ".join(str(n) for n in self._outbound_nets))
        if self._legacy_nets:
            log.info("  legacy (beidseitig): %s — IDS_SELF_IPS gesetzt",
                     ", ".join(str(n) for n in self._legacy_nets))

    @staticmethod
    def _ip_in_nets(ip_str: str | None, nets: list) -> bool:
        if not ip_str or not nets:
            return False
        try:
            # Einige Alerts liefern "192.168.1.1/32" — defensiv den Suffix abschneiden
            clean = ip_str.split("/")[0]
            ip = ip_address(clean)
            return any(ip in net for net in nets)
        except ValueError:
            return False

    def is_self(self, ip_str: str | None) -> bool:
        """Backwards-compat-Helper: True wenn IP in irgendeiner Range
        (loopback, outbound oder legacy). Test-Code benutzt das; die
        produktive should_drop-Logik unterscheidet zwischen Richtungen."""
        return (
            self._ip_in_nets(ip_str, self._loopback_nets)
            or self._ip_in_nets(ip_str, self._outbound_nets)
            or self._ip_in_nets(ip_str, self._legacy_nets)
        )

    def should_drop(self, src_ip: str | None, dst_ip: str | None) -> bool:
        """True wenn Alert verworfen werden soll (Self-Traffic).

        Richtungs-bewusste Logik:
        - Loopback/Docker-Bridge: src ODER dst matcht → drop. Beide Seiten
          sind sowieso intern.
        - Outbound-only (Management-IP): nur droppen wenn src matcht.
          Eingehende Angriffe gegen die Appliance (dst=mgmt-IP, src extern)
          kommen damit durch.
        - Legacy IDS_SELF_IPS: beidseitig (alte Semantik) — für
          Bestandsdeployments, die nicht migriert haben.
        """
        # Loopback / Docker-Bridge: symmetrisch
        if self._ip_in_nets(src_ip, self._loopback_nets):
            return True
        if self._ip_in_nets(dst_ip, self._loopback_nets):
            return True
        # Mgmt-IP: nur wenn Appliance Sender ist
        if self._ip_in_nets(src_ip, self._outbound_nets):
            return True
        # Legacy: beidseitig
        if self._ip_in_nets(src_ip, self._legacy_nets):
            return True
        if self._ip_in_nets(dst_ip, self._legacy_nets):
            return True
        return False

    @property
    def ranges(self) -> Iterable:
        """Backwards-compat: alle Ranges in einer Liste."""
        return tuple(self._loopback_nets + self._outbound_nets + self._legacy_nets)
