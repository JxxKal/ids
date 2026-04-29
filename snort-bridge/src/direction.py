"""
Connection-Direction-Heuristik für Suricata-EVE-Alerts.

Suricata feuert Regeln auf einzelnen Paketen, wodurch src/dst dem Paket-
Trigger entsprechen – nicht der aufbauenden Verbindung. Beispiel: SID
2260001 ('applayer wrong direction first data') feuert auf einem Server→
Client-Paket, also liefert EVE src=Server, dst=Client. Im Frontend wollen
wir aber konsistent die Initiator-Richtung sehen (Client→Server).

Diese Funktion normalisiert ein EVE-Record-Tupel auf die Verbindungs-
richtung. Heuristik (definitiv → wahrscheinlich), gleiche Reihenfolge wie
in flow-aggregator/src/flow.py:

  1. EVE-Feld 'direction' wenn vorhanden (Suricata's eigene Sicht):
       'to_server' → src ist bereits Client, kein Swap
       'to_client' → src ist Server, swap nötig
  2. RFC1918/Loopback/Link-Local/CGNAT vs Public: private Seite = Client
  3. Well-Known-Port (<1024) vs Ephemeral (>=1024): Well-Known-Seite = Server
  4. low<high als Tie-Breaker
  5. Default: kein Swap (first-packet wins)
"""
from __future__ import annotations

from ipaddress import ip_address
from typing import Optional


def _is_private_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ip = ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or (ip.version == 4 and 0x64400000 <= int(ip) <= 0x647FFFFF)  # CGNAT
        )
    except ValueError:
        return False


def normalize(rec: dict) -> tuple[Optional[str], Optional[int], Optional[str], Optional[int]]:
    """Liefert (client_ip, client_port, server_ip, server_port) für ein EVE-Record.

    Felder die fehlen (z.B. src_port bei ICMP) werden als None zurückgegeben.
    Die Reihenfolge entspricht der aufbauenden Verbindung – Client zuerst.
    """
    sip  = rec.get("src_ip")
    dip  = rec.get("dest_ip")
    sport_raw = rec.get("src_port")
    dport_raw = rec.get("dest_port")
    sport = int(sport_raw) if sport_raw not in (None, "") else None
    dport = int(dport_raw) if dport_raw not in (None, "") else None

    swap = False
    decided = False

    direction = rec.get("direction")
    if direction == "to_server":
        decided = True       # src ist bereits Client
    elif direction == "to_client":
        swap = True
        decided = True

    if not decided:
        sip_priv = _is_private_ip(sip)
        dip_priv = _is_private_ip(dip)
        if sip_priv and not dip_priv:
            decided = True   # privat (src) → public (dst): src=Client
        elif dip_priv and not sip_priv:
            swap = True
            decided = True

    if not decided and sport is not None and dport is not None:
        sport_well_known = sport < 1024
        dport_well_known = dport < 1024
        if sport_well_known and not dport_well_known:
            swap = True      # src bedient Service-Port → src=Server
            decided = True
        elif dport_well_known and not sport_well_known:
            decided = True   # dst bedient Service-Port → src=Client

    if not decided and sport is not None and dport is not None:
        if sport < dport:
            swap = True      # niedrigerer Port = Server → src=Server, swap

    if swap:
        return dip, dport, sip, sport
    return sip, sport, dip, dport
