"""
Egress-Boundary-Klassifikator.

Annotiert pro Alert das Tupel (net_known, src_known, dst_known) plus eine
Priority P0–P3, basierend auf:

  net_known  = dst_ip ist in einem konfigurierten known_networks-CIDR
  src_known  = host_info.trusted = true für src_ip
  dst_known  = host_info.trusted = true für dst_ip

Priority-Mapping ist als system_config-Key 'boundary_priority_map' editierbar
(GUI: Settings → System → Egress-Prioritäten); fällt auf den hier definierten
Default zurück wenn der Key fehlt.

Default-Mapping (aus Spec):
  (✗,✗,✗) → P0  Vollständig unbekannter Egress
  (✗,✓,✗) → P1  Bekannter Host → unbekannt (C2/Exfil-Verdacht)
  (✗,✗,✓) → P1  Unbekannte Quelle → bekanntes externes Ziel
  (✓,✗,✗) → P2  Rogue Device im Managed-Netz nach draußen
  (✗,✓,✓) → P2  Routing-/VPN-Anomalie zwischen bekannten Hosts
  (✓,✗,✓) → P3  Inventory-Lücke intern
  (✓,✓,✗) → P3  Bekannter Host → unbekanntes lokales Ziel
  (✓,✓,✓) → None (nicht in Egress-View)

Tuple-Encoding für die Priority-Map:
  Schlüssel ist ein 3-Char-String aus '0' (✗) und '1' (✓), in Reihenfolge
  net,src,dst. Beispiel: "010" = (✗,✓,✗) → P1.
"""
from __future__ import annotations

from typing import Literal, Optional

Priority = Literal["P0", "P1", "P2", "P3"]

# In-Code-Default. Wird überschrieben durch system_config-Key
# 'boundary_priority_map' wenn vorhanden.
DEFAULT_PRIORITY_MAP: dict[str, Optional[Priority]] = {
    "000": "P0",  # net✗ src✗ dst✗
    "010": "P1",  # net✗ src✓ dst✗
    "001": "P1",  # net✗ src✗ dst✓
    "100": "P2",  # net✓ src✗ dst✗
    "011": "P2",  # net✗ src✓ dst✓
    "101": "P3",  # net✓ src✗ dst✓
    "110": "P3",  # net✓ src✓ dst✗
    "111": None,  # net✓ src✓ dst✓ – nicht in Egress-View
}


def encode_tuple(net_known: bool, src_known: bool, dst_known: bool) -> str:
    """Tuple → 3-Char-Schlüssel für die Priority-Map."""
    return f"{'1' if net_known else '0'}{'1' if src_known else '0'}{'1' if dst_known else '0'}"


def classify(
    net_known: bool,
    src_known: bool,
    dst_known: bool,
    priority_map: dict[str, Optional[Priority]] | None = None,
) -> Optional[Priority]:
    """Gibt P0–P3 oder None (für ✓✓✓ oder unbekannten Schlüssel)."""
    pmap = priority_map or DEFAULT_PRIORITY_MAP
    return pmap.get(encode_tuple(net_known, src_known, dst_known))


def parse_priority_map(raw: dict) -> dict[str, Optional[Priority]]:
    """
    Validiert + normalisiert eine User-konfigurierte Priority-Map aus
    system_config. Erwartetes Format:
      {"000": "P0", "010": "P1", ..., "111": null}
    Schlüssel die nicht 3 Zeichen aus 0/1 sind werden ignoriert. Werte
    die nicht zu P0/P1/P2/P3/None passen werden auf None gemapped.
    """
    out: dict[str, Optional[Priority]] = {}
    valid_priorities = {"P0", "P1", "P2", "P3"}
    for k, v in (raw or {}).items():
        if not isinstance(k, str) or len(k) != 3 or any(c not in "01" for c in k):
            continue
        if v is None or v == "":
            out[k] = None
            continue
        if isinstance(v, str) and v.upper() in valid_priorities:
            out[k] = v.upper()  # type: ignore[assignment]
        else:
            out[k] = None
    return out


# ── V2: Zone-basierte Klassifikation (Migration 017) ────────────────────────
#
# Statt 2³ = 8 Tupel-Kombis aus (net_known, src_known, dst_known) klassifizieren
# wir Source × Destination über 3 Zonen:
#   ot       — known_networks.kind='ot' (OT-Scope)
#   it       — known_networks.kind='it' (Corporate IT, nicht im OT-Scope)
#   internet — alles außerhalb von known_networks
#
# Die V1-Tupel-Map (oben) bleibt für Bestandsalerts und das Backwards-Compat-
# Schreiben der V1-Felder (net_known/src_known/dst_known) erhalten.

Zone = Literal["ot", "it", "internet"]

# Default-Map. User-Konfiguration via system_config-Key 'boundary_priority_map_v2'
# (siehe Migration 017) überschreibt einzelne Zellen. Diagonale (gleiche Zone
# auf beiden Seiten) ist None — kein Alert für In-Zone-Traffic.
DEFAULT_PRIORITY_MAP_V2: dict[str, Optional[Priority]] = {
    "ot/ot":             None,
    "ot/it":             "P2",
    "ot/internet":       "P0",
    "it/ot":             "P1",
    "it/it":             None,
    "it/internet":       "P2",
    "internet/ot":       "P0",
    "internet/it":       "P2",
    "internet/internet": None,
}


def encode_v2(src_zone: Zone, dst_zone: Zone) -> str:
    """Zone-Pair → Schlüssel für die V2-Priority-Map."""
    return f"{src_zone}/{dst_zone}"


def classify_v2(
    src_zone:     Zone,
    dst_zone:     Zone,
    priority_map: dict[str, Optional[Priority]] | None = None,
) -> Optional[Priority]:
    """V2-Klassifikator. Gibt P0–P3 oder None (für Diagonale oder unbekannten
    Schlüssel)."""
    pmap = priority_map or DEFAULT_PRIORITY_MAP_V2
    return pmap.get(encode_v2(src_zone, dst_zone))


def parse_priority_map_v2(raw: dict) -> dict[str, Optional[Priority]]:
    """Validiert + normalisiert die User-konfigurierte V2-Map aus system_config.
    Erwartetes Format: {"ot/internet": "P0", "ot/it": "P2", ..., "ot/ot": null}.
    Schlüssel die nicht "<zone>/<zone>" mit zone ∈ {ot,it,internet} sind werden
    ignoriert."""
    out: dict[str, Optional[Priority]] = {}
    valid_priorities = {"P0", "P1", "P2", "P3"}
    valid_zones = {"ot", "it", "internet"}
    for k, v in (raw or {}).items():
        if not isinstance(k, str) or "/" not in k:
            continue
        parts = k.split("/", 1)
        if len(parts) != 2 or parts[0] not in valid_zones or parts[1] not in valid_zones:
            continue
        if v is None or v == "":
            out[k] = None
            continue
        if isinstance(v, str) and v.upper() in valid_priorities:
            out[k] = v.upper()  # type: ignore[assignment]
        else:
            out[k] = None
    return out
