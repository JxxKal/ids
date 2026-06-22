"""Rollen-Matching + Provenance/Lock-Merge.

Matcht ein HostProfile gegen den Katalog (RoleDef) und baut den neuen
`detected_roles`-Stand — unter strenger Beachtung der manual-Locks aus dem
bestehenden Eintrag (Contract §1):

  • source="manual" / manual[id].locked=true ⇒ Rolle unverändert durchreichen,
    nie neu berechnen, nie entfernen.
  • auto-Rollen werden frisch berechnet; `since` vom alten auto-Eintrag
    übernommen (stabil über Cycles), sonst now.
  • nicht mehr matchende auto-Rollen fallen weg.

Provenance-Muster gespiegelt aus rule-tuner (_copy_existing): bestehende
fremd-verwaltete Einträge bleiben unangetastet, nur die eigene Klasse
(hier: auto) wird neu geschrieben.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from aggregator import HostProfile
from catalog import FlagSpec, PortSpec, RoleDef

log = logging.getLogger(__name__)


@dataclass
class RoleMatch:
    role_id: str
    confidence: float
    ports: list[dict]          # [{"port": int, "proto": str}, ...]
    evidence: list[str]
    flags: list[str]
    flow_count: int


def _port_served(profile: HostProfile, spec: PortSpec, min_flows: int) -> bool:
    """Ist der geforderte Port serviert? proto=ANY matcht jedes Protokoll,
    sonst muss flows.proto exakt passen. Der Port-Flow-Count muss die
    per-Rolle-Schwelle min_flows erreichen (Contract HAVING count>=min_flows)."""
    for (port, proto), n in profile.served.items():
        if port != spec.port or n < min_flows:
            continue
        if spec.proto == "ANY" or spec.proto == proto:
            return True
    return False


def _flag_served(profile: HostProfile, flag: FlagSpec, min_flows: int) -> bool:
    for (port, proto), n in profile.served.items():
        if port != flag.port or n < min_flows:
            continue
        if flag.proto == "ANY" or flag.proto == proto:
            return True
    return False


def match_role(profile: HostProfile, role: RoleDef, oui_bonus: float) -> RoleMatch | None:
    """Wertet eine einzelne Rolle gegen das Profil aus. None = kein Match."""
    mf = role.min_flows_per_port
    # 1. required_ports: ALLE müssen serviert sein.
    for spec in role.required_ports:
        if not _port_served(profile, spec, mf):
            return None

    # 2. any_ports: mind. min_any aus der Liste.
    any_hits = sum(1 for spec in role.any_ports if _port_served(profile, spec, mf))
    if role.min_any > 0 and any_hits < role.min_any:
        return None

    # Ab hier matcht die Rolle strukturell — confidence aufbauen.
    confidence = role.base_confidence
    evidence: list[str] = []
    ports: list[dict] = []
    flags: list[str] = []

    for spec in role.required_ports:
        ports.append({"port": spec.port, "proto": spec.proto})
        evidence.append(f"port:{spec.port}/{spec.proto}")
    # Getroffene any_ports zählen als evidence + per_optional_port-Bonus.
    for spec in role.any_ports:
        if _port_served(profile, spec, mf):
            ports.append({"port": spec.port, "proto": spec.proto})
            evidence.append(f"port:{spec.port}/{spec.proto}")
            confidence += role.per_optional_port

    # 3. optional_flags: kein Match-Zwang, setzen flags/evidence (+Bonus).
    for flag in role.optional_flags:
        if _flag_served(profile, flag, mf):
            flags.append(flag.flag)
            evidence.append(f"flag:{flag.flag}({flag.port})")
            confidence += role.per_optional_port

    # 4. long_lived-Bonus.
    if profile.long_lived and role.long_lived_bonus:
        confidence += role.long_lived_bonus

    # 5. MAC-OUI-Bonus: Präfix-Match (erste 3 Oktette) → confidence + evidence.
    if profile.oui and role.mac_oui and profile.oui in role.mac_oui:
        confidence += oui_bonus
        evidence.append(f"oui:{profile.oui}")

    confidence = max(0.0, min(1.0, confidence))
    return RoleMatch(
        role_id=role.id,
        confidence=round(confidence, 4),
        ports=ports,
        evidence=evidence,
        flags=flags,
        flow_count=profile.total_flows,
    )


def _is_manual(existing_role: dict, existing_manual: dict, role_id: str) -> bool:
    """Rolle gilt als manual-gelockt, wenn source=manual ODER ein
    manual[role_id].locked=true-Eintrag existiert (Contract §1)."""
    if isinstance(existing_role, dict) and existing_role.get("source") == "manual":
        return True
    man = existing_manual.get(role_id)
    if isinstance(man, dict) and man.get("locked") is True:
        return True
    return False


def build_detected_roles(
    profile: HostProfile,
    catalog: list[RoleDef],
    existing: dict | None,
    min_confidence: float,
    oui_bonus: float,
) -> dict:
    """Baut den neuen detected_roles-Stand für einen Host.

    existing: bisheriger Eintrag (oder None). manual-Rollen werden unverändert
    durchgereicht, auto-Rollen neu berechnet.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    existing = existing if isinstance(existing, dict) else {}
    old_roles = existing.get("roles") if isinstance(existing.get("roles"), dict) else {}
    old_manual = existing.get("manual") if isinstance(existing.get("manual"), dict) else {}

    new_roles: dict[str, dict] = {}

    # 1. manual-gelockte Rollen 1:1 übernehmen (nie anfassen).
    for rid, entry in old_roles.items():
        if _is_manual(entry, old_manual, rid):
            new_roles[rid] = entry

    # 2. auto-Rollen frisch berechnen.
    for role in catalog:
        # manual-Lock gewinnt — kein auto-Override.
        if role.id in new_roles:
            continue
        m = match_role(profile, role, oui_bonus)
        if m is None or m.confidence < min_confidence:
            continue
        # `since` stabil halten, wenn die Rolle vorher schon auto war.
        prev = old_roles.get(role.id)
        since = now_iso
        if isinstance(prev, dict) and prev.get("source") == "auto":
            prev_since = prev.get("since")
            if isinstance(prev_since, str) and prev_since:
                since = prev_since
        new_roles[role.id] = {
            "confidence":     m.confidence,
            "source":         "auto",
            "ports":          m.ports,
            "evidence":       m.evidence,
            "flags":          m.flags,
            "flow_count":     m.flow_count,
            "since":          since,
            "last_confirmed": now_iso,
        }

    out: dict = {"roles": new_roles, "evaluated_at": now_iso}
    # manual-Block nur durchreichen, wenn er nicht leer ist — saubere Files.
    if old_manual:
        out["manual"] = old_manual
    return out
