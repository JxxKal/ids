"""Lädt den Host-Rollen-Katalog aus dem YAML-Dir (ROLE_CATALOG_DIR).

Schema eingefroren in docs/contracts/host-roles.md §2. Jede *.yml-Datei
enthält eine Liste von Rollen-Definitionen. Wir parsen sie in normalisierte
`RoleDef`-Objekte, die der Matcher direkt auswertet. Defekte Einträge werden
geloggt und übersprungen — eine kaputte Datei darf nicht den ganzen Cycle
killen.

V1-Scope: `required_ports`, `any_ports`, `optional_flags`, `mac_oui`. Das
`fingerprint`-Feld wird gelesen aber ignoriert (V2).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

log = logging.getLogger(__name__)

# proto-Werte aus dem Contract.
_VALID_PROTO = {"TCP", "UDP", "ANY"}


@dataclass(frozen=True)
class PortSpec:
    port: int
    proto: str  # TCP | UDP | ANY


@dataclass(frozen=True)
class FlagSpec:
    flag: str
    port: int
    proto: str


@dataclass(frozen=True)
class RoleDef:
    id: str
    label: str
    category: str
    required_ports: tuple[PortSpec, ...]
    any_ports: tuple[PortSpec, ...]
    min_any: int
    optional_flags: tuple[FlagSpec, ...]
    min_flows_per_port: int
    base_confidence: float
    per_optional_port: float
    long_lived_bonus: float
    mac_oui: tuple[str, ...] = field(default=())


def _parse_port(raw: dict) -> Optional[PortSpec]:
    try:
        port = int(raw["port"])
        proto = str(raw.get("proto", "ANY")).upper()
    except (KeyError, TypeError, ValueError):
        return None
    if proto not in _VALID_PROTO:
        log.warning("Port-Spec mit ungültigem proto=%s ignoriert", proto)
        return None
    return PortSpec(port=port, proto=proto)


def _parse_flag(raw: dict) -> Optional[FlagSpec]:
    try:
        flag = str(raw["flag"])
        port = int(raw["port"])
        proto = str(raw.get("proto", "ANY")).upper()
    except (KeyError, TypeError, ValueError):
        return None
    if proto not in _VALID_PROTO:
        return None
    return FlagSpec(flag=flag, port=port, proto=proto)


def _parse_role(raw: dict) -> Optional[RoleDef]:
    rid = raw.get("id")
    if not rid or not isinstance(rid, str):
        log.warning("Rollen-Eintrag ohne id übersprungen: %r", raw)
        return None

    match = raw.get("match") or {}

    required = tuple(
        p for p in (_parse_port(x) for x in (match.get("required_ports") or []))
        if p is not None
    )

    any_block = match.get("any_ports") or {}
    if not isinstance(any_block, dict):
        any_block = {}
    any_ports = tuple(
        p for p in (_parse_port(x) for x in (any_block.get("ports") or []))
        if p is not None
    )
    min_any = int(any_block.get("min_any", 0) or 0)

    optional_flags = tuple(
        f for f in (_parse_flag(x) for x in (match.get("optional_flags") or []))
        if f is not None
    )

    bonus = raw.get("confidence_bonus") or {}

    # OUI-Präfixe normalisieren: Upper-Case, ohne Trenner — der Matcher
    # vergleicht gegen die ersten 3 Oktette der Mode-MAC im selben Format.
    mac_oui = tuple(
        _norm_oui(x) for x in (raw.get("mac_oui") or []) if isinstance(x, str)
    )

    return RoleDef(
        id=rid,
        label=str(raw.get("label", rid)),
        category=str(raw.get("category", "")),
        required_ports=required,
        any_ports=any_ports,
        min_any=min_any,
        optional_flags=optional_flags,
        min_flows_per_port=int(raw.get("min_flows_per_port", 1) or 1),
        base_confidence=float(raw.get("base_confidence", 0.0) or 0.0),
        per_optional_port=float(bonus.get("per_optional_port", 0.0) or 0.0),
        long_lived_bonus=float(bonus.get("long_lived", 0.0) or 0.0),
        mac_oui=mac_oui,
    )


def _norm_oui(raw: str) -> str:
    """'00:0E:8C' / '000e8c' / '00-0e-8c' → '000E8C' (erste 3 Oktette)."""
    hexed = "".join(c for c in raw if c.isalnum()).upper()
    return hexed[:6]


def load_catalog(catalog_dir: str) -> list[RoleDef]:
    """Liest alle *.yml/*.yaml aus dem Dir und parst die Rollen. Bei einem
    Parse-Fehler in einer Datei wird diese übersprungen (nicht der Rest)."""
    roles: list[RoleDef] = []
    if not os.path.isdir(catalog_dir):
        log.warning("Katalog-Dir %s existiert nicht — keine Rollen geladen", catalog_dir)
        return roles

    seen_ids: set[str] = set()
    for name in sorted(os.listdir(catalog_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(catalog_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            log.warning("Katalog-Datei %s nicht lesbar: %s", name, exc)
            continue
        if not isinstance(docs, list):
            log.warning("Katalog-Datei %s hat kein Listen-Top-Level — übersprungen", name)
            continue
        for entry in docs:
            if not isinstance(entry, dict):
                continue
            role = _parse_role(entry)
            if role is None:
                continue
            if role.id in seen_ids:
                log.warning("Doppelte Rollen-id %s in %s — erste gewinnt", role.id, name)
                continue
            seen_ids.add(role.id)
            roles.append(role)

    log.info("Katalog geladen: %d Rollen aus %s", len(roles), catalog_dir)
    return roles
