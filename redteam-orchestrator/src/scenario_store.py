"""Persistierung + Validierung von KI-generierten Payload-Scenarios.

Layout im cyjan-scenarios-Volume:
  /scenarios/generated/<scenario_id>.yml   ← von KI via MCP angelegt
  /scenarios/templates/<scenario_id>.yml   ← orchestrator-builtin (im Image
                                             shipped, beim Startup gesseedet,
                                             immer overwrite — Image = truth)
  /scenarios/imported/...                  ← aus Pattern-Federation-Bundles

Lookup-Reihenfolge (load_scenario): generated → templates → imported.
KI- und Federation-Inputs gewinnen damit gegen Builtin-Templates wenn
IDs kollidieren — Builtin ist Fallback/Library.

Format der YAMLs (lab-curated oder KI-generiert):
  id: MODBUS_PROBE_FC_01
  description: "Modbus Function Code 1 (Read Coils) Probe"
  protocol: tcp
  target_port: 502
  payload_b64: AAAAAAAGAQEAAAAB
  expected_alert_rule_id: SURICATA:1:2018927
  tags: [modbus, ics, recon]
  mitre: [T0855]
  created_by: cyjan-redteam-orchestrator
  created_at: 2026-05-11T13:00:00Z

Validator-Regeln:
  - id: ^[A-Z][A-Z0-9_]{2,63}$
  - protocol: tcp|udp
  - target_port: 1-65535
  - payload_b64: max 5460 b64-chars (= 4096 decoded bytes)
  - expected_alert_rule_id: optional, max 128 chars
  - tags/mitre: lists of strings, max 16 entries jeweils
"""
from __future__ import annotations

import base64
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

GENERATED_DIR = Path("/scenarios/generated")
TEMPLATES_DIR = Path("/scenarios/templates")
IMPORTED_DIR  = Path("/scenarios/imported")
BUILTIN_SOURCE = Path("/opt/cyjan/templates")  # Image-shipped, read-only
MAX_PAYLOAD_BYTES = 4096
ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class ScenarioValidationError(Exception):
    pass


def validate_scenario_dict(d: dict[str, Any]) -> None:
    """Wirft ScenarioValidationError mit klarer Message bei jeder
    Inkonsistenz. Keine Side-Effects."""
    sid = d.get("id", "")
    if not isinstance(sid, str) or not ID_PATTERN.match(sid):
        raise ScenarioValidationError(
            f"id {sid!r} ungültig — Pattern ^[A-Z][A-Z0-9_]{{2,63}}$"
        )

    proto = (d.get("protocol") or "").lower()
    if proto not in ("tcp", "udp"):
        raise ScenarioValidationError(f"protocol {proto!r} nicht in (tcp, udp)")

    port = d.get("target_port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ScenarioValidationError(f"target_port {port!r} außerhalb 1-65535")

    pl = d.get("payload_b64", "")
    if not isinstance(pl, str) or not pl:
        raise ScenarioValidationError("payload_b64 muss non-empty string sein")
    try:
        decoded = base64.b64decode(pl, validate=True)
    except Exception as exc:
        raise ScenarioValidationError(f"payload_b64 nicht valides base64: {exc}")
    if len(decoded) > MAX_PAYLOAD_BYTES:
        raise ScenarioValidationError(
            f"payload {len(decoded)} bytes > MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES})"
        )

    eid = d.get("expected_alert_rule_id")
    if eid is not None and (not isinstance(eid, str) or len(eid) > 128):
        raise ScenarioValidationError(
            "expected_alert_rule_id muss string ≤128 chars sein"
        )

    for field in ("tags", "mitre"):
        v = d.get(field) or []
        if not isinstance(v, list):
            raise ScenarioValidationError(f"{field} muss list sein")
        if len(v) > 16 or not all(isinstance(x, str) for x in v):
            raise ScenarioValidationError(f"{field}: max 16 strings")


def save_scenario(d: dict[str, Any]) -> Path:
    """Validiert, fügt created_at/created_by-Metadaten dazu, schreibt
    atomar als YAML ins generated/-Verzeichnis. Returns Pfad."""
    validate_scenario_dict(d)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    out = {
        "id":                     d["id"],
        "description":            d.get("description") or "",
        "protocol":               d["protocol"].lower(),
        "target_port":            int(d["target_port"]),
        "payload_b64":            d["payload_b64"],
        "expected_alert_rule_id": d.get("expected_alert_rule_id"),
        "tags":                   list(d.get("tags") or []),
        "mitre":                  list(d.get("mitre") or []),
        "created_by":             d.get("created_by") or "cyjan-redteam-orchestrator",
        "created_at":             datetime.now(timezone.utc).isoformat(),
    }
    target = GENERATED_DIR / f"{out['id']}.yml"
    tmp = target.with_suffix(".yml.tmp")
    tmp.write_text(yaml.safe_dump(out, sort_keys=False))
    tmp.replace(target)
    log.info("Scenario %s saved → %s (%d bytes payload)",
             out["id"], target, len(base64.b64decode(out["payload_b64"])))
    return target


def load_scenario(scenario_id: str) -> dict[str, Any]:
    """Lädt ein Scenario aus generated/, templates/ oder imported/. KI-
    Generated gewinnt vor Builtin-Templates gewinnt vor Federation-Imports.
    Wirft FileNotFoundError wenn nicht da."""
    candidates = [
        GENERATED_DIR / f"{scenario_id}.yml",
        TEMPLATES_DIR / f"{scenario_id}.yml",
        IMPORTED_DIR  / f"{scenario_id}.yml",
    ]
    for p in candidates:
        if p.is_file():
            doc = yaml.safe_load(p.read_text())
            if not isinstance(doc, dict) or doc.get("id") != scenario_id:
                raise ScenarioValidationError(
                    f"{p}: id mismatch oder kein dict"
                )
            return doc
    raise FileNotFoundError(f"Scenario {scenario_id!r} nicht gefunden (gesucht: {candidates})")


def delete_scenario(scenario_id: str) -> bool:
    """Löscht ein KI-generated Scenario. Builtin-Templates + Imported-
    Scenarios bleiben unangetastet (Templates kommen vom Image, Imports
    aus Pattern-Federation-Bundles — beide gehören nicht zur MCP-
    Verwaltungs-Domäne). Returns True wenn gelöscht, False wenn nicht da."""
    target = GENERATED_DIR / f"{scenario_id}.yml"
    if target.is_file():
        target.unlink()
        log.info("Scenario %s deleted", scenario_id)
        return True
    return False


def seed_builtin_templates() -> int:
    """Kopiert alle YAMLs aus /opt/cyjan/templates/ in /scenarios/templates/.
    Wird beim Orchestrator-Startup aufgerufen. Image = source of truth →
    immer overwrite, damit Updates der Templates bei Container-Restart
    ankommen. User-Edits an /scenarios/templates/ gehen dabei verloren
    (Templates sind read-only-Library — wer ändern will, legt ein
    generated-Scenario mit gleicher ID an, das gewinnt im load_scenario-
    Lookup). Returns Anzahl geseedeter Files."""
    if not BUILTIN_SOURCE.is_dir():
        log.info("Builtin-Templates-Source %s nicht vorhanden, überspringe Seed",
                 BUILTIN_SOURCE)
        return 0
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    seeded = 0
    for src in sorted(BUILTIN_SOURCE.glob("*.yml")):
        try:
            doc = yaml.safe_load(src.read_text())
            if not isinstance(doc, dict) or not doc.get("id"):
                log.warning("Template %s: kein dict oder fehlende id, skip", src)
                continue
            validate_scenario_dict(doc)
        except (yaml.YAMLError, ScenarioValidationError) as exc:
            log.warning("Template %s invalid, skip: %s", src, exc)
            continue
        dst = TEMPLATES_DIR / src.name
        shutil.copy2(src, dst)
        seeded += 1
    log.info("Builtin-Templates seeded: %d Files nach %s", seeded, TEMPLATES_DIR)
    return seeded
