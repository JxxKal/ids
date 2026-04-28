"""
Signature-Engine YAML-Regeln: Auflistung + Per-Regel-Overrides.

Architektur:
  • signature-engine lädt YAML-Regeln aus /rules/builtin (RO im Repo) und
    /rules/custom (RW, persistente Volume signature-rules).
  • api hat /opt/ids gemountet (Repo-Stand → Builtin-YAMLs lesbar) und seit
    diesem Commit auch die signature-rules-Volume unter /sig-rules → kann
    Custom-Files + Overrides-File lesen UND schreiben.
  • Override-Datei: /sig-rules/custom/_overrides.json (vom Loader gelesen)
    Format:
      {
        "DNS_AMP_001": {"enabled": false, "severity": null},
        "SCAN_002":    {"enabled": true,  "severity": "low"}
      }
  • signature-engine lädt die Datei via mtime-Watch automatisch nach (kein
    Restart nötig).

Endpoints:
  GET  /api/sig-rules/list       – Alle Regeln + ihr aktueller Override-Status
  GET  /api/sig-rules/overrides  – Roher Inhalt der Overrides-Datei
  PUT  /api/sig-rules/overrides  – Overrides setzen (validierte Schreibe)
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth import require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sig-rules", tags=["sig-rules"])

# Pfade: Built-in YAMLs liegen im Repo unter signature-engine/rules/.
# Custom YAMLs + Overrides liegen im persistenten Volume.
BUILTIN_DIR = Path(os.getenv("SIG_BUILTIN_DIR", "/opt/ids/signature-engine/rules"))
CUSTOM_DIR  = Path(os.getenv("SIG_CUSTOM_DIR",  "/sig-rules/custom"))
OVERRIDES_FILE = CUSTOM_DIR / "_overrides.json"

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


# ── Schemas ────────────────────────────────────────────────────────────────


class SigRuleEntry(BaseModel):
    id:                 str
    name:               str
    description:        str
    severity:           str           # die effektive Severity nach Override
    severity_default:   str           # was die YAML ursprünglich sagt
    tags:               list[str]
    file:               str           # relativer Pfad ab rules-root
    builtin:            bool
    enabled:            bool          # Override-State (Default: true)
    severity_override:  str | None    # gesetzt wenn != severity_default


class SigRuleOverride(BaseModel):
    enabled:  bool | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None


class SigRulesOverrides(BaseModel):
    overrides: dict[str, SigRuleOverride] = Field(default_factory=dict)


# ── Helpers ────────────────────────────────────────────────────────────────


def _read_yaml_files() -> list[tuple[Path, list[dict], bool]]:
    """Sammelt alle YAML-Regelfiles. Custom überschreibt builtin per ID."""
    out: list[tuple[Path, list[dict], bool]] = []

    # Custom hat Vorrang (im Loader sortiert; hier matchen wir die Reihenfolge)
    if CUSTOM_DIR.is_dir():
        for f in sorted(CUSTOM_DIR.rglob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    out.append((f, data, False))
            except (OSError, yaml.YAMLError) as exc:
                log.warning("YAML konnte nicht gelesen werden (%s): %s", f, exc)

    if BUILTIN_DIR.is_dir():
        for f in sorted(BUILTIN_DIR.rglob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    out.append((f, data, True))
            except (OSError, yaml.YAMLError) as exc:
                log.warning("YAML konnte nicht gelesen werden (%s): %s", f, exc)

    return out


def _read_overrides_file() -> dict[str, dict]:
    if not OVERRIDES_FILE.exists():
        return {}
    try:
        data = json.loads(OVERRIDES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"Overrides-Datei nicht lesbar: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _write_overrides_file(payload: dict[str, dict]) -> None:
    try:
        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        # Atomic write: erst .tmp, dann rename
        tmp = OVERRIDES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(OVERRIDES_FILE)
    except OSError as exc:
        raise HTTPException(500, f"Overrides-Datei nicht schreibbar: {exc}") from exc


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.get(
    "/list",
    response_model=list[SigRuleEntry],
    dependencies=[Depends(require_admin)],
    summary="Alle YAML-Regeln + ihr aktueller Override-Status",
)
async def list_rules() -> list[SigRuleEntry]:
    overrides = _read_overrides_file()
    seen: set[str] = set()
    out: list[SigRuleEntry] = []

    for path, raw_rules, builtin in _read_yaml_files():
        for raw in raw_rules:
            rid = str(raw.get("id") or "")
            if not rid or rid in seen:
                continue
            seen.add(rid)
            sev_default = str(raw.get("severity", "medium")).lower()
            if sev_default not in VALID_SEVERITIES:
                sev_default = "medium"

            ov: dict[str, Any] = overrides.get(rid) or {}
            enabled = ov.get("enabled")
            if not isinstance(enabled, bool):
                enabled = True
            sev_override = ov.get("severity")
            if isinstance(sev_override, str) and sev_override.lower() in VALID_SEVERITIES:
                sev_override = sev_override.lower()
            else:
                sev_override = None
            effective = sev_override or sev_default

            try:
                rel = str(path.relative_to(BUILTIN_DIR.parent if builtin else CUSTOM_DIR.parent))
            except ValueError:
                rel = path.name

            out.append(SigRuleEntry(
                id=rid,
                name=str(raw.get("name") or rid),
                description=str(raw.get("description") or ""),
                severity=effective,
                severity_default=sev_default,
                tags=list(raw.get("tags") or []),
                file=rel,
                builtin=builtin,
                enabled=enabled,
                severity_override=sev_override,
            ))

    out.sort(key=lambda r: (not r.builtin, r.id))
    return out


@router.get(
    "/overrides",
    response_model=SigRulesOverrides,
    dependencies=[Depends(require_admin)],
    summary="Aktueller Inhalt der Overrides-Datei",
)
async def get_overrides() -> SigRulesOverrides:
    raw = _read_overrides_file()
    cleaned: dict[str, SigRuleOverride] = {}
    for rid, ov in raw.items():
        if not isinstance(ov, dict):
            continue
        cleaned[rid] = SigRuleOverride(
            enabled=ov.get("enabled") if isinstance(ov.get("enabled"), bool) else None,
            severity=ov.get("severity") if (
                isinstance(ov.get("severity"), str)
                and ov.get("severity", "").lower() in VALID_SEVERITIES
            ) else None,
        )
    return SigRulesOverrides(overrides=cleaned)


@router.put(
    "/overrides",
    response_model=SigRulesOverrides,
    dependencies=[Depends(require_admin)],
    summary="Overrides setzen (komplett ersetzen)",
)
async def put_overrides(body: SigRulesOverrides) -> SigRulesOverrides:
    payload: dict[str, dict] = {}
    for rid, ov in body.overrides.items():
        entry: dict = {}
        if ov.enabled is not None:
            entry["enabled"] = ov.enabled
        if ov.severity is not None:
            entry["severity"] = ov.severity
        if entry:
            payload[rid] = entry

    _write_overrides_file(payload)
    log.info("Sig-Rule-Overrides geschrieben: %d Einträge", len(payload))
    return await get_overrides()
