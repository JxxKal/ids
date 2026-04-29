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

from deps import require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sig-rules", tags=["sig-rules"])

# Pfade: Built-in YAMLs liegen im Repo unter signature-engine/rules/.
# Custom YAMLs + Overrides liegen im persistenten Volume signature-rules.
# WICHTIG: Das Volume wird im signature-engine-Container unter /rules/custom
# gemountet. Damit der dortige Loader _overrides.json findet, MUSS die API
# direkt in den Volume-Root schreiben — nicht in einen weiteren custom/-Subdir
# (sonst landet die Datei eine Ebene zu tief und greift nie).
BUILTIN_DIR = Path(os.getenv("SIG_BUILTIN_DIR", "/opt/ids/signature-engine/rules"))
CUSTOM_DIR  = Path(os.getenv("SIG_CUSTOM_DIR",  "/sig-rules"))
OVERRIDES_FILE = CUSTOM_DIR / "_overrides.json"
SURICATA_OVERRIDES_FILE = CUSTOM_DIR / "_suricata_overrides.json"

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_PARAM_TYPES = {"int", "float"}
VALID_PARAM_SOURCES = {"manual", "ml"}


# ── Schemas ────────────────────────────────────────────────────────────────


class SigRuleParamSchema(BaseModel):
    """Schema-Eintrag pro Parameter (Default/Range/Label aus YAML)."""
    type:    Literal["int", "float"]
    default: float
    min:     float | None = None
    max:     float | None = None
    label:   str = ""
    # Phase 2: Symbolischer Name der Counting-Funktion, die dieser Param
    # steuert (z.B. "unique_dst_ports"). Der ML-Tuner nutzt das für
    # Shadow-Metrik-Sammeln. None = nicht ML-tunbar.
    metric:  str | None = None


class SigRuleParamOverride(BaseModel):
    """Strukturierter Override-Eintrag pro Parameter mit Provenance + Scope-Split.

    `value`           – Schwellwert für externe Quellen oder global
    `value_internal`  – optionaler Schwellwert für Quellen in known_networks
    `source`          – wer hat den Wert zuletzt gesetzt (manual/ml)
    `ml`              – freie Metadaten vom rule-tuner (Trainingszeitpunkt etc.)
    """
    value:           float
    value_internal:  float | None = None
    source:          Literal["manual", "ml"] | None = None
    ml:              dict[str, Any] | None = None


class SigRuleEntry(BaseModel):
    id:                  str
    name:                str
    description:         str
    severity:            str            # die effektive Severity nach Override
    severity_default:    str            # was die YAML ursprünglich sagt
    tags:                list[str]
    file:                str            # relativer Pfad ab rules-root
    builtin:             bool
    enabled:             bool           # Override-State (Default: true)
    severity_override:   str | None     # gesetzt wenn != severity_default
    parameters_schema:   dict[str, SigRuleParamSchema] = Field(default_factory=dict)
    parameters_default:  dict[str, float]              = Field(default_factory=dict)
    # Skalar-Form bleibt aus Backwards-Compat für die existierende GUI: enthält
    # den effektiven externen Wert (= value, oder default falls kein Override).
    parameters:          dict[str, float]              = Field(default_factory=dict)
    parameters_override: dict[str, float]              = Field(default_factory=dict)
    # Vollform (Phase 1): pro Param Provenance + value_internal + ml-Metadaten,
    # wenn vorhanden. Wird von der neuen UI in Phase 5 + dem rule-tuner gelesen.
    parameters_full:     dict[str, SigRuleParamOverride] = Field(default_factory=dict)


class SigRuleOverride(BaseModel):
    """Override für eine einzelne Rule.

    Param-Werte können wahlweise als Skalar (Backwards-Compat) ODER als
    `SigRuleParamOverride` (mit Scope-Split + Provenance) übergeben werden.
    Bei PUT wird die kompakte Skalar-Form gespeichert wenn keine
    Provenance/internal_value vorliegt — sonst die strukturierte Form."""
    enabled:    bool | None = None
    severity:   Literal["critical", "high", "medium", "low"] | None = None
    parameters: dict[str, float | SigRuleParamOverride] | None = None


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


def _parse_yaml_param_schema(raw_params: Any) -> dict[str, SigRuleParamSchema]:
    """Spiegelt loader._parse_param_schema, aber API-seitig (für GET /list).

    Liefert ausschließlich gültige Schema-Einträge zurück. Skalar-Shortcuts wie
    `port_count: 50` werden zu int+default akzeptiert. Bei Inkonsistenzen wird
    der Eintrag still verworfen — der Loader logged in dem Fall ohnehin.
    """
    if not isinstance(raw_params, dict):
        return {}
    out: dict[str, SigRuleParamSchema] = {}
    for name, spec in raw_params.items():
        if not isinstance(name, str) or not name.isidentifier():
            continue
        if isinstance(spec, (int, float)) and not isinstance(spec, bool):
            ptype = "float" if isinstance(spec, float) else "int"
            out[name] = SigRuleParamSchema(type=ptype, default=float(spec))
            continue
        if not isinstance(spec, dict):
            continue
        ptype = str(spec.get("type", "int")).lower()
        if ptype not in VALID_PARAM_TYPES:
            continue
        if "default" not in spec:
            continue
        try:
            default_val = float(spec["default"])
            min_val = float(spec["min"]) if spec.get("min") is not None else None
            max_val = float(spec["max"]) if spec.get("max") is not None else None
        except (TypeError, ValueError):
            continue
        if min_val is not None and max_val is not None and min_val > max_val:
            min_val = max_val = None
        metric_raw = spec.get("metric")
        metric = metric_raw if isinstance(metric_raw, str) and metric_raw.isidentifier() else None
        out[name] = SigRuleParamSchema(
            type=ptype,
            default=default_val,
            min=min_val,
            max=max_val,
            label=str(spec.get("label", "")),
            metric=metric,
        )
    return out


def _clamp_param(value: float, schema: SigRuleParamSchema) -> float:
    """Cast + Range-Clamp eines Override-Wertes gegen ein Schema."""
    cast = float(value) if schema.type == "float" else int(value)
    if schema.min is not None and cast < schema.min:
        cast = schema.min if schema.type == "float" else int(schema.min)
    if schema.max is not None and cast > schema.max:
        cast = schema.max if schema.type == "float" else int(schema.max)
    return cast


def _normalize_param_ov_raw(value: Any) -> dict[str, Any] | None:
    """Akzeptiert eine Rohform aus dem File (Skalar ODER Objekt) und gibt sie
    als normalisiertes Dict {value, value_internal, source, ml} zurück. None
    wenn das Eingabe-Format unbrauchbar ist."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {"value": float(value), "value_internal": None, "source": None, "ml": None}
    if isinstance(value, dict):
        v = value.get("value")
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            return None
        vi = value.get("value_internal")
        if vi is not None and (not isinstance(vi, (int, float)) or isinstance(vi, bool)):
            vi = None
        src = value.get("source")
        if src not in VALID_PARAM_SOURCES:
            src = None
        ml = value.get("ml") if isinstance(value.get("ml"), dict) else None
        return {"value": float(v), "value_internal": float(vi) if vi is not None else None,
                "source": src, "ml": ml}
    return None


def _ov_is_trivial(entry: dict[str, Any]) -> bool:
    """True wenn der Override-Eintrag keine Information außer `value` trägt
    (= als Skalar speicherbar). False sobald value_internal/source/ml gesetzt
    sind — dann muss die Object-Form persistiert werden."""
    return (
        entry.get("value_internal") is None
        and entry.get("source") is None
        and not entry.get("ml")
    )


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

            params_schema = _parse_yaml_param_schema(raw.get("parameters"))
            params_default = {n: s.default for n, s in params_schema.items()}

            params_ov_clean: dict[str, float] = {}
            params_full: dict[str, SigRuleParamOverride] = {}
            raw_params_ov = ov.get("parameters") or {}
            if isinstance(raw_params_ov, dict):
                for pname, pval in raw_params_ov.items():
                    schema = params_schema.get(str(pname))
                    if schema is None:
                        continue
                    norm = _normalize_param_ov_raw(pval)
                    if norm is None:
                        continue
                    cast_v = _clamp_param(norm["value"], schema)
                    cast_vi = (
                        _clamp_param(norm["value_internal"], schema)
                        if norm["value_internal"] is not None else None
                    )
                    params_ov_clean[str(pname)] = cast_v
                    params_full[str(pname)] = SigRuleParamOverride(
                        value=cast_v,
                        value_internal=cast_vi,
                        source=norm["source"],
                        ml=norm["ml"],
                    )

            params_effective = {**params_default, **params_ov_clean}

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
                parameters_schema=params_schema,
                parameters_default=params_default,
                parameters=params_effective,
                parameters_override=params_ov_clean,
                parameters_full=params_full,
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
        params_raw = ov.get("parameters")
        params: dict[str, float | SigRuleParamOverride] | None = None
        if isinstance(params_raw, dict) and params_raw:
            tmp: dict[str, float | SigRuleParamOverride] = {}
            for k, v in params_raw.items():
                norm = _normalize_param_ov_raw(v)
                if norm is None:
                    continue
                # Skalar zurückgeben wenn trivial — Pydantic-Modell lässt
                # beides zu, GUI-Code sieht weiter Skalare wo möglich.
                if _ov_is_trivial(norm):
                    tmp[str(k)] = norm["value"]
                else:
                    tmp[str(k)] = SigRuleParamOverride(
                        value=norm["value"],
                        value_internal=norm["value_internal"],
                        source=norm["source"],
                        ml=norm["ml"],
                    )
            params = tmp or None
        cleaned[rid] = SigRuleOverride(
            enabled=ov.get("enabled") if isinstance(ov.get("enabled"), bool) else None,
            severity=ov.get("severity") if (
                isinstance(ov.get("severity"), str)
                and ov.get("severity", "").lower() in VALID_SEVERITIES
            ) else None,
            parameters=params,
        )
    return SigRulesOverrides(overrides=cleaned)


@router.put(
    "/overrides",
    response_model=SigRulesOverrides,
    dependencies=[Depends(require_admin)],
    summary="Overrides setzen (komplett ersetzen)",
)
async def put_overrides(body: SigRulesOverrides) -> SigRulesOverrides:
    # Schema pro Rule-ID einsammeln, damit wir Parameter-Werte clampen + auf
    # bekannte Param-Namen filtern können. Unbekannte Rule-IDs werden hier nicht
    # rausgefiltert (sonst sind Custom-Rules problematisch); Parameter-Cleanup
    # passiert nur, wenn die Rule-ID im aktuellen Repo-Stand bekannt ist.
    schema_by_rid: dict[str, dict[str, SigRuleParamSchema]] = {}
    for _, raw_rules, _ in _read_yaml_files():
        for raw in raw_rules:
            rid = str(raw.get("id") or "")
            if rid and rid not in schema_by_rid:
                schema_by_rid[rid] = _parse_yaml_param_schema(raw.get("parameters"))

    payload: dict[str, dict] = {}
    for rid, ov in body.overrides.items():
        entry: dict = {}
        if ov.enabled is not None:
            entry["enabled"] = ov.enabled
        if ov.severity is not None:
            entry["severity"] = ov.severity
        if ov.parameters:
            schema = schema_by_rid.get(rid, {})
            cleaned_params: dict[str, Any] = {}
            for pname, pval in ov.parameters.items():
                ps = schema.get(pname)
                # Pydantic hat den Eintrag bereits zu float ODER
                # SigRuleParamOverride aufgelöst. Wir normalisieren beides
                # auf {value, value_internal, source, ml}.
                if isinstance(pval, SigRuleParamOverride):
                    norm = {
                        "value": float(pval.value),
                        "value_internal": float(pval.value_internal) if pval.value_internal is not None else None,
                        "source": pval.source,
                        "ml": pval.ml,
                    }
                else:
                    norm = {"value": float(pval), "value_internal": None,
                            "source": None, "ml": None}

                if ps is None:
                    # Unbekannter Parameter: nur durchwinken wenn die ganze
                    # Rule unbekannt ist (Custom-File noch nicht gespeichert).
                    # Bei bekannter Rule mit unbekanntem Param: ignorieren.
                    if rid not in schema_by_rid:
                        cleaned_params[pname] = (
                            norm["value"] if _ov_is_trivial(norm) else norm
                        )
                    continue

                norm["value"] = _clamp_param(norm["value"], ps)
                if norm["value_internal"] is not None:
                    norm["value_internal"] = _clamp_param(norm["value_internal"], ps)

                # Trivial → Skalar für kompaktes File. Sonst Object-Form.
                cleaned_params[pname] = (
                    norm["value"] if _ov_is_trivial(norm) else norm
                )
            if cleaned_params:
                entry["parameters"] = cleaned_params
        if entry:
            payload[rid] = entry

    _write_overrides_file(payload)
    log.info("Sig-Rule-Overrides geschrieben: %d Einträge", len(payload))
    return await get_overrides()


# ── Suricata-SID-Overrides ─────────────────────────────────────────────────


class SuricataOverrideEntry(BaseModel):
    enabled:  bool | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None


class SuricataOverridesPayload(BaseModel):
    overrides: dict[str, SuricataOverrideEntry] = Field(default_factory=dict)


def _read_suricata_overrides_file() -> dict[str, dict]:
    if not SURICATA_OVERRIDES_FILE.exists():
        return {}
    try:
        data = json.loads(SURICATA_OVERRIDES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"Suricata-Overrides-Datei nicht lesbar: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _write_suricata_overrides_file(payload: dict[str, dict]) -> None:
    try:
        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SURICATA_OVERRIDES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(SURICATA_OVERRIDES_FILE)
    except OSError as exc:
        raise HTTPException(500, f"Suricata-Overrides-Datei nicht schreibbar: {exc}") from exc


@router.get(
    "/suricata-overrides",
    response_model=SuricataOverridesPayload,
    dependencies=[Depends(require_admin)],
    summary="Per-SID Severity-Override + Disable für Suricata-Regeln",
)
async def get_suricata_overrides() -> SuricataOverridesPayload:
    raw = _read_suricata_overrides_file()
    cleaned: dict[str, SuricataOverrideEntry] = {}
    for sid, ov in raw.items():
        if not isinstance(ov, dict):
            continue
        # Validate SID is numeric — wir akzeptieren nur Stringkeys mit int-Wert
        try:
            int(str(sid))
        except ValueError:
            continue
        cleaned[str(sid)] = SuricataOverrideEntry(
            enabled=ov.get("enabled") if isinstance(ov.get("enabled"), bool) else None,
            severity=ov.get("severity") if (
                isinstance(ov.get("severity"), str)
                and ov.get("severity", "").lower() in VALID_SEVERITIES
            ) else None,
        )
    return SuricataOverridesPayload(overrides=cleaned)


@router.put(
    "/suricata-overrides",
    response_model=SuricataOverridesPayload,
    dependencies=[Depends(require_admin)],
    summary="Suricata-SID-Overrides setzen (komplett ersetzen)",
)
async def put_suricata_overrides(body: SuricataOverridesPayload) -> SuricataOverridesPayload:
    payload: dict[str, dict] = {}
    for sid, ov in body.overrides.items():
        # Numerischen Schlüssel verlangen – snort-bridge filtert das ohnehin,
        # aber wir wollen kein Schrott-File schreiben.
        try:
            int(sid)
        except ValueError:
            continue
        entry: dict = {}
        if ov.enabled is not None:
            entry["enabled"] = ov.enabled
        if ov.severity is not None:
            entry["severity"] = ov.severity
        if entry:
            payload[str(sid)] = entry

    _write_suricata_overrides_file(payload)
    log.info("Suricata-SID-Overrides geschrieben: %d Einträge", len(payload))
    return await get_suricata_overrides()
