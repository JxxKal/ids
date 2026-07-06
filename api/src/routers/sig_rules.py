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

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import asyncpg
import yaml
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from database import get_pool
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
    # Version-Tag des _overrides.json-Standes für Optimistic-Concurrency. Wird
    # von GET gesetzt; PUT ignoriert das Body-Feld und liest den If-Match-Header
    # (siehe put_overrides). Optional — GUI-Clients ohne Concurrency-Check
    # lassen es weg.
    version: str | None = None


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


def _overrides_version() -> str:
    """Version-Tag des aktuellen _overrides.json-Standes für Optimistic-
    Concurrency. Hash der rohen Datei-Bytes; '0' wenn die Datei (noch) nicht
    existiert. Ändert sich bei jedem Schreibvorgang (GUI oder rule-tuner),
    sodass ein zwischenzeitlicher Fremd-Write vom If-Match-Check beim PUT
    erkannt wird."""
    if not OVERRIDES_FILE.exists():
        return "0"
    try:
        return hashlib.sha256(OVERRIDES_FILE.read_bytes()).hexdigest()
    except OSError:
        return "0"


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
    return SigRulesOverrides(overrides=cleaned, version=_overrides_version())


@router.put(
    "/overrides",
    response_model=SigRulesOverrides,
    dependencies=[Depends(require_admin)],
    summary="Overrides setzen (komplett ersetzen)",
)
async def put_overrides(
    body: SigRulesOverrides,
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> SigRulesOverrides:
    # Optimistic-Concurrency: schickt der Client ein If-Match (nur der
    # rule-tuner tut das), lehnen wir mit 409 ab, falls die Datei seit seinem
    # GET fremd-geschrieben wurde — sonst würde ein stale Merge z.B. einen frisch
    # gesetzten source=manual-Lock aus der GUI überschreiben. Version-Check und
    # Write laufen ohne await dazwischen im selben Event-Loop, sind also atomar.
    # GUI-Clients ohne If-Match behalten das bisherige Last-Writer-Wins-Verhalten.
    if if_match is not None and if_match != _overrides_version():
        raise HTTPException(409, "Overrides-Datei wurde zwischenzeitlich geändert (Version-Mismatch)")

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


# ── ML-Tuning State + Baselines (Phase 3) ─────────────────────────────────────
#
# Endpoints unter /api/sig-rules/ml/. Werden vom Phase-5-Frontend (Settings →
# Rule Adjustments → Tab "ML-Tuning") sowie vom Phase-4-rule-tuner-Service
# konsumiert. Die State-Transitions sind absichtlich minimal — der eigentliche
# tuning-Loop läuft als separater Service, der den State nur als Eingabe liest
# und nach Trainingsende selbst auf "tuning" hochsetzt (kein Endpoint dafür,
# damit die UI nichts versehentlich überschreibt).

ML_VALID_STATES = {"idle", "training", "tuning", "paused"}


class MlTuningState(BaseModel):
    state: Literal["idle", "training", "tuning", "paused"] = "idle"
    started_at: str | None = None
    training_until: str | None = None
    last_tuning_at: str | None = None
    # paused_from speichert den State vor pause(), damit resume() den
    # vorherigen Zustand wiederherstellt — sonst landet man immer in 'tuning'
    # und überspringt eine evtl. noch laufende Trainingsphase.
    paused_from: Literal["idle", "training", "tuning"] | None = None


class MlTuningConfig(BaseModel):
    window_s: int = 36000
    target_alert_rate_per_hour: float = 0.5
    scope_split_enabled: bool = True
    quantile: float = 0.995
    max_change_per_cycle: float = 0.20
    blacklist: list[str] = Field(default_factory=list)


class MlTuningStatus(BaseModel):
    state: MlTuningState
    config: MlTuningConfig
    total_samples: int


class StartTrainingPayload(BaseModel):
    """Optionaler Override aller config-Werte. Nicht-übergebene Felder bleiben
    wie aktuell in system_config.ml_tuning_config gespeichert."""
    window_s: int | None = Field(default=None, ge=60, le=30 * 24 * 3600)
    target_alert_rate_per_hour: float | None = Field(default=None, ge=0.0)
    scope_split_enabled: bool | None = None
    quantile: float | None = Field(default=None, ge=0.5, le=0.9999)
    max_change_per_cycle: float | None = Field(default=None, ge=0.0, le=1.0)
    blacklist: list[str] | None = None


class BaselineEntry(BaseModel):
    rule_id: str
    param_name: str
    scope: Literal["internal", "external", "global"]
    p50: float | None
    p99: float | None
    p995: float | None
    p999: float | None
    sample_count: int
    updated_at: str


# Der api-Pool installiert in database._init_conn() einen json/jsonb-Codec
# (json.dumps als encoder, json.loads als decoder). asyncpg wendet ihn bei
# JSONB-Spalten *automatisch* an — Python-Dicts gehen direkt rein, gelesene
# Werte kommen direkt als Dict zurück. Eigenes json.dumps/loads würde
# doppelt kodieren (Object → JSON-String → JSONB-String).

async def _read_state(conn: asyncpg.Connection) -> dict:
    row = await conn.fetchrow(
        "SELECT value FROM system_config WHERE key='ml_tuning_state'"
    )
    if not row or not isinstance(row["value"], dict):
        return {"state": "idle"}
    return row["value"]


async def _read_config(conn: asyncpg.Connection) -> dict:
    row = await conn.fetchrow(
        "SELECT value FROM system_config WHERE key='ml_tuning_config'"
    )
    if not row or not isinstance(row["value"], dict):
        return {}
    return row["value"]


async def _write_state(conn: asyncpg.Connection, payload: dict) -> None:
    await conn.execute(
        """
        INSERT INTO system_config (key, value)
        VALUES ('ml_tuning_state', $1::jsonb)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """,
        payload,
    )


async def _write_config(conn: asyncpg.Connection, payload: dict) -> None:
    await conn.execute(
        """
        INSERT INTO system_config (key, value)
        VALUES ('ml_tuning_config', $1::jsonb)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """,
        payload,
    )


async def _build_status(conn: asyncpg.Connection) -> MlTuningStatus:
    state = await _read_state(conn)
    cfg = await _read_config(conn)
    total = await conn.fetchval(
        "SELECT COALESCE(SUM(sample_count), 0)::bigint FROM rule_baselines"
    ) or 0
    return MlTuningStatus(
        state=MlTuningState(**{k: state.get(k) for k in MlTuningState.model_fields}),
        config=MlTuningConfig(**{k: cfg.get(k) for k in MlTuningConfig.model_fields if k in cfg}),
        total_samples=int(total),
    )


@router.get(
    "/ml/status",
    response_model=MlTuningStatus,
    dependencies=[Depends(require_admin)],
    summary="ML-Tuning Status + Konfiguration + globaler Sample-Count",
)
async def ml_status(pool: asyncpg.Pool = Depends(get_pool)) -> MlTuningStatus:
    async with pool.acquire() as conn:
        return await _build_status(conn)


@router.post(
    "/ml/start-training",
    response_model=MlTuningStatus,
    dependencies=[Depends(require_admin)],
    summary="Trainings-Phase starten (idle/paused/tuning → training)",
)
async def ml_start_training(
    body: StartTrainingPayload,
    pool: asyncpg.Pool = Depends(get_pool),
) -> MlTuningStatus:
    """Setzt state='training' und merged optional übergebene Config-Werte in
    system_config.ml_tuning_config. Aus 'training' heraus erneut aufgerufen
    bewirkt einen Restart mit neuem Fenster — das ist gewünscht (User möchte
    z.B. blacklist mid-flight ändern).
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            cur_cfg = await _read_config(conn)
            merged: dict[str, Any] = {**MlTuningConfig().model_dump(), **cur_cfg}
            if body.window_s is not None:
                merged["window_s"] = int(body.window_s)
            if body.target_alert_rate_per_hour is not None:
                merged["target_alert_rate_per_hour"] = float(body.target_alert_rate_per_hour)
            if body.scope_split_enabled is not None:
                merged["scope_split_enabled"] = bool(body.scope_split_enabled)
            if body.quantile is not None:
                merged["quantile"] = float(body.quantile)
            if body.max_change_per_cycle is not None:
                merged["max_change_per_cycle"] = float(body.max_change_per_cycle)
            if body.blacklist is not None:
                merged["blacklist"] = sorted({str(x) for x in body.blacklist})
            await _write_config(conn, merged)

            cur_state = await _read_state(conn)
            now = datetime.now(timezone.utc)
            until = now + timedelta(seconds=int(merged["window_s"]))
            new_state = {
                "state": "training",
                "started_at": now.isoformat(),
                "training_until": until.isoformat(),
                "last_tuning_at": cur_state.get("last_tuning_at"),
                "paused_from": None,
            }
            await _write_state(conn, new_state)
            log.info("ML-Tuning Training gestartet (window_s=%d, until=%s)",
                     merged["window_s"], until.isoformat())
        return await _build_status(conn)


@router.post(
    "/ml/pause",
    response_model=MlTuningStatus,
    dependencies=[Depends(require_admin)],
    summary="Tuner pausieren (training/tuning → paused, idempotent)",
)
async def ml_pause(pool: asyncpg.Pool = Depends(get_pool)) -> MlTuningStatus:
    async with pool.acquire() as conn:
        async with conn.transaction():
            cur = await _read_state(conn)
            if cur.get("state") == "paused":
                return await _build_status(conn)
            prev = cur.get("state") or "idle"
            if prev not in ("idle", "training", "tuning"):
                prev = "idle"
            cur["paused_from"] = prev
            cur["state"] = "paused"
            await _write_state(conn, cur)
            log.info("ML-Tuning pausiert (paused_from=%s)", prev)
        return await _build_status(conn)


@router.post(
    "/ml/resume",
    response_model=MlTuningStatus,
    dependencies=[Depends(require_admin)],
    summary="Tuner wieder anlaufen lassen (paused → vorheriger State)",
)
async def ml_resume(pool: asyncpg.Pool = Depends(get_pool)) -> MlTuningStatus:
    async with pool.acquire() as conn:
        async with conn.transaction():
            cur = await _read_state(conn)
            if cur.get("state") != "paused":
                raise HTTPException(409, f"Aktueller State {cur.get('state')!r} ist nicht 'paused'")
            target = cur.get("paused_from") or "idle"
            if target not in ("idle", "training", "tuning"):
                target = "idle"
            # Wenn paused_from='training' aber training_until bereits abgelaufen
            # ist, springen wir direkt nach 'tuning' — der rule-tuner nimmt das
            # so auf, ohne dass das Fenster künstlich verlängert wird.
            if target == "training":
                ti = cur.get("training_until")
                if ti:
                    try:
                        if datetime.fromisoformat(ti) <= datetime.now(timezone.utc):
                            target = "tuning"
                    except ValueError:
                        pass
            cur["state"] = target
            cur["paused_from"] = None
            await _write_state(conn, cur)
            log.info("ML-Tuning resumed → %s", target)
        return await _build_status(conn)


@router.get(
    "/ml/baselines",
    response_model=list[BaselineEntry],
    dependencies=[Depends(require_admin)],
    summary="Quantile-Baselines pro (rule, param, scope) für UI-Sparklines",
)
async def ml_baselines(
    rule_id: str | None = None,
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[BaselineEntry]:
    async with pool.acquire() as conn:
        if rule_id:
            rows = await conn.fetch(
                """
                SELECT rule_id, param_name, scope, p50, p99, p995, p999,
                       sample_count, updated_at
                  FROM rule_baselines
                 WHERE rule_id = $1
                 ORDER BY param_name, scope
                """,
                rule_id,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT rule_id, param_name, scope, p50, p99, p995, p999,
                       sample_count, updated_at
                  FROM rule_baselines
                 ORDER BY rule_id, param_name, scope
                """
            )
    return [
        BaselineEntry(
            rule_id=r["rule_id"],
            param_name=r["param_name"],
            scope=r["scope"],
            p50=r["p50"],
            p99=r["p99"],
            p995=r["p995"],
            p999=r["p999"],
            sample_count=int(r["sample_count"]),
            updated_at=r["updated_at"].isoformat(),
        )
        for r in rows
    ]
