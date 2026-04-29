"""
Rule Loader – lädt und kompiliert YAML-Regelfiles mit Hot-Reload.

Jede Regel hat folgende Felder:
  id          – eindeutige ID (z.B. SCAN_001)
  name        – Kurzname
  description – Beschreibung
  severity    – critical | high | medium | low
  tags        – Liste von Strings
  condition   – Python-Ausdruck (wird als Code-Objekt kompiliert)

Verfügbare Variablen in condition:
  flow  – das aktuell bewertete Flow-Dict
  ctx   – RuleContext-Instanz
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

log = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_PARAM_TYPES = {"int", "float"}

# Override-Datei für Per-Regel Disable + Severity-Override + Parameter-Tuning.
# Format:
#   { "DNS_AMP_001": {"enabled": false},
#     "SCAN_001":    {"parameters": {"port_count": 200, "window_s": 60}} }
# Liegt im custom/-Volume, damit GUI-Edits persistieren und der Loader sie via
# inotify-mtime aufpickt.
OVERRIDES_FILENAME = "_overrides.json"


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    tags: list[str]
    condition_src: str
    condition_code: Any   # compiled code object
    cooldown_s: int = 60  # Sekunden zwischen zwei Alerts derselben Regel+Src-IP
    # Parameter-Schema (aus YAML) und effektive Werte (Default ⊕ Override).
    # parameters_schema: { name: {type, default, min, max, label} }
    parameters_schema: dict[str, dict] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    params_ns: SimpleNamespace = field(default_factory=SimpleNamespace)


def _parse_param_schema(rule_id: str, raw_params: Any) -> dict[str, dict]:
    """Parst und validiert den `parameters:`-Block einer Rule.

    Erwartet ein Mapping {name: {type, default, min?, max?, label?}}. Akzeptiert
    auch Skalar-Default als Shortcut: `port_count: 50` → int mit default 50.
    Ungültige Einträge werden geloggt und übersprungen, statt die Rule zu killen.
    """
    if raw_params is None:
        return {}
    if not isinstance(raw_params, dict):
        log.warning("Rule %s: 'parameters' muss ein Mapping sein – ignoriert", rule_id)
        return {}

    out: dict[str, dict] = {}
    for name, spec in raw_params.items():
        if not isinstance(name, str) or not name.isidentifier():
            log.warning("Rule %s: Parameter-Name '%s' ist kein gültiger Bezeichner – übersprungen", rule_id, name)
            continue
        # Shortcut: `port_count: 50` → {type, default}
        if isinstance(spec, (int, float)) and not isinstance(spec, bool):
            ptype = "float" if isinstance(spec, float) else "int"
            out[name] = {"type": ptype, "default": spec, "min": None, "max": None, "label": ""}
            continue
        if not isinstance(spec, dict):
            log.warning("Rule %s: Parameter '%s' hat unerwartetes Format – übersprungen", rule_id, name)
            continue
        ptype = str(spec.get("type", "int")).lower()
        if ptype not in VALID_PARAM_TYPES:
            log.warning("Rule %s: Parameter '%s' hat unbekannten Typ '%s' – übersprungen", rule_id, name, ptype)
            continue
        if "default" not in spec:
            log.warning("Rule %s: Parameter '%s' hat keinen 'default' – übersprungen", rule_id, name)
            continue
        try:
            default_val = float(spec["default"]) if ptype == "float" else int(spec["default"])
        except (TypeError, ValueError):
            log.warning("Rule %s: Parameter '%s' default nicht in %s konvertierbar – übersprungen", rule_id, name, ptype)
            continue
        min_val = spec.get("min")
        max_val = spec.get("max")
        try:
            min_val = (float(min_val) if ptype == "float" else int(min_val)) if min_val is not None else None
            max_val = (float(max_val) if ptype == "float" else int(max_val)) if max_val is not None else None
        except (TypeError, ValueError):
            log.warning("Rule %s: Parameter '%s' min/max ungültig – auf None gesetzt", rule_id, name)
            min_val = max_val = None
        if min_val is not None and max_val is not None and min_val > max_val:
            log.warning("Rule %s: Parameter '%s' min > max – min/max ignoriert", rule_id, name)
            min_val = max_val = None
        out[name] = {
            "type": ptype,
            "default": default_val,
            "min": min_val,
            "max": max_val,
            "label": str(spec.get("label", "")),
        }
    return out


def _compile_rule(raw: dict, source_file: str) -> Rule | None:
    """Validiert und kompiliert eine einzelne Regel. Gibt None zurück bei Fehler."""
    rule_id = raw.get("id", "<unknown>")
    try:
        severity = raw.get("severity", "medium").lower()
        if severity not in VALID_SEVERITIES:
            log.warning("Rule %s has invalid severity '%s', defaulting to 'medium'", rule_id, severity)
            severity = "medium"

        condition_src = raw.get("condition", "").strip()
        if not condition_src:
            log.error("Rule %s in %s has empty condition – skipped", rule_id, source_file)
            return None

        # Mehrzeilige YAML-Conditions (block scalar |) in Klammern einwickeln,
        # damit Python-eval Zeilenumbrüche bei and/or-Ketten akzeptiert.
        code = compile(f"(\n{condition_src}\n)", f"<rule:{rule_id}>", "eval")

        params_schema = _parse_param_schema(rule_id, raw.get("parameters"))
        params_default = {n: s["default"] for n, s in params_schema.items()}

        return Rule(
            id=rule_id,
            name=raw.get("name", rule_id),
            description=raw.get("description", ""),
            severity=severity,
            tags=list(raw.get("tags") or []),
            condition_src=condition_src,
            condition_code=code,
            cooldown_s=int(raw.get("cooldown_s", 60)),
            parameters_schema=params_schema,
            parameters=params_default,
            params_ns=SimpleNamespace(**params_default),
        )
    except SyntaxError as exc:
        log.error("Rule %s in %s has syntax error: %s – skipped", rule_id, source_file, exc)
        return None
    except Exception as exc:
        log.error("Rule %s in %s failed to compile: %s – skipped", rule_id, source_file, exc)
        return None


def load_rules_from_file(path: str | Path) -> list[Rule]:
    """Lädt alle Regeln aus einer einzelnen YAML-Datei."""
    path = Path(path)
    rules: list[Rule] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw_list = yaml.safe_load(fh)
        if not isinstance(raw_list, list):
            log.error("Rule file %s does not contain a YAML list – skipped", path)
            return rules
        for raw in raw_list:
            rule = _compile_rule(raw, str(path))
            if rule is not None:
                rules.append(rule)
    except FileNotFoundError:
        log.error("Rule file not found: %s", path)
    except yaml.YAMLError as exc:
        log.error("YAML parse error in %s: %s", path, exc)
    except Exception as exc:
        log.error("Unexpected error loading %s: %s", path, exc)
    return rules


class RuleLoader:
    """
    Verwaltet alle geladenen Regeln und erkennt Änderungen für Hot-Reload.

    Laden:
      loader = RuleLoader(rules_dir)
      loader.load()        # initiales Laden
      loader.reload_if_changed()  # periodisch aufrufen

    Zugriff:
      loader.rules  → List[Rule]
    """

    # test.yml wird immer geladen, unabhängig vom rules_dir
    _BUILTIN_FILE = Path(__file__).parent.parent / "rules" / "test.yml"

    def __init__(self, rules_dir: str) -> None:
        self._rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        # {path: mtime}
        self._mtimes: dict[Path, float] = {}
        # Override-Tracking (separat von YAML-Files, aber gleicher Reload-Trigger)
        self._overrides_path: Path | None = None
        self._overrides_mtime: float = 0.0
        self._overrides: dict[str, dict] = {}

    def load(self) -> None:
        """Erstes vollständiges Laden aller Regeln."""
        self.rules = self._load_all()
        log.info("Loaded %d rules from %s", len(self.rules), self._rules_dir)

    def reload_if_changed(self) -> bool:
        """
        Prüft ob sich Regelfiles geändert haben; lädt falls ja neu.
        Gibt True zurück wenn ein Reload stattgefunden hat.
        """
        if not self._has_changed():
            return False
        self.rules = self._load_all()
        log.info("Rules reloaded: %d rules active", len(self.rules))
        return True

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────────

    def _yaml_files(self) -> list[Path]:
        """Gibt alle .yml-Dateien im rules_dir zurück, plus die eingebaute test.yml.

        Sortier-Priorität: custom/ vor builtin/. Damit gewinnen Custom-Dateien
        bei doppelten Rule-IDs gegen die Builtin-Variante – und der User kann
        eine builtin-Regel "überschreiben", indem er ihre ID in einer eigenen
        Datei unter custom/ mit anderen Schwellwerten erneut definiert. Der
        Loader skippt dann beim zweiten Auftauchen den builtin-Eintrag.
        """
        files: list[Path] = []
        if self._rules_dir.is_dir():
            # rglob durchsucht auch Unterverzeichnisse (builtin/, custom/, …)
            files = list(self._rules_dir.rglob("*.yml"))
        else:
            log.warning("Rules dir not found: %s", self._rules_dir)

        # custom/-Pfade kriegen Vorrang vor builtin/-Pfaden, dann alphabetisch.
        def _priority(p: Path) -> tuple[int, str]:
            return (0 if "custom" in p.parts else 1, str(p))
        files.sort(key=_priority)

        # Eingebaute Test-Signatur immer einschließen (falls nicht schon drin)
        if self._BUILTIN_FILE.exists() and self._BUILTIN_FILE not in files:
            files.append(self._BUILTIN_FILE)

        return files

    def _has_changed(self) -> bool:
        files = self._yaml_files()
        current_paths = {f for f in files}
        known_paths = set(self._mtimes.keys())

        # Neue oder gelöschte Dateien
        if current_paths != known_paths:
            return True

        # Geänderte mtimes
        for f in files:
            try:
                mtime = f.stat().st_mtime
            except OSError:
                return True
            if self._mtimes.get(f) != mtime:
                return True

        # Auch _overrides.json triggert Reload
        op = self._find_overrides_file()
        try:
            new_om = op.stat().st_mtime if op and op.exists() else 0.0
        except OSError:
            new_om = 0.0
        if new_om != self._overrides_mtime:
            return True

        return False

    def _find_overrides_file(self) -> Path | None:
        """_overrides.json bevorzugt im custom/-Subdir suchen, fallback auf rules_dir."""
        if not self._rules_dir.is_dir():
            return None
        candidates = [
            self._rules_dir / "custom" / OVERRIDES_FILENAME,
            self._rules_dir / OVERRIDES_FILENAME,
        ]
        for c in candidates:
            if c.exists():
                return c
        # Default: custom/_overrides.json (auch wenn noch nicht existiert),
        # damit der Pfad fürs spätere Schreiben deterministisch ist.
        return candidates[0]

    def _load_overrides(self) -> dict[str, dict]:
        op = self._find_overrides_file()
        try:
            mtime = op.stat().st_mtime if op and op.exists() else 0.0
        except OSError:
            mtime = 0.0
        self._overrides_mtime = mtime

        if not op or not op.exists():
            return {}

        try:
            data = json.loads(op.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("_overrides.json konnte nicht gelesen werden (%s): %s", op, exc)
            return {}

        if not isinstance(data, dict):
            log.warning("_overrides.json hat unerwartetes Format (kein Objekt): %s", op)
            return {}

        cleaned: dict[str, dict] = {}
        for rule_id, ov in data.items():
            if not isinstance(ov, dict):
                continue
            entry: dict = {}
            if "enabled" in ov and isinstance(ov["enabled"], bool):
                entry["enabled"] = ov["enabled"]
            sev = ov.get("severity")
            if isinstance(sev, str) and sev.lower() in VALID_SEVERITIES:
                entry["severity"] = sev.lower()
            params = ov.get("parameters")
            if isinstance(params, dict) and params:
                # Roh übernehmen — Validierung gegen Schema passiert in _apply_overrides,
                # weil das Schema rule-spezifisch ist und hier noch nicht verfügbar.
                entry["parameters"] = {
                    str(k): v for k, v in params.items()
                    if isinstance(v, (int, float)) and not isinstance(v, bool)
                }
            if entry:
                cleaned[rule_id] = entry
        return cleaned

    def _apply_overrides(self, rules: list[Rule]) -> list[Rule]:
        if not self._overrides:
            return rules
        out: list[Rule] = []
        suppressed = 0
        adjusted = 0
        param_tuned = 0
        for r in rules:
            ov = self._overrides.get(r.id)
            if ov is None:
                out.append(r)
                continue
            if ov.get("enabled") is False:
                suppressed += 1
                continue
            new_severity = r.severity
            sev_override = ov.get("severity")
            if sev_override and sev_override != r.severity:
                new_severity = sev_override
                adjusted += 1

            new_params = dict(r.parameters)
            raw_param_ov = ov.get("parameters") or {}
            param_changed = False
            for name, value in raw_param_ov.items():
                schema = r.parameters_schema.get(name)
                if schema is None:
                    log.warning("Override für Rule %s: unbekannter Parameter '%s' – ignoriert", r.id, name)
                    continue
                try:
                    cast = float(value) if schema["type"] == "float" else int(value)
                except (TypeError, ValueError):
                    log.warning("Override für Rule %s: Parameter '%s' Wert nicht castbar – ignoriert", r.id, name)
                    continue
                lo, hi = schema.get("min"), schema.get("max")
                if lo is not None and cast < lo:
                    log.warning("Override für Rule %s: Parameter '%s'=%s < min %s – auf min gesetzt", r.id, name, cast, lo)
                    cast = lo
                if hi is not None and cast > hi:
                    log.warning("Override für Rule %s: Parameter '%s'=%s > max %s – auf max gesetzt", r.id, name, cast, hi)
                    cast = hi
                if cast != new_params.get(name):
                    new_params[name] = cast
                    param_changed = True
            if param_changed:
                param_tuned += 1

            if new_severity != r.severity or param_changed:
                r = Rule(
                    id=r.id, name=r.name, description=r.description,
                    severity=new_severity, tags=r.tags,
                    condition_src=r.condition_src, condition_code=r.condition_code,
                    cooldown_s=r.cooldown_s,
                    parameters_schema=r.parameters_schema,
                    parameters=new_params,
                    params_ns=SimpleNamespace(**new_params),
                )
            out.append(r)
        if suppressed or adjusted or param_tuned:
            log.info(
                "Overrides angewendet: %d disabled, %d severity-override, %d parameter-tuned",
                suppressed, adjusted, param_tuned,
            )
        return out

    def _load_all(self) -> list[Rule]:
        files = self._yaml_files()
        new_mtimes: dict[Path, float] = {}
        rules: list[Rule] = []
        seen_ids: set[str] = set()

        for f in files:
            try:
                mtime = f.stat().st_mtime
            except OSError:
                mtime = 0.0
            new_mtimes[f] = mtime

            for rule in load_rules_from_file(f):
                if rule.id in seen_ids:
                    log.warning("Duplicate rule id '%s' in %s – skipped", rule.id, f)
                    continue
                seen_ids.add(rule.id)
                rules.append(rule)

        self._mtimes = new_mtimes

        # Overrides aus _overrides.json einlesen + anwenden (disabled raus,
        # severity-override patcht das Rule-Objekt). Mtime wird in
        # _load_overrides gesetzt, damit _has_changed() den File-Touch erkennt.
        self._overrides = self._load_overrides()
        return self._apply_overrides(rules)
