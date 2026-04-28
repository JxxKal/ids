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
from typing import Any

import yaml

log = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Override-Datei für Per-Regel Disable + Severity-Override.
# Format:
#   { "DNS_AMP_001": {"enabled": false, "severity": null},
#     "SCAN_002":    {"enabled": true,  "severity": "low"} }
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

        return Rule(
            id=rule_id,
            name=raw.get("name", rule_id),
            description=raw.get("description", ""),
            severity=severity,
            tags=list(raw.get("tags") or []),
            condition_src=condition_src,
            condition_code=code,
            cooldown_s=int(raw.get("cooldown_s", 60)),
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
            if entry:
                cleaned[rule_id] = entry
        return cleaned

    def _apply_overrides(self, rules: list[Rule]) -> list[Rule]:
        if not self._overrides:
            return rules
        out: list[Rule] = []
        suppressed = 0
        adjusted = 0
        for r in rules:
            ov = self._overrides.get(r.id)
            if ov is None:
                out.append(r)
                continue
            if ov.get("enabled") is False:
                suppressed += 1
                continue
            sev_override = ov.get("severity")
            if sev_override and sev_override != r.severity:
                r = Rule(
                    id=r.id, name=r.name, description=r.description,
                    severity=sev_override, tags=r.tags,
                    condition_src=r.condition_src, condition_code=r.condition_code,
                    cooldown_s=r.cooldown_s,
                )
                adjusted += 1
            out.append(r)
        if suppressed or adjusted:
            log.info("Overrides angewendet: %d disabled, %d severity-override", suppressed, adjusted)
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
