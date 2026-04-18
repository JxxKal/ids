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

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    tags: list[str]
    condition_src: str
    condition_code: Any  # compiled code object


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

        code = compile(condition_src, f"<rule:{rule_id}>", "eval")

        return Rule(
            id=rule_id,
            name=raw.get("name", rule_id),
            description=raw.get("description", ""),
            severity=severity,
            tags=list(raw.get("tags") or []),
            condition_src=condition_src,
            condition_code=code,
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
        """Gibt alle .yml-Dateien im rules_dir zurück, plus die eingebaute test.yml."""
        files: list[Path] = []
        if self._rules_dir.is_dir():
            # rglob durchsucht auch Unterverzeichnisse (builtin/, custom/, …)
            files = sorted(self._rules_dir.rglob("*.yml"))
        else:
            log.warning("Rules dir not found: %s", self._rules_dir)

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

        return False

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
        return rules
