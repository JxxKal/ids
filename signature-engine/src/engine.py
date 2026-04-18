"""
Signature Engine – wertet Regeln gegen eingehende Flows aus.

Für jede Regel wird die kompilierte Condition gegen den Flow evaluiert.
Bei einem Match wird ein Alert-Dict erzeugt und zurückgegeben.

Alert-Schema:
  rule_id       – z.B. "SCAN_001"
  rule_name     – Kurzname der Regel
  severity      – critical | high | medium | low
  tags          – Liste von Strings
  description   – Regelbeschreibung
  src_ip        – Quell-IP aus dem Flow
  dst_ip        – Ziel-IP aus dem Flow
  dst_port      – Ziel-Port (oder null)
  proto         – Protokoll (oder null)
  flow_id       – flow.get('flow_id')
  ts            – Zeitstempel des Flows (end_ts oder jetzt)
"""
from __future__ import annotations

import logging
import time
from typing import Any

from context import RuleContext
from loader import Rule, RuleLoader

log = logging.getLogger(__name__)

# Erlaubte Builtins für Regel-Conditions (Sicherheits-Sandbox)
_SAFE_BUILTINS: dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "round": round,
    "set": set,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "True": True,
    "False": False,
    "None": None,
}

_EVAL_GLOBALS: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}


class SignatureEngine:
    """
    Verwaltet RuleLoader und RuleContext; bewertet Flows gegen alle aktiven Regeln.

    Verwendung:
      engine = SignatureEngine(rules_dir)
      engine.setup()

      # pro Flow:
      alerts = engine.evaluate(flow_dict)
      engine.maybe_reload()   # periodisch aufrufen
    """

    def __init__(self, rules_dir: str) -> None:
        self._loader = RuleLoader(rules_dir)
        self._ctx = RuleContext()

    def setup(self) -> None:
        """Regeln initial laden."""
        self._loader.load()

    def maybe_reload(self) -> bool:
        """Hot-Reload wenn Regelfiles geändert wurden."""
        return self._loader.reload_if_changed()

    @property
    def rule_count(self) -> int:
        return len(self._loader.rules)

    def evaluate(self, flow: dict) -> list[dict]:
        """
        Registriert den Flow im Kontext, dann wertet jede Regel aus.
        Gibt eine Liste von Alert-Dicts zurück (kann leer sein).

        Hinweis: stats-Felder (tcp_flags_abs, pps, duration_s, …) werden vor
        der Auswertung in die oberste Ebene des Flow-Dicts gemergt, damit
        Regelausdrücke direkt mit flow.get('tcp_flags_abs', …) arbeiten können.
        """
        # stats-Dict flach in den Flow mergen (top-level-Felder bleiben erhalten)
        flat = {**flow, **flow.get("stats", {})}

        self._ctx.record(flat)

        alerts: list[dict] = []
        local_vars = {"flow": flat, "ctx": self._ctx}
        eval_globals = _EVAL_GLOBALS

        for rule in self._loader.rules:
            try:
                match = eval(rule.condition_code, eval_globals, local_vars)  # noqa: S307
            except Exception as exc:
                log.debug("Rule %s eval error: %s", rule.id, exc)
                continue

            if match:
                alerts.append(_make_alert(rule, flow))

        return alerts


def _make_alert(rule: Rule, flow: dict) -> dict:
    return {
        "rule_id":     rule.id,
        "rule_name":   rule.name,
        "severity":    rule.severity,
        "tags":        rule.tags,
        "description": rule.description,
        "src_ip":      flow.get("src_ip"),
        "dst_ip":      flow.get("dst_ip"),
        "dst_port":    flow.get("dst_port"),
        "proto":       flow.get("proto"),
        "flow_id":     flow.get("flow_id"),
        "ts":          float(flow.get("end_ts") or time.time()),
    }
