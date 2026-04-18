"""
Signature Engine – wertet Regeln gegen eingehende Flows aus.

Neuerungen:
- Cooldown pro (rule_id, src_ip): verhindert Alert-Flooding
- Dynamische Beschreibung: zeigt zur Laufzeit gemessene Werte (Ports, Flows, …)
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
    "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict,
    "float": float, "int": int, "isinstance": isinstance, "len": len,
    "list": list, "max": max, "min": min, "round": round, "set": set,
    "str": str, "sum": sum, "tuple": tuple,
    "True": True, "False": False, "None": None,
}
_EVAL_GLOBALS: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}


class SignatureEngine:
    def __init__(self, rules_dir: str) -> None:
        self._loader  = RuleLoader(rules_dir)
        self._ctx     = RuleContext()
        # {(rule_id, src_ip): last_fired_ts}
        self._cooldowns: dict[tuple[str, str], float] = {}

    def setup(self) -> None:
        self._loader.load()

    def maybe_reload(self) -> bool:
        return self._loader.reload_if_changed()

    @property
    def rule_count(self) -> int:
        return len(self._loader.rules)

    def evaluate(self, flow: dict) -> list[dict]:
        # stats-Dict flach in den Flow mergen
        flat = {**flow, **flow.get("stats", {})}
        self._ctx.record(flat)

        now        = time.time()
        alerts     = []
        local_vars = {"flow": flat, "ctx": self._ctx}

        for rule in self._loader.rules:
            try:
                match = eval(rule.condition_code, _EVAL_GLOBALS, local_vars)  # noqa: S307
            except Exception as exc:
                log.debug("Rule %s eval error: %s", rule.id, exc)
                continue

            if not match:
                continue

            # ── Cooldown-Prüfung ──────────────────────────────────────────────
            src_ip = flat.get("src_ip") or ""
            key    = (rule.id, src_ip)
            if now - self._cooldowns.get(key, 0.0) < rule.cooldown_s:
                continue   # zu kurz nach dem letzten Alert dieser Regel+IP

            self._cooldowns[key] = now
            alerts.append(_make_alert(rule, flat, self._ctx))

        return alerts


# ── Alert-Erstellung mit dynamischer Beschreibung ─────────────────────────────

def _make_alert(rule: Rule, flow: dict, ctx: RuleContext) -> dict:
    src_ip = flow.get("src_ip") or ""

    # Kontextwerte zum Zeitpunkt des Feuerns sammeln
    unique_ports = ctx.unique_dst_ports(src_ip, 60)
    unique_ips   = ctx.unique_dst_ips(src_ip, 60)
    flow_rate_30 = ctx.flow_rate(src_ip, 30)
    syn_10       = ctx.syn_count(src_ip, 10)

    # Dynamische Zusatzinfos je nach Regel-Tags
    tags = set(rule.tags)
    extras: list[str] = []

    if "scan" in tags and unique_ports > 1:
        extras.append(f"{unique_ports} Ports")
    if unique_ips > 1 and ("recon" in tags or "scan" in tags):
        extras.append(f"{unique_ips} Ziel-IPs")
    if "flood" in tags or "dos" in tags:
        if syn_10 > 0:
            extras.append(f"{syn_10} SYNs/10s")
        elif flow_rate_30 > 0:
            extras.append(f"{flow_rate_30} Flows/30s")
    if not extras and flow_rate_30 > 0:
        extras.append(f"{flow_rate_30} Flows/30s")

    description = rule.description
    if extras:
        description = f"{description} – {', '.join(extras)}"

    return {
        "rule_id":     rule.id,
        "rule_name":   rule.name,
        "severity":    rule.severity,
        "tags":        rule.tags,
        "description": description,
        "src_ip":      flow.get("src_ip"),
        "dst_ip":      flow.get("dst_ip"),
        "dst_port":    flow.get("dst_port"),
        "proto":       flow.get("proto"),
        "flow_id":     flow.get("flow_id"),
        "ts":          float(flow.get("end_ts") or time.time()),
        "is_test":     bool(flow.get("is_test", False)),
    }
