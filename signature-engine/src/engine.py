"""
Signature Engine – wertet Regeln gegen eingehende Flows aus.

Neuerungen:
- Cooldown pro (rule_id, src_ip): verhindert Alert-Flooding
- Dynamische Beschreibung: zeigt zur Laufzeit gemessene Werte (Ports, Flows, …)
- Flow-kontextabhängiger Param-Resolver: liest `value_internal` statt `value`,
  wenn der Quell-Host in einem `known_networks`-CIDR liegt. Fehlt der Split
  (kein `value_internal` gesetzt oder leeres known_networks-File), wird
  überall der globale `value` benutzt → kein Verhaltensunterschied zur Ära
  vor Phase 1.
- Phase 2 Shadow-Metrik: `compute_metrics(flow)` liefert pro `(rule, param)`
  mit `metric:`-Deklaration im YAML einen Telemetry-Eintrag. Wert wird mit
  den aktuellen effektiven Params (scope-aware) berechnet — auch wenn die
  Rule-Condition nicht feuert. Aufrufer (main.py) entscheidet via Sampling
  ob/wie oft tatsächlich emittiert wird.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable

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


# ── Metric-Funktions-Registry (Phase 2 Shadow-Metrik-Pipeline) ────────────────
#
# Jeder symbolische `metric:`-Name aus dem Rule-YAML wird hier auf eine
# Berechnungs-Funktion gemappt. Signatur:
#     metric_fn(ctx, flow, params) -> int | float
# wobei `params` ein _FlowParams-Resolver ist (siehe unten) – damit fenster-
# basierte Metriken den aktuellen `window_s`-Wert der Rule benutzen, inkl.
# scope-aware Override (`value_internal` vs `value`).
#
# Erweiterung: einfach hier eine neue Funktion hinzufügen und im YAML
# `metric: <name>` setzen. Kein Schema-Migrationsbedarf.

def _metric_unique_dst_ports(ctx: "RuleContext", flow: dict, params: "_FlowParams") -> int:
    return ctx.unique_dst_ports(flow.get("src_ip", "") or "", params.window_s)


def _metric_unique_dst_ips(ctx: "RuleContext", flow: dict, params: "_FlowParams") -> int:
    return ctx.unique_dst_ips(flow.get("src_ip", "") or "", params.window_s)


def _metric_flow_rate(ctx: "RuleContext", flow: dict, params: "_FlowParams") -> int:
    return ctx.flow_rate(flow.get("src_ip", "") or "", params.window_s)


def _metric_syn_count(ctx: "RuleContext", flow: dict, params: "_FlowParams") -> int:
    return ctx.syn_count(flow.get("src_ip", "") or "", params.window_s)


def _metric_pps(ctx: "RuleContext", flow: dict, params: "_FlowParams") -> float:
    # Flow-intrinsisch — kein Window. Float-fähig (flow-aggregator schreibt
    # round(.., 2)).
    return float(flow.get("pps", 0) or 0)


METRIC_FUNCS: dict[str, Callable[["RuleContext", dict, "_FlowParams"], Any]] = {
    "unique_dst_ports": _metric_unique_dst_ports,
    "unique_dst_ips":   _metric_unique_dst_ips,
    "flow_rate":        _metric_flow_rate,
    "syn_count":        _metric_syn_count,
    "pps":              _metric_pps,
}


class _NetHelper:
    """Schmaler Namespace, der den eval-Sandboxen `net.is_multicast(ip)`,
    `net.is_broadcast(ip)` und `net.is_internal(ip)` exponiert.

    Wir reichen NICHT den ganzen Loader durch — der hat auch interne
    Methoden, die Rule-Autoren in einer Condition nichts angehen. Diese
    Wrapper-Klasse ist die explizite Schnittstelle, gegen die Rule-YAMLs
    schreiben dürfen.
    """

    __slots__ = ("_loader",)

    def __init__(self, loader: "RuleLoader") -> None:
        self._loader = loader

    def is_multicast(self, ip: str) -> bool:
        return self._loader.is_multicast(ip)

    def is_broadcast(self, ip: str) -> bool:
        return self._loader.is_broadcast(ip)

    def is_internal(self, ip: str) -> bool:
        return self._loader.is_internal(ip)


class _FlowParams:
    """Pro-Flow Param-Resolver. Lazy-Lookup gegen rule.parameters mit Auswahl
    von `value_internal` vs. `value` anhand `is_internal`.

    Beispiel: `params.port_count` in einer Rule-Condition.

    Attribut-Zugriff für unbekannte Param-Namen liefert AttributeError –
    damit fällt die Rule-Auswertung in eval() in den except-Pfad und der
    Alert wird nicht gefeuert (Vorhandensein des Attributs heißt: Rule
    deklariert den Param). Der Loader stellt sicher, dass alle in der
    Condition referenzierten Params auch im Schema deklariert sind.
    """

    __slots__ = ("_params", "_is_internal")

    def __init__(self, params: dict[str, dict], is_internal: bool) -> None:
        self._params = params
        self._is_internal = is_internal

    def __getattr__(self, name: str) -> Any:
        try:
            entry = self._params[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        if self._is_internal and entry.get("value_internal") is not None:
            return entry["value_internal"]
        return entry["value"]


class SignatureEngine:
    def __init__(self, rules_dir: str, own_ips=None, own_nets=None) -> None:
        self._loader  = RuleLoader(rules_dir)
        self._ctx     = RuleContext()
        self._net     = _NetHelper(self._loader)
        # {(rule_id, src_ip): last_fired_ts}
        self._cooldowns: dict[tuple[str, str], float] = {}
        # Self-Traffic-Filter: IDS-eigene IPs/CIDRs. Flows mit src ODER dst
        # in dieser Liste werden in evaluate() + compute_metrics() vor der
        # Rule-Auswertung gedroppt. Verhindert FPs durch enrichment-
        # service-ICMP-Pings, DNS-Lookups vom Master, etc.
        self._own_ips: frozenset[str] = frozenset(own_ips or ())
        self._own_nets = tuple(own_nets or ())

    def _is_own_ip(self, ip: str) -> bool:
        if not ip:
            return False
        if ip in self._own_ips:
            return True
        if not self._own_nets:
            return False
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self._own_nets:
            if ip_obj.version == net.version and ip_obj in net:
                return True
        return False

    def setup(self) -> None:
        self._loader.load()

    def maybe_reload(self) -> bool:
        return self._loader.reload_if_changed()

    @property
    def rule_count(self) -> int:
        return len(self._loader.rules)

    def evaluate(self, flow: dict) -> list[dict]:
        # Self-Traffic-Filter — Flows wo IDS selbst beteiligt ist (als
        # Quelle ODER Ziel) werden komplett übersprungen. Verhindert dass
        # enrichment-service-ICMP-Pings als DOS_ICMP_001-Flood, DNS-
        # Lookups vom Master als DOS_UDP_001 oder als IRMA-Bridge-Polls
        # als ML-Anomaly auftauchen.
        src_ip0 = flow.get("src_ip") or ""
        dst_ip0 = flow.get("dst_ip") or ""
        if self._is_own_ip(src_ip0) or self._is_own_ip(dst_ip0):
            return []

        # stats-Dict flach in den Flow mergen
        flat = {**flow, **flow.get("stats", {})}
        self._ctx.record(flat)

        # Internal/external einmal pro Flow bestimmen — alle Rules sehen das
        # gleiche Ergebnis. is_internal() ist ein O(N)-Scan über die CIDRs,
        # ohne Cache leicht hot bei N Rules × M Flows; daher nur 1× pro Flow.
        src_ip = flat.get("src_ip") or ""
        is_internal = self._loader.is_internal(src_ip)
        # Für downstream-Konsumenten (Phase 2 ML-Tuner) optional schon mal
        # ins flow-Dict mergen — Alerts werden ohnehin neu gebaut.
        flat.setdefault("src_internal", is_internal)

        now        = time.time()
        alerts     = []

        for rule in self._loader.rules:
            fparams = _FlowParams(rule.parameters, is_internal)
            local_vars = {
                "flow": flat,
                "ctx": self._ctx,
                "params": fparams,
                "net": self._net,
            }
            try:
                match = eval(rule.condition_code, _EVAL_GLOBALS, local_vars)  # noqa: S307
            except Exception as exc:
                log.debug("Rule %s eval error: %s", rule.id, exc)
                continue

            if not match:
                continue

            # ── Cooldown-Prüfung ───────────────────────────────────────────────────
            key = (rule.id, src_ip)
            if now - self._cooldowns.get(key, 0.0) < rule.cooldown_s:
                continue   # zu kurz nach dem letzten Alert dieser Regel+IP

            self._cooldowns[key] = now
            alerts.append(_make_alert(rule, flat, self._ctx, fparams))

        return alerts

    def compute_metrics(self, flow: dict) -> list[dict]:
        """Phase-2 Shadow-Metrik: für jeden Param mit `metric:`-Deklaration
        einen Telemetry-Eintrag berechnen.

        Schema des Rückgabe-Eintrags (matched Topic `rule-metrics`):
          {rule_id, param_name, metric_value, src_ip, scope, ts}

        Wichtig:
          - Wir berechnen *unabhängig* davon, ob die Rule-Condition gefeuert
            hätte (sonst Bias: man sähe nur Werte oberhalb des Schwellwerts).
          - Wir nutzen dieselbe `_FlowParams`-Resolution wie bei der Auswertung,
            damit z.B. `params.window_s` den aktiven Wert (inkl. scope-Split)
            verwendet.
          - Methode setzt voraus, dass evaluate() für diesen Flow bereits
            durchgelaufen ist (oder zumindest ctx.record() — sonst ist der
            Sliding-Window-Stand nicht aktuell). main.py ruft sie genau in der
            Reihenfolge.
        """
        if not self._loader.rules:
            return []
        # Self-Traffic-Filter (analog evaluate): IDS-eigene Flows raus —
        # sonst landen unsere enrichment-Pings im Reservoir des
        # rule-tuners und verschieben die DOS_ICMP_001-Schwelle.
        if self._is_own_ip(flow.get("src_ip") or "") or self._is_own_ip(flow.get("dst_ip") or ""):
            return []

        flat = {**flow, **flow.get("stats", {})}
        src_ip = flat.get("src_ip") or ""
        is_internal = self._loader.is_internal(src_ip)
        scope = "internal" if is_internal else "external"
        ts = float(flat.get("end_ts") or time.time())

        out: list[dict] = []
        for rule in self._loader.rules:
            if not rule.parameters_schema:
                continue
            # Phase 6: Eligibility-Filter — wenn die Rule eine eligibility:
            # deklariert, samplen wir nur Flows die zur Rule überhaupt passen.
            # Verhindert Reservoir-Kontamination (z.B. UDP-Flows im Reservoir
            # einer TCP-SYN-Scan-Rule). Rules ohne eligibility samplen alles
            # weiter — Backwards-Compat.
            if rule.eligibility_code is not None:
                fparams_eli: _FlowParams | None = None
                try:
                    if fparams_eli is None:
                        fparams_eli = _FlowParams(rule.parameters, is_internal)
                    elig = eval(  # noqa: S307
                        rule.eligibility_code,
                        _EVAL_GLOBALS,
                        {
                            "flow": flat,
                            "ctx": self._ctx,
                            "params": fparams_eli,
                            "net": self._net,
                        },
                    )
                except Exception as exc:
                    log.debug("Rule %s eligibility eval error: %s — sample skipped",
                              rule.id, exc)
                    continue
                if not elig:
                    continue
            fparams: _FlowParams | None = None
            for pname, schema in rule.parameters_schema.items():
                metric_name = schema.get("metric")
                if not metric_name:
                    continue
                fn = METRIC_FUNCS.get(metric_name)
                if fn is None:
                    log.debug("Rule %s Param %s: metric '%s' nicht in METRIC_FUNCS",
                              rule.id, pname, metric_name)
                    continue
                if fparams is None:
                    fparams = _FlowParams(rule.parameters, is_internal)
                try:
                    value = fn(self._ctx, flat, fparams)
                except Exception as exc:
                    log.debug("Metric %s for rule %s/%s failed: %s",
                              metric_name, rule.id, pname, exc)
                    continue
                out.append({
                    "rule_id":      rule.id,
                    "param_name":   pname,
                    "metric_value": value,
                    "src_ip":       src_ip,
                    "scope":        scope,
                    "ts":           ts,
                })
        return out


# ── Alert-Erstellung mit dynamischer Beschreibung ─────────────────────────────────

def _make_alert(rule: Rule, flow: dict, ctx: RuleContext, fparams: "_FlowParams") -> dict:
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

    # Phase-4.5: metric_values pro Param mit `metric:`-Deklaration einsammeln —
    # alert-manager persistiert das, rule-tuner nutzt min/max-Werte aus
    # FP/TP-Markierungen als Constraint.
    metric_values: dict[str, float] = {}
    for pname, schema in rule.parameters_schema.items():
        metric_name = schema.get("metric")
        if not metric_name:
            continue
        fn = METRIC_FUNCS.get(metric_name)
        if fn is None:
            continue
        try:
            metric_values[pname] = float(fn(ctx, flow, fparams))
        except Exception:  # nosec - cleaner Fallback als crash im Alert-Pfad
            pass

    # Phase 7 (Suppression-Refactor): tunable=True markiert Alerts, deren Rule
    # vom rule-tuner via Threshold-Anpassung verwaltet werden kann (mind. ein
    # Param mit metric:-Deklaration). alert-manager nutzt das, um Suppression
    # für solche Alerts zu skippen — sonst würde der Tuner an einem Knopf und
    # die Suppression am anderen ziehen, was zu Severity-Drop trotz zukünftig
    # angepasstem Threshold führt.
    tunable = any(
        bool(s.get("metric")) for s in rule.parameters_schema.values()
    )

    return {
        "rule_id":      rule.id,
        "rule_name":    rule.name,
        "severity":     rule.severity,
        "tags":         rule.tags,
        "description":  description,
        "src_ip":       flow.get("src_ip"),
        "src_port":     flow.get("src_port"),
        "dst_ip":       flow.get("dst_ip"),
        "dst_port":     flow.get("dst_port"),
        "proto":        flow.get("proto"),
        "flow_id":      flow.get("flow_id"),
        "ts":           float(flow.get("end_ts") or time.time()),
        "is_test":      bool(flow.get("is_test", False)),
        "metric_values": metric_values or None,
        "tunable":      tunable,
    }
