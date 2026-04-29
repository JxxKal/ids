"""rule-tuner Hauptlogik.

Hält pro `(rule_id, param_name, scope)` ein Reservoir (Algorithm R), schreibt
periodisch Quantile nach `rule_baselines` und im Tuning-State alle
`tuning_cycle_s` Sekunden Overrides via PUT /api/sig-rules/overrides.

State-Maschine (gespiegelt aus system_config.ml_tuning_state):
  • idle    – nur Sampling, keine Schreibe
  • training– Sampling, kein Override-Write (Heuristiken laufen mit Defaults)
  • tuning  – periodischer Override-Write
  • paused  – alles steht (auch Persistierung)

Übergang training → tuning: der Tuner ist der einzige der diese Transition
auslöst (sobald training_until < now). User-Aktionen (start/pause/resume)
laufen über die API.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import asyncpg
import orjson
from confluent_kafka import Consumer, KafkaError

from api_client import ApiClient
from config import Config
from reservoir import Reservoir

log = logging.getLogger(__name__)

QUANTILES = (0.5, 0.99, 0.995, 0.999)
SAFETY_MARGIN = 1.05  # Quantil × 1.05, damit knappe Treffer nicht alarmieren

# Phase 4.5 FP/TP-Constraint:
# - mind. FP_TP_MIN_FEEDBACK Markierungen pro Rule
# - TPs setzen Obergrenze: threshold ≤ min(metric@TP)
# - FPs setzen Untergrenze: threshold ≥ max(metric@FP) + 1
# - Konflikt (FP-Untergrenze > TP-Obergrenze): Constraint verwerfen, alten Wert behalten.
FP_TP_MIN_FEEDBACK = 3


async def _init_conn(conn: asyncpg.Connection) -> None:
    """Spiegelt api/src/database.py: Codec für json/jsonb registrieren, damit
    Python-Dicts direkt nach $1::jsonb-Parametern wandern und gelesene Werte
    direkt als dict ankommen. Ohne diesen Codec liefert asyncpg jsonb als
    Python-str — und meine system_config-State-Updates crashen mit DataError."""
    for pg_type in ("json", "jsonb"):
        await conn.set_type_codec(
            pg_type,
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )


class Tuner:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        # Reservoir-Map: {(rule_id, param_name, scope): Reservoir}
        self._reservoirs: dict[tuple[str, str, str], Reservoir] = defaultdict(
            lambda: Reservoir(capacity=cfg.reservoir_size)
        )
        # Reservoir-Mutex (Kafka-Consumer läuft im Thread, persist_loop in async).
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._consumer_thread: threading.Thread | None = None
        self._pool: asyncpg.Pool | None = None
        # Cache des letzten gelesenen Status — verhindert Race zwischen
        # state-poll und tuning-loop.
        self._status_cache: dict | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def setup(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._cfg.postgres_dsn, min_size=1, max_size=4, init=_init_conn,
        )

    async def teardown(self) -> None:
        self._stop.set()
        if self._consumer_thread:
            self._consumer_thread.join(timeout=5)
        if self._pool:
            await self._pool.close()

    # ── Kafka-Consumer ───────────────────────────────────────────────────

    def _consumer_run(self) -> None:
        consumer = Consumer({
            "bootstrap.servers": self._cfg.kafka_brokers,
            "group.id":          self._cfg.consumer_group,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        })
        consumer.subscribe([self._cfg.metrics_topic])
        log.info("Kafka-Consumer subscribed: %s", self._cfg.metrics_topic)
        try:
            while not self._stop.is_set():
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.warning("Kafka error: %s", msg.error())
                    continue
                payload = msg.value()
                if not payload:
                    continue
                try:
                    rec = orjson.loads(payload)
                except Exception as exc:
                    log.debug("Decode-Fehler: %s", exc)
                    continue
                rid = str(rec.get("rule_id") or "")
                pname = str(rec.get("param_name") or "")
                scope = str(rec.get("scope") or "")
                value = rec.get("metric_value")
                if not rid or not pname or scope not in ("internal", "external"):
                    continue
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    continue
                with self._lock:
                    self._reservoirs[(rid, pname, scope)].add(float(value))
        finally:
            consumer.close()
            log.info("Kafka-Consumer beendet")

    def start_consumer(self) -> None:
        self._consumer_thread = threading.Thread(
            target=self._consumer_run, daemon=True, name="rule-metrics-consumer"
        )
        self._consumer_thread.start()

    # ── Persistierung in rule_baselines ──────────────────────────────────

    async def persist_baselines(self) -> int:
        """Schreibt alle aktuellen Reservoir-Quantile als UPSERT nach
        `rule_baselines`. Rückgabe: Anzahl geschriebener Zeilen."""
        assert self._pool is not None
        # Snapshot ziehen unter Lock — danach Lock freigeben, damit Consumer
        # nicht blockiert wird.
        with self._lock:
            snapshot = [
                (key, res._samples.copy(), res.total_seen)
                for key, res in self._reservoirs.items()
                if res.size > 0
            ]
        if not snapshot:
            return 0

        rows: list[tuple] = []
        now = datetime.now(timezone.utc)
        for (rid, pname, scope), samples, _seen in snapshot:
            # Quantile aus Snapshot — wir bauen ein temporäres Reservoir,
            # damit die quantiles()-Methode wiederverwendbar bleibt.
            tmp = Reservoir(capacity=len(samples) or 1)
            tmp._samples = samples
            qs = tmp.quantiles(QUANTILES)
            rows.append((
                rid, pname, scope,
                qs[0.5], qs[0.99], qs[0.995], qs[0.999],
                len(samples), now,
            ))
        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO rule_baselines
                  (rule_id, param_name, scope, p50, p99, p995, p999, sample_count, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (rule_id, param_name, scope) DO UPDATE SET
                  p50 = EXCLUDED.p50,
                  p99 = EXCLUDED.p99,
                  p995 = EXCLUDED.p995,
                  p999 = EXCLUDED.p999,
                  sample_count = EXCLUDED.sample_count,
                  updated_at = EXCLUDED.updated_at
                """,
                rows,
            )
        return len(rows)

    async def persist_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(self._cfg.persist_interval_s)
            try:
                n = await self.persist_baselines()
                if n:
                    log.info("rule_baselines aktualisiert: %d Zeilen", n)
            except Exception as exc:
                log.exception("persist_baselines fehlgeschlagen: %s", exc)

    # ── State-Maschine + Override-Write ──────────────────────────────────

    async def state_loop(self, api: ApiClient) -> None:
        """Pollt /ml/status, triggert training→tuning-Transition und
        Tuning-Cycles. Eine Iteration tut max. eine Aktion (write_overrides),
        damit Fehler isoliert bleiben."""
        while not self._stop.is_set():
            try:
                self._status_cache = await api.get_ml_status()
            except Exception as exc:
                log.warning("ml/status-Poll fehlgeschlagen: %s", exc)
                await asyncio.sleep(self._cfg.state_poll_interval_s)
                continue

            state = self._status_cache.get("state", {})
            cur = state.get("state")
            now = datetime.now(timezone.utc)

            try:
                if cur == "training":
                    ti = self._parse_iso(state.get("training_until"))
                    if ti and ti <= now:
                        log.info("Training abgeschlossen — schalte auf tuning + erster Override-Write")
                        await self._do_tuning_cycle(api, first_apply=True)
                        await self._transition_to_tuning(now)
                elif cur == "tuning":
                    last = self._parse_iso(state.get("last_tuning_at"))
                    if last is None or (now - last).total_seconds() >= self._cfg.tuning_cycle_s:
                        log.info("Tuning-Cycle fällig (last=%s) — schreibe Overrides", last)
                        await self._do_tuning_cycle(api, first_apply=False)
                        await self._update_last_tuning(now)
                # idle / paused: nichts tun (Reservoirs laufen weiter)
            except Exception as exc:
                log.exception("Tuning-Cycle gescheitert: %s", exc)

            await asyncio.sleep(self._cfg.state_poll_interval_s)

    @staticmethod
    def _parse_iso(s: Any) -> datetime | None:
        if not s or not isinstance(s, str):
            return None
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None

    async def _transition_to_tuning(self, now: datetime) -> None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM system_config WHERE key='ml_tuning_state'"
            )
            cur = row["value"] if row and isinstance(row["value"], dict) else {}
            cur["state"] = "tuning"
            cur["last_tuning_at"] = now.isoformat()
            cur["paused_from"] = None
            await conn.execute(
                """
                INSERT INTO system_config (key, value)
                VALUES ('ml_tuning_state', $1::jsonb)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                cur,
            )

    async def _update_last_tuning(self, now: datetime) -> None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM system_config WHERE key='ml_tuning_state'"
            )
            cur = row["value"] if row and isinstance(row["value"], dict) else {}
            cur["last_tuning_at"] = now.isoformat()
            await conn.execute(
                """
                INSERT INTO system_config (key, value)
                VALUES ('ml_tuning_state', $1::jsonb)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                cur,
            )

    async def _do_tuning_cycle(self, api: ApiClient, first_apply: bool) -> None:
        """Berechnet aus den aktuellen Reservoirs neue Schwellwerte und
        schreibt sie als Override per API.

        first_apply=True: keine max_change_per_cycle-Klemme, weil der
        Sprung von Default → Quantil-Wert sonst willkürlich gedeckelt wäre.
        Subsequent Cycles: Klemme auf ±max_change_per_cycle des alten
        ml-Werts.
        """
        if self._status_cache is None:
            return
        cfg = self._status_cache.get("config", {})
        quantile = float(cfg.get("quantile", 0.995))
        scope_split = bool(cfg.get("scope_split_enabled", True))
        max_change = float(cfg.get("max_change_per_cycle", 0.20))
        blacklist = set(str(x) for x in cfg.get("blacklist", []) or [])

        rules = await api.list_rules()
        existing_ovs = await api.get_overrides()
        # Phase 4.5: FP/TP-Markierungen pro (rule, param) als Constraint-Quelle.
        # Pre-Loaded für alle Rules in diesem Cycle, damit wir keine N+1-Query
        # pro Param machen.
        feedback_by_rule = await self._load_feedback_metrics(rules)

        # Snapshot der Reservoirs.
        with self._lock:
            res_snapshot: dict[tuple[str, str, str], list[float]] = {
                k: r._samples.copy() for k, r in self._reservoirs.items()
            }

        new_overrides: dict[str, dict] = {}

        # Vorhandene Einträge beibehalten (enabled, severity, manuelle Params)
        for rid, ov in existing_ovs.items():
            new_overrides[rid] = self._copy_existing(ov)

        ml_updates = 0
        for rule in rules:
            rid = rule.get("id")
            if not rid or rid in blacklist:
                continue
            schema = rule.get("parameters_schema") or {}
            ovs_full = (existing_ovs.get(rid) or {}).get("parameters") or {}
            fb_for_rule = feedback_by_rule.get(rid, {})

            for pname, ps in schema.items():
                metric_name = ps.get("metric")
                if not metric_name:
                    continue  # Param nicht ML-tunbar

                # Manueller Lock?
                existing_param = ovs_full.get(pname)
                if isinstance(existing_param, dict):
                    src = existing_param.get("source")
                    if src == "manual":
                        continue  # User hat den Wert gesetzt, nicht anfassen
                    old_value = existing_param.get("value")
                else:
                    # Skalar = entweder pre-Phase-1 (= manual implizit) oder
                    # einfach kein ML-Eintrag. Behalten & nicht überschreiben,
                    # damit wir Bestandsdaten nicht ungefragt mutieren.
                    if existing_param is not None:
                        continue
                    old_value = None

                # Reservoirs holen
                ext = res_snapshot.get((rid, pname, "external"), [])
                intern = res_snapshot.get((rid, pname, "internal"), [])

                if scope_split:
                    new_v = self._quantile_of(ext, quantile)
                    new_vi = self._quantile_of(intern, quantile)
                    if new_v is None and new_vi is None:
                        continue
                    # Min-Sample-Cutoff pro Scope
                    if new_v is not None and len(ext) < self._cfg.min_samples:
                        new_v = None
                    if new_vi is not None and len(intern) < self._cfg.min_samples:
                        new_vi = None
                    if new_v is None and new_vi is None:
                        continue
                else:
                    # Combined reservoir
                    combined = ext + intern
                    if len(combined) < self._cfg.min_samples:
                        continue
                    new_v = self._quantile_of(combined, quantile)
                    new_vi = None

                # Safety-Margin + Schema-Clamp
                new_v = self._postprocess(new_v, ps)
                new_vi = self._postprocess(new_vi, ps) if new_vi is not None else None

                # Phase 4.5: FP/TP-Constraints anwenden — nur wenn ≥3 Markierungen
                # für die Rule INSGESAMT existieren (mit jeweils metric_values
                # für diesen Param). Constraint wirkt uniform auf value und
                # value_internal — V1, eine scope-bewusste Aufteilung wäre
                # später möglich, ist aber spec-konform "kein Verlass darauf".
                fp_max, tp_min, conflict = self._fp_tp_bounds(fb_for_rule, pname, ps)
                if conflict:
                    log.warning(
                        "Rule %s/%s: FP/TP-Konflikt (FP_max+1=%s > TP_min=%s) — alten Wert behalten",
                        rid, pname, fp_max, tp_min,
                    )
                    new_v = old_value if isinstance(old_value, (int, float)) else None
                    new_vi = None
                else:
                    if new_v is not None:
                        new_v = self._apply_fp_tp(new_v, fp_max, tp_min, ps)
                    if new_vi is not None:
                        new_vi = self._apply_fp_tp(new_vi, fp_max, tp_min, ps)

                # max_change_per_cycle (nur ab 2. Apply mit altem ml-Wert)
                if not first_apply and old_value is not None and isinstance(old_value, (int, float)) and new_v is not None:
                    new_v = self._clamp_change(new_v, float(old_value), max_change)
                if not first_apply and new_vi is not None and isinstance(existing_param, dict):
                    old_vi = existing_param.get("value_internal")
                    if isinstance(old_vi, (int, float)):
                        new_vi = self._clamp_change(new_vi, float(old_vi), max_change)

                # Override-Eintrag bauen
                ml_meta = {
                    "trained_at":   datetime.now(timezone.utc).isoformat(),
                    "quantile":     quantile,
                    "p995_external": self._quantile_of(ext, 0.995),
                    "p995_internal": self._quantile_of(intern, 0.995),
                    "sample_count_external": len(ext),
                    "sample_count_internal": len(intern),
                    "scope_split":   scope_split,
                    # FP/TP-Constraint-Diagnose
                    "fp_seen":  len(fb_for_rule.get(pname, {}).get("fp", [])),
                    "tp_seen":  len(fb_for_rule.get(pname, {}).get("tp", [])),
                    "fp_max":   fp_max,
                    "tp_min":   tp_min,
                }
                entry = {
                    "value":          new_v if new_v is not None else (old_value or ps.get("default")),
                    "value_internal": new_vi,
                    "source":         "ml",
                    "ml":             ml_meta,
                }
                rule_payload = new_overrides.setdefault(rid, {})
                rule_payload.setdefault("parameters", {})
                rule_payload["parameters"][pname] = entry
                ml_updates += 1

        if ml_updates:
            await api.put_overrides(new_overrides)
            log.info("Override-Write: %d Param-Einträge auf %d Rules aktualisiert",
                     ml_updates, len([r for r in new_overrides.values() if r.get("parameters")]))
        else:
            log.info("Tuning-Cycle ohne Updates (nicht genug Samples oder alle manual)")

    async def _load_feedback_metrics(
        self, rules: list[dict]
    ) -> dict[str, dict[str, dict[str, list[float]]]]:
        """Lädt für alle Rules mit ≥FP_TP_MIN_FEEDBACK Markierungen die
        metric_values der gefeedbackten Alerts. Rückgabe-Format:
          {rule_id: {param_name: {"fp": [...], "tp": [...]}}}

        Filtert auf alerts mit metric_values IS NOT NULL — alte Alerts
        (vor Phase 4.5) haben das Feld nicht. Gating-Schwelle ≥3 wirkt PRO
        Rule (Summe fp+tp), nicht pro Param — weil die Markierungen ohnehin
        mehrere Params der gleichen Rule tragen.
        """
        assert self._pool is not None
        rule_ids = [r.get("id") for r in rules if r.get("id")]
        if not rule_ids:
            return {}
        async with self._pool.acquire() as conn:
            # Einzelne Query pro Rule wäre N+1 — wir holen alles in einem
            # Round-Trip und filtern in Python.
            rows = await conn.fetch(
                """
                SELECT rule_id, feedback, metric_values
                  FROM alerts
                 WHERE rule_id = ANY($1::text[])
                   AND feedback IS NOT NULL
                   AND metric_values IS NOT NULL
                """,
                rule_ids,
            )
        out: dict[str, dict[str, dict[str, list[float]]]] = {}
        per_rule_count: dict[str, int] = {}
        for r in rows:
            rid = r["rule_id"]
            fb = r["feedback"]
            mv = r["metric_values"]
            if not isinstance(mv, dict):
                continue
            per_rule_count[rid] = per_rule_count.get(rid, 0) + 1
            for pname, val in mv.items():
                if not isinstance(val, (int, float)) or isinstance(val, bool):
                    continue
                bucket = out.setdefault(rid, {}).setdefault(pname, {"fp": [], "tp": []})
                if fb in bucket:
                    bucket[fb].append(float(val))
        # Rules unterhalb des Schwellwerts wieder entfernen — kein Verlass
        # auf einzelne Markierungen.
        for rid in list(out.keys()):
            if per_rule_count.get(rid, 0) < FP_TP_MIN_FEEDBACK:
                del out[rid]
        return out

    @staticmethod
    def _fp_tp_bounds(
        rule_feedback: dict[str, dict[str, list[float]]],
        pname: str,
        schema: dict,
    ) -> tuple[float | None, float | None, bool]:
        """Liefert (fp_lower_bound, tp_upper_bound, conflict).

        fp_lower_bound = max(FP-metrics) + 1 (für Int-Schwellwerte) bzw.
                         max(FP-metrics) + epsilon (für Float).
        tp_upper_bound = min(TP-metrics).
        conflict = True wenn fp_lower_bound > tp_upper_bound.
        """
        bucket = rule_feedback.get(pname)
        if not bucket:
            return None, None, False
        fp_vals = bucket.get("fp") or []
        tp_vals = bucket.get("tp") or []

        fp_max = max(fp_vals) if fp_vals else None
        tp_min = min(tp_vals) if tp_vals else None

        # FP-Untergrenze: Int +1, Float epsilon — damit der Schwellwert
        # genau über dem max-FP liegt und das FP-Pattern nicht mehr feuert.
        if fp_max is not None:
            if schema.get("type") == "int":
                fp_max = float(int(fp_max)) + 1.0
            else:
                fp_max = float(fp_max) + 1e-6

        conflict = (fp_max is not None and tp_min is not None and fp_max > tp_min)
        return fp_max, tp_min, conflict

    @staticmethod
    def _apply_fp_tp(
        value: float,
        fp_lower: float | None,
        tp_upper: float | None,
        schema: dict,
    ) -> float:
        """Klemmt `value` auf das FP/TP-Constraint-Intervall. Annahme:
        kein Konflikt (das filtert der Caller bereits)."""
        if fp_lower is not None and value < fp_lower:
            value = fp_lower
        if tp_upper is not None and value > tp_upper:
            value = tp_upper
        if schema.get("type") == "int":
            value = float(int(round(value)))
        return value

    @staticmethod
    def _copy_existing(ov: dict) -> dict:
        """Bewahrt enabled, severity, manuelle Param-Einträge — ml-Einträge
        werden gleich überschrieben, also raus. Skalar-Werte (Backwards-
        Compat) werden behalten, weil deren Provenance nicht 'ml' ist."""
        out: dict = {}
        if isinstance(ov.get("enabled"), bool):
            out["enabled"] = ov["enabled"]
        if isinstance(ov.get("severity"), str):
            out["severity"] = ov["severity"]
        params = ov.get("parameters")
        if isinstance(params, dict):
            kept: dict = {}
            for k, v in params.items():
                # Object-Form mit source!='ml' → behalten
                if isinstance(v, dict):
                    if v.get("source") != "ml":
                        kept[k] = v
                # Skalar → behalten (impliziter manual-Lock)
                elif isinstance(v, (int, float)) and not isinstance(v, bool):
                    kept[k] = v
            if kept:
                out["parameters"] = kept
        return out

    @staticmethod
    def _quantile_of(samples: list[float], q: float) -> float | None:
        if not samples:
            return None
        s = sorted(samples)
        n = len(s)
        if q <= 0.0:
            return s[0]
        if q >= 1.0:
            return s[-1]
        pos = q * (n - 1)
        lo = int(pos)
        hi = min(lo + 1, n - 1)
        frac = pos - lo
        return s[lo] * (1.0 - frac) + s[hi] * frac

    @staticmethod
    def _postprocess(value: float | None, schema: dict) -> float | None:
        """Apply safety margin, schema clamp + cast."""
        if value is None:
            return None
        v = float(value) * SAFETY_MARGIN
        ptype = schema.get("type", "int")
        lo = schema.get("min")
        hi = schema.get("max")
        if lo is not None and v < lo:
            v = float(lo)
        if hi is not None and v > hi:
            v = float(hi)
        if ptype == "int":
            return float(int(round(v)))
        return v

    @staticmethod
    def _clamp_change(new_v: float, old_v: float, max_change: float) -> float:
        """Beschränkt new_v auf [old_v*(1-mc), old_v*(1+mc)]. Wenn old_v=0,
        bleibt new_v unverändert (sonst Divide-By-Zero-Effekt)."""
        if old_v == 0 or max_change <= 0:
            return new_v
        lo = old_v * (1.0 - max_change)
        hi = old_v * (1.0 + max_change)
        return max(lo, min(hi, new_v))
