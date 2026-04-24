"""ML/KI-Engine Status, Konfiguration und Retrain-Trigger."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from database import get_pool

router = APIRouter(prefix="/api/ml", tags=["ml"])

MODELS_DIR        = Path(os.getenv("MODELS_DIR", "/models"))
BOOTSTRAP_MIN     = int(os.getenv("ML_BOOTSTRAP_MIN", "500"))
ALERT_THRESHOLD   = 0.65
ML_CONFIG_FILE    = MODELS_DIR / "ml_config.json"
RETRAIN_TRIGGER   = MODELS_DIR / "retrain.trigger"

# Defaults
DEFAULT_CONFIG: dict = {
    "alert_threshold":      0.65,
    "contamination":        0.01,
    "bootstrap_min_samples": 500,
    "partial_fit_interval": 200,
}

# Menschenlesbare Feature-Labels
FEATURE_LABELS: dict[str, dict[str, str]] = {
    "duration_s":    {"label": "Flow-Dauer",           "unit": "s"},
    "pkt_count":     {"label": "Paketanzahl",           "unit": "Pkts"},
    "byte_count":    {"label": "Datenmenge",            "unit": "Bytes"},
    "pps":           {"label": "Pakete/Sekunde",        "unit": "pps"},
    "bps":           {"label": "Bytes/Sekunde",         "unit": "bps"},
    "pkt_size_mean": {"label": "Mittl. Paketgröße",    "unit": "Bytes"},
    "pkt_size_std":  {"label": "Paketgröße-Streuung",  "unit": "Bytes"},
    "iat_mean":      {"label": "Mittl. Paketabstand",  "unit": "ms"},
    "iat_std":       {"label": "Paketabstand-Streuung","unit": "ms"},
    "entropy_iat":   {"label": "Timing-Entropie",      "unit": ""},
    "syn_ratio":     {"label": "SYN-Flag-Anteil",      "unit": "%"},
    "rst_ratio":     {"label": "RST-Flag-Anteil",      "unit": "%"},
    "fin_ratio":     {"label": "FIN-Flag-Anteil",      "unit": "%"},
    "dst_port":      {"label": "Zielport",             "unit": ""},
}


# ── Modelle ────────────────────────────────────────────────────────────────────

class ModelInfo(BaseModel):
    trained:       bool
    n_samples:     int
    trained_at:    float | None
    contamination: float
    n_attack:      int

class BootstrapInfo(BaseModel):
    required:              int
    current_flows:         int
    progress_pct:          float
    estimated_remaining_s: int | None   # None wenn nicht schätzbar

class Stats24h(BaseModel):
    flows_total:      int
    ml_alerts:        int
    filter_rate_pct:  float
    alert_threshold:  float

class FeatureDeviation(BaseModel):
    name:          str
    label:         str
    unit:          str
    avg_in_alerts: float
    avg_normal:    float
    deviation_pct: float   # (avg_in_alerts - avg_normal) / max(avg_normal, 0.001) * 100

class MLConfig(BaseModel):
    alert_threshold:       float   # 0.50 – 0.95
    contamination:         float   # 0.001 – 0.50
    bootstrap_min_samples: int     # 100 – 50000
    partial_fit_interval:  int     # 50 – 5000

class MLConfigPatch(BaseModel):
    alert_threshold:       float | None = None
    contamination:         float | None = None
    bootstrap_min_samples: int   | None = None
    partial_fit_interval:  int   | None = None

class RetrainStatus(BaseModel):
    triggered:    bool
    triggered_at: float | None

class MLStatus(BaseModel):
    phase:                  str   # "passthrough" | "learning" | "active"
    phase_label:            str
    model:                  ModelInfo
    bootstrap:              BootstrapInfo
    stats_24h:              Stats24h
    top_anomaly_features:   list[FeatureDeviation]


# ── Hilfsfunktionen ────────────────────────────────────────────────────────────

def _read_ml_config() -> dict:
    if ML_CONFIG_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(ML_CONFIG_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def _write_ml_config(cfg: dict) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ML_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def _read_meta() -> dict:
    meta_file = MODELS_DIR / "meta.json"
    if not meta_file.exists():
        return {}
    try:
        return json.loads(meta_file.read_text())
    except Exception:
        return {}


def _determine_phase(meta: dict, current_flows: int) -> tuple[str, str]:
    if not meta:
        return ("passthrough", "Datensammlung – kein Modell vorhanden")
    n = meta.get("n_samples", 0)
    if n < BOOTSTRAP_MIN:
        return ("learning", "Lernphase – Modell noch im Aufbau")
    return ("active", "Aktiv – KI/ML-Filterung läuft")


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.get("/status", response_model=MLStatus)
async def ml_status(pool: asyncpg.Pool = Depends(get_pool)) -> MLStatus:
    meta = _read_meta()

    async with pool.acquire() as conn:
        # Flow-Zähler gesamt
        total_flows: int = await conn.fetchval("SELECT COUNT(*) FROM flows") or 0

        # Flow-Rate der letzten Stunde (für Zeitschätzung)
        flows_last_hour: int = await conn.fetchval(
            "SELECT COUNT(*) FROM flows WHERE start_ts > now() - INTERVAL '1 hour'"
        ) or 0

        # Flows + ML-Alerts letzte 24h
        flows_24h: int = await conn.fetchval(
            "SELECT COUNT(*) FROM flows WHERE start_ts > now() - INTERVAL '24 hours'"
        ) or 0
        ml_alerts_24h: int = await conn.fetchval(
            """SELECT COUNT(*) FROM alerts
               WHERE source = 'ml' AND ts > now() - INTERVAL '24 hours' AND is_test = false"""
        ) or 0

        # Feature-Abweichungs-Analyse: ML-Alerts vs. normale Flows (letzte 24h)
        # Flows die zu ML-Alerts gehören
        alert_features_row = await conn.fetchrow(
            """
            SELECT
                AVG(EXTRACT(EPOCH FROM (f.end_ts - f.start_ts)))          AS duration_s,
                AVG(f.pkt_count)                                           AS pkt_count,
                AVG(f.byte_count)                                          AS byte_count,
                AVG((f.stats->>'pps')::float)                              AS pps,
                AVG((f.stats->>'bps')::float)                              AS bps,
                AVG((f.stats->'pkt_size'->>'mean')::float)                 AS pkt_size_mean,
                AVG((f.stats->'pkt_size'->>'std')::float)                  AS pkt_size_std,
                AVG((f.stats->'iat'->>'mean')::float)                      AS iat_mean,
                AVG((f.stats->'iat'->>'std')::float)                       AS iat_std,
                AVG((f.stats->>'entropy_iat')::float)                      AS entropy_iat,
                AVG((f.stats->'tcp_flags'->>'SYN')::float)                 AS syn_ratio,
                AVG((f.stats->'tcp_flags'->>'RST')::float)                 AS rst_ratio,
                AVG((f.stats->'tcp_flags'->>'FIN')::float)                 AS fin_ratio,
                AVG(f.dst_port)                                            AS dst_port
            FROM flows f
            INNER JOIN alerts a ON a.flow_id::text = f.flow_id::text
            WHERE a.source = 'ml'
              AND a.ts > now() - INTERVAL '24 hours'
              AND a.is_test = false
            """
        )

        normal_features_row = await conn.fetchrow(
            """
            SELECT
                AVG(EXTRACT(EPOCH FROM (end_ts - start_ts)))               AS duration_s,
                AVG(pkt_count)                                             AS pkt_count,
                AVG(byte_count)                                            AS byte_count,
                AVG((stats->>'pps')::float)                                AS pps,
                AVG((stats->>'bps')::float)                                AS bps,
                AVG((stats->'pkt_size'->>'mean')::float)                   AS pkt_size_mean,
                AVG((stats->'pkt_size'->>'std')::float)                    AS pkt_size_std,
                AVG((stats->'iat'->>'mean')::float)                        AS iat_mean,
                AVG((stats->'iat'->>'std')::float)                         AS iat_std,
                AVG((stats->>'entropy_iat')::float)                        AS entropy_iat,
                AVG((stats->'tcp_flags'->>'SYN')::float)                   AS syn_ratio,
                AVG((stats->'tcp_flags'->>'RST')::float)                   AS rst_ratio,
                AVG((stats->'tcp_flags'->>'FIN')::float)                   AS fin_ratio,
                AVG(dst_port)                                              AS dst_port
            FROM flows
            WHERE start_ts > now() - INTERVAL '24 hours'
            """
        )

    # ── Model-Info ──────────────────────────────────────────────────────────
    model = ModelInfo(
        trained       = bool(meta),
        n_samples     = meta.get("n_samples", 0),
        trained_at    = meta.get("ts"),
        contamination = meta.get("contamination", 0.01),
        n_attack      = meta.get("n_attack", 0),
    )

    # ── Bootstrap-Info ──────────────────────────────────────────────────────
    current = min(total_flows, BOOTSTRAP_MIN) if not meta else total_flows
    progress = min(100.0, round(current / BOOTSTRAP_MIN * 100, 1)) if not meta else 100.0

    remaining_s: int | None = None
    if not meta and flows_last_hour > 0:
        flows_needed = max(0, BOOTSTRAP_MIN - total_flows)
        remaining_s  = int(flows_needed / flows_last_hour * 3600)

    bootstrap = BootstrapInfo(
        required              = BOOTSTRAP_MIN,
        current_flows         = total_flows,
        progress_pct          = progress,
        estimated_remaining_s = remaining_s,
    )

    # ── 24h-Stats ───────────────────────────────────────────────────────────
    current_threshold = _read_ml_config().get("alert_threshold", ALERT_THRESHOLD)
    filter_rate = round(ml_alerts_24h / max(flows_24h, 1) * 100, 3)
    stats_24h   = Stats24h(
        flows_total     = flows_24h,
        ml_alerts       = ml_alerts_24h,
        filter_rate_pct = filter_rate,
        alert_threshold = current_threshold,
    )

    # ── Feature-Abweichungen ────────────────────────────────────────────────
    feature_deviations: list[FeatureDeviation] = []
    if alert_features_row and normal_features_row and ml_alerts_24h > 0:
        for feat, info in FEATURE_LABELS.items():
            a_val = alert_features_row[feat]
            n_val = normal_features_row[feat]
            if a_val is None or n_val is None:
                continue
            a_val = float(a_val)
            n_val = float(n_val)
            base  = max(abs(n_val), 0.001)
            dev   = round((a_val - n_val) / base * 100, 1)
            if abs(dev) < 5:   # Unter 5% Abweichung nicht relevant
                continue
            feature_deviations.append(FeatureDeviation(
                name          = feat,
                label         = info["label"],
                unit          = info["unit"],
                avg_in_alerts = round(a_val, 4),
                avg_normal    = round(n_val, 4),
                deviation_pct = dev,
            ))

        # Sortiert nach absoluter Abweichung, max 6 anzeigen
        feature_deviations.sort(key=lambda x: abs(x.deviation_pct), reverse=True)
        feature_deviations = feature_deviations[:6]

    # ── Phase ───────────────────────────────────────────────────────────────
    phase, phase_label = _determine_phase(meta, total_flows)

    return MLStatus(
        phase               = phase,
        phase_label         = phase_label,
        model               = model,
        bootstrap           = bootstrap,
        stats_24h           = stats_24h,
        top_anomaly_features = feature_deviations,
    )


# ── Konfigurations-Endpunkte ───────────────────────────────────────────────────

@router.get("/config", response_model=MLConfig)
async def get_ml_config() -> MLConfig:
    return MLConfig(**_read_ml_config())


@router.patch("/config", response_model=MLConfig)
async def update_ml_config(body: MLConfigPatch) -> MLConfig:
    cfg = _read_ml_config()
    needs_retrain = False

    if body.alert_threshold is not None:
        cfg["alert_threshold"] = round(max(0.5, min(0.95, body.alert_threshold)), 3)
    if body.contamination is not None:
        new_c = round(max(0.001, min(0.5, body.contamination)), 4)
        if abs(new_c - cfg["contamination"]) > 0.0001:
            needs_retrain = True
        cfg["contamination"] = new_c
    if body.bootstrap_min_samples is not None:
        cfg["bootstrap_min_samples"] = max(100, min(50_000, body.bootstrap_min_samples))
    if body.partial_fit_interval is not None:
        cfg["partial_fit_interval"] = max(50, min(5_000, body.partial_fit_interval))

    _write_ml_config(cfg)

    # Contamination-Änderung → Retrain anstoßen
    if needs_retrain:
        RETRAIN_TRIGGER.write_text(str(time.time()))

    return MLConfig(**cfg)


@router.post("/retrain", response_model=RetrainStatus)
async def trigger_retrain() -> RetrainStatus:
    """Manuellen Sofort-Retrain anstoßen."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    RETRAIN_TRIGGER.write_text(str(now))
    return RetrainStatus(triggered=True, triggered_at=now)


# ── ML-Adaptive Auto-Suppression-Muster ──────────────────────────────────────

@router.get("/learned-patterns")
async def get_learned_patterns(
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Liefert Muster (rule_id, src_ip, dst_ip) mit gelernter Baseline
    (mean/std Alerts/Stunde), aktueller Rate und z-Score.

    Suppression greift beim Alert-Manager nur wenn z_score < threshold.
    Spikes (z >= threshold) durchbrechen die Suppression automatisch.

    ENV-Konfiguration (muss mit alert-manager übereinstimmen):
      SUPPRESSION_LEARN_WINDOW_D  (default 14)
      SUPPRESSION_MIN_HOURS       (default 24)
      SUPPRESSION_Z_THRESHOLD     (default 2.0)
    """
    window_d    = int(os.environ.get("SUPPRESSION_LEARN_WINDOW_D", "14"))
    min_hours   = int(os.environ.get("SUPPRESSION_MIN_HOURS",      "24"))
    z_threshold = float(os.environ.get("SUPPRESSION_Z_THRESHOLD",  "2.0"))

    async with pool.acquire() as conn:
        # Adaptive Baseline: per (rule_id, ip_pair) werden Mittelwert und
        # StdDev der stündlichen Alert-Zahlen über LEARN_WINDOW_D Tagen
        # berechnet. Kombiniert mit der aktuellen Stunde → z-Score.
        rows = await conn.fetch(
            """
            WITH hourly AS (
                SELECT
                    rule_id,
                    LEAST(src_ip, dst_ip)    AS ip_a,
                    GREATEST(src_ip, dst_ip) AS ip_b,
                    date_trunc('hour', ts)   AS hour_bucket,
                    COUNT(*)                 AS cnt
                FROM alerts
                WHERE ts > NOW() - ($1::int * INTERVAL '1 day')
                  AND ts < date_trunc('hour', NOW())
                  AND is_test = false
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
                GROUP BY 1, 2, 3, 4
            ),
            baseline AS (
                SELECT
                    rule_id, ip_a, ip_b,
                    AVG(cnt)::float                 AS mean_h,
                    COALESCE(STDDEV(cnt), 0)::float AS std_h,
                    COUNT(*)::int                   AS hours_with_data,
                    SUM(cnt)::int                   AS total_baseline
                FROM hourly
                GROUP BY rule_id, ip_a, ip_b
                HAVING COUNT(*) >= $2::int
            ),
            recent AS (
                SELECT
                    rule_id,
                    LEAST(src_ip, dst_ip)    AS ip_a,
                    GREATEST(src_ip, dst_ip) AS ip_b,
                    COUNT(*)::int            AS cnt_1h
                FROM alerts
                WHERE ts > NOW() - INTERVAL '1 hour'
                  AND is_test = false
                GROUP BY 1, 2, 3
            ),
            tp_pat AS (
                SELECT DISTINCT
                    rule_id,
                    LEAST(src_ip, dst_ip)    AS ip_a,
                    GREATEST(src_ip, dst_ip) AS ip_b
                FROM alerts WHERE feedback = 'tp'
            ),
            manual_fp AS (
                SELECT DISTINCT
                    rule_id,
                    LEAST(src_ip, dst_ip)    AS ip_a,
                    GREATEST(src_ip, dst_ip) AS ip_b
                FROM alerts WHERE feedback = 'fp'
            ),
            ts_bounds AS (
                SELECT
                    rule_id,
                    LEAST(src_ip, dst_ip)    AS ip_a,
                    GREATEST(src_ip, dst_ip) AS ip_b,
                    MIN(ts)                  AS first_seen,
                    MAX(ts)                  AS last_seen
                FROM alerts
                WHERE ts > NOW() - ($1::int * INTERVAL '1 day')
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
                GROUP BY 1, 2, 3
            )
            SELECT
                b.rule_id,
                host(b.ip_a)   AS ip_a,
                host(b.ip_b)   AS ip_b,
                b.mean_h,
                b.std_h,
                b.hours_with_data,
                b.total_baseline,
                COALESCE(r.cnt_1h, 0) AS recent_1h,
                CASE
                    WHEN b.std_h > 0
                      THEN (COALESCE(r.cnt_1h, 0) - b.mean_h) / b.std_h
                    WHEN COALESCE(r.cnt_1h, 0) > b.mean_h THEN 99.0
                    ELSE 0.0
                END AS z_score,
                ts.first_seen,
                ts.last_seen,
                (m.rule_id IS NOT NULL) AS is_manual
            FROM baseline b
            LEFT JOIN recent    r  ON r.rule_id  = b.rule_id AND r.ip_a  = b.ip_a AND r.ip_b  = b.ip_b
            LEFT JOIN tp_pat    tp ON tp.rule_id = b.rule_id AND tp.ip_a = b.ip_a AND tp.ip_b = b.ip_b
            LEFT JOIN manual_fp m  ON m.rule_id  = b.rule_id AND m.ip_a  = b.ip_a AND m.ip_b  = b.ip_b
            LEFT JOIN ts_bounds ts ON ts.rule_id = b.rule_id AND ts.ip_a = b.ip_a AND ts.ip_b = b.ip_b
            WHERE tp.rule_id IS NULL
              -- manual FPs werden MIT zurückgegeben, damit Spike-Durchbrüche
              -- auch bei manuell markierten Verbindungen sichtbar werden.
            ORDER BY b.mean_h DESC, b.total_baseline DESC
            LIMIT 500
            """,
            window_d, min_hours,
        )

    return {
        "config": {
            "window_days":  window_d,
            "min_hours":    min_hours,
            "z_threshold":  z_threshold,
        },
        "patterns": [
            {
                "rule_id":         r["rule_id"],
                "src_ip":          r["ip_a"],
                "dst_ip":          r["ip_b"],
                "source":          "manual" if r["is_manual"] else "learned",
                "mean_h":          round(float(r["mean_h"]), 2),
                "std_h":           round(float(r["std_h"]),  2),
                "hours_with_data": r["hours_with_data"],
                "total_baseline":  r["total_baseline"],
                "recent_1h":       r["recent_1h"],
                "z_score":         round(float(r["z_score"]), 2),
                "suppressed":      float(r["z_score"]) < z_threshold,
                "first_seen":      r["first_seen"].isoformat() if r["first_seen"] else None,
                "last_seen":       r["last_seen"].isoformat()  if r["last_seen"]  else None,
            }
            for r in rows
        ],
    }
