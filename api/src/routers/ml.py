"""ML/KI-Engine Status: Lernphase, Filter-Rate, Feature-Analyse."""
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

class MLStatus(BaseModel):
    phase:                  str   # "passthrough" | "learning" | "active"
    phase_label:            str
    model:                  ModelInfo
    bootstrap:              BootstrapInfo
    stats_24h:              Stats24h
    top_anomaly_features:   list[FeatureDeviation]


# ── Hilfsfunktionen ────────────────────────────────────────────────────────────

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
    filter_rate = round(ml_alerts_24h / max(flows_24h, 1) * 100, 3)
    stats_24h   = Stats24h(
        flows_total     = flows_24h,
        ml_alerts       = ml_alerts_24h,
        filter_rate_pct = filter_rate,
        alert_threshold = ALERT_THRESHOLD,
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
