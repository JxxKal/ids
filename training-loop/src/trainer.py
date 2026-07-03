"""
Model Trainer: Vollständiges Retrain des Isolation-Forest-Modells.

Nutzt denselben Feature-Raum wie der ml-engine:
  - Unlabeled Flows aus DB (normale Baseline)
  - Labeled Samples aus training_samples (attack=Anomalie, normal=inlier)

Strategie (semi-supervised):
  1. Lade unlabeled Flows → bilden den "normalen" Trainingsdatensatz
  2. Ergänze attack-labeled Samples als Outlier (contamination anpassen)
  3. Trainiere IsolationForest, speichere Modell auf /models

Modell-Dateien (kompatibel mit ml-engine):
  /models/scaler.joblib
  /models/iforest.joblib
  /models/meta.json
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

log = logging.getLogger(__name__)

_SCALER_FILE  = "scaler.joblib"
_IFOREST_FILE = "iforest.joblib"
_META_FILE    = "meta.json"
_CONFIG_FILE  = "ml_config.json"


def _calibrate_and_persist_threshold(
    iforest: IsolationForest,
    X_scaled_normal: np.ndarray,
    models_path: Path,
) -> None:
    """Leitet nach dem Training den Alert-Threshold aus der Score-Verteilung der
    NORMAL-Samples ab und schreibt ihn nach ml_config.json.

    Score-Mapping identisch zur ml-engine (`clip(0.5 - decision_function)`).
    Threshold = (1 - target_rate)-Quantil, geclamped auf [0.50, 0.90]. So trifft
    der Threshold die gewünschte Alert-Rate statt einer Magic-Zahl, die je nach
    Modell über der gesamten Score-Verteilung liegen kann (→ 0 Alerts).

    Respektiert einen manuellen Lock: steht in ml_config.json
    `threshold_source == "manual"`, wird der Threshold NICHT überschrieben (aber
    andere Keys bleiben unberührt). target_alert_rate wird aus ml_config.json
    gelesen (operator-tunbar), sonst aus ML_TARGET_ALERT_RATE, sonst 0.1 %."""
    cfg_path = models_path / _CONFIG_FILE
    cfg: dict = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            cfg = {}

    if cfg.get("threshold_source") == "manual":
        log.info("Threshold manuell gelockt (%.4f) – Kalibrierung übersprungen",
                 cfg.get("alert_threshold", 0.0))
        return

    if len(X_scaled_normal) < 100:
        log.info("Zu wenige Normal-Samples (%d) für Threshold-Kalibrierung",
                 len(X_scaled_normal))
        return

    target_rate = float(cfg.get("target_alert_rate",
                                os.environ.get("ML_TARGET_ALERT_RATE", "0.001")))
    raw = iforest.decision_function(X_scaled_normal)
    scores = np.clip(0.5 - raw, 0.0, 1.0)
    q = float(np.quantile(scores, 1.0 - target_rate))
    threshold = round(max(0.50, min(0.90, q)), 4)

    cfg.update({
        "alert_threshold":   threshold,
        "threshold_source":  "auto",
        "target_alert_rate": target_rate,
        "calibrated_at":     time.time(),
    })
    tmp = cfg_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg))
    tmp.rename(cfg_path)
    log.info("Threshold auto-kalibriert: %.4f (target_rate=%.4f, n_normal=%d, "
             "score P50=%.3f P99=%.3f max=%.3f)",
             threshold, target_rate, len(scores),
             float(np.percentile(scores, 50)), float(np.percentile(scores, 99)),
             float(scores.max()))


# Muss synchron zu ml-engine/src/features.py FEATURE_DIM=18 bleiben
_KNOWN_PORTS = {22, 80, 443, 53, 25, 3389, 21, 23, 110, 143, 8080, 8443, 587, 465, 161}


def _flow_to_vec(flow: dict) -> np.ndarray:
    """Konvertiert einen Flow-Dict in einen Feature-Vektor (18-dimensional).

    WICHTIG: muss exakt mit ml-engine/src/features.py:extract() übereinstimmen,
    sonst lädt ml-engine das Modell mit shape-mismatch."""
    pkt_count = float(flow.get("pkt_count") or 0)
    syn = float(flow.get("syn_ratio") or 0)
    rst = float(flow.get("rst_ratio") or 0)
    fin = float(flow.get("fin_ratio") or 0)
    dst_port = flow.get("dst_port")

    is_short_flow     = 1.0 if pkt_count <= 2.0 else 0.0
    is_syn_only       = 1.0 if (syn >= 0.99 and rst < 0.01 and fin < 0.01) else 0.0
    dst_port_known    = 1.0 if (dst_port is not None and int(dst_port) in _KNOWN_PORTS) else 0.0
    is_privileged_dst = 1.0 if (dst_port is not None and 0 < int(dst_port) < 1024) else 0.0
    dst_port_norm     = float(dst_port) / 65535.0 if dst_port is not None else 0.0

    return np.array([
        float(flow.get("duration_s")    or 0),
        pkt_count,
        float(flow.get("byte_count")    or 0),
        float(flow.get("pps")           or 0),
        float(flow.get("bps")           or 0),
        float(flow.get("pkt_size_mean") or 0),
        float(flow.get("pkt_size_std")  or 0),
        float(flow.get("iat_mean")      or 0),
        float(flow.get("iat_std")       or 0),
        float(flow.get("entropy_iat")   or 0),
        syn, rst, fin,
        dst_port_norm,
        is_short_flow, is_syn_only, dst_port_known, is_privileged_dst,
    ], dtype=np.float32)


def _sample_to_vec(sample: dict) -> np.ndarray | None:
    """Konvertiert einen training_sample-Row in Feature-Vektor."""
    features = sample.get("features")
    if not features:
        return None
    if isinstance(features, str):
        try:
            features = json.loads(features)
        except Exception:
            return None
    return _flow_to_vec(features)


def retrain(
    normal_flows: list[dict],
    labeled_samples: list[dict],
    models_dir: str,
    contamination: float = 0.01,
) -> bool:
    """
    Trainiert ein neues Modell und speichert es nach models_dir.
    Gibt True bei Erfolg zurück.
    """
    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)

    # Unlabeled Flows → normale Samples
    X_normal: list[np.ndarray] = []
    for f in normal_flows:
        vec = _flow_to_vec(f)
        if not np.any(np.isnan(vec)) and not np.any(np.isinf(vec)):
            X_normal.append(vec)

    # Labeled Samples trennen
    X_attack: list[np.ndarray] = []
    X_benign: list[np.ndarray] = []
    for s in labeled_samples:
        vec = _sample_to_vec(s)
        if vec is None:
            continue
        np.nan_to_num(vec, copy=False)
        if s.get("label") == "attack":
            X_attack.append(vec)
        else:
            X_benign.append(vec)

    if X_benign:
        X_normal.extend(X_benign)

    if not X_normal:
        log.warning("No normal samples available – aborting retrain")
        return False

    X = np.stack(X_normal)

    # Contamination anpassen wenn Angriffsdaten vorhanden
    actual_contamination = contamination
    if X_attack:
        attack_ratio = len(X_attack) / (len(X_normal) + len(X_attack))
        actual_contamination = max(contamination, min(0.5, attack_ratio))
        # Angriffsdaten dem Trainingsset hinzufügen
        X_all = np.vstack([X, np.stack(X_attack)])
    else:
        X_all = X

    log.info(
        "Retraining: %d normal + %d attack samples | contamination=%.3f",
        len(X_normal), len(X_attack), actual_contamination,
    )

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_all)

    iforest = IsolationForest(
        n_estimators=200,
        contamination=actual_contamination,
        random_state=42,
        n_jobs=-1,
    )
    iforest.fit(X_scaled)

    # Threshold aus der Score-Verteilung der NORMAL-Samples kalibrieren. X_all
    # ist [normal … , attack …] — die ersten len(X_normal) Zeilen sind die
    # Normal-Samples (inkl. der als benign gelabelten). Fehler dürfen den
    # Retrain nicht scheitern lassen (Modell ist wichtiger als der Threshold).
    try:
        _calibrate_and_persist_threshold(iforest, X_scaled[:len(X_normal)], models_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("Threshold-Kalibrierung fehlgeschlagen: %s", exc)

    # Atomar: erst tmp-Dateien, dann umbenennen
    tmp_s = models_path / "scaler.tmp.joblib"
    tmp_f = models_path / "iforest.tmp.joblib"
    joblib.dump(scaler,  tmp_s)
    joblib.dump(iforest, tmp_f)
    tmp_s.rename(models_path / _SCALER_FILE)
    tmp_f.rename(models_path / _IFOREST_FILE)

    meta = {
        "n_samples":     len(X_all),
        "n_attack":      len(X_attack),
        "contamination": actual_contamination,
        "ts":            time.time(),
        "version":       "1",
        "retrained_by":  "training-loop",
    }
    (models_path / _META_FILE).write_text(json.dumps(meta))

    log.info("Model saved to %s (n=%d)", models_dir, len(X_all))
    return True
