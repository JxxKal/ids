"""
ML-Modell-Verwaltung: Isolation Forest + StandardScaler.

Lifecycle:
  1. Bootstrap: Flows aus DB laden, initiales Modell trainieren, speichern.
  2. Inference: Flows aus Kafka → Feature-Vektor → Anomalie-Score.
  3. Partial-Fit: Alle N Flows den Scaler inkrementell anpassen
     (IsolationForest selbst unterstützt kein partial_fit – bei ausreichend
     neuen Daten wird ein Full-Retrain angestoßen).

Dateien im MODELS_DIR:
  scaler.joblib     – StandardScaler
  iforest.joblib    – IsolationForest
  meta.json         – Trainings-Metadaten (n_samples, ts, version)
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

from features import FEATURE_DIM, extract

log = logging.getLogger(__name__)

_SCALER_FILE  = "scaler.joblib"
_IFOREST_FILE = "iforest.joblib"
_META_FILE    = "meta.json"


class AnomalyModel:
    """
    Kapselt Scaler + IsolationForest.
    thread-safe: nein (single-threaded main loop reicht).
    """

    def __init__(self, models_dir: str, contamination: float = 0.01) -> None:
        self._dir = Path(models_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._contamination = contamination

        self._scaler:  StandardScaler  | None = None
        self._iforest: IsolationForest | None = None
        self._n_samples = 0
        self._trained = False

        # Buffer für inkrementelles Scaler-Update
        self._buffer: list[np.ndarray] = []

    @property
    def is_ready(self) -> bool:
        return self._trained

    def load_if_exists(self) -> bool:
        """Lädt gespeichertes Modell. Gibt True zurück wenn erfolgreich."""
        sf = self._dir / _SCALER_FILE
        ff = self._dir / _IFOREST_FILE
        mf = self._dir / _META_FILE

        if not (sf.exists() and ff.exists()):
            return False
        try:
            self._scaler  = joblib.load(sf)
            self._iforest = joblib.load(ff)
            if mf.exists():
                meta = json.loads(mf.read_text())
                self._n_samples = meta.get("n_samples", 0)
            self._trained = True
            log.info("Model loaded from %s (n_samples=%d)", self._dir, self._n_samples)
            return True
        except Exception as exc:
            log.warning("Could not load model: %s – will retrain", exc)
            return False

    def train(self, flows: list[dict]) -> None:
        """Vollständiges Training auf einer Liste von Flow-Dicts."""
        if not flows:
            log.warning("train() called with empty flow list")
            return

        X = np.stack([extract(f) for f in flows]).astype(np.float32)
        log.info("Training on %d flows …", len(X))

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        iforest = IsolationForest(
            n_estimators=100,
            contamination=self._contamination,
            random_state=42,
            n_jobs=-1,
        )
        iforest.fit(X_scaled)

        self._scaler  = scaler
        self._iforest = iforest
        self._n_samples = len(X)
        self._trained = True
        self._buffer.clear()

        self._save()
        log.info("Model trained and saved (n_samples=%d)", self._n_samples)

    def score(self, flow: dict) -> float:
        """
        Gibt einen Anomalie-Score zwischen 0.0 (normal) und 1.0 (anomal) zurück.
        Basiert auf dem negativen decision_function-Wert des IsolationForest.
        Gibt -1.0 zurück wenn kein Modell geladen ist.
        """
        if not self._trained:
            return -1.0

        vec = extract(flow).reshape(1, -1)
        vec_scaled = self._scaler.transform(vec)        # type: ignore[union-attr]
        # decision_function: negativ = anomal, positiv = normal
        raw = float(self._iforest.decision_function(vec_scaled)[0])  # type: ignore[union-attr]
        # Auf [0, 1] normieren: score ≈ 0 bei raw > 0 (normal), ≈ 1 bei raw << 0
        score = max(0.0, min(1.0, 0.5 - raw))
        return round(score, 4)

    def add_to_buffer(self, flow: dict) -> int:
        """
        Fügt einen Flow zum Scaler-Update-Buffer hinzu.
        Gibt aktuelle Buffer-Größe zurück.
        """
        self._buffer.append(extract(flow))
        return len(self._buffer)

    def partial_fit_scaler(self) -> None:
        """Passt den Scaler inkrementell an und leert den Buffer."""
        if not self._buffer or self._scaler is None:
            return
        X = np.stack(self._buffer).astype(np.float32)
        self._scaler.partial_fit(X)
        self._n_samples += len(X)
        self._buffer.clear()
        log.debug("Scaler partial_fit: n_samples now %d", self._n_samples)

    # ── Persistenz ────────────────────────────────────────────────────────────

    def _save(self) -> None:
        joblib.dump(self._scaler,  self._dir / _SCALER_FILE)
        joblib.dump(self._iforest, self._dir / _IFOREST_FILE)
        meta = {
            "n_samples": self._n_samples,
            "ts": time.time(),
            "version": "1",
            "contamination": self._contamination,
        }
        (self._dir / _META_FILE).write_text(json.dumps(meta))

    def save(self) -> None:
        if self._trained:
            self._save()
            log.debug("Model saved (n_samples=%d)", self._n_samples)
