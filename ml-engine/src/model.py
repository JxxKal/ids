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
from collections import deque
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

# Obergrenze für den Scaler-Update-Buffer. Im Passthrough-/Bootstrap-Modus
# (kein Scaler geladen) drainiert partial_fit_scaler() den Buffer nicht →
# ohne Cap wüchse er pro Flow unbegrenzt bis zum OOM. Als Ring-Buffer hält er
# nur die jüngsten Flows; sobald ein Scaler da ist, verarbeitet partial_fit
# sie und leert ihn.
_BUFFER_MAXLEN = 10_000


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
        # mtime der iforest.joblib zum Zeitpunkt des letzten Load/Save. Damit
        # erkennt reload_if_updated(), ob training-loop zwischenzeitlich ein
        # frisches Modell eingespielt hat.
        self._loaded_mtime: float = 0.0

        # Buffer für inkrementelles Scaler-Update (bounded → OOM-Schutz im
        # Passthrough-Modus, wenn partial_fit_scaler() nichts drainiert).
        self._buffer: deque[np.ndarray] = deque(maxlen=_BUFFER_MAXLEN)

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
            try:
                self._loaded_mtime = ff.stat().st_mtime
            except OSError:
                self._loaded_mtime = time.time()
            log.info("Model loaded from %s (n_samples=%d)", self._dir, self._n_samples)
            return True
        except Exception as exc:
            log.warning("Could not load model: %s – will retrain", exc)
            return False

    def reload_if_updated(self) -> bool:
        """Lädt das Modell neu, wenn die Dateien auf Disk NEUER sind als unser
        In-Memory-Stand — z.B. weil training-loop atomar ein Retrain eingespielt
        hat. Ohne diesen Check würde ein anschließendes save() den frischeren
        Stand mit dem alten In-Memory-Modell überschreiben (Retrain wirkungslos).

        Race-Sicherheit: training-loop benennt scaler.joblib VOR iforest.joblib
        atomar um (rename). Wir triggern auf der iforest-mtime (zuletzt
        geschrieben) → sobald sie neuer ist, sind beide Dateien bereits der neue,
        konsistente Stand. Gibt True zurück, wenn neu geladen wurde."""
        ff = self._dir / _IFOREST_FILE
        try:
            disk_mtime = ff.stat().st_mtime
        except OSError:
            return False
        # +1e-6 Epsilon gegen Float-Gleichheits-Jitter beim eigenen Save.
        if disk_mtime <= self._loaded_mtime + 1e-6:
            return False
        log.info(
            "Neueres Modell auf Disk erkannt (mtime %.3f > %.3f) – lade neu",
            disk_mtime, self._loaded_mtime,
        )
        return self.load_if_exists()

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
            n_estimators=200,
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

    def score_batch(self, flows: list[dict]) -> "np.ndarray":
        """Vektorisiertes Scoring einer Flow-Liste (nur für Kalibrierung).
        Ungültige Flows werden übersprungen. Gibt ein 1D-Array der Scores
        zurück (leer, wenn Modell nicht bereit oder keine gültigen Flows)."""
        if not self._trained:
            return np.empty(0, dtype=np.float32)
        vecs: list[np.ndarray] = []
        for f in flows:
            try:
                v = extract(f)
                if not (np.any(np.isnan(v)) or np.any(np.isinf(v))):
                    vecs.append(v)
            except Exception:
                continue
        if not vecs:
            return np.empty(0, dtype=np.float32)
        X = np.stack(vecs).astype(np.float32)
        Xs = self._scaler.transform(X)                    # type: ignore[union-attr]
        raw = self._iforest.decision_function(Xs)          # type: ignore[union-attr]
        # Identisch zu score(): clip(0.5 - decision_function).
        return np.clip(0.5 - raw, 0.0, 1.0)

    def calibrate_threshold(
        self,
        flows: list[dict],
        target_rate: float,
        floor: float = 0.50,
        ceil:  float = 0.90,
        min_samples: int = 100,
    ) -> float | None:
        """Leitet einen Alert-Threshold aus der Score-Verteilung realer Flows ab.

        Warum: der IsolationForest-Score ist `clip(0.5 - decision_function)`;
        für Normal-Traffic liegt er strukturell knapp unter/um 0.5, der Max
        selten über ~0.6. Ein fixer Default (0.65) liegt damit ÜBER der ganzen
        Verteilung → nie ein Alert. Statt einer Magic-Zahl kalibrieren wir den
        Threshold als (1 - target_rate)-Quantil der beobachteten Scores: er
        trifft die gewünschte Alert-Rate und wandert automatisch mit dem Modell
        mit. Geclamped auf [floor, ceil] (floor=0.5 = Modell-Entscheidungsgrenze,
        konsistent mit dem [0.5, 0.95]-Contract der API).

        Gibt None zurück, wenn zu wenige gültige Samples vorliegen (dann bleibt
        der bestehende/Default-Threshold unangetastet)."""
        scores = self.score_batch(flows)
        if scores.size < min_samples:
            return None
        q = float(np.quantile(scores, 1.0 - target_rate))
        return round(max(floor, min(ceil, q)), 4)

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
        ff = self._dir / _IFOREST_FILE
        joblib.dump(self._scaler,  self._dir / _SCALER_FILE)
        joblib.dump(self._iforest, ff)
        meta = {
            "n_samples": self._n_samples,
            "ts": time.time(),
            "version": "1",
            "contamination": self._contamination,
        }
        (self._dir / _META_FILE).write_text(json.dumps(meta))
        # eigene Schreib-mtime merken, damit reload_if_updated() den eigenen
        # Save nicht fälschlich als fremdes Retrain interpretiert.
        try:
            self._loaded_mtime = ff.stat().st_mtime
        except OSError:
            self._loaded_mtime = time.time()

    def save(self) -> None:
        if not self._trained:
            return
        # Falls training-loop zwischenzeitlich ein Retrain atomar eingespielt
        # hat: erst nachladen, damit wir es nicht mit dem alten Stand
        # überschreiben. Danach persistieren wir den (ggf. neu geladenen) Stand.
        self.reload_if_updated()
        self._save()
        log.debug("Model saved (n_samples=%d)", self._n_samples)
