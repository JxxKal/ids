"""
ML Engine – Einstiegspunkt.

Konsumiert Flows vom Topic 'flows', bewertet sie mit einem Isolation-Forest-
Modell auf Anomalien und publiziert Alerts auf 'alerts'.

Lifecycle:
  1. Gespeichertes Modell laden (falls vorhanden)
  2. Falls kein Modell: Bootstrap aus DB, initiales Training
  3. Haupt-Loop: Flow lesen → Score → bei Anomalie Alert publizieren
  4. Alle PARTIAL_FIT_INTERVAL Flows: Scaler inkrementell anpassen
  5. Alle SAVE_INTERVAL Flows: Modell speichern

Alert-Schema (kompatibel mit alert-manager):
  rule_id     = "ML_ANOMALY"
  source      = "ml"
  score       = 0.0–1.0
  + Flow-Felder: src_ip, dst_ip, dst_port, proto, flow_id, ts
"""
from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from bootstrap import load_flows
from config import Config
from model import AnomalyModel

_ML_CONFIG_FILE = None  # wird in run() gesetzt


def _read_runtime_config(models_dir: str) -> dict:
    """Liest ml_config.json aus dem geteilten Models-Volume."""
    import json
    path = Path(models_dir) / "ml_config.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def _write_runtime_config(models_dir: str, updates: dict) -> None:
    """Merged `updates` in ml_config.json und schreibt atomar zurück. Bestehende
    Keys (z.B. contamination, retrain_interval_s, manuelle Overrides) bleiben
    erhalten."""
    import json
    path = Path(models_dir) / "ml_config.json"
    cfg = _read_runtime_config(models_dir)
    cfg.update(updates)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg))
    tmp.rename(path)


def _calibrate_startup(model, cfg) -> None:
    """Einmalige Threshold-Kalibrierung beim Start.

    Greift für Hosts, die ein Modell haben, aber (noch) keine kalibrierte
    ml_config.json — genau der Fall nach einer Neuinstallation / frischem
    Models-Volume, wo sonst der Fallback-Threshold gälte und ML wirkungslos
    wäre. Respektiert einen manuellen Lock (threshold_source == "manual") und
    fasst dann nichts an."""
    rt = _read_runtime_config(cfg.models_dir)
    if rt.get("threshold_source") == "manual":
        log.info("Threshold ist manuell gesetzt (%.4f) – keine Auto-Kalibrierung",
                 rt.get("alert_threshold", ALERT_THRESHOLD))
        return
    if not model.is_ready:
        return
    target_rate = float(rt.get("target_alert_rate", cfg.target_alert_rate))
    flows = load_flows(cfg.postgres_dsn, limit=cfg.calibration_samples)
    thr = model.calibrate_threshold(flows, target_rate)
    if thr is None:
        log.info("Kalibrierung übersprungen (nur %d Flows) – Threshold bleibt %.4f",
                 len(flows), rt.get("alert_threshold", ALERT_THRESHOLD))
        return
    _write_runtime_config(cfg.models_dir, {
        "alert_threshold":   thr,
        "threshold_source":  "auto",
        "target_alert_rate": target_rate,
        "calibrated_at":     time.time(),
    })
    log.info("Auto-kalibrierter Threshold: %.4f (target_rate=%.4f, n_flows=%d)",
             thr, target_rate, len(flows))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ml-engine")

# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Die Hauptschleife touch't /tmp/heartbeat (rate-limited auf 5 s); der
# Compose-Healthcheck meldet unhealthy, wenn das File älter als 120 s ist.
# Bewusst an die Schleife gekoppelt statt an den Prozess: ein hängender
# Consumer fällt so auf, ein bloß lebender Interpreter reicht nicht.
_HB_LAST = 0.0


def _beat() -> None:
    global _HB_LAST
    now = time.monotonic()
    if now - _HB_LAST < 5.0:
        return
    _HB_LAST = now
    try:
        Path("/tmp/heartbeat").touch()
    except OSError:
        pass


FLOWS_TOPIC  = "flows"
ALERTS_TOPIC = "alerts-raw"
POLL_TIMEOUT = 1.0
GROUP_ID     = "ml-engine"

# Fallback-Score-Schwellwert (überschreibbar via ml_config.json). Bewusst NICHT
# mehr 0.65: der IsolationForest-Score (clip(0.5 - decision_function)) liegt für
# Normal-Traffic strukturell knapp um/unter 0.5, der Max real selten über ~0.6.
# 0.65 lag damit über der GESAMTEN Verteilung → nie ein Alert. Der echte Wert
# wird beim Startup + nach jedem Retrain aus der Score-Verteilung kalibriert
# (siehe _calibrate_startup / trainer.retrain); 0.55 ist nur der Notnagel, falls
# noch keine Kalibrierung stattfand.
ALERT_THRESHOLD   = 0.55
CONFIG_POLL_FLOWS = 500   # Alle N Flows Konfig-Datei prüfen


def _make_consumer(brokers: str) -> Consumer:
    return Consumer({
        "bootstrap.servers":  brokers,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })


def _make_producer(brokers: str) -> Producer:
    return Producer({
        "bootstrap.servers": brokers,
        "acks":              "1",
        "linger.ms":         10,
        "compression.type":  "lz4",
    })


def _delivery_cb(err, msg):
    if err:
        log.error("Alert delivery failed: %s", err)


def _make_alert(flow: dict, score: float) -> dict:
    return {
        "rule_id":     "ML_ANOMALY",
        "rule_name":   "ML Anomalie-Erkennung",
        "severity":    _score_to_severity(score),
        "tags":        ["ml", "anomaly"],
        "description": f"Isolation-Forest-Anomalie-Score {score:.2f} (Schwellwert {ALERT_THRESHOLD})",
        "source":      "ml",
        "score":       score,
        "src_ip":      flow.get("src_ip"),
        "dst_ip":      flow.get("dst_ip"),
        "dst_port":    flow.get("dst_port"),
        "proto":       flow.get("proto"),
        "flow_id":     flow.get("flow_id"),
        "ts":          float(flow.get("end_ts") or time.time()),
    }


def _score_to_severity(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"


def run(cfg: Config) -> None:
    model = AnomalyModel(cfg.models_dir, contamination=cfg.contamination)

    # Gespeichertes Modell laden oder bootstrappen
    if not model.load_if_exists():
        log.info("No saved model found – bootstrapping from DB …")
        bootstrap_flows = load_flows(cfg.postgres_dsn, limit=cfg.bootstrap_min_samples * 2)
        if len(bootstrap_flows) >= cfg.bootstrap_min_samples:
            model.train(bootstrap_flows)
        else:
            log.warning(
                "Only %d bootstrap flows available (need %d) – starting in passthrough mode",
                len(bootstrap_flows),
                cfg.bootstrap_min_samples,
            )
            if bootstrap_flows:
                model.train(bootstrap_flows)

    # Threshold beim Start aus der echten Score-Verteilung kalibrieren, damit
    # ein frisch installierter Host (Modell da, aber keine ml_config.json) nicht
    # mit dem toten Fallback-Threshold läuft. Fehler hier dürfen den Start nicht
    # verhindern — im Zweifel gilt der Fallback/das bestehende Config-File.
    try:
        _calibrate_startup(model, cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("Startup-Kalibrierung fehlgeschlagen: %s", exc)

    consumer = _make_consumer(cfg.kafka_brokers)
    producer  = _make_producer(cfg.kafka_brokers)
    consumer.subscribe([FLOWS_TOPIC])
    _startup_thr = _read_runtime_config(cfg.models_dir).get("alert_threshold", ALERT_THRESHOLD)
    log.info("ML engine ready | model_ready=%s | threshold=%.3f", model.is_ready, _startup_thr)

    running = True
    flows_since_partial = 0
    flows_since_save    = 0
    flows_since_cfg_poll = 0
    total_flows  = 0
    total_alerts = 0
    alert_threshold = _read_runtime_config(cfg.models_dir).get("alert_threshold", ALERT_THRESHOLD)
    partial_fit_interval = cfg.partial_fit_interval

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    try:
        while running:
            _beat()
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            if msg is None:
                if cfg.test_mode:
                    log.info("Test mode: no more messages, exiting")
                    break
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    if cfg.test_mode:
                        break
                    continue
                raise KafkaException(msg.error())

            try:
                flow = orjson.loads(msg.value())
            except Exception as exc:
                log.warning("Could not decode flow: %s", exc)
                continue

            total_flows += 1
            flows_since_partial  += 1
            flows_since_save     += 1
            flows_since_cfg_poll += 1

            # Buffer für Scaler-Update füllen
            model.add_to_buffer(flow)

            # Konfig-Datei periodisch neu lesen (Threshold-Änderungen zur Laufzeit)
            if flows_since_cfg_poll >= CONFIG_POLL_FLOWS:
                rt = _read_runtime_config(cfg.models_dir)
                new_thr = rt.get("alert_threshold", ALERT_THRESHOLD)
                new_pfi = rt.get("partial_fit_interval", cfg.partial_fit_interval)
                if abs(new_thr - alert_threshold) > 0.001:
                    log.info("Threshold updated: %.3f → %.3f", alert_threshold, new_thr)
                    alert_threshold = new_thr
                if new_pfi != partial_fit_interval:
                    log.info("partial_fit_interval updated: %d → %d", partial_fit_interval, new_pfi)
                    partial_fit_interval = new_pfi
                flows_since_cfg_poll = 0

            # Score berechnen (nur wenn Modell bereit)
            if model.is_ready:
                score = model.score(flow)

                if score >= alert_threshold:
                    total_alerts += 1
                    alert = _make_alert(flow, score)
                    log.info(
                        "ALERT [ML_ANOMALY] score=%.3f | %s → %s:%s | severity=%s",
                        score,
                        flow.get("src_ip", "-"),
                        flow.get("dst_ip", "-"),
                        flow.get("dst_port", "-"),
                        alert["severity"],
                    )
                    producer.produce(
                        ALERTS_TOPIC,
                        value=orjson.dumps(alert),
                        callback=_delivery_cb,
                    )
                    producer.poll(0)

            # Inkrementeller Scaler-Update
            if flows_since_partial >= partial_fit_interval:
                model.partial_fit_scaler()
                flows_since_partial = 0

            # Periodisches Speichern
            if flows_since_save >= cfg.save_interval:
                model.save()
                flows_since_save = 0

    finally:
        log.info(
            "Shutting down – flows: %d, alerts: %d",
            total_flows,
            total_alerts,
        )
        model.save()
        producer.flush(timeout=10)
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting ml-engine | brokers=%s models_dir=%s test_mode=%s",
        cfg.kafka_brokers,
        cfg.models_dir,
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
