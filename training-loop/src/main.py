"""
Training Loop – Einstiegspunkt.

Zwei parallele Aufgaben:

1. Feedback-Collector (Kafka-Thread):
   Liest `feedback`-Events vom Topic, holt Flow-Features aus DB,
   schreibt gelabelte Samples in `training_samples`.

2. Retrain-Loop (Haupt-Thread):
   Prüft alle RETRAIN_INTERVAL_S ob ausreichend neue gelabelte
   Samples vorliegen; trainiert das Modell neu und überschreibt
   die Dateien im geteilten /models-Volume.

Label-Mapping:
  feedback=tp → label=attack   (True Positive: echter Angriff)
  feedback=fp → label=normal   (False Positive: kein Angriff)
"""
from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path

import orjson
from confluent_kafka import Consumer, KafkaError

from config import Config
from db import TrainingDB
from trainer import retrain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("training-loop")

# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Prozess-Liveness: ein Daemon-Thread touch't /tmp/heartbeat alle 30 s; der
# Compose-Healthcheck meldet unhealthy, wenn das File älter als 120 s ist.
# Bewusst NICHT an die Hauptschleife gekoppelt — die blockiert hier legitim
# minutenlang (Training-Lauf bzw. laufendes Test-Szenario).
def _heartbeat_thread() -> None:
    while True:
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        time.sleep(30)


FEEDBACK_TOPIC = "feedback"
GROUP_ID       = "training-loop"
POLL_TIMEOUT   = 2.0

_LABEL_MAP = {"tp": "attack", "fp": "normal"}


def _feedback_collector(cfg: Config, db: TrainingDB, stop: threading.Event) -> None:
    """Läuft als Background-Thread."""
    consumer = Consumer({
        "bootstrap.servers":  cfg.kafka_brokers,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([FEEDBACK_TOPIC])
    log.info("Feedback collector started")

    try:
        while not stop.is_set():
            msg = consumer.poll(timeout=POLL_TIMEOUT)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("Kafka error: %s", msg.error())
                continue

            try:
                event = orjson.loads(msg.value())
            except Exception:
                continue

            alert_id = event.get("alert_id")
            feedback = event.get("feedback")
            label    = _LABEL_MAP.get(feedback or "")

            if not alert_id or not label:
                continue

            # Feature-Dict aus DB laden (über alert → flow)
            features = _load_features(db, alert_id, event)
            if features:
                db.save_sample(alert_id, label, features)
                log.info("Sample saved: %s → %s", alert_id[:8], label)

    finally:
        consumer.close()
        log.info("Feedback collector stopped")


def _load_features(db: TrainingDB, alert_id: str, event: dict) -> dict | None:
    """
    Versucht Flow-Features für ein Alert aus der DB zu laden.
    Fallback: Metadaten aus dem Feedback-Event selbst verwenden.
    """
    try:
        db._connect()
        with db._conn.cursor() as cur:    # type: ignore[union-attr]
            cur.execute(
                """
                SELECT f.stats, f.pkt_count, f.byte_count,
                       f.dst_port,
                       EXTRACT(EPOCH FROM (f.end_ts - f.start_ts)) AS duration_s
                FROM alerts a
                JOIN flows f ON f.flow_id = a.flow_id
                WHERE a.alert_id = %s::uuid
                """,
                (alert_id,),
            )
            row = cur.fetchone()
    except Exception as exc:
        log.debug("_load_features DB error: %s", exc)
        db._conn = None
        return None

    if row:
        stats = row[0] or {}
        return {
            "duration_s":    row[4],
            "pkt_count":     row[1],
            "byte_count":    row[2],
            "dst_port":      row[3],
            "pps":           stats.get("pps"),
            "bps":           stats.get("bps"),
            "pkt_size_mean": (stats.get("pkt_size") or {}).get("mean"),
            "pkt_size_std":  (stats.get("pkt_size") or {}).get("std"),
            "iat_mean":      (stats.get("iat") or {}).get("mean"),
            "iat_std":       (stats.get("iat") or {}).get("std"),
            "entropy_iat":   stats.get("entropy_iat"),
            "syn_ratio":     (stats.get("tcp_flags") or {}).get("SYN"),
            "rst_ratio":     (stats.get("tcp_flags") or {}).get("RST"),
            "fin_ratio":     (stats.get("tcp_flags") or {}).get("FIN"),
        }

    # Kein Flow-Join möglich: minimale Features aus Event
    return {
        "score": event.get("score"),
        "rule_id": event.get("rule_id"),
    }


def run(cfg: Config) -> None:
    db   = TrainingDB(cfg.postgres_dsn)
    stop = threading.Event()

    # Feedback-Collector als Daemon-Thread starten
    collector = threading.Thread(
        target=_feedback_collector,
        args=(cfg, db, stop),
        daemon=True,
        name="feedback-collector",
    )
    collector.start()

    running = True
    last_retrain_ts = 0.0

    def _stopper(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False
        stop.set()

    signal.signal(signal.SIGTERM, _stopper)
    signal.signal(signal.SIGINT,  _stopper)

    log.info(
        "Training loop started | retrain_interval=%.0fs min_new=%d",
        cfg.retrain_interval_s,
        cfg.min_new_samples,
    )

    status_file = Path(cfg.models_dir) / "retrain_status.json"

    def _read_runtime_interval() -> float:
        """retrain_interval_s zur Laufzeit aus ml_config.json — wenn der User
        den Wert im UI ändert, greift es ohne Container-Restart."""
        cfg_file = Path(cfg.models_dir) / "ml_config.json"
        if cfg_file.exists():
            try:
                rt = json.loads(cfg_file.read_text())
                v = rt.get("retrain_interval_s")
                if isinstance(v, (int, float)) and v >= 60:
                    return float(v)
            except Exception:
                pass
        return cfg.retrain_interval_s

    def _write_status(*, currently_training: bool,
                      last_trained_at: float | None,
                      last_run_duration_s: float | None,
                      last_run_samples: int | None,
                      retrain_interval_s: float,
                      next_scheduled_at: float | None,
                      last_error: str | None = None) -> None:
        """Schreibt den aktuellen Trainings-State in /models/retrain_status.json.
        Wird von der API gelesen und an das Frontend ausgeliefert."""
        try:
            status_file.write_text(json.dumps({
                "currently_training":   currently_training,
                "last_trained_at":      last_trained_at,
                "last_run_duration_s":  last_run_duration_s,
                "last_run_samples":     last_run_samples,
                "retrain_interval_s":   retrain_interval_s,
                "next_scheduled_at":    next_scheduled_at,
                "last_error":           last_error,
                "updated_at":           time.time(),
            }))
        except Exception as exc:
            log.warning("Konnte retrain_status.json nicht schreiben: %s", exc)

    last_run_duration_s: float | None = None
    last_run_samples: int | None = None
    last_error: str | None = None
    interval = _read_runtime_interval()
    _write_status(
        currently_training=False, last_trained_at=None,
        last_run_duration_s=None, last_run_samples=None,
        retrain_interval_s=interval, next_scheduled_at=None,
    )

    threading.Thread(target=_heartbeat_thread, daemon=True, name="heartbeat").start()
    try:
        while running:
            time.sleep(60)  # Prüfintervall: jede Minute

            if not running:
                break

            now = time.time()
            interval = _read_runtime_interval()
            next_scheduled = (last_retrain_ts + interval) if last_retrain_ts > 0 else None
            # Status-File alle 60 s aktualisieren (auch wenn nicht trainiert wird —
            # damit das UI den next_scheduled-Countdown live sieht).
            _write_status(
                currently_training=False,
                last_trained_at=last_retrain_ts if last_retrain_ts > 0 else None,
                last_run_duration_s=last_run_duration_s,
                last_run_samples=last_run_samples,
                retrain_interval_s=interval,
                next_scheduled_at=next_scheduled,
                last_error=last_error,
            )

            if now - last_retrain_ts < interval:
                continue

            # Sofort-Retrain via Trigger-Datei (z.B. nach Konfig-Änderung im UI)
            trigger_file = Path(cfg.models_dir) / "retrain.trigger"
            force_retrain = trigger_file.exists()
            if force_retrain:
                log.info("Retrain-Trigger erkannt – starte sofortigen Retrain")
                trigger_file.unlink(missing_ok=True)

            new_count = db.count_new_samples(last_retrain_ts)
            if not force_retrain and new_count < cfg.min_new_samples and last_retrain_ts > 0:
                log.info(
                    "Only %d new samples (need %d) – skipping retrain",
                    new_count,
                    cfg.min_new_samples,
                )
                last_retrain_ts = now  # Intervall zurücksetzen
                continue

            log.info("Starting retrain (%d new samples since last run, forced=%s)", new_count, force_retrain)

            # Contamination aus ml_config.json lesen (falls vorhanden)
            contamination = cfg.contamination
            cfg_file = Path(cfg.models_dir) / "ml_config.json"
            if cfg_file.exists():
                try:
                    rt_cfg = json.loads(cfg_file.read_text())
                    contamination = float(rt_cfg.get("contamination", contamination))
                    log.info("Using contamination=%.4f from ml_config.json", contamination)
                except Exception:
                    pass

            # currently_training=True während retrain() läuft.
            _write_status(
                currently_training=True,
                last_trained_at=last_retrain_ts if last_retrain_ts > 0 else None,
                last_run_duration_s=last_run_duration_s,
                last_run_samples=last_run_samples,
                retrain_interval_s=interval,
                next_scheduled_at=next_scheduled,
                last_error=last_error,
            )

            run_started = time.time()
            normal_flows    = db.load_flows_for_bootstrap(cfg.max_train_samples)
            labeled_samples = db.load_samples(cfg.max_train_samples)

            try:
                success = retrain(
                    normal_flows=normal_flows,
                    labeled_samples=labeled_samples,
                    models_dir=cfg.models_dir,
                    contamination=contamination,
                )
            except Exception as exc:
                log.exception("Retrain crashed: %s", exc)
                success = False
                last_error = str(exc)

            run_dur = time.time() - run_started
            if success:
                last_retrain_ts = run_started
                last_run_duration_s = run_dur
                last_run_samples = len(normal_flows) + len(labeled_samples)
                last_error = None
                log.info("Retrain complete (%.1fs, %d samples)",
                         run_dur, last_run_samples)
            else:
                log.warning("Retrain failed – will retry next interval")
                if last_error is None:
                    last_error = "retrain returned False"

            _write_status(
                currently_training=False,
                last_trained_at=last_retrain_ts if last_retrain_ts > 0 else None,
                last_run_duration_s=last_run_duration_s,
                last_run_samples=last_run_samples,
                retrain_interval_s=interval,
                next_scheduled_at=last_retrain_ts + interval if last_retrain_ts > 0 else None,
                last_error=last_error,
            )

            if cfg.test_mode:
                log.info("Test mode: exiting after first retrain attempt")
                break

    finally:
        stop.set()
        collector.join(timeout=10)
        db.close()
        log.info("Training loop shutdown complete")


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting training-loop | brokers=%s models_dir=%s interval=%.0fs test_mode=%s",
        cfg.kafka_brokers,
        cfg.models_dir,
        cfg.retrain_interval_s,
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
