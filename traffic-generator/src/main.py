"""
Traffic Generator – Einstiegspunkt.

Wartet auf `test-commands`-Kafka-Events (vom API-Service),
injiziert synthetische Flow-Records direkt in das Kafka-Topic 'flows'
(kein Packet-Capture nötig) und pollt anschließend die DB auf einen
passenden Alert um den TestRun-Eintrag zu aktualisieren.

Kafka-Event-Format (Eingang):
  { "run_id": "uuid", "scenario_id": "SCAN_001", "ts": 1234567890.0 }

Flows werden mit is_test=True markiert; die Signature-Engine propagiert
dieses Flag auf generierte Alerts.

TestRun-Update:
  - status = "completed" / "failed"
  - triggered = true/false
  - alert_id = UUID des ausgelösten Alerts (falls gefunden)
  - latency_ms = Zeit zwischen Szenario-Start und Alert
"""
from __future__ import annotations

import logging
import signal
import sys
import time

import orjson
import psycopg2
import psycopg2.extras
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from config import Config
from scenarios import SCENARIOS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("traffic-generator")

COMMANDS_TOPIC = "test-commands"
GROUP_ID       = "traffic-generator"
POLL_TIMEOUT   = 1.0
ALERT_WAIT_S   = 30   # Wie lange auf passenden Alert gewartet wird
ALERT_POLL_S   = 1    # Wie oft die DB gepollt wird


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
        "linger.ms":         5,
    })


def _inject_flows(
    producer: Producer,
    flows_topic: str,
    flows: list[dict],
) -> None:
    """Publiziert synthetische Flows ins flows-Topic."""
    for flow in flows:
        producer.produce(flows_topic, value=orjson.dumps(flow))
    producer.flush(timeout=10)
    log.info("Injected %d synthetic flows", len(flows))


def _wait_for_alert(
    conn: psycopg2.extensions.connection,
    expected_rule: str,
    after_ts: float,
    timeout_s: int = ALERT_WAIT_S,
) -> dict | None:
    """Pollt die DB bis ein passender Alert erscheint oder Timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT alert_id, ts
                    FROM alerts
                    WHERE rule_id = %s
                      AND ts > to_timestamp(%s)
                      AND is_test = true
                    ORDER BY ts ASC
                    LIMIT 1
                    """,
                    (expected_rule, after_ts),
                )
                row = cur.fetchone()
            if row:
                return dict(row)
        except Exception as exc:
            log.debug("DB poll error: %s", exc)
        time.sleep(ALERT_POLL_S)
    return None


def _update_run(
    conn: psycopg2.extensions.connection,
    run_id: str,
    status: str,
    triggered: bool,
    alert_id: str | None,
    latency_ms: int | None,
    error: str | None = None,
) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE test_runs
                SET status       = %s,
                    completed_at = now(),
                    triggered    = %s,
                    alert_id     = %s,
                    latency_ms   = %s,
                    error        = %s
                WHERE id = %s::uuid
                """,
                (status, triggered, alert_id, latency_ms, error, run_id),
            )
        conn.commit()
    except Exception as exc:
        log.error("_update_run: %s", exc)
        conn.rollback()


def run(cfg: Config) -> None:
    conn     = psycopg2.connect(cfg.postgres_dsn)
    conn.autocommit = False

    consumer = _make_consumer(cfg.kafka_brokers)
    producer = _make_producer(cfg.kafka_brokers)
    consumer.subscribe([COMMANDS_TOPIC])
    log.info(
        "Traffic generator ready | flows_topic=%s src_ip=%s",
        cfg.flows_topic,
        cfg.src_ip,
    )

    running = True

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    try:
        while running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(msg.error())

            try:
                cmd = orjson.loads(msg.value())
            except Exception:
                continue

            run_id      = cmd.get("run_id")
            scenario_id = cmd.get("scenario_id")

            if not run_id or scenario_id not in SCENARIOS:
                log.warning("Unknown scenario or missing run_id: %s", cmd)
                continue

            expected_rule, scenario_fn = SCENARIOS[scenario_id]
            log.info("Running scenario %s (run_id=%s)", scenario_id, run_id[:8])

            start_ts  = time.time()
            error_msg: str | None = None

            try:
                flows = scenario_fn(cfg.src_ip, cfg.target_ip)
                _inject_flows(producer, cfg.flows_topic, flows)
            except Exception as exc:
                error_msg = str(exc)
                log.error("Scenario %s failed: %s", scenario_id, exc)

            if error_msg:
                _update_run(conn, run_id, "failed", False, None, None, error_msg)
                continue

            # Auf passenden Alert warten
            alert = _wait_for_alert(conn, expected_rule, start_ts)

            if alert:
                latency_ms = int((time.time() - start_ts) * 1000)
                alert_id   = str(alert["alert_id"])
                log.info(
                    "Scenario %s triggered %s in %dms",
                    scenario_id, expected_rule, latency_ms,
                )
                _update_run(conn, run_id, "completed", True, alert_id, latency_ms)
            else:
                log.warning(
                    "Scenario %s: alert %s not triggered within %ds",
                    scenario_id, expected_rule, ALERT_WAIT_S,
                )
                _update_run(conn, run_id, "completed", False, None, None)

    finally:
        conn.close()
        consumer.close()
        producer.flush(timeout=5)
        log.info("Traffic generator stopped")


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting traffic-generator | brokers=%s flows_topic=%s",
        cfg.kafka_brokers,
        cfg.flows_topic,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
