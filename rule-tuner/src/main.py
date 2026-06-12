"""rule-tuner Service — Einstiegspunkt.

Konsumiert das Kafka-Topic `rule-metrics` (Master + via tap-uplink
geforwardete Tap-Records), hält pro `(rule_id, param_name, scope)` ein
Reservoir, persistiert Quantile alle PERSIST_INTERVAL_S nach
`rule_baselines` und schreibt im State `tuning` alle TUNING_CYCLE_S
einen neuen Override-Stand via PUT /api/sig-rules/overrides.

Läuft NUR am Master (Compose-Profil `prod`). Tap-side existieren weder
DB noch API-Endpoint — Tap-Beiträge kommen über master-uplink ins
Master-Kafka.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

from api_client import ApiClient
from config import Config
from tuner import Tuner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("rule-tuner")

# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Touch't /tmp/heartbeat solange die Worker-Tasks leben — stirbt persist- oder
# state-loop, bleibt das File stehen und der Compose-Healthcheck meldet
# unhealthy (Prozess + Eventloop allein reichen nicht als Lebenszeichen).
async def _heartbeat_loop(watched: tuple) -> None:
    while not any(t.done() for t in watched):
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        await asyncio.sleep(30)



async def amain() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting rule-tuner | brokers=%s topic=%s api=%s reservoir=%d persist=%.0fs cycle=%.0fs",
        cfg.kafka_brokers, cfg.metrics_topic, cfg.api_base_url,
        cfg.reservoir_size, cfg.persist_interval_s, cfg.tuning_cycle_s,
    )

    tuner = Tuner(cfg)
    await tuner.setup()
    tuner.start_consumer()

    stop_event = asyncio.Event()

    def _stop(*_args) -> None:
        log.info("Shutdown-Signal empfangen")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _stop)

    async with ApiClient(cfg) as api:
        # Beim Boot kurz warten, damit api healthy ist (depends_on regelt nur
        # den Container-Start, nicht die Migration-Fertigstellung).
        await asyncio.sleep(2)
        # Sanity-Probe — wenn /ml/status sofort fehlschlägt, bringt's nichts
        # weiterzulaufen. Aber wir loggen und retryn statt zu crashen.
        for attempt in range(10):
            try:
                await api.get_ml_status()
                log.info("API erreichbar — starte Hauptschleifen")
                break
            except Exception as exc:
                log.warning("API noch nicht bereit (Versuch %d/10): %s", attempt + 1, exc)
                await asyncio.sleep(5)

        persist = asyncio.create_task(tuner.persist_loop(), name="persist-loop")
        state   = asyncio.create_task(tuner.state_loop(api), name="state-loop")
        beat    = asyncio.create_task(_heartbeat_loop((persist, state)), name="heartbeat")

        try:
            await stop_event.wait()
        finally:
            persist.cancel()
            state.cancel()
            for t in (persist, state):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
            await tuner.teardown()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
    except Exception:
        log.exception("Fatal")
        sys.exit(1)


if __name__ == "__main__":
    main()
