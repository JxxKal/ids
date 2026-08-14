"""Kafka-Consumer für `alerts-enriched` (protocol.md §1.5).

Outage-Strategie wörtlich aus der Spec: `auto.offset.reset=latest`, **kein**
manueller Commit (Muster von `mqtt-bridge`). Fällt der Tunnel aus, laufen
Events ins Leere; nach Reconnect wird ab „jetzt" weitergemacht. Es gibt
bewusst KEINEN Disk-Buffer wie in tap-uplink — nachgereichte Push-
Nachrichten von vor zwei Stunden sind für einen Operator wertlos, und die
kanonische Kopie liegt ohnehin in TimescaleDB.

Der Consumer läuft unabhängig vom Tunnel-Zustand. Die Queue dazwischen ist
klein und bounded: läuft sie voll (Tunnel unten oder Alert-Sturm), fliegt
der ÄLTESTE Eintrag raus. Das ist die richtige Richtung — bei einem
Alarm-Sturm interessiert den Operator der aktuelle Stand, nicht der von
vor 40 Sekunden.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import orjson
from confluent_kafka import Consumer, KafkaError

from config import Config, RuntimeConfig
from fields import severity_at_least

log = logging.getLogger(__name__)


def make_consumer(cfg: Config) -> Consumer:
    return Consumer({
        "bootstrap.servers": cfg.kafka_brokers,
        "group.id": cfg.kafka_group_id,
        # §1.5 — ab "jetzt", nie Backlog nachreichen.
        "auto.offset.reset": "latest",
        # Auto-Commit reicht: wir haben keine At-Least-Once-Zusage zu
        # halten, ein verlorener Offset kostet höchstens ein paar
        # Sekunden Events (die wir bei einem Neustart ohnehin verwerfen).
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
    })


class EventSource:
    """Poll-Loop im Worker-Thread → bounded asyncio.Queue."""

    def __init__(self, cfg: Config, runtime: RuntimeConfig) -> None:
        self._cfg = cfg
        self._rt = runtime
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=cfg.event_queue_max)
        self.dropped = 0
        self.consumed = 0

    def _offer(self, alert: dict) -> None:
        """Non-blocking put mit Drop-Oldest."""
        try:
            self.queue.put_nowait(alert)
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
            try:
                self.queue.put_nowait(alert)
            except asyncio.QueueFull:
                self.dropped += 1

    async def run(self) -> None:
        consumer = make_consumer(self._cfg)
        consumer.subscribe([self._cfg.alerts_topic])
        log.info("Kafka-Consumer subscribed: %s (group=%s, offset=latest)",
                 self._cfg.alerts_topic, self._cfg.kafka_group_id)

        # Shield-Muster aus mqtt-bridge: librdkafka ist nicht threadsafe
        # für paralleles poll/close — der laufende poll-Thread muss zu Ende
        # laufen, bevor close() kommt, auch wenn wir gecancelt werden.
        poll_task: Optional[asyncio.Task] = None
        try:
            while True:
                if poll_task is None:
                    poll_task = asyncio.ensure_future(
                        asyncio.to_thread(consumer.poll, 1.0)
                    )
                msg = await asyncio.shield(poll_task)
                poll_task = None
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    log.warning("Kafka-Error: %s", msg.error())
                    continue

                try:
                    alert = orjson.loads(msg.value())
                except Exception as exc:
                    log.debug("Ungültiges Alert-JSON: %s", exc)
                    continue
                if not isinstance(alert, dict):
                    continue

                self.consumed += 1
                # Grobfilter schon hier, damit die Queue bei einem
                # low-severity-Sturm nicht durchrotiert. Der feine Filter
                # sitzt nochmal im Tunnel, weil ein `config`-Frame die
                # Schwelle live ändern darf.
                if not severity_at_least(
                    alert.get("severity") or "low", self._rt.event_severity_min
                ):
                    continue
                self._offer(alert)
        finally:
            if poll_task is not None:
                while not poll_task.done():
                    try:
                        await asyncio.shield(poll_task)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
            consumer.close()
