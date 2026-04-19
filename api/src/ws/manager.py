"""
WebSocket Connection Manager + Kafka-Consumer-Thread.

Der Kafka-Consumer läuft in einem eigenen Thread (confluent-kafka ist sync).
Neue Nachrichten werden über eine asyncio.Queue an den Event-Loop übermittelt
und von dort an alle verbundenen WebSocket-Clients gebroadcastet.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

import orjson
from confluent_kafka import Consumer, KafkaError
from fastapi import WebSocket

log = logging.getLogger(__name__)

ALERTS_TOPIC = "alerts-enriched"
PUSH_TOPIC   = "alerts-enriched-push"
GROUP_ID     = "api-ws"


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        log.debug("WS client connected (%d total)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
        log.debug("WS client disconnected (%d total)", len(self._clients))

    async def broadcast(self, data: dict) -> None:
        if not self._clients:
            return
        payload = orjson.dumps(data).decode()
        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


class AlertStreamer:
    """Startet einen Background-Thread mit Kafka-Consumer."""

    def __init__(self, brokers: str, queue: asyncio.Queue) -> None:
        self._brokers = brokers
        self._queue   = queue
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._thread = threading.Thread(target=self._consume, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _consume(self) -> None:
        consumer = Consumer({
            "bootstrap.servers":  self._brokers,
            "group.id":           GROUP_ID,
            "auto.offset.reset":  "latest",   # nur neue Alerts ab jetzt
            "enable.auto.commit": True,
        })
        consumer.subscribe([ALERTS_TOPIC, PUSH_TOPIC])
        log.info("WS Kafka consumer started (topics: %s, %s)", ALERTS_TOPIC, PUSH_TOPIC)

        try:
            while not self._stop_event.is_set():
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.error("WS Kafka error: %s", msg.error())
                    continue
                try:
                    payload = orjson.loads(msg.value())
                    # alerts-enriched-push already has {type, data} structure
                    if payload.get("type") in ("alert_enriched", "pcap_available", "feedback_updated"):
                        outmsg = payload
                    else:
                        outmsg = {"type": "alert", "data": payload}
                    asyncio.run_coroutine_threadsafe(
                        self._queue.put(outmsg),
                        self._loop,
                    )
                except Exception as exc:
                    log.debug("WS message parse error: %s", exc)
        finally:
            consumer.close()
            log.info("WS Kafka consumer stopped")
