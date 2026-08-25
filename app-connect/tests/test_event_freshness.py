"""Frische des Live-Kanals (protocol.md §1.5): kein Backlog, kein Rückstand.

Hintergrund ist der 25.08.: Nach einem Neustart von app-connect lieferte der
Kafka-Consumer die komplette Ausfallzeit nach — Suricata-Alarme von 11:05
erschienen um 12:11 als „live" in der App, jeder mit einem Push. Ursache war
`enable.auto.commit=true`: `auto.offset.reset=latest` greift nur ohne
gespeicherten Offset, und der Auto-Commit speicherte alle 5 s einen.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import events
from fields import is_stale


def test_consumer_committet_nie(monkeypatch):
    """§1.5 verlangt „ab jetzt" bei JEDEM Start — nicht nur beim ersten.

    Mit einem gespeicherten Offset setzt Kafka dort fort und `latest` wird
    nie befragt. Kein Commit ⇒ kein gespeicherter Offset ⇒ jeder Start
    beginnt in der Gegenwart. mqtt-bridge committet absichtlich (ihr
    Rückstand ist ein Feature) — dieses Muster gehört hier NICHT hin.
    """
    captured: dict = {}

    class FakeConsumer:
        def __init__(self, conf):
            captured.update(conf)

    monkeypatch.setattr(events, "Consumer", FakeConsumer)

    class Cfg:
        kafka_brokers = "kafka:9092"
        kafka_group_id = "app-connect"

    events.make_consumer(Cfg())

    assert captured["enable.auto.commit"] is False
    assert captured["auto.offset.reset"] == "latest"
    assert "auto.commit.interval.ms" not in captured


def test_is_stale_unix_und_iso():
    assert is_stale(time.time() - 4000, 300) is True
    assert is_stale(time.time() - 10, 300) is False
    alt = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert is_stale(alt, 300) is True
    assert is_stale(datetime.now(timezone.utc).isoformat(), 300) is False
    # Z-Suffix, wie es der Retention-Monitor produziert
    assert is_stale("2020-01-01T00:00:00Z", 300) is True


def test_is_stale_faellt_offen():
    """Unlesbares gilt als frisch. Der Wächter sortiert Rückstand aus — er
    darf bei einem Formatwechsel in der Pipeline nicht stillschweigend den
    gesamten Alarmkanal abdrehen. Ein stummer Kanal wäre der teurere Fehler.
    """
    assert is_stale(None, 300) is False
    assert is_stale("", 300) is False
    assert is_stale("kein-datum", 300) is False
    assert is_stale({"unerwartet": True}, 300) is False
