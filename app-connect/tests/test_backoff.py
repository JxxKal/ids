"""Reconnect-Backoff: 1 s → 60 s exponentiell, ±20 % Jitter (protocol.md §1.4)."""
import random

from backoff import backoff_sequence, next_backoff, with_jitter
from config import RECONNECT_JITTER, RECONNECT_MAX_S, RECONNECT_MIN_S


def test_sequence_matches_spec():
    assert backoff_sequence(10) == [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]


def test_starts_at_one_second():
    assert RECONNECT_MIN_S == 1.0
    assert backoff_sequence(1) == [1.0]


def test_caps_at_sixty():
    assert RECONNECT_MAX_S == 60.0
    cur = RECONNECT_MIN_S
    for _ in range(50):
        cur = next_backoff(cur)
    assert cur == 60.0


def test_next_backoff_doubles():
    assert next_backoff(1.0) == 2.0
    assert next_backoff(16.0) == 32.0
    assert next_backoff(32.0) == 60.0   # Deckel greift vor 64
    assert next_backoff(60.0) == 60.0


def test_next_backoff_floors_at_min():
    """Ein zurückgesetzter/kaputter Wert darf keine Hot-Loop erzeugen."""
    assert next_backoff(0.0) == RECONNECT_MIN_S
    assert next_backoff(-5.0) == RECONNECT_MIN_S


def test_jitter_stays_within_twenty_percent():
    rng = random.Random(1337)
    for base in backoff_sequence(8):
        for _ in range(200):
            v = with_jitter(base, rng)
            assert base * (1 - RECONNECT_JITTER) <= v <= base * (1 + RECONNECT_JITTER)


def test_jitter_actually_varies():
    """Ohne echten Jitter synchronisieren sich N Sentries nach einem
    Proxy-Neustart auf dieselbe Sekunde."""
    rng = random.Random(7)
    values = {round(with_jitter(60.0, rng), 6) for _ in range(50)}
    assert len(values) > 40


def test_jitter_never_negative():
    rng = random.Random(3)
    assert with_jitter(0.0, rng) == 0.0
    assert all(with_jitter(1.0, rng) >= 0 for _ in range(100))
