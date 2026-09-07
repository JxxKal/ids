"""Unit-Tests für die Alert-Drossel. Laufen lokal: `pytest snort-bridge/tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from throttle import AlertThrottle, is_engine_event  # noqa: E402


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _throttle(**kw) -> tuple[AlertThrottle, Clock]:
    clk = Clock()
    kw.setdefault("cooldown_s", 60)
    kw.setdefault("max_rate", 50)
    kw.setdefault("drop_engine_events", True)
    return AlertThrottle(now=clk, **kw), clk


def test_engine_event_range():
    assert is_engine_event(1, 2210029)          # STREAM ESTABLISHED invalid ack
    assert is_engine_event(1, 2200000)
    assert is_engine_event(1, 2299999)
    assert not is_engine_event(1, 2199999)
    assert not is_engine_event(1, 2300000)
    assert not is_engine_event(3, 2210029)      # andere gid → keine Engine-SID


def test_engine_events_dropped_by_default():
    th, _ = _throttle()
    assert not th.allow(1, 2210029, "10.0.0.1", "10.0.0.2")
    assert th.allow(1, 2001219, "10.0.0.1", "10.0.0.2")


def test_engine_events_pass_when_disabled():
    th, _ = _throttle(drop_engine_events=False)
    assert th.allow(1, 2210029, "10.0.0.1", "10.0.0.2")


def test_cooldown_per_connection():
    th, clk = _throttle(max_rate=0)
    assert th.allow(1, 9000210, "a", "b")
    assert not th.allow(1, 9000210, "a", "b")          # Wiederholung im Fenster
    assert th.allow(1, 9000210, "a", "c")              # anderes Ziel → eigener Key
    assert th.allow(1, 2026850, "a", "b")              # andere SID → eigener Key
    clk.t += 59
    assert not th.allow(1, 9000210, "a", "b")
    clk.t += 2
    assert th.allow(1, 9000210, "a", "b")              # Fenster abgelaufen


def test_cooldown_disabled():
    th, _ = _throttle(cooldown_s=0, max_rate=0)
    for _ in range(5):
        assert th.allow(1, 1, "a", "b")


def test_rate_limit_burst_and_refill():
    th, clk = _throttle(cooldown_s=0, max_rate=10)
    # Bucket startet voll: 10 dürfen sofort, der 11. nicht.
    assert sum(th.allow(1, 1, "a", str(i)) for i in range(11)) == 10
    clk.t += 0.5                                       # 5 Tokens nachgefüllt
    assert sum(th.allow(1, 1, "a", str(i)) for i in range(11)) == 5
    clk.t += 10                                        # Kapazität ist gedeckelt
    assert sum(th.allow(1, 1, "a", str(i)) for i in range(20)) == 10


def test_report_counts_and_resets(caplog):
    th, clk = _throttle(cooldown_s=0, max_rate=2)
    for i in range(5):
        th.allow(1, 4242, "a", "b")
    th.allow(1, 2210029, "a", "b")
    clk.t += 61
    with caplog.at_level("WARNING"):
        th.maybe_report()
    msg = caplog.records[-1].getMessage()
    assert "4 Alerts verworfen" in msg
    assert "rate-limit=3" in msg and "engine-event=1" in msg
    assert "sid 4242×3" in msg
    # Nach dem Report sind die Zähler leer.
    caplog.clear()
    clk.t += 61
    th.maybe_report()
    assert not caplog.records


def test_purge_keeps_map_bounded():
    import throttle as mod
    old = mod._PURGE_AT
    mod._PURGE_AT = 100
    try:
        th, clk = _throttle(cooldown_s=10, max_rate=0)
        for i in range(100):
            th.allow(1, 1, "a", str(i))
        clk.t += 11
        th.allow(1, 1, "a", "neu")                     # löst Purge aus
        assert len(th._last_seen) == 1
    finally:
        mod._PURGE_AT = old
