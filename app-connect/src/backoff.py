"""Reconnect-Backoff (protocol.md §1.4): exponentiell 1 s → 60 s, ±20 %
Jitter, Reset nach erfolgreichem `hello_ack`.

Bewusst als eigenes Modul, damit die Sequenz ohne Netzwerk testbar ist —
und weil dieselbe Kurve in tap-uplink/master-uplink steckt: wer den einen
Tunnel debuggen kann, kann auch den anderen.

Der Jitter ist der Grund, warum das hier nicht zwei Zeilen inline sind:
ohne ihn synchronisieren sich N Sentries nach einem Proxy-Neustart auf
dieselbe Sekunde und schlagen im Gleichtakt auf.
"""
from __future__ import annotations

import random

from config import RECONNECT_JITTER, RECONNECT_MAX_S, RECONNECT_MIN_S


def next_backoff(current: float) -> float:
    """Nächster Basiswert (ohne Jitter), gedeckelt auf RECONNECT_MAX_S."""
    if current < RECONNECT_MIN_S:
        return RECONNECT_MIN_S
    return min(current * 2.0, RECONNECT_MAX_S)


def backoff_sequence(steps: int) -> list[float]:
    """Die ersten `steps` Basiswerte — 1, 2, 4, 8, …, 60, 60. Für Tests
    und für die Dokumentation im README."""
    out: list[float] = []
    cur = RECONNECT_MIN_S
    for _ in range(steps):
        out.append(cur)
        cur = next_backoff(cur)
    return out


def with_jitter(value: float, rng: random.Random | None = None) -> float:
    """±RECONNECT_JITTER (20 %) um den Basiswert. Nie negativ."""
    r = rng or random
    factor = 1.0 + r.uniform(-RECONNECT_JITTER, RECONNECT_JITTER)
    return max(0.0, value * factor)
