"""Reservoir Sampling pro Metric-Stream.

Algorithm R (Vitter 1985): bei Stream-Item N + 1 ersetzen wir mit
Wahrscheinlichkeit K/N einen zufälligen Slot. Liefert eine unbiasierte
Stichprobe von K Werten aus dem gesamten Stream — egal wie groß N ist.

Wir halten pro `(rule_id, param_name, scope)` ein eigenes Reservoir;
Quantile werden by-demand aus dem aktuellen Reservoir-Inhalt berechnet
(Sortierung über K Elemente — bei K=10k unter 1 ms).
"""
from __future__ import annotations

import bisect
import random
from typing import Iterable


class Reservoir:
    """Bounded-size unbiased random sample of a numeric stream."""

    __slots__ = ("_capacity", "_samples", "_seen")

    def __init__(self, capacity: int = 10_000) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._samples: list[float] = []
        # Total stream size (NOT len(samples) — wir brauchen N für die
        # Replace-Wahrscheinlichkeit, Reservoir bleibt bei K nach Aufwärm-
        # phase stehen).
        self._seen: int = 0

    @property
    def size(self) -> int:
        return len(self._samples)

    @property
    def total_seen(self) -> int:
        return self._seen

    def add(self, value: float) -> None:
        self._seen += 1
        if len(self._samples) < self._capacity:
            self._samples.append(float(value))
            return
        # Replace random slot mit Wahrscheinlichkeit K/N.
        # randrange(N) gibt 0..N-1; wir akzeptieren wenn der gewählte Index
        # < K ist (dh innerhalb des Reservoirs).
        idx = random.randrange(self._seen)
        if idx < self._capacity:
            self._samples[idx] = float(value)

    def extend(self, values: Iterable[float]) -> None:
        for v in values:
            self.add(v)

    def quantile(self, q: float) -> float | None:
        """Empirisches Quantil. None wenn Reservoir leer.

        q ∈ [0, 1]. Linear interpolation zwischen Nachbar-Werten — bei großen
        Reservoirs (K=10k) und Quantilen wie 0.995 ist das exakt genug; eine
        echte percentile_cont-Implementierung wäre unnötig schwer."""
        if not self._samples:
            return None
        s = sorted(self._samples)
        n = len(s)
        if q <= 0.0:
            return s[0]
        if q >= 1.0:
            return s[-1]
        pos = q * (n - 1)
        lo = int(pos)
        hi = min(lo + 1, n - 1)
        frac = pos - lo
        return s[lo] * (1.0 - frac) + s[hi] * frac

    def quantiles(self, qs: Iterable[float]) -> dict[float, float | None]:
        """Effizientere Berechnung mehrerer Quantile gleichzeitig — sortiert
        nur einmal."""
        if not self._samples:
            return {q: None for q in qs}
        s = sorted(self._samples)
        n = len(s)
        out: dict[float, float | None] = {}
        for q in qs:
            if q <= 0.0:
                out[q] = s[0]
            elif q >= 1.0:
                out[q] = s[-1]
            else:
                pos = q * (n - 1)
                lo = int(pos)
                hi = min(lo + 1, n - 1)
                frac = pos - lo
                out[q] = s[lo] * (1.0 - frac) + s[hi] * frac
        return out

    def merge_into(self, other: "Reservoir") -> "Reservoir":
        """Liefert ein neues Reservoir mit den vereinten Samples beider —
        verwendet, wenn `scope_split_enabled=false` ist und der Tuner für
        die `global`-Berechnung internal+external zusammenführen muss.

        Achtung: Das vereinte Reservoir hat wieder Capacity = max(self, other);
        wir reservoirsamplen *aus* den vereinten Samples ein neues Reservoir.
        Das ist statistisch nicht ganz so sauber wie ein direktes Sampling
        des Quellstreams (weil ältere Werte bereits durch Algorithm R
        runter-gesampelt sind), aber für unsere Zwecke (P99,5 von 10k
        Samples) reicht es."""
        merged = Reservoir(capacity=max(self._capacity, other._capacity))
        merged.extend(self._samples)
        merged.extend(other._samples)
        # Stream-Größe approximieren: Summe — Algorithm R braucht das nicht
        # mehr da wir nur quantile() aufrufen werden, aber wir wollen
        # total_seen halbwegs sinnvoll halten.
        merged._seen = self._seen + other._seen
        return merged
