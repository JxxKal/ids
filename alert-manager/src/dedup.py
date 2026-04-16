"""
Alert-Deduplication: verhindert Alert-Flut bei wiederkehrenden Anomalien.

Dedup-Schlüssel: (rule_id, src_ip, dst_ip, dst_port)
Innerhalb des Zeitfensters (dedup_window_s) wird pro Schlüssel nur ein Alert
weitergeleitet. Ältere Einträge werden beim Cleanup entfernt.

Kein externes State-Store nötig – alles in-memory (single-threaded).
"""
from __future__ import annotations

import time
from collections import OrderedDict


class DedupCache:
    """
    LRU-ähnlicher Dedup-Cache auf Basis eines geordneten Dicts.

    Einträge: {dedup_key: last_seen_ts}
    Cleanup: alle MAX_CHECKS Operationen oder wenn der Cache zu groß wird.
    """

    MAX_SIZE    = 50_000   # maximale Anzahl gecachter Keys
    CLEANUP_MOD = 500      # jede N-te is_duplicate()-Prüfung → Cleanup

    def __init__(self, window_s: float) -> None:
        self._window_s = window_s
        self._cache: OrderedDict[tuple, float] = OrderedDict()
        self._ops = 0

    def is_duplicate(self, alert: dict) -> bool:
        """
        Gibt True zurück wenn ein strukturell gleicher Alert innerhalb
        des Zeitfensters bereits gesehen wurde.
        Registriert den Alert im Cache wenn er neu ist.
        """
        key = _dedup_key(alert)
        now = time.time()

        self._ops += 1
        if self._ops % self.CLEANUP_MOD == 0:
            self._cleanup(now)

        last_seen = self._cache.get(key)
        if last_seen is not None and (now - last_seen) < self._window_s:
            return True

        # Neu oder abgelaufen: eintragen / aktualisieren
        self._cache[key] = now
        self._cache.move_to_end(key)

        # Cache-Größe begrenzen (älteste Einträge entfernen)
        while len(self._cache) > self.MAX_SIZE:
            self._cache.popitem(last=False)

        return False

    def _cleanup(self, now: float) -> None:
        cutoff = now - self._window_s
        stale = [k for k, ts in self._cache.items() if ts < cutoff]
        for k in stale:
            del self._cache[k]


def _dedup_key(alert: dict) -> tuple:
    return (
        alert.get("rule_id", ""),
        alert.get("src_ip", ""),
        alert.get("dst_ip", ""),
        str(alert.get("dst_port", "")),
    )
