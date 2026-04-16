"""
Sliding-Window-Paketpuffer.

Hält die letzten MAX_WINDOW_S Sekunden an Paketen im Speicher.
Eingehende Pakete werden als (timestamp, raw_bytes) gespeichert.
Für einen Alert-Timestamp wird das Fenster [ts - window_s, ts + window_s]
extrahiert – dabei werden Pakete NACH dem Alert-Timestamp aus dem laufenden
Buffer abgewartet (bis zu window_s Sekunden Wartezeit).

Design-Entscheidung: kein Warten auf Future-Pakete im Main-Loop.
Stattdessen: Pending-Alerts werden mit dem frühestmöglichen Flush-Zeitpunkt
gespeichert und beim nächsten Tick ausgewertet.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class PendingAlert:
    alert_id:   str
    alert_ts:   float       # Unix-Timestamp des Alerts
    window_s:   float       # ±Sekunden
    ready_at:   float       # monotonic: frühester Flush-Zeitpunkt
    alert_data: dict        # vollständiges Alert-Dict


class PacketBuffer:
    """
    Ringpuffer für (timestamp, raw_bytes) Pakete.

    Pakete älter als MAX_WINDOW_S werden beim Hinzufügen neuer Pakete
    automatisch verworfen.
    """

    def __init__(self, max_window_s: float) -> None:
        # etwas größer als das PCAP-Fenster um sicher alle Pakete zu haben
        self._max_s = max_window_s * 2 + 10
        self._buf: deque[tuple[float, bytes]] = deque()

    def add(self, ts: float, raw: bytes) -> None:
        self._buf.append((ts, raw))
        # Cleanup: alte Pakete verwerfen
        cutoff = time.time() - self._max_s
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

    def extract(self, center_ts: float, window_s: float) -> list[tuple[float, bytes]]:
        """Gibt alle Pakete im Fenster [center_ts-window_s, center_ts+window_s] zurück."""
        lo = center_ts - window_s
        hi = center_ts + window_s
        return [(ts, raw) for ts, raw in self._buf if lo <= ts <= hi]

    def newest_ts(self) -> float:
        """Timestamp des neuesten Pakets (0.0 wenn leer)."""
        if self._buf:
            return self._buf[-1][0]
        return 0.0
