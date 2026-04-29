"""
SQLite-Disk-Queue für Outage-Resilienz am Remote-Tap.

Wenn der Master nicht erreichbar ist, schreibt das tap-uplink seine
Alerts in eine SQLite-Datei. Sobald der WSS wieder steht, werden die
ältesten Einträge zuerst nachgesendet (FIFO). Bei Überlauf >
MAX_BYTES wird vom Anfang her gedroppt – damit ein dauerhaft offline
gegangener Master das Tap-Filesystem nicht volllaufen lässt.

Schema bewusst simpel: id (autoinc), ts (epoch), payload (JSON-Bytes).
Keine TTL-Logik separately, weil FIFO + Größencap das gleiche Problem
löst.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Iterator

log = logging.getLogger("queue")

MAX_BYTES_DEFAULT = 1 * 1024 * 1024 * 1024   # 1 GB ≈ 1 Mio Alerts
TRIM_BATCH        = 5_000


class DiskQueue:
    def __init__(self, path: str, max_bytes: int = MAX_BYTES_DEFAULT) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._max_bytes = max_bytes
        self._lock = Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS queue (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      REAL NOT NULL,
                payload BLOB NOT NULL
            )"""
        )

    def push(self, payload: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO queue (ts, payload) VALUES (?, ?)",
                (time.time(), payload),
            )
            self._maybe_trim()

    def pop_batch(self, n: int) -> list[tuple[int, bytes]]:
        """Liefert (id, payload)-Liste älteste zuerst, ohne zu löschen.
        Erst nach erfolgreichem Send darf der Caller `ack(ids)` aufrufen."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, payload FROM queue ORDER BY id ASC LIMIT ?",
                (n,),
            )
            return list(cur.fetchall())

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            self._conn.execute(
                f"DELETE FROM queue WHERE id IN ({placeholders})",
                ids,
            )

    def stats(self) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0), MIN(ts), MAX(ts) FROM queue"
            )
            count, bytes_, min_ts, max_ts = cur.fetchone()
        return {
            "count":   int(count),
            "bytes":   int(bytes_ or 0),
            "min_ts":  min_ts,
            "max_ts":  max_ts,
        }

    def _maybe_trim(self) -> None:
        # Cheap-and-correct: nur prüfen wenn die Tabelle nicht-leer ist und
        # über dem Limit liegt. Wir drehen uns auf SUM(LENGTH()) als grobe
        # Größenmetrik – overhead durch Indizes ignorieren wir bewusst.
        cur = self._conn.execute("SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM queue")
        size = int(cur.fetchone()[0] or 0)
        if size <= self._max_bytes:
            return
        # In TRIM_BATCH-Häppchen droppen, damit eine einzige Insert-Ladung
        # nicht die gesamte Queue umkrempelt.
        deleted = self._conn.execute(
            f"DELETE FROM queue WHERE id IN (SELECT id FROM queue ORDER BY id ASC LIMIT {TRIM_BATCH})"
        ).rowcount
        log.warning("Queue über %d Bytes – %d älteste Einträge verworfen",
                    self._max_bytes, deleted)
