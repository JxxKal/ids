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
        # In-Memory-Byte-Zähler: einmalig aus der DB berechnet, danach
        # inkrementell bei push/ack/trim gepflegt. Ersetzt den früheren
        # SUM(LENGTH(payload))-Full-Table-Scan pro push() (lief unter dem
        # Lock und blockierte damit pop_batch_after).
        row = self._conn.execute(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM queue"
        ).fetchone()
        self._bytes = int(row[0] or 0)

    def push(self, payload: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO queue (ts, payload) VALUES (?, ?)",
                (time.time(), payload),
            )
            self._bytes += len(payload)
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

    def pop_batch_after(self, after_id: int, n: int) -> list[tuple[int, bytes]]:
        """Wie pop_batch, aber nur Zeilen mit id > after_id. Erlaubt dem
        Sender, einen Cursor mitzuführen und innerhalb einer Verbindung nicht
        dieselben (noch nicht bestätigten) Frames erneut zu poppen. Bei
        Reconnect startet der Sender wieder bei after_id=0 und liefert alle
        noch nicht per ack gelöschten (= unbestätigten) Frames neu aus."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, payload FROM queue WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, n),
            )
            return list(cur.fetchall())

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            # Freigegebene Bytes über die (kleine) Ack-Menge bestimmen und vom
            # Zähler abziehen — Scan bleibt auf die ack-ids beschränkt, kein
            # Full-Table-Scan.
            freed = self._conn.execute(
                f"SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM queue "
                f"WHERE id IN ({placeholders})",
                ids,
            ).fetchone()[0] or 0
            self._conn.execute(
                f"DELETE FROM queue WHERE id IN ({placeholders})",
                ids,
            )
            self._bytes = max(0, self._bytes - int(freed))

    def stats(self) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*), MIN(ts), MAX(ts) FROM queue"
            )
            count, min_ts, max_ts = cur.fetchone()
            bytes_ = self._bytes
        return {
            "count":   int(count),
            "bytes":   int(bytes_),
            "min_ts":  min_ts,
            "max_ts":  max_ts,
        }

    def _maybe_trim(self) -> None:
        # Nutzt den in-memory Byte-Zähler statt SUM(LENGTH()) über die ganze
        # Queue — kein Full-Table-Scan mehr pro push() unter gehaltenem Lock.
        if self._bytes <= self._max_bytes:
            return
        # In TRIM_BATCH-Häppchen droppen, damit eine einzige Insert-Ladung
        # nicht die gesamte Queue umkrempelt. Die tatsächlich freigegebenen
        # Bytes (über die gedroppte Häppchen-Menge, per PK-Index limitiert)
        # ziehen wir vom Zähler ab.
        rows = self._conn.execute(
            "SELECT id, LENGTH(payload) FROM queue ORDER BY id ASC LIMIT ?",
            (TRIM_BATCH,),
        ).fetchall()
        if not rows:
            return
        ids = [r[0] for r in rows]
        freed = sum(int(r[1]) for r in rows)
        placeholders = ",".join("?" * len(ids))
        self._conn.execute(
            f"DELETE FROM queue WHERE id IN ({placeholders})", ids
        )
        self._bytes = max(0, self._bytes - freed)
        log.warning("Queue über %d Bytes – %d älteste Einträge verworfen",
                    self._max_bytes, len(ids))
