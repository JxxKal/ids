"""
Status-Datei für den tap-api-Container.

tap-uplink schreibt periodisch ein JSON-Snapshot mit Verbindungs- und
Queue-Statistiken. tap-api liest das (read-only) und rendert es in der
Status-Seite. Verzeichnis wird per Volume-Share zwischen den beiden
Containern geteilt.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import orjson

DEFAULT_PATH = "/run/cyjan/tap-uplink.state.json"


class StateWriter:
    def __init__(self, path: str = DEFAULT_PATH) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(
        self,
        connection: str,             # 'connected' | 'reconnecting' | 'down' | 'starting'
        master_url: str,
        last_connect_at: float | None,
        last_disconnect_at: float | None,
        last_send_at: float | None,
        sent_total: int,
        queue_count: int,
        queue_bytes: int,
        cert_expires_at: float | None,
        last_error: str | None,
    ) -> None:
        payload = {
            "connection":          connection,
            "master_url":          master_url,
            "last_connect_at":     last_connect_at,
            "last_disconnect_at":  last_disconnect_at,
            "last_send_at":        last_send_at,
            "sent_total":          sent_total,
            "queue_count":         queue_count,
            "queue_bytes":         queue_bytes,
            "cert_expires_at":     cert_expires_at,
            "last_error":          last_error,
            "updated_at":          time.time(),
        }
        # Atomisches Replace, damit tap-api beim Lesen nie eine halb
        # geschriebene Datei erwischt.
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
        os.replace(tmp, self._path)
