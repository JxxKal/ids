"""State-File für `cyjan-app status` (Muster: tap-uplink/src/state.py).

Der Tunnel schreibt seinen Zustand nach /run/cyjan/app-connect.state.json;
die CLI liest ihn. Damit braucht `cyjan-app status` weder einen offenen
Port noch eine Verbindung zum Proxy — es funktioniert auch (und gerade
dann) wenn der Tunnel unten ist.

Atomic write über tmp+rename, damit die CLI nie ein halbes JSON liest.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import orjson

log = logging.getLogger(__name__)


class StateWriter:
    """Schreibt den Zustand als Datei UND hält ihn im Speicher.

    Die In-Memory-Kopie (`last`) bedient die interne HTTP-API — `GET /status`
    soll nicht bei jeder Anfrage eine Datei lesen, und sie muss auch dann
    antworten können, wenn das State-File nicht schreibbar ist.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._warned = False
        self.last: dict = {}
        # Merker für die Unterscheidung starting ⇄ reconnecting in der API.
        self.ever_connected = False

    def write(self, **fields) -> None:
        payload = dict(fields)
        payload["updated_at"] = time.time()
        self.last = payload
        if fields.get("connection") == "connected":
            self.ever_connected = True
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
            os.replace(tmp, self._path)
        except OSError as exc:
            # Kein Grund, den Tunnel zu reißen — das State-File ist Komfort.
            if not self._warned:
                log.warning("State-File %s nicht schreibbar: %s", self._path, exc)
                self._warned = True


def read_state(path: str) -> dict:
    try:
        return orjson.loads(Path(path).read_bytes())
    except Exception:
        return {}
