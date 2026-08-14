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
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._warned = False

    def write(self, **fields) -> None:
        payload = dict(fields)
        payload["updated_at"] = time.time()
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
