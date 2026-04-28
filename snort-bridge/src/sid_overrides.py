"""
Per-SID Severity-Override + Disable für Suricata-Regeln.

Liest eine JSON-Datei mit Override-Einträgen pro Suricata-SID und wendet sie
in der snort-bridge auf jeden eingehenden Alert an, BEVOR er nach Kafka
publiziert wird. Dadurch:

  - "disabled" → Alert wird komplett verworfen
  - "severity"-Override → die Severity (und der Score) werden auf den Wert
    aus der Datei umgeschrieben

Format der Override-Datei (geschrieben von der api):
  {
    "2001219": {"enabled": false},
    "2018927": {"severity": "low"}
  }

SID-Schlüssel sind Strings (JSON erlaubt nur String-Keys), aber numerisch
parsebar. Ein fehlender oder leerer Wert wird wie "kein Override" behandelt.

Die Datei wird beim Start einmal geladen und danach alle 30s anhand der mtime
nachgezogen. Das hält den Hot-Path billig (kein File-IO pro Alert).
"""
from __future__ import annotations

import json
import logging
import os
import time
from threading import Lock

log = logging.getLogger(__name__)

REFRESH_INTERVAL_S = 30.0
VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Wir wollen identisches Mapping wie in main.py – damit der Score zur Severity
# passt, auch wenn wir per Override umrouten.
_SCORE_FOR: dict[str, float] = {
    "critical": 0.95,
    "high":     0.80,
    "medium":   0.55,
    "low":      0.30,
}


class SuricataOverrides:
    """Threadsafe Cache für SID-Overrides mit mtime-Refresh."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path or os.environ.get(
            "SURICATA_OVERRIDES_FILE",
            "/sig-rules/custom/_suricata_overrides.json",
        )
        self._lock = Lock()
        self._overrides: dict[int, dict] = {}
        self._mtime: float = 0.0
        self._last_check: float = 0.0

    def reload_if_changed(self) -> None:
        """Bei Bedarf die Datei neu lesen. Sicher zu spammen, billig wenn nichts ändert."""
        now = time.monotonic()
        if now - self._last_check < REFRESH_INTERVAL_S:
            return
        self._last_check = now

        try:
            mtime = os.path.getmtime(self._path)
        except OSError:
            with self._lock:
                if self._overrides:
                    log.info("Suricata-Overrides-Datei verschwunden – Cache geleert")
                self._overrides = {}
                self._mtime = 0.0
            return

        if mtime == self._mtime:
            return

        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            log.warning("Konnte Suricata-Overrides nicht lesen (%s): %s", self._path, exc)
            return

        if not isinstance(data, dict):
            log.warning("Suricata-Overrides hat unerwartetes Format (%s): erwarte Objekt", self._path)
            return

        cleaned: dict[int, dict] = {}
        for raw_sid, ov in data.items():
            if not isinstance(ov, dict):
                continue
            try:
                sid = int(str(raw_sid))
            except ValueError:
                continue
            entry: dict = {}
            if "enabled" in ov and isinstance(ov["enabled"], bool):
                entry["enabled"] = ov["enabled"]
            sev = ov.get("severity")
            if isinstance(sev, str) and sev.lower() in VALID_SEVERITIES:
                entry["severity"] = sev.lower()
            if entry:
                cleaned[sid] = entry

        with self._lock:
            self._overrides = cleaned
            self._mtime = mtime
        log.info("Suricata-Overrides nachgeladen: %d Einträge aus %s", len(cleaned), self._path)

    def apply(self, alert: dict, sid: int) -> dict | None:
        """Mutiert (gibt zurück) den Alert, oder None wenn er gedroppt werden soll."""
        with self._lock:
            ov = self._overrides.get(sid)
        if not ov:
            return alert
        if ov.get("enabled") is False:
            return None
        sev = ov.get("severity")
        if sev and sev != alert.get("severity"):
            alert["severity"] = sev
            alert["score"] = _SCORE_FOR.get(sev, alert.get("score", 0.55))
            tags = list(alert.get("tags") or [])
            if "sid-override" not in tags:
                tags.append("sid-override")
            alert["tags"] = tags
        return alert
