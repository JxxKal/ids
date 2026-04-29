"""
Sync-Helper: schreibt Sidecar-Dateien für die signature-engine ins
sig-rules-Volume, damit der Loader sie via mtime-Watch aufpicken kann.

Aktuell:
  • _known_networks.json — CIDR-Liste der bekannten/internen Netzwerke,
    Quelle der Wahrheit ist die TimescaleDB-Tabelle `known_networks`. Wird
    vom signature-engine-Loader als CIDR-Cache benutzt, um pro Flow den
    `params.value_internal` vs. `params.value` zu wählen (Phase-1-ML-Tuner).

Volume-Layout: die API mountet `signature-rules` unter `/sig-rules`. Dort
liegen sowohl `_overrides.json` als auch `_known_networks.json` direkt im
Volume-Root — die signature-engine sieht den gleichen Inhalt unter
`/rules/custom/<file>` (Container-internes Mountpoint).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import asyncpg

log = logging.getLogger(__name__)

CUSTOM_DIR = Path(os.getenv("SIG_CUSTOM_DIR", "/sig-rules"))
KNOWN_NETWORKS_FILE = CUSTOM_DIR / "_known_networks.json"


async def sync_known_networks_file(pool: asyncpg.Pool) -> int:
    """Liest alle CIDRs aus `known_networks` und schreibt sie als JSON ins
    sig-rules-Volume. Atomic write (.tmp + rename). Idempotent: wenn die
    Datei sich inhaltlich nicht ändert, bleibt mtime stabil (kein Rewrite).
    Liefert die Anzahl der CIDRs zurück, oder -1 bei Fehler.
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT cidr FROM known_networks ORDER BY cidr"
            )
    except Exception as exc:
        log.warning("sync_known_networks: DB-Read fehlgeschlagen: %s", exc)
        return -1

    cidrs = [str(r["cidr"]) for r in rows]
    payload = {"version": "1", "networks": cidrs}
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")

    try:
        # Inhalt-Identität: kein Rewrite, kein mtime-Bump → kein unnötiger
        # Reload in der signature-engine.
        if KNOWN_NETWORKS_FILE.is_file():
            existing = KNOWN_NETWORKS_FILE.read_bytes()
            if existing == body:
                return len(cidrs)
        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        tmp = KNOWN_NETWORKS_FILE.with_suffix(".tmp")
        tmp.write_bytes(body)
        tmp.replace(KNOWN_NETWORKS_FILE)
        log.info("sync_known_networks: %d CIDRs nach %s geschrieben",
                 len(cidrs), KNOWN_NETWORKS_FILE)
        return len(cidrs)
    except OSError as exc:
        log.warning("sync_known_networks: Schreiben fehlgeschlagen: %s", exc)
        return -1
