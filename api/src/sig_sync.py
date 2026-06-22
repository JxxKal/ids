"""
Sync-Helper: schreibt Sidecar-Dateien für die signature-engine ins
sig-rules-Volume, damit der Loader sie via mtime-Watch aufpicken kann.

Aktuell:
  • _known_networks.json — CIDR-Liste der bekannten/internen Netzwerke,
    Quelle der Wahrheit ist die TimescaleDB-Tabelle `known_networks`. Wird
    vom signature-engine-Loader als CIDR-Cache benutzt, um pro Flow den
    `params.value_internal` vs. `params.value` zu wählen (Phase-1-ML-Tuner).
  • _host_role_catalog.json — gebündelte Host-Rollen-Katalog-YAMLs (Schema
    docs/contracts/host-roles.md §2), Quelle ist das Read-only-Mount unter
    `ROLE_CATALOG_DIR`. Wird über den Reverse-Channel an gepairte Taps
    verteilt, damit ein dortiger Detektor (V1-forward) denselben Katalog
    sieht. Inhalt: {filename: yaml_content}.

Volume-Layout: die API mountet `signature-rules` unter `/sig-rules`. Dort
liegen sowohl `_overrides.json` als auch `_known_networks.json` direkt im
Volume-Root — die signature-engine sieht den gleichen Inhalt unter
`/rules/custom/<file>` (Container-internes Mountpoint).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

import asyncpg

log = logging.getLogger(__name__)

CUSTOM_DIR = Path(os.getenv("SIG_CUSTOM_DIR", "/sig-rules"))
KNOWN_NETWORKS_FILE = CUSTOM_DIR / "_known_networks.json"

# Host-Rollen-Katalog: gleiche Quelle wie role_catalog.py (Read-only-Mount der
# YAMLs aus signature-engine/rules/host-roles). Default deckt sich mit dem dort.
ROLE_CATALOG_DIR = Path(
    os.getenv("ROLE_CATALOG_DIR", "/opt/ids/signature-engine/rules/host-roles")
)
HOST_ROLE_CATALOG_FILE = CUSTOM_DIR / "_host_role_catalog.json"


async def sync_known_networks_file(pool: asyncpg.Pool) -> int:
    """Liest alle CIDRs aus `known_networks` und schreibt sie als JSON ins
    sig-rules-Volume. Atomic write (.tmp + rename). Idempotent: wenn die
    Datei sich inhaltlich nicht ändert, bleibt mtime stabil (kein Rewrite).
    Liefert die Anzahl der CIDRs zurück, oder -1 bei Fehler.
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT cidr, kind FROM known_networks ORDER BY cidr"
            )
    except Exception as exc:
        log.warning("sync_known_networks: DB-Read fehlgeschlagen: %s", exc)
        return -1

    # Schema-V2: Liste von {cidr, kind}-Records. Schema-V1 (nur cidrs als
    # flache Liste) bleibt zusätzlich befüllt für Backwards-Compat — die
    # signature-engine kennt aktuell nur das flache Format und braucht den
    # kind-Tag (noch) nicht.
    cidrs = [str(r["cidr"]) for r in rows]
    networks_v2 = [{"cidr": str(r["cidr"]), "kind": r["kind"]} for r in rows]
    payload = {"version": "2", "networks": cidrs, "networks_v2": networks_v2}
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


async def sync_host_role_catalog_file(pool: asyncpg.Pool | None = None) -> int:
    """Liest die Host-Rollen-Katalog-YAMLs aus `ROLE_CATALOG_DIR` und schreibt
    sie gebündelt als `_host_role_catalog.json` ins sig-rules-Volume. Atomic
    write (.tmp + rename). Idempotent: ändert sich der Inhalt nicht, bleibt
    mtime stabil (kein Rewrite, kein Reverse-Channel-ETag-Bump).

    Signatur-symmetrisch zu `sync_known_networks_file` (async + Pool-Argument),
    damit die beiden Sync-Helper im Startup-Hook / nach CRUD identisch
    aufgerufen werden können. Die Quelle des Katalogs ist allerdings ein
    File-Mount, kein DB-Read — `pool` wird hier nicht benötigt. Die eigentliche
    File-IO läuft im Thread-Executor, damit der Event-Loop nicht blockiert.
    Liefert die Anzahl der gebündelten Katalog-Dateien zurück, oder -1 bei
    Fehler.

    Layout: ``{"version": "1", "files": {filename: yaml_content}}`` — bewusst
    der gleiche {filename: content}-Stil wie das Reverse-Channel-Rules-Bundle
    (master-uplink `_build_bundle_sync`), damit der Tap die YAMLs unverändert
    ins lokale Katalog-Dir ablegen kann.
    """
    return await asyncio.to_thread(_sync_host_role_catalog_sync)


def _sync_host_role_catalog_sync() -> int:
    """Synchrone Implementierung von `sync_host_role_catalog_file` (File-IO)."""
    if not ROLE_CATALOG_DIR.is_dir():
        log.warning("sync_host_role_catalog: Katalog-Verzeichnis nicht gefunden: %s",
                    ROLE_CATALOG_DIR)
        return -1

    files: dict[str, str] = {}
    try:
        for path in sorted(ROLE_CATALOG_DIR.glob("*.yml")):
            files[path.name] = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("sync_host_role_catalog: Lesen fehlgeschlagen: %s", exc)
        return -1

    payload = {"version": "1", "files": files}
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")

    try:
        # Inhalt-Identität: kein Rewrite → kein mtime-Bump.
        if HOST_ROLE_CATALOG_FILE.is_file():
            existing = HOST_ROLE_CATALOG_FILE.read_bytes()
            if existing == body:
                return len(files)
        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        tmp = HOST_ROLE_CATALOG_FILE.with_suffix(".tmp")
        tmp.write_bytes(body)
        tmp.replace(HOST_ROLE_CATALOG_FILE)
        log.info("sync_host_role_catalog: %d Katalog-Dateien nach %s geschrieben",
                 len(files), HOST_ROLE_CATALOG_FILE)
        return len(files)
    except OSError as exc:
        log.warning("sync_host_role_catalog: Schreiben fehlgeschlagen: %s", exc)
        return -1
