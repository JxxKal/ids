"""host-role-detector — Einstiegspunkt.

Master-only Service. Aggregiert alle DETECT_INTERVAL_S aus der `flows`-
Hypertable über die letzten DETECT_WINDOW_DAYS pro Host die SERVIERTEN Ports
(dst_ip=Responder, connection_state ∈ ESTABLISHED|CLOSED) + die Mode-MAC,
matcht gegen den YAML-Katalog (ROLE_CATALOG_DIR) und schreibt das Ergebnis als
`host_info.detected_roles` (alleiniger Schreiber, manual-Locks respektiert).

Läuft NUR am Master (Compose-Profil `prod`). Kein Kafka — reine DB-Aggregation.
Struktur (Heartbeat, Signal-Handling, Hauptschleife) gespiegelt aus rule-tuner.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aggregator import build_profiles
from catalog import load_catalog, parse_role
from config import Config
from db import Db
from matcher import build_detected_roles, prune_auto_roles

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("host-role-detector")


# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Touch't /tmp/heartbeat solange die Detektor-Task lebt — stirbt sie, bleibt
# das File stehen und der Compose-Healthcheck meldet unhealthy.
async def _heartbeat_loop(watched: asyncio.Task) -> None:
    while not watched.done():
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        await asyncio.sleep(30)


async def _run_cycle(cfg: Config, db: Db) -> None:
    """Ein Detektions-Cycle: Katalog laden, aggregieren, matchen, schreiben.

    Katalog wird pro Cycle frisch gelesen — so wirken Katalog-Änderungen ohne
    Service-Restart. Jeder Host wird einzeln geschrieben (FOR UPDATE pro Zeile),
    damit ein einzelner Fehler nicht den ganzen Cycle abbricht.
    """
    catalog = load_catalog(cfg.catalog_dir)

    # Benutzerdefinierte Rollen (DB, host_role_custom) anhängen — gleiche
    # Auswertung wie Built-ins. Bei id-Kollision gewinnt die Built-in-Rolle.
    try:
        custom = await db.load_custom_roles()
    except Exception as exc:
        log.warning("Custom-Rollen laden fehlgeschlagen: %s", exc)
        custom = []
    if custom:
        builtin_ids = {r.id for r in catalog}
        added = 0
        for raw in custom:
            # Eine defekte host_role_custom-Zeile (nicht-numerisches
            # min_flows_per_port/base_confidence/min_any) würde in parse_role
            # eine uncaught ValueError werfen und den kompletten Cycle abbrechen
            # — pro Eintrag abfangen, überspringen, Cycle läuft weiter.
            try:
                rd = parse_role(raw)
            except Exception as exc:
                log.warning("Defekte Custom-Rolle %s übersprungen: %s",
                            raw.get("id", "?"), exc)
                continue
            if rd is None:
                continue
            if rd.id in builtin_ids:
                log.warning("Custom-Rolle %s kollidiert mit Built-in-id — übersprungen", rd.id)
                continue
            catalog.append(rd)
            added += 1
        if added:
            log.info("Custom-Rollen aktiv: %d", added)

    if not catalog:
        log.warning("Leerer Katalog — Cycle übersprungen")
        return

    # Floor = niedrigste min_flows_per_port-Schwelle im Katalog: damit holt die
    # DB-Query keine Ports raus, die eine permissive Rolle noch bräuchte. Die
    # strengere per-Rolle-Schwelle setzt der matcher gegen den Port-Flow-Count.
    floor = min((r.min_flows_per_port for r in catalog), default=1)
    profiles = await build_profiles(
        db, cfg.detect_window_days, max(1, floor), cfg.long_lived_min_days,
    )

    written = 0
    for ip, profile in profiles.items():
        try:
            # Read-Modify-Write atomar: build_detected_roles läuft INNERHALB
            # der FOR-UPDATE-Transaktion auf dem gesperrten Stand, damit ein
            # zeitgleicher manueller Roles-PUT nicht verloren geht (TOCTOU).
            def _build(existing, _profile=profile):
                return build_detected_roles(
                    _profile, catalog, existing,
                    cfg.min_confidence, cfg.oui_confidence_bonus,
                )
            payload = await db.update_detected_roles(ip, _build)
            if payload and payload.get("roles"):
                written += 1
        except Exception as exc:
            log.warning("Host %s: Detektion fehlgeschlagen: %s", ip, exc)

    # ── Aging ────────────────────────────────────────────────────────────────
    # Hosts, die im Fenster nicht mehr als Responder auftauchen (nicht in
    # `profiles`), werden von der Detektions-Schleife nie angefasst und behielten
    # ihre auto-Rollen sonst ewig — ein IP-Nachnutzer erbte sie. auto-Rollen mit
    # last_confirmed älter als ROLE_STALE_DAYS entfernen; manual/suppress bleibt.
    pruned = 0
    if cfg.role_stale_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.role_stale_days)
        try:
            candidates = await db.hosts_with_roles()
        except Exception as exc:
            log.warning("Aging-Kandidaten laden fehlgeschlagen: %s", exc)
            candidates = []
        for ip, snapshot in candidates:
            if ip in profiles:
                continue   # frisch evaluiert — die reguläre Auswertung altert selbst
            # Billige Vorprüfung auf dem Snapshot: nur wenn hier tatsächlich eine
            # auto-Rolle veraltet ist, den FOR-UPDATE-Schreibpfad betreten. Sonst
            # zahlte jeder Cycle N Transaktionen + Row-Locks nur um "nichts zu
            # tun" festzustellen. Der Schreibpfad prüft unter Lock erneut (TOCTOU).
            if prune_auto_roles(snapshot, cutoff) is None:
                continue
            try:
                result = await db.update_detected_roles(
                    ip, lambda existing, _cut=cutoff: prune_auto_roles(existing, _cut),
                )
                if result is not None:
                    pruned += 1
            except Exception as exc:
                log.warning("Host %s: Aging fehlgeschlagen: %s", ip, exc)

    log.info(
        "Cycle fertig: %d Hosts evaluiert, %d mit ≥1 Rolle, %d veraltete Rollen-Sets bereinigt",
        len(profiles), written, pruned,
    )


async def amain() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting host-role-detector | dsn=%s catalog=%s interval=%.0fs window=%dd min_conf=%.2f",
        cfg.postgres_dsn.split("@")[-1], cfg.catalog_dir,
        cfg.detect_interval_s, cfg.detect_window_days, cfg.min_confidence,
    )

    db = Db(cfg.postgres_dsn)
    # Beim Boot retryn, bis die DB (und die Migration 027) bereit ist.
    for attempt in range(12):
        try:
            await db.connect()
            log.info("DB erreichbar — starte Detektions-Schleife")
            break
        except Exception as exc:
            log.warning("DB noch nicht bereit (Versuch %d/12): %s", attempt + 1, exc)
            await asyncio.sleep(5)
    else:
        log.error("DB nach 12 Versuchen nicht erreichbar — Abbruch")
        sys.exit(1)

    stop_event = asyncio.Event()

    def _stop(*_args) -> None:
        log.info("Shutdown-Signal empfangen")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _stop)

    async def _detect_loop() -> None:
        while not stop_event.is_set():
            try:
                await _run_cycle(cfg, db)
            except Exception as exc:
                log.exception("Detektions-Cycle gescheitert: %s", exc)
            # Interruptibles Warten — Shutdown unterbricht das Intervall sofort.
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=cfg.detect_interval_s)
            except asyncio.TimeoutError:
                pass

    detect = asyncio.create_task(_detect_loop(), name="detect-loop")
    beat = asyncio.create_task(_heartbeat_loop(detect), name="heartbeat")

    try:
        await stop_event.wait()
    finally:
        detect.cancel()
        beat.cancel()
        for t in (detect, beat):
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await db.close()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
    except Exception:
        log.exception("Fatal")
        sys.exit(1)


if __name__ == "__main__":
    main()
