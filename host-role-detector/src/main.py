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
from pathlib import Path

from aggregator import build_profiles
from catalog import load_catalog
from config import Config
from db import Db
from matcher import build_detected_roles

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
            existing = await db.get_detected_roles(ip)
            payload = build_detected_roles(
                profile, catalog, existing, cfg.min_confidence, cfg.oui_confidence_bonus,
            )
            await db.write_detected_roles(ip, payload)
            if payload.get("roles"):
                written += 1
        except Exception as exc:
            log.warning("Host %s: Detektion fehlgeschlagen: %s", ip, exc)

    log.info("Cycle fertig: %d Hosts evaluiert, %d mit ≥1 Rolle", len(profiles), written)


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
