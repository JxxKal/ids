"""app-connect — CYJAN-Tunnel-Agent für die iOS-App.

    Kafka alerts-enriched ──┐
                            ├──► app-connect ──(WSS, ausgehend :443)──► proxy.cyjan.dev
    ids-api:8000  ◄─────────┘         │
      (RPC-Relay, Service-JWT)        └── HTTP-CONNECT durch HTTPS_PROXY, falls gesetzt

Verbindlicher Vertrag: cyjan-mobile/docs/architecture/protocol.md (v1).

Zwei Eigenschaften, die dieser Service anders macht als der Rest des Stacks:

1. **Er darf schlafen.** Ist kein Proxy-URL oder kein Device-Token
   konfiguriert, loggt er das genau einmal und geht in eine Idle-Schleife.
   Es gibt bewusst keine `${VAR:?}`-Fail-Closed-Variable im Compose-Block —
   ein unkonfiguriertes App-Connect darf den Stack nicht am Boot hindern.

2. **Sein Heartbeat hängt nicht am Tunnel.** `/tmp/heartbeat` wird von
   einem eigenen Task getouched, der nichts über den Zustand der
   Cloud-Verbindung weiß. Ein nicht erreichbarer Proxy (kein Internet im
   OT-Netz, Wartungsfenster beim Betreiber) macht den Container NICHT
   unhealthy — sonst würde `cyjan-stack-health` beim Boot auf eine fremde
   Infrastruktur warten. Gleiche Begründung wie bei mqtt-bridge.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from allowlist import Allowlist
from api_client import ApiClient
from config import Config, RuntimeConfig
from events import EventSource
from proxy_egress import proxy_for_url
from state import StateWriter
from tunnel import Tunnel

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [app-connect] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("app-connect")

HEARTBEAT_INTERVAL_S = 30
# Wie oft im Dormant-Zustand nachgesehen wird, ob inzwischen ein
# Device-Token da ist. Das erlaubt Pairing per Datei-Drop ohne Restart.
DORMANT_RECHECK_S = 60


async def _heartbeat_loop() -> None:
    """Prozess-Liveness, unabhängig vom Tunnel (siehe Modul-Docstring)."""
    while True:
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL_S)


async def _run_tunnel(cfg: Config, state: StateWriter) -> None:
    runtime = RuntimeConfig(event_severity_min=cfg.severity_min)
    allowlist = Allowlist(allow_triage=cfg.allow_triage)
    source = EventSource(cfg, runtime)

    if cfg.allow_triage:
        log.warning("APP_CONNECT_ALLOW_TRIAGE=true — Triage-Endpoints (Feedback "
                    "setzen/löschen) sind über den Tunnel erreichbar, "
                    "hello.read_only=false")
    else:
        log.info("Triage deaktiviert (Default) — Tunnel ist read-only, "
                 "capabilities=%s", allowlist.capabilities())

    proxy = proxy_for_url(cfg.proxy_url, cfg.https_proxy, cfg.no_proxy)
    if proxy is not None:
        log.info("Egress über HTTP-CONNECT-Proxy %s", proxy)
    elif cfg.https_proxy:
        log.info("HTTPS_PROXY gesetzt, aber no_proxy greift für %s — direkt",
                 cfg.proxy_url)

    async with ApiClient(cfg.api_base_url, cfg.api_secret_key,
                         timeout_s=cfg.rpc_timeout_s) as api:
        tunnel = Tunnel(cfg, runtime, allowlist, api, source.queue, state)
        await asyncio.gather(source.run(), tunnel.run())


async def _idle(cfg: Config, state: StateWriter) -> Config:
    """Dormant: wartet, bis eine Konfiguration auftaucht. Liefert die dann
    gültige Config zurück."""
    log.warning(
        "app-connect ist nicht konfiguriert (%s fehlt) — Dienst bleibt "
        "im Leerlauf. Der Container ist dabei absichtlich *healthy*: ohne "
        "App-Anbindung ist das kein Fehlerzustand.",
        ", ".join(cfg.missing()) or "Konfiguration",
    )
    state.write(connection="dormant", missing=cfg.missing())
    while True:
        await asyncio.sleep(DORMANT_RECHECK_S)
        fresh = Config.from_env()
        if fresh.configured:
            log.info("Konfiguration aufgetaucht — starte Tunnel zu %s",
                     fresh.proxy_url)
            return fresh


async def amain() -> None:
    cfg = Config.from_env()
    state = StateWriter(cfg.state_path)

    # Referenz halten, damit der Task nicht vom GC eingesammelt wird.
    _hb_task = asyncio.create_task(_heartbeat_loop(), name="heartbeat")  # noqa: F841

    if not cfg.enabled:
        log.warning("APP_CONNECT_ENABLED=false — Dienst bleibt im Leerlauf.")
        state.write(connection="disabled")
        while True:
            await asyncio.sleep(3600)

    if not cfg.api_secret_key:
        log.warning("API_SECRET_KEY ist leer — RPC-Aufrufe gegen die lokale "
                    "api werden mit 401 scheitern. Variable im Compose-Block "
                    "setzen (identisch zum SECRET_KEY der api).")

    while True:
        if not cfg.configured:
            cfg = await _idle(cfg, state)
            continue
        try:
            await _run_tunnel(cfg, state)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Der Tunnel hat seine eigene Reconnect-Schleife; hier landen
            # nur Fehler, die den ganzen Stack gerissen haben (Kafka weg,
            # Consumer-Init kaputt). Nie crashen — nur langsamer machen.
            log.exception("app-connect-Stack abgestürzt: %s — Neustart in 15s", exc)
            state.write(connection="crashed", last_error=f"{type(exc).__name__}: {exc}")
            await asyncio.sleep(15)


def main() -> None:
    log.info("app-connect startup")

    def _handle_signal(*_):
        log.info("Signal empfangen — fahre runter")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
