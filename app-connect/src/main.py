"""app-connect — CYJAN-Tunnel-Agent für die iOS-App.

    Kafka alerts-enriched ──┐
                            ├──► app-connect ──(WSS, ausgehend :443)──► proxy.cyjan.dev
    ids-api:8000  ◄─────────┘         │
      (RPC-Relay, Service-JWT)        └── HTTP-CONNECT durch HTTPS_PROXY, falls gesetzt

Verbindlicher Vertrag: cyjan-mobile/docs/architecture/protocol.md (v1).

Drei Eigenschaften, die dieser Service anders macht als der Rest des Stacks:

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

3. **Seine interne API läuft auch im Schlaf.** Der aiohttp-Server auf
   :8090 startet vor allem anderen und bleibt oben, egal was der Tunnel
   macht — sonst könnte die GUI das Feature nie einrichten
   (docs/internal-api.md).

Konfiguration kommt aus ENV (Bootstrap) und wird feldweise von
`system_config['app_connect']` überlagert; ein Watcher pollt das alle 30 s.
Ändert sich eines der `CONNECTION_FIELDS`, wird der Tunnel sauber neu
aufgebaut — der Prozess läuft dabei weiter.
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
from config import (
    CONFIG_RELOAD_INTERVAL_S,
    CONNECTION_FIELDS,
    Config,
    RuntimeConfig,
    env_dict,
)
from db_config import ConfigStore
from events import EventSource
from proxy_egress import proxy_for_url
from server import InternalServer, ServiceRuntime
from state import StateWriter
from tunnel import Tunnel

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [app-connect] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("app-connect")

HEARTBEAT_INTERVAL_S = 30


async def _heartbeat_loop() -> None:
    """Prozess-Liveness, unabhängig vom Tunnel (siehe Modul-Docstring)."""
    while True:
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL_S)


def _changed_fields(old: Config, new: Config) -> list[str]:
    fields = ("enabled", "sentry_name", "allow_triage", "severity_min",
              *CONNECTION_FIELDS)
    return [f for f in fields if getattr(old, f) != getattr(new, f)]


async def _config_watch(
    session_cfg: Config,
    store: ConfigStore,
    runtime: ServiceRuntime,
    rt: RuntimeConfig,
) -> None:
    """Pollt die effektive Konfiguration. Kehrt zurück, sobald der Tunnel
    neu aufgebaut werden muss; alles andere wird live übernommen."""
    applied = session_cfg
    while True:
        await asyncio.sleep(CONFIG_RELOAD_INTERVAL_S)
        try:
            fresh = await store.effective()
        except Exception as exc:  # pragma: no cover — Sicherheitsnetz
            log.warning("Config-Poll fehlgeschlagen: %s", exc)
            continue
        if fresh == applied:
            continue

        changed = _changed_fields(applied, fresh)
        runtime.cfg = fresh
        if fresh.needs_restart(applied):
            log.info("Konfigurationsänderung in %s — Tunnel wird neu aufgebaut",
                     ", ".join(changed) or "Verbindungsfeldern")
            return

        # Live-Übernahme ohne Reconnect.
        #
        # `allow_triage` steht hier bewusst NICHT mehr: es erzwingt seit
        # needs_restart() einen Tunnel-Neuaufbau. Anders erführen Proxy und App
        # die geänderten `read_only`/`capabilities` nie — beide lesen sie
        # ausschließlich aus dem `hello`.
        if fresh.severity_min != applied.severity_min:
            rt.event_severity_min = fresh.severity_min
        log.info("Konfiguration live übernommen: %s", ", ".join(changed))
        applied = fresh


async def _run_session(
    cfg: Config, state: StateWriter, store: ConfigStore, runtime: ServiceRuntime
) -> None:
    """Eine Session = 1× aufgebauter Tunnel-Stack. Endet, wenn der
    Config-Watcher einen Neuaufbau verlangt oder etwas abstürzt."""
    rt = RuntimeConfig(event_severity_min=cfg.severity_min)
    allowlist = Allowlist(allow_triage=cfg.allow_triage)
    source = EventSource(cfg, rt)

    if cfg.allow_triage:
        log.warning("Triage aktiviert — Triage-Endpoints (Feedback "
                    "setzen/löschen) sind über den Tunnel erreichbar, "
                    "hello.read_only=false")
    else:
        log.info("Triage deaktiviert (Default) — Tunnel ist read-only, "
                 "capabilities=%s", allowlist.capabilities())

    proxy = proxy_for_url(cfg.proxy_url, cfg.https_proxy, cfg.no_proxy)
    if proxy is not None:
        log.info("Egress über HTTP-CONNECT-Proxy %s", proxy)
    elif cfg.https_proxy:
        log.info("Egress-Proxy gesetzt, aber no_proxy greift für %s — direkt",
                 cfg.proxy_url)

    async with ApiClient(cfg.api_base_url, cfg.api_secret_key,
                         timeout_s=cfg.rpc_timeout_s) as api:
        tunnel = Tunnel(cfg, rt, allowlist, api, source.queue, state)
        tasks = [
            asyncio.create_task(source.run(), name="events"),
            asyncio.create_task(tunnel.run(), name="tunnel"),
            asyncio.create_task(
                _config_watch(cfg, store, runtime, rt),
                name="config-watch",
            ),
        ]
        try:
            done, _pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        # Exceptions aus dem zuerst beendeten Task weiterreichen; der
        # Watcher endet dagegen regulär (Reconnect gewünscht).
        for task in done:
            task.result()


async def _idle(cfg: Config, state: StateWriter, store: ConfigStore) -> None:
    """Ruhezustand: warten, bis sich die Konfiguration ändert. Die interne
    API läuft weiter — genau hier setzt die GUI die Einrichtung an."""
    if not cfg.enabled:
        log.warning("app-connect ist abgeschaltet (enabled=false) — Dienst "
                    "bleibt im Leerlauf. Die interne API bleibt erreichbar.")
        state.write(connection="disabled")
    else:
        log.warning(
            "app-connect ist nicht eingerichtet (%s fehlt) — Dienst bleibt "
            "im Leerlauf. Der Container ist dabei absichtlich *healthy*: ohne "
            "App-Anbindung ist das kein Fehlerzustand. Einrichtung über "
            "Einstellungen → Integrationen → CYJAN App oder per .env.",
            ", ".join(cfg.missing()) or "Konfiguration",
        )
        state.write(connection="dormant", missing=cfg.missing())
    await store.wait_for_change(cfg)
    log.info("Konfigurationsänderung erkannt — werte neu aus")


async def amain() -> None:
    env = env_dict()
    cfg = Config.from_dict(env)
    state = StateWriter(cfg.state_path)
    runtime = ServiceRuntime(cfg, state)
    state.write(connection="dormant")

    # Referenz halten, damit der Task nicht vom GC eingesammelt wird.
    _hb_task = asyncio.create_task(_heartbeat_loop(), name="heartbeat")  # noqa: F841

    if not cfg.api_secret_key:
        log.warning("API_SECRET_KEY ist leer — RPC-Aufrufe gegen die lokale "
                    "api werden mit 401 scheitern und die interne API "
                    "antwortet mit 503. Variable im Compose-Block setzen "
                    "(identisch zum SECRET_KEY der api).")

    server = InternalServer(runtime)
    try:
        await server.start()
    except OSError as exc:
        # Ein belegter Port darf den Tunnel nicht verhindern — dann fehlt
        # eben die GUI-Anbindung, und das steht laut und deutlich im Log.
        log.error("Interne API konnte nicht starten (%s) — die GUI kann "
                  "app-connect nicht verwalten, der Tunnel läuft trotzdem.", exc)

    store = ConfigStore(cfg.postgres_dsn, env)

    while True:
        try:
            cfg = await store.effective()
        except Exception as exc:
            log.warning("Effektive Konfiguration nicht ermittelbar (%s) — "
                        "ENV-Konfiguration bleibt aktiv", exc)
            cfg = Config.from_dict(env)
        runtime.cfg = cfg

        if not cfg.configured:
            await _idle(cfg, state, store)
            continue

        log.info("Konfiguration aktiv (Quelle: %s) — Tunnel zu %s",
                 cfg.config_source, cfg.proxy_url)
        try:
            await _run_session(cfg, state, store, runtime)
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
