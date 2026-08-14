"""WSS-Tunnel zum CYJAN-Proxy (protocol.md §1 und §2).

Struktur bewusst analog zu `tap-uplink/src/main.py`:

    run()                    Reconnect-Schleife mit Backoff + Jitter
      └─ _session(ws)        eine Verbindung
           ├─ hello / hello_ack
           ├─ _receive_loop  Frames vom Proxy (ping/rpc/config)
           ├─ _event_loop    Kafka-Alerts → event-Frames
           ├─ _threat_loop   /api/stats/threat-level → event-Frames
           └─ _status_loop   Zähler → event-Frames

Unterschied zu tap-uplink: **keine DiskQueue**. protocol.md §1.5 verlangt
explizit, dass nicht auf Platte gepuffert wird — der Tunnel transportiert
Benachrichtigungen, keine Ereignis-Persistenz. Die kanonische Kopie liegt
in TimescaleDB und wird beim nächsten App-Refresh nachgeladen. Beim
Verbindungsaufbau wird die In-Memory-Queue deshalb VERWORFEN, statt sie
nachzureichen.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import orjson
import websockets

from allowlist import Allowlist, RejectedPath
from api_client import ApiClient
from backoff import next_backoff, with_jitter
from config import (
    HEARTBEAT_TIMEOUT_S,
    RECONNECT_MIN_S,
    SCHEMA_VERSION,
    WS_MAX_SIZE,
    Config,
    RuntimeConfig,
)
from fields import sanitize_alert
from proxy_egress import ProxyError, open_proxied_socket, proxy_for_url, target_from_url
from state import StateWriter

log = logging.getLogger(__name__)

# Gleichzeitig ausgeführte RPCs. Der Proxy serialisiert nicht, und ein
# Gerät mit einer hektischen Listen-Ansicht darf die lokale api nicht
# fluten. 8 ist großzügig für eine Handvoll iPhones.
MAX_CONCURRENT_RPC = 8


class Tunnel:
    def __init__(
        self,
        cfg: Config,
        runtime: RuntimeConfig,
        allowlist: Allowlist,
        api: ApiClient,
        events: asyncio.Queue,
        state: StateWriter,
    ) -> None:
        self._cfg = cfg
        self._rt = runtime
        self._acl = allowlist
        self._api = api
        self._events = events
        self._state = state

        self._send_lock = asyncio.Lock()
        self._rpc_sem = asyncio.Semaphore(MAX_CONCURRENT_RPC)
        self._rpc_tasks: set[asyncio.Task] = set()

        self._started_at = time.time()
        self._connected_since: float | None = None
        self._last_error: str | None = None
        self._push_enabled: bool | None = None
        self._proxy_version: str | None = None

        # Zähler — landen im status-Event und im State-File.
        self.events_sent = 0
        self.events_dropped = 0
        self.rpc_ok = 0
        self.rpc_rejected = 0
        self.rpc_failed = 0

    # ── State ────────────────────────────────────────────────────────────

    def _write_state(self, connection: str) -> None:
        self._state.write(
            connection=connection,
            proxy_url=self._cfg.proxy_url,
            sentry_name=self._cfg.sentry_name,
            version=self._cfg.version,
            read_only=self._acl.read_only,
            capabilities=self._acl.capabilities(),
            connected_since=self._connected_since,
            push_enabled=self._push_enabled,
            proxy_version=self._proxy_version,
            event_severity_min=self._rt.event_severity_min,
            push_detail=self._rt.push_detail,
            events_sent=self.events_sent,
            events_dropped=self.events_dropped,
            rpc_ok=self.rpc_ok,
            rpc_rejected=self.rpc_rejected,
            rpc_failed=self.rpc_failed,
            last_error=self._last_error,
            uptime_s=int(time.time() - self._started_at),
        )

    # ── TLS + Egress ─────────────────────────────────────────────────────

    def _ssl_context(self) -> ssl.SSLContext:
        """WebPKI gegen den Proxy (Let's Encrypt/Caddy, protocol.md §0).
        Optional eine eigene CA für Setups mit TLS-inspizierendem
        Corporate-Proxy."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if self._cfg.ca_file:
            ctx.load_verify_locations(cafile=self._cfg.ca_file)
        if self._cfg.tls_insecure:
            # Nur für Lab-Bring-up. Laut und deutlich ins Log.
            log.warning("APP_CONNECT_TLS_INSECURE=true — Zertifikatsprüfung "
                        "des Proxys ist AUS. Niemals in Produktion.")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _connect(self):
        """websockets-Verbindung, ggf. durch einen HTTP-CONNECT-Tunnel.

        Liefert (connector, sock). `sock` ist nur gesetzt, wenn über einen
        Egress-Proxy getunnelt wird — der Aufrufer muss ihn schließen,
        falls der WebSocket-Handshake danach scheitert (sonst leakt pro
        Fehlversuch ein FD, und Fehlversuche sind hier der Normalfall,
        solange der Proxy nicht erreichbar ist).
        """
        headers = {"Authorization": f"Bearer {self._cfg.device_token}"}
        kwargs: dict[str, Any] = dict(
            extra_headers=headers,
            ping_interval=None,        # eigener Heartbeat auf Frame-Ebene
            open_timeout=20,
            close_timeout=5,
            max_size=WS_MAX_SIZE,
        )
        # Der Produktionspfad ist wss://. Ein ssl-Argument an einer ws://-URI
        # lässt die websockets-Lib mit ValueError abbrechen — deshalb nur
        # setzen, wenn das Schema es hergibt. Plain ws:// bleibt damit für
        # lokale Bring-up-Tests benutzbar, ohne Sonderpfade im Code.
        if urlparse(self._cfg.proxy_url).scheme == "wss":
            kwargs["ssl"] = self._ssl_context()
        else:
            log.warning("APP_CONNECT_PROXY_URL nutzt %s statt wss:// — der "
                        "Tunnel läuft UNVERSCHLÜSSELT. Nur für lokale Tests.",
                        urlparse(self._cfg.proxy_url).scheme or "?")

        sock = None
        proxy = proxy_for_url(
            self._cfg.proxy_url, self._cfg.https_proxy, self._cfg.no_proxy
        )
        if proxy is not None:
            host, port = target_from_url(self._cfg.proxy_url)
            sock = await open_proxied_socket(host, port, proxy)
            kwargs["sock"] = sock
        return websockets.connect(self._cfg.proxy_url, **kwargs), sock

    # ── Frame-Versand ────────────────────────────────────────────────────

    async def _send(self, ws, frame: dict) -> None:
        """Ein Frame, serialisiert. Der Lock verhindert, dass sich ein
        PCAP-Chunk-Stream und ein gleichzeitiges Alert-Event ins Gehege
        kommen."""
        async with self._send_lock:
            await ws.send(orjson.dumps(frame).decode())

    async def _send_event(self, ws, kind: str, data: dict) -> None:
        await self._send(ws, {"type": "event", "payload": {"kind": kind, "data": data}})

    # ── Verbindungs-Lebenszyklus ─────────────────────────────────────────

    async def run(self) -> None:
        backoff = RECONNECT_MIN_S
        while True:
            acked = False

            def _on_ack() -> None:
                nonlocal acked
                acked = True

            self._write_state("connecting")
            sock = None
            try:
                connector, sock = await self._connect()
                async with connector as ws:
                    sock = None   # gehört jetzt der websockets-Verbindung
                    self._connected_since = time.time()
                    self._last_error = None
                    log.info("WSS verbunden mit %s (sentry=%s read_only=%s)",
                             self._cfg.proxy_url, self._cfg.sentry_name,
                             self._acl.read_only)
                    await self._session(ws, on_ack=_on_ack)
                    # Sauberer Close vom Proxy — trotzdem Reconnect.
                    raise ConnectionError("Proxy hat den Tunnel geschlossen")
            except asyncio.CancelledError:
                raise
            except ProxyError as exc:
                self._last_error = str(exc)
                log.warning("Egress-Proxy: %s", exc)
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                log.warning("Tunnel weg: %s", self._last_error)
            finally:
                if sock is not None:
                    sock.close()
                self._connected_since = None
                await self._cancel_rpc_tasks()

            self._write_state("down")
            # §1.4: Reset erst nach erfolgreichem hello_ack. Ein Proxy, der
            # zwar TCP annimmt, aber jedes hello ablehnt (Token revoked,
            # Schema-Mismatch), darf uns nicht in eine 1-Sekunden-Schleife
            # zwingen.
            if acked:
                backoff = RECONNECT_MIN_S
            delay = with_jitter(backoff)
            log.info("Reconnect in %.1fs (Basis %.0fs%s)", delay, backoff,
                     ", nach hello_ack zurückgesetzt" if acked else "")
            await asyncio.sleep(delay)
            backoff = next_backoff(backoff)

    async def _session(self, ws, on_ack) -> None:
        """Eine Verbindung: hello → hello_ack → Loops."""
        # Stale Events aus der Outage verwerfen (protocol.md §1.5).
        dropped = 0
        while not self._events.empty():
            try:
                self._events.get_nowait()
                dropped += 1
            except asyncio.QueueEmpty:
                break
        if dropped:
            self.events_dropped += dropped
            log.info("%d Events aus der Outage verworfen (kein Disk-Buffer, §1.5)",
                     dropped)

        await self._send(ws, {
            "type": "hello",
            "payload": {
                "schema": SCHEMA_VERSION,
                "sentry_name": self._cfg.sentry_name,
                "version": self._cfg.version,
                "capabilities": self._acl.capabilities(),
                "read_only": self._acl.read_only,
            },
        })

        # hello_ack abwarten, bevor die Sende-Loops loslaufen — sonst
        # schieben wir Events in einen Tunnel, den der Proxy gerade wegen
        # Schema-Mismatch (Close 4400) zumacht. Ein zwischendurch
        # eintrudelnder `ping` wird beantwortet und übersprungen, statt die
        # Verbindung wegen Reihenfolge-Pedanterie zu reißen.
        deadline = time.monotonic() + HEARTBEAT_TIMEOUT_S
        payload: dict = {}
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionError("Kein hello_ack innerhalb des Heartbeat-Fensters")
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            frame = self._parse(raw)
            if frame is None:
                continue
            ftype = frame.get("type")
            if ftype == "hello_ack":
                payload = frame.get("payload") or {}
                break
            if ftype == "ping":
                await self._send(ws, {"type": "pong", "payload": {}})
                continue
            log.info("Frame %r vor hello_ack verworfen", ftype)
        self._push_enabled = payload.get("push_enabled")
        self._proxy_version = payload.get("proxy_version")
        log.info("hello_ack: proxy_version=%s push_enabled=%s",
                 self._proxy_version, self._push_enabled)
        on_ack()
        self._write_state("connected")

        # §1.5: direkt nach hello_ack ein status-Event mit den aktuellen
        # Zählern, damit die App den Sprung über die Outage sieht.
        await self._send_status(ws)
        await self._send_threat(ws)

        await asyncio.gather(
            self._receive_loop(ws),
            self._event_loop(ws),
            self._threat_loop(ws),
            self._status_loop(ws),
        )

    @staticmethod
    def _parse(raw) -> dict | None:
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            frame = orjson.loads(raw)
            return frame if isinstance(frame, dict) else None
        except Exception:
            return None

    # ── Empfang ──────────────────────────────────────────────────────────

    async def _receive_loop(self, ws) -> None:
        """Frames vom Proxy. §1.4: bleibt es länger als 75 s still, gilt
        die Verbindung als tot — der Proxy pingt alle 30 s."""
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=HEARTBEAT_TIMEOUT_S)
            except asyncio.TimeoutError:
                raise ConnectionError(
                    f"Proxy >{HEARTBEAT_TIMEOUT_S:.0f}s still — Reconnect"
                ) from None

            frame = self._parse(raw)
            if frame is None:
                log.warning("Unparsebares Frame vom Proxy verworfen")
                continue

            ftype = frame.get("type")
            payload = frame.get("payload") or {}

            if ftype == "ping":
                await self._send(ws, {"type": "pong", "payload": {}})
            elif ftype == "rpc":
                self._spawn_rpc(ws, frame.get("id"), payload)
            elif ftype == "config":
                if self._rt.apply(payload):
                    log.info("config-Frame übernommen: event_severity_min=%s "
                             "push_detail=%s", self._rt.event_severity_min,
                             self._rt.push_detail)
                    self._write_state("connected")
            elif ftype == "hello_ack":
                log.debug("Zweites hello_ack ignoriert")
            else:
                # §1.2 — Unbekanntes wird verworfen und geloggt, nie als
                # Fehler behandelt (Vorwärtskompatibilität).
                log.info("Unbekannter Frame-Typ %r verworfen", ftype)

    # ── RPC ──────────────────────────────────────────────────────────────

    def _spawn_rpc(self, ws, rpc_id, payload: dict) -> None:
        task = asyncio.create_task(self._handle_rpc(ws, rpc_id, payload))
        self._rpc_tasks.add(task)
        task.add_done_callback(self._rpc_tasks.discard)

    async def _cancel_rpc_tasks(self) -> None:
        for task in list(self._rpc_tasks):
            task.cancel()
        if self._rpc_tasks:
            await asyncio.gather(*list(self._rpc_tasks), return_exceptions=True)
        self._rpc_tasks.clear()

    async def _rpc_error(self, ws, rpc_id, error: str, detail: str) -> None:
        self.rpc_failed += 1
        await self._send(ws, {
            "type": "rpc_error", "id": rpc_id,
            "payload": {"error": error, "detail": detail},
        })

    async def _handle_rpc(self, ws, rpc_id, payload: dict) -> None:
        method = str(payload.get("method") or "GET")
        raw_path = str(payload.get("path") or "")
        query = payload.get("query") or {}
        if not isinstance(query, dict):
            query = {}
        query = {str(k): str(v) for k, v in query.items()}
        want_stream = bool(payload.get("stream"))

        try:
            path, extra_query = self._acl.check(method, raw_path)
        except RejectedPath as exc:
            self.rpc_rejected += 1
            await self._send(ws, {
                "type": "rpc_error", "id": rpc_id,
                "payload": {"error": exc.reason, "detail": exc.detail},
            })
            return

        # Query aus dem Pfad ergänzt die explizite query-Map, überschreibt
        # sie aber nicht.
        for k, v in extra_query.items():
            query.setdefault(k, v)

        body: bytes | None = None
        b64 = payload.get("body_b64")
        if b64:
            try:
                body = base64.b64decode(b64, validate=True)
            except Exception:
                self.rpc_rejected += 1
                await self._send(ws, {
                    "type": "rpc_error", "id": rpc_id,
                    "payload": {"error": "bad_request", "detail": "body_b64 ungültig"},
                })
                return

        async with self._rpc_sem:
            try:
                if want_stream and self._acl.is_streamable(path):
                    ok = await asyncio.wait_for(
                        self._stream_rpc(ws, rpc_id, method, path, query),
                        # Ein PCAP-Stream darf länger dauern als ein
                        # JSON-Roundtrip; der Proxy hat sein eigenes
                        # RPC_TIMEOUT_S für die App-Seite.
                        timeout=max(self._cfg.rpc_timeout_s * 10, 60.0),
                    )
                else:
                    ok = await asyncio.wait_for(
                        self._unary_rpc(ws, rpc_id, method, path, query, body),
                        timeout=self._cfg.rpc_timeout_s,
                    )
                if ok:
                    self.rpc_ok += 1
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                log.warning("RPC-Timeout: %s %s", method, path)
                await self._rpc_error(ws, rpc_id, "timeout",
                                      f"ids-api antwortete nicht in "
                                      f"{self._cfg.rpc_timeout_s:.0f}s")
            except Exception as exc:
                log.warning("RPC fehlgeschlagen: %s %s — %s", method, path, exc)
                await self._rpc_error(ws, rpc_id, "upstream_error",
                                      f"{type(exc).__name__}: {exc}")

    async def _unary_rpc(self, ws, rpc_id, method, path, query, body) -> bool:
        resp = await self._api.execute(
            method, path, query, body, max_bytes=self._cfg.max_body_bytes
        )
        if resp.truncated:
            log.info("RPC-Antwort > %d Bytes — truncated (%s %s)",
                     self._cfg.max_body_bytes, method, path)
        await self._send(ws, {
            "type": "rpc_result", "id": rpc_id,
            "payload": {
                "status": resp.status,
                "headers": resp.headers,
                "body_b64": base64.b64encode(resp.body).decode("ascii"),
                "truncated": resp.truncated,
            },
        })
        return True

    async def _stream_rpc(self, ws, rpc_id, method, path, query) -> bool:
        """PCAP-Streaming (protocol.md §2.5): Folge von rpc_chunk-Frames
        mit {seq, data_b64, final}. Kein Zwischenspeichern auf Platte.

        Erweiterung gegenüber der Spec: das Frame mit seq=0 trägt
        zusätzlich `status` und `headers`, damit der Proxy einen HTTP-Fehler
        vom Sentry unterscheiden kann, ohne auf ein rpc_result zu warten.
        §8 erlaubt zusätzliche Payload-Felder ohne Schema-Bump.
        """
        seq = 0
        sent_any = False
        async for status, headers, chunk, truncated in self._api.stream(
            method, path, query,
            chunk_bytes=self._cfg.chunk_bytes,
            max_bytes=self._cfg.max_stream_bytes,
        ):
            if seq == 0 and status >= 400:
                await self._rpc_error(ws, rpc_id, "upstream_error",
                                      f"ids-api lieferte HTTP {status}")
                return False
            frame_payload: dict[str, Any] = {
                "seq": seq,
                "data_b64": base64.b64encode(chunk).decode("ascii"),
                "final": False,
            }
            if seq == 0:
                frame_payload["status"] = status
                frame_payload["headers"] = headers
            if truncated:
                frame_payload["truncated"] = True
            await self._send(ws, {
                "type": "rpc_chunk", "id": rpc_id, "payload": frame_payload,
            })
            seq += 1
            sent_any = True

        # Abschluss-Frame. `final` sitzt bewusst auf einem eigenen Frame,
        # damit der Proxy den Stream auch dann sauber beenden kann, wenn
        # der letzte Datenchunk exakt die Chunk-Größe hatte.
        final_payload: dict[str, Any] = {"seq": seq, "data_b64": "", "final": True}
        if not sent_any:
            final_payload["status"] = 204
        await self._send(ws, {
            "type": "rpc_chunk", "id": rpc_id, "payload": final_payload,
        })
        return True

    # ── Sende-Loops ──────────────────────────────────────────────────────

    async def _event_loop(self, ws) -> None:
        """Kafka-Alerts → `event`-Frames. Filter + Feld-Whitelist laufen
        hier, damit ein `config`-Frame ohne Reconnect greift."""
        while True:
            alert = await self._events.get()
            severity = (alert.get("severity") or "low").lower()
            if not self._rt.severity_passes(severity):
                continue
            data = sanitize_alert(alert)
            if not data.get("alert_id"):
                continue
            await self._send_event(ws, "alert", data)
            self.events_sent += 1

    async def _threat_loop(self, ws) -> None:
        while True:
            await asyncio.sleep(self._cfg.threat_interval_s)
            await self._send_threat(ws)

    async def _send_threat(self, ws) -> None:
        data = await self._api.get_threat_level()
        if data is None:
            return
        await self._send_event(ws, "threat_level", {
            "level": data.get("level"),
            "label": data.get("label"),
            "alert_counts": data.get("alert_counts") or {},
            "window_min": data.get("window_min"),
        })

    async def _status_loop(self, ws) -> None:
        while True:
            await asyncio.sleep(self._cfg.status_interval_s)
            await self._send_status(ws)
            self._write_state("connected")

    async def _send_status(self, ws) -> None:
        await self._send_event(ws, "status", {
            "online": True,
            "sentry_name": self._cfg.sentry_name,
            "version": self._cfg.version,
            "read_only": self._acl.read_only,
            "capabilities": self._acl.capabilities(),
            "uptime_s": int(time.time() - self._started_at),
            "connected_since": self._connected_since,
            "events_sent": self.events_sent,
            "events_dropped": self.events_dropped,
            "rpc_ok": self.rpc_ok,
            "rpc_rejected": self.rpc_rejected,
            "rpc_failed": self.rpc_failed,
            "event_severity_min": self._rt.event_severity_min,
        })
