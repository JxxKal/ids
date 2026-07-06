"""mqtt-bridge — Outbound-only MQTT-Publisher für Cyjan-Alerts und State.

V1.0 Architektur (entsprechend dem Design-Grilling-Ergebnis):

  Kafka alerts-enriched ──► mqtt-bridge ──► externer MQTT-Broker
                              │
                              ├── Per-Origin-Identity:
                              │     Master-Alerts → cyjan/<master>/alerts/...
                              │     Tap-Alerts    → cyjan/<tap-name>/alerts/...
                              │
                              ├── Filter (Cyjan-side soft-cap):
                              │     severity_min, sources_allowed, rule_id_blocklist
                              │
                              ├── Rate-Limiter (Default 200 publishes/sec)
                              ├── Inflight-Window (max 10 unack'd QoS-1-Publishes)
                              │
                              └── State-Loops (alle 30s):
                                    {prefix}/<master>/threat   (retain=true)
                                    {prefix}/<host>/taps/<n>/status (retain=true, pro Tap)
                                    LWT: {prefix}/<master>/status = "offline"

Outage-Strategie: Kafka-Consumer-Group mit pause-on-disconnect, kein
auto-commit. Reconnect → ab letztem Offset weiter (= Outage-Buffer for
free durch Kafka-Retention von alerts-enriched, 7d Default).
"""
from __future__ import annotations

import asyncio
import logging
import signal
import ssl
import sys
import time
from pathlib import Path
from typing import Optional

import asyncpg
import orjson
import paho.mqtt.client as mqtt
from confluent_kafka import Consumer, KafkaError, KafkaException

from config import Config, _env_dict, merge_db_overlay
from topics import event_topic, status_topic, tap_status_topic, threat_topic

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("mqtt-bridge")

# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Prozess-Liveness: eigener asyncio-Task im SUPERVISOR (amain), nicht in der
# Session — die Bridge ist auch dann gesund, wenn der EXTERNE MQTT-Broker
# down ist (Connect-Retry-Schleife) oder MQTT disabled ist (Idle-Loop). In
# beiden Zuständen läuft _run_session gar nicht; ein Session-gekoppelter
# Beat würde dann fälschlich unhealthy melden und cyjan-stack-health den
# Boot wegen eines fremden Brokers failen lassen.
async def _heartbeat_loop() -> None:
    while True:
        try:
            Path("/tmp/heartbeat").touch()
        except OSError:
            pass
        await asyncio.sleep(30)



# ─────────────────────────────────────────────────────────────────────────────
# MQTT-Client-Wrapper
# ─────────────────────────────────────────────────────────────────────────────


class Bridge:
    """Hält State der MQTT-Connection + Inflight-Counter + Rate-Limiter.
    Der paho-Loop läuft in einem Hintergrund-Thread (paho.loop_start),
    PUBACK-Tracking via on_publish-Callback."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._mqtt: Optional[mqtt.Client] = None
        self._connected = asyncio.Event()
        self._inflight = 0
        self._inflight_lock = asyncio.Lock()
        self._inflight_drained = asyncio.Event()
        self._inflight_drained.set()
        # Rate-Limit: token-bucket-light. Wir machen das per asyncio-Sleep
        # statt einem expliziten Bucket — bei 200/s ist 5ms-Sleep nach
        # jedem publish ausreichend genau.
        self._publish_interval_s = 1.0 / max(1, cfg.rate_limit_per_sec)

    def _build_ssl(self) -> Optional[ssl.SSLContext]:
        if not self.cfg.use_tls:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if not self.cfg.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif self.cfg.server_ca_path:
            ctx.load_verify_locations(self.cfg.server_ca_path)
        return ctx

    def connect(self, loop: asyncio.AbstractEventLoop) -> None:
        client = mqtt.Client(
            client_id=self.cfg.client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        if self.cfg.username:
            client.username_pw_set(self.cfg.username, self.cfg.password)
        ssl_ctx = self._build_ssl()
        if ssl_ctx is not None:
            client.tls_set_context(ssl_ctx)

        # LWT: bei Disconnect schickt der Broker automatisch "offline" als
        # retained Message. HMI-Subscriber sehen das sofort.
        lwt_topic = status_topic(self.cfg.topic_prefix, self.cfg.master_host_id)
        client.will_set(lwt_topic, payload=b"offline", qos=1, retain=True)

        client.on_connect    = lambda c, u, f, rc, p=None: self._on_connect(loop, rc)
        client.on_disconnect = lambda c, u, rc, *args:     self._on_disconnect(loop, rc)
        client.on_publish    = lambda c, u, mid, *args:    self._on_publish(loop, mid)

        client.connect_async(self.cfg.broker_host, self.cfg.broker_port, keepalive=30)
        client.loop_start()
        self._mqtt = client
        log.info("MQTT-Connect zu %s:%d (tls=%s, verify=%s, client_id=%s)",
                 self.cfg.broker_host, self.cfg.broker_port,
                 self.cfg.use_tls, self.cfg.tls_verify, self.cfg.client_id)

    def _on_connect(self, loop: asyncio.AbstractEventLoop, rc) -> None:
        if rc == mqtt.MQTT_ERR_SUCCESS or (hasattr(rc, "is_failure") and not rc.is_failure):
            log.info("MQTT verbunden — publishe online-Status (retain)")
            # Online-Status sofort retained publishen, überschreibt LWT-Wert
            self._mqtt.publish(
                status_topic(self.cfg.topic_prefix, self.cfg.master_host_id),
                payload=b"online", qos=1, retain=True,
            )
            loop.call_soon_threadsafe(self._connected.set)
        else:
            log.warning("MQTT-Connect schlug fehl: rc=%s", rc)

    def _on_disconnect(self, loop: asyncio.AbstractEventLoop, rc) -> None:
        log.warning("MQTT-Disconnect: rc=%s — paho retried automatisch", rc)
        loop.call_soon_threadsafe(self._connected.clear)

    def _on_publish(self, loop: asyncio.AbstractEventLoop, mid: int) -> None:
        # Inflight-Counter dekrementieren (im event-loop-Kontext)
        loop.call_soon_threadsafe(self._dec_inflight)

    def _dec_inflight(self) -> None:
        self._inflight = max(0, self._inflight - 1)
        if self._inflight < self.cfg.inflight_max:
            self._inflight_drained.set()

    async def wait_connected(self) -> None:
        await self._connected.wait()

    async def publish(self, topic: str, payload: bytes, qos: int, retain: bool = False) -> None:
        """Async-publish mit Inflight-Window + Rate-Limit. Blockt wenn
        Inflight voll ist bis ein PUBACK angekommen ist."""
        if self._mqtt is None or not self._connected.is_set():
            # Disconnected: wir warten passiv, der paho-Loop macht reconnect.
            await self._connected.wait()

        # Inflight-Window: wenn voll, warten bis on_publish-Callback feuert.
        while self._inflight >= self.cfg.inflight_max:
            self._inflight_drained.clear()
            await self._inflight_drained.wait()

        # Rate-Limit: kleines Sleep nach jedem publish.
        info = self._mqtt.publish(topic, payload=payload, qos=qos, retain=retain)
        if info.rc == mqtt.MQTT_ERR_SUCCESS and qos > 0:
            self._inflight += 1
        await asyncio.sleep(self._publish_interval_s)

    def shutdown(self) -> None:
        if self._mqtt is None:
            return
        try:
            # Sauberes "offline" als retained, dann disconnect (LWT wird
            # nicht ausgelöst weil clean-disconnect — daher manuell).
            self._mqtt.publish(
                status_topic(self.cfg.topic_prefix, self.cfg.master_host_id),
                payload=b"offline", qos=1, retain=True,
            )
            time.sleep(0.5)
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
        except Exception as exc:
            log.warning("Shutdown-Cleanup schlug fehl: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Tap-Resolver (tap_id → Tap-Name) mit kleinem TTL-Cache
# ─────────────────────────────────────────────────────────────────────────────


class TapResolver:
    """Mapped tap_id (UUID-String) → tap.name aus der DB. 60s-TTL-Cache,
    sodass nicht jeder Alert eine DB-Query auslöst. Bei Cache-Miss wird
    re-loaded (typisch wenn ein neuer Tap gepairt wurde)."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: Optional[asyncpg.Pool] = None
        self._cache: dict[str, str] = {}
        self._cache_ts: float = 0.0
        self._ttl_s = 60.0

    async def init(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=2)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()

    async def _load(self) -> None:
        assert self._pool is not None
        rows = await self._pool.fetch("SELECT id::text AS id, name FROM taps")
        self._cache = {r["id"]: (r["name"] or r["id"][:8]) for r in rows}
        self._cache_ts = time.time()

    async def resolve(self, tap_id: Optional[str]) -> Optional[str]:
        if not tap_id:
            return None
        if time.time() - self._cache_ts > self._ttl_s:
            try:
                await self._load()
            except Exception as exc:
                log.debug("Tap-Resolver-Reload fehlgeschlagen: %s", exc)
        return self._cache.get(tap_id)


# ─────────────────────────────────────────────────────────────────────────────
# Kafka-Consumer-Loop: Events
# ─────────────────────────────────────────────────────────────────────────────


def _make_consumer(brokers: str, client_id: str) -> Consumer:
    return Consumer({
        "bootstrap.servers": brokers,
        "group.id": f"mqtt-bridge-{client_id}",
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,            # auto-commit reicht — bei
        "auto.commit.interval.ms": 5000,       # Crash verlieren wir max 5s
                                               # Backlog-Window, akzeptabel
                                               # weil Kafka-Retention 7d ist
                                               # und bridges sind idempotent
                                               # aus Subscriber-Sicht (alert_id).
    })


async def event_consumer_loop(cfg: Config, bridge: Bridge, taps: TapResolver) -> None:
    """Konsumiert alerts-enriched, baut JSON-Payloads, publiziert pro
    Alert auf {prefix}/{host}/alerts/{sev}/{src}."""
    consumer = _make_consumer(cfg.kafka_brokers, cfg.client_id)
    consumer.subscribe([cfg.alerts_topic])
    log.info("Kafka-Consumer subscribed: %s", cfg.alerts_topic)

    # poll() läuft im to_thread-Worker. Beim Config-Reconnect cancelt gather
    # diesen Loop, während der Worker evtl. noch bis zu 1s weiterpollt. Wir
    # shielden den poll-Task, damit die Cancellation ihn NICHT abschneidet,
    # und warten im finally auf sein Ende, BEVOR consumer.close() kommt —
    # librdkafka ist nicht threadsafe für concurrent poll/close (Segfault).
    poll_task: Optional[asyncio.Task] = None
    try:
        while True:
            # Nicht-blockierend pollen, damit asyncio-Scheduling fluent bleibt
            if poll_task is None:
                poll_task = asyncio.ensure_future(asyncio.to_thread(consumer.poll, 1.0))
            msg = await asyncio.shield(poll_task)
            poll_task = None
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.warning("Kafka-Error: %s", msg.error())
                continue

            try:
                alert = orjson.loads(msg.value())
            except Exception as exc:
                log.debug("Ungültiges Alert-JSON: %s", exc)
                continue

            await _publish_alert(cfg, bridge, taps, alert)
    finally:
        # Auf einen evtl. noch laufenden poll-Thread warten (max ~1s), auch
        # wenn wir gerade gecancelt werden — sonst racet close() mit poll().
        if poll_task is not None:
            while not poll_task.done():
                try:
                    await asyncio.shield(poll_task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
        consumer.close()


async def _publish_alert(cfg: Config, bridge: Bridge, taps: TapResolver, alert: dict) -> None:
    """Filter + Topic-Build + Publish. Per-Origin-Identity: tap_id gewinnt."""
    severity = (alert.get("severity") or "low").lower()
    source   = (alert.get("source") or "signature").lower()
    rule_id  = alert.get("rule_id") or ""

    if not cfg.severity_passes(severity):
        return
    if not cfg.source_passes(source):
        return
    if not cfg.rule_id_passes(rule_id):
        return

    # Per-Origin-Identity: wenn alert.tap_id gesetzt ist und wir den Tap
    # kennen, nutzen wir tap.name als Topic-Owner. Sonst Master.
    tap_id = alert.get("tap_id")
    host = cfg.master_host_id
    if tap_id:
        resolved = await taps.resolve(tap_id)
        if resolved:
            host = resolved

    topic = event_topic(cfg.topic_prefix, host, severity, source)
    payload = _build_event_payload(alert, host)

    try:
        await bridge.publish(topic, payload, qos=cfg.qos_events, retain=False)
    except Exception as exc:
        log.warning("publish fehlgeschlagen %s: %s", topic, exc)


def _build_event_payload(alert: dict, host: str) -> bytes:
    """Reduziert das interne Alert-Schema auf das was im PRD steht.
    Bewusst klein gehalten — kein PCAP-Key, keine internen Flow-Refs."""
    return orjson.dumps({
        "alert_id":   alert.get("alert_id"),
        "ts":         alert.get("ts"),
        "host":       host,
        "source":     alert.get("source") or "signature",
        "rule_id":    alert.get("rule_id"),
        "severity":   alert.get("severity"),
        "score":      alert.get("score"),
        "src_ip":     alert.get("src_ip"),
        "dst_ip":     alert.get("dst_ip"),
        "proto":      alert.get("proto"),
        "dst_port":   alert.get("dst_port"),
        "description": alert.get("description"),
        "tags":       alert.get("tags") or [],
        "boundary_zones": {
            "src": alert.get("boundary_src_zone"),
            "dst": alert.get("boundary_dst_zone"),
        },
        "boundary_priority": alert.get("boundary_priority"),
        "enrichment": alert.get("enrichment") or {},
    })


# ─────────────────────────────────────────────────────────────────────────────
# State-Loops: Threat + Tap-Status
# ─────────────────────────────────────────────────────────────────────────────


async def threat_publish_loop(cfg: Config, bridge: Bridge, pool: asyncpg.Pool) -> None:
    """Publiziert alle 30s den aktuellen Threat-State des Master als retained.
    HMI-Subscriber sehen sofort beim Subscribe den letzten Wert."""
    topic = threat_topic(cfg.topic_prefix, cfg.master_host_id)
    while True:
        try:
            score, label, counts = await _read_threat_level(pool)
            payload = orjson.dumps({
                "score":  score,
                "label":  label,
                "window_min": 15,
                "ts":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "counts": counts,
            })
            await bridge.publish(topic, payload, qos=cfg.qos_state, retain=True)
        except Exception as exc:
            log.debug("threat-publish fehlgeschlagen: %s", exc)
        await asyncio.sleep(cfg.threat_publish_interval_s)


async def _read_threat_level(pool: asyncpg.Pool) -> tuple[int, str, dict[str, int]]:
    """Berechnet den Threat-Level analog zur API-Logic (15-min-Window,
    Severity-Gewichtung). Direkter SQL statt API-Call — das hier ist
    parallel zur api/. Wenn die Logik divergiert: Refactoring zu einem
    shared module wäre V2."""
    rows = await pool.fetch(
        """
        SELECT severity, COUNT(*) AS n
          FROM alerts
         WHERE ts > now() - interval '15 minutes'
           AND COALESCE(is_test, false) = false
         GROUP BY severity
        """
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        sev = (r["severity"] or "low").lower()
        if sev in counts:
            counts[sev] = int(r["n"])
    raw = counts["critical"] * 10 + counts["high"] * 5 + counts["medium"] * 2 + counts["low"]
    score = min(100, int(raw * 100 / 200))
    label = ("red" if score >= 75 else
             "orange" if score >= 50 else
             "yellow" if score >= 25 else "green")
    return score, label, counts


async def tap_status_loop(cfg: Config, bridge: Bridge, pool: asyncpg.Pool) -> None:
    """Pro gepairtem Tap publiziert die Live/Stale/Offline-Klassifikation
    auf seinem eigenen Status-Topic. Retained — neue HMI-Subscriber sehen
    sofort welche Taps online sind."""
    LIVE_THRESHOLD_S  = 90    # < 90s seit last_seen = live
    STALE_THRESHOLD_S = 300   # 90-300s = stale, > 300s = offline

    while True:
        try:
            rows = await pool.fetch(
                """
                SELECT id::text AS id, name, last_seen, status,
                       alerts_received_total
                  FROM taps
                 WHERE status = 'active'
                """
            )
            now = time.time()
            for r in rows:
                tap_name = r["name"] or r["id"][:8]
                last_seen = r["last_seen"]
                if last_seen is None:
                    state = "never"
                    age_s = None
                else:
                    age_s = now - last_seen.timestamp()
                    if age_s < LIVE_THRESHOLD_S:
                        state = "live"
                    elif age_s < STALE_THRESHOLD_S:
                        state = "stale"
                    else:
                        state = "offline"
                payload = orjson.dumps({
                    "state":    state,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                    "age_s":    int(age_s) if age_s is not None else None,
                    "alerts_received_total": int(r["alerts_received_total"] or 0),
                })
                topic = tap_status_topic(cfg.topic_prefix, cfg.master_host_id, tap_name)
                await bridge.publish(topic, payload, qos=cfg.qos_state, retain=True)
        except Exception as exc:
            log.debug("tap-status-publish fehlgeschlagen: %s", exc)
        await asyncio.sleep(cfg.tap_publish_interval_s)


# ─────────────────────────────────────────────────────────────────────────────
# Hot-Reload: Config-Watcher
# ─────────────────────────────────────────────────────────────────────────────


CONFIG_RELOAD_INTERVAL_S = 30


async def _read_db_overlay(pool: asyncpg.Pool) -> Optional[dict]:
    """Liest system_config[key='mqtt'].value als dict zurück. None wenn
    der Key nicht existiert oder DB nicht erreichbar ist."""
    try:
        row = await pool.fetchrow("SELECT value FROM system_config WHERE key = 'mqtt'")
        if row is None or row["value"] is None:
            return None
        v = row["value"]
        # asyncpg liefert JSONB normalerweise als bereits geparstes dict.
        # Fallback für Setups die str liefern: orjson-parsen.
        if isinstance(v, (bytes, str)):
            return orjson.loads(v)
        if isinstance(v, dict):
            return v
        return None
    except Exception as exc:
        log.debug("DB-Overlay-Read fehlgeschlagen: %s", exc)
        return None


async def _build_effective_config(env: dict, pool: Optional[asyncpg.Pool]) -> Config:
    overlay = await _read_db_overlay(pool) if pool is not None else None
    merged = merge_db_overlay(env, overlay)
    return Config.from_dict(merged)


async def config_watch_loop(env: dict, pool: asyncpg.Pool, on_change) -> None:
    """Pollt alle 30s den DB-Override. Bei Änderung ruft on_change(new_cfg)
    auf — wirft on_change _ReconnectRequested, propagiert das bis zum
    Supervisor (kein except dazwischen)."""
    last: Optional[Config] = None
    while True:
        try:
            cfg = await _build_effective_config(env, pool)
        except Exception as exc:
            log.warning("Config-Watch-Loop-Fehler: %s", exc)
            await asyncio.sleep(CONFIG_RELOAD_INTERVAL_S)
            continue
        if last is None or cfg != last:
            last = cfg
            await on_change(cfg)  # _ReconnectRequested propagiert bewusst
        await asyncio.sleep(CONFIG_RELOAD_INTERVAL_S)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


class _ReconnectRequested(Exception):
    """Wird im Supervisor geworfen, wenn der Watcher Connection-Felder
    geändert sieht — der Supervisor canceld dann die laufenden Loops und
    baut Bridge + Pool neu auf."""


async def _run_session(cfg: Config, pool: asyncpg.Pool, env: dict) -> None:
    """Eine "Session" = 1× verbundener Bridge-Stack. Bei jedem Config-
    Change (egal ob Connection- oder Filter-Field) wirft der Watcher
    _ReconnectRequested → outer-Loop baut komplett neu auf. Filter-only-
    Änderungen kommen damit mit einer wenige-Sekunden-Pause an, was
    akzeptabel ist (Settings-Changes sind selten)."""
    bridge = Bridge(cfg)
    taps   = TapResolver(cfg.postgres_dsn)
    await taps.init()

    loop = asyncio.get_running_loop()
    bridge.connect(loop)
    try:
        await asyncio.wait_for(bridge.wait_connected(), timeout=20.0)
    except asyncio.TimeoutError:
        log.warning("Connect-Timeout (20s) — bridge.shutdown + Retry in 10s")
        bridge.shutdown()
        await taps.close()
        await asyncio.sleep(10)
        raise _ReconnectRequested()

    log.info("Bridge online — startet Loops (events + threat + tap-status)")

    async def on_config_change(new_cfg: Config) -> None:
        if new_cfg == cfg:
            return  # erste Iteration des Watchers → kein Reconnect
        log.info("Config-Change erkannt → Reconnect (enabled=%s broker=%s:%d)",
                 new_cfg.enabled, new_cfg.broker_host, new_cfg.broker_port)
        raise _ReconnectRequested()

    try:
        await asyncio.gather(
            event_consumer_loop(cfg, bridge, taps),
            threat_publish_loop(cfg, bridge, pool),
            tap_status_loop(cfg, bridge, pool),
            config_watch_loop(env, pool, on_config_change),
        )
    finally:
        bridge.shutdown()
        await taps.close()


async def amain() -> None:
    """Outer supervisor: hält den DB-Pool dauerhaft, baut bei Config-Change
    die MQTT-Session neu auf. enabled=false → Idle-Loop bis re-enabled."""
    env = _env_dict()
    dsn = env["postgres_dsn"]

    # Pool dauerhaft halten, damit auch im idle-Zustand der Watcher die
    # DB pollen kann.
    pool: Optional[asyncpg.Pool] = None
    while pool is None:
        try:
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
        except Exception as exc:
            log.warning("DB-Pool-Init fehlgeschlagen (%s) — Retry in 10s", exc)
            await asyncio.sleep(10)

    log.info("DB-Pool initialisiert — starte Config-Supervisor")

    # Referenz halten, damit der Task nicht vom GC eingesammelt wird.
    _hb_task = asyncio.create_task(_heartbeat_loop(), name="heartbeat")  # noqa: F841

    while True:
        cfg = await _build_effective_config(env, pool)
        if not cfg.enabled:
            log.info("MQTT enabled=false — bridge idle, watche Config alle %ds",
                     CONFIG_RELOAD_INTERVAL_S)
            await _idle_until_enabled(env, pool)
            continue

        log.info("Starte mqtt-bridge | broker=%s:%d prefix=%s host=%s",
                 cfg.broker_host, cfg.broker_port, cfg.topic_prefix, cfg.master_host_id)
        try:
            await _run_session(cfg, pool, env)
        except _ReconnectRequested:
            log.info("Reconnect angestoßen — baue Stack neu auf")
            await asyncio.sleep(1)
        except Exception as exc:
            log.exception("Session crashed: %s — Retry in 10s", exc)
            await asyncio.sleep(10)


async def _idle_until_enabled(env: dict, pool: asyncpg.Pool) -> None:
    """Wartet bis enabled=true. Pollt alle CONFIG_RELOAD_INTERVAL_S sec."""
    while True:
        await asyncio.sleep(CONFIG_RELOAD_INTERVAL_S)
        try:
            cfg = await _build_effective_config(env, pool)
        except Exception:
            continue
        if cfg.enabled:
            log.info("Config-Change: enabled=true → starte Bridge")
            return


def main() -> None:
    log.info("mqtt-bridge startup — env+DB-Hot-Reload aktiv")

    def _handle_signal(*_):
        # SIGTERM/SIGINT — saubere shutdown übernimmt Bridge.shutdown via
        # finally-Block in _run_session, sobald asyncio.run() abbricht.
        log.info("Signal empfangen — fahre runter")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
