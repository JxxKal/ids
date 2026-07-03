"""Tap-seitige Host-Profil-Aggregation für die Rollenerkennung am Master.

Der Master-Detektor klassifiziert Hosts aus der `flows`-Tabelle des Masters —
Hosts, die NUR ein Remote-Tap sieht, fehlen dort. Dieser Aggregator konsumiert
den lokalen `flows`-Kafka-Stream, hält pro Host ein verdichtetes Port-Profil
(servierte Ports + Flow-Count, Mode-MAC, first_seen) und liefert periodisch
Snapshots, die main.py als `host_profile`-Frames über den Uplink an den Master
schickt. Bewusst KEIN Forwarding roher Flows (Volumen) — nur das Aggregat.

Servierte Ports = Host als Responder (dst_ip) mit connection_state in
ESTABLISHED|CLOSED — identisch zur Master-Detektor-Aggregation, damit Tap- und
Master-Profile dasselbe bedeuten.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import orjson
from confluent_kafka import Consumer, KafkaError

log = logging.getLogger("tap-uplink.host_profiler")

FLOWS_TOPIC          = os.environ.get("FLOWS_TOPIC", "flows")
HOST_PROFILE_ENABLED = os.environ.get("HOST_PROFILE_ENABLED", "true").lower() != "false"
PROFILE_INTERVAL_S   = float(os.environ.get("HOST_PROFILE_INTERVAL_S", "1800"))
PROFILE_WINDOW_S     = float(os.environ.get("HOST_PROFILE_WINDOW_S", str(7 * 86400)))
PROFILE_MIN_FLOWS    = int(os.environ.get("HOST_PROFILE_MIN_FLOWS", "1"))
# Speicher-Deckel: bei Überschreitung werden keine NEUEN Hosts mehr
# aufgenommen (bestehende laufen weiter). Schützt vor Runaway auf großen Netzen.
MAX_HOSTS            = int(os.environ.get("HOST_PROFILE_MAX_HOSTS", "5000"))

_SERVED_STATES = {"ESTABLISHED", "CLOSED"}


def _looks_like_mac(mac) -> bool:
    return isinstance(mac, str) and mac.count(":") == 5 and len(mac) >= 11


@dataclass
class _HostAgg:
    # (port, proto) -> [count, last_ts]
    ports:      dict = field(default_factory=dict)
    macs:       dict = field(default_factory=dict)   # mac -> count
    first_seen: float = 0.0
    last_seen:  float = 0.0


class HostProfiler:
    """Thread-safer Aggregator. consume_loop() läuft im Kafka-Thread,
    snapshot() greift den aktuellen Stand für den Emit-Thread."""

    def __init__(self, brokers: str, group_id: str) -> None:
        self._brokers = brokers
        self._group = f"{group_id}-hostprofile"
        self._lock = threading.Lock()
        self._hosts: dict[str, _HostAgg] = {}

    # ── Kafka-Consumer-Thread ─────────────────────────────────────────────
    def consume_loop(self, beat, stop: threading.Event) -> None:
        consumer = Consumer({
            "bootstrap.servers": self._brokers,
            "group.id": self._group,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        })
        try:
            consumer.subscribe([FLOWS_TOPIC])
        except Exception as exc:
            log.warning("flows-Subscribe fehlgeschlagen: %s — Host-Profiling aus", exc)
            consumer.close()
            return
        log.info("Host-Profiler subscribed: %s @ %s (interval=%.0fs window=%.0fs)",
                 FLOWS_TOPIC, self._brokers, PROFILE_INTERVAL_S, PROFILE_WINDOW_S)
        try:
            while not stop.is_set():
                if beat:
                    beat()
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.debug("flows Kafka error: %s", msg.error())
                    continue
                val = msg.value()
                if not val:
                    continue
                try:
                    self._ingest(orjson.loads(val))
                except Exception as exc:
                    log.debug("flow-Record verworfen: %s", exc)
        finally:
            consumer.close()
            log.info("Host-Profiler-Consumer beendet")

    def _ingest(self, flow: dict) -> None:
        now = time.time()
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        # MAC-Tracking für beide Seiten (Client=src_mac, Server=dst_mac, vgl.
        # flow-aggregator-Konvention). Mode-MAC pro Host über beide Rollen.
        src_mac = flow.get("src_mac")
        dst_mac = flow.get("dst_mac")
        with self._lock:
            # Servierter Port ZUERST: nur ein Responder (dst_ip) mit BEANTWORTETER
            # Verbindung (ESTABLISHED|CLOSED UND pkt_count_rev>0) legt einen Host-
            # Slot an. Ohne den pkt_count_rev-Check würde eine unbeantwortete
            # UDP/ICMP-Probe (flow.py setzt UDP/ICMP nach 1 Paket auf ESTABLISHED)
            # als 'serviert' zählen — ein einzelnes nmap -sU verpasst dem Ziel
            # sonst eine Rolle.
            state = flow.get("connection_state")
            dst_port = flow.get("dst_port")
            answered = int(flow.get("pkt_count_rev") or 0) > 0
            if dst_ip and dst_port and state in _SERVED_STATES and answered:
                proto = str(flow.get("proto") or "")
                agg = self._get(dst_ip, now)
                if agg is not None:
                    key = (int(dst_port), proto)
                    slot = agg.ports.get(key)
                    if slot is None:
                        agg.ports[key] = [1, now]
                    else:
                        slot[0] += 1
                        slot[1] = now
                    agg.last_seen = now
            # MAC-Tracking NUR für Hosts, die bereits einen Slot haben (d.h.
            # mindestens einen Port servieren). Sonst fressen reine Client-/
            # Remote-IPs (Internet-Mirror) die MAX_HOSTS-Slots mit Nur-MAC-
            # Einträgen und der echte interne Server wird nie profiliert.
            if _looks_like_mac(src_mac) and src_ip:
                self._touch_mac(src_ip, src_mac, now)
            if _looks_like_mac(dst_mac) and dst_ip:
                self._touch_mac(dst_ip, dst_mac, now)

    def _get(self, ip: str, now: float) -> _HostAgg | None:
        agg = self._hosts.get(ip)
        if agg is None:
            if len(self._hosts) >= MAX_HOSTS:
                return None
            agg = _HostAgg(first_seen=now, last_seen=now)
            self._hosts[ip] = agg
        return agg

    def _touch_mac(self, ip: str, mac: str, now: float) -> None:
        """MAC-Zähler eines Hosts fortschreiben — legt KEINEN neuen Host an
        (nur bereits servierende Hosts tragen einen Slot). Reine Client-IPs
        ohne servierten Port bleiben damit außen vor."""
        agg = self._hosts.get(ip)
        if agg is None:
            return
        agg.macs[mac] = agg.macs.get(mac, 0) + 1
        agg.last_seen = now

    # ── Snapshot für den Emit-Thread ──────────────────────────────────────
    def snapshot(self) -> list[dict]:
        """Liefert pro aktivem Responder-Host ein Profil-Payload. Veraltete
        Ports/Hosts (außerhalb des Fensters) werden dabei gepruned."""
        now = time.time()
        cutoff = now - PROFILE_WINDOW_S
        out: list[dict] = []
        with self._lock:
            for ip in list(self._hosts.keys()):
                agg = self._hosts[ip]
                if agg.last_seen < cutoff:
                    del self._hosts[ip]
                    continue
                # veraltete Ports prunen
                for key in [k for k, (_, last) in agg.ports.items() if last < cutoff]:
                    del agg.ports[key]
                served = [
                    {"port": p, "proto": proto, "count": cnt}
                    for (p, proto), (cnt, _) in agg.ports.items()
                    if cnt >= PROFILE_MIN_FLOWS
                ]
                if not served:
                    continue
                mode_mac = max(agg.macs, key=agg.macs.get) if agg.macs else None
                out.append({
                    "host_ip": ip,
                    "ports": served,
                    "mac": mode_mac,
                    "first_seen": datetime.fromtimestamp(agg.first_seen, timezone.utc)
                                  .isoformat().replace("+00:00", "Z"),
                    "observed_until": datetime.fromtimestamp(now, timezone.utc)
                                  .isoformat().replace("+00:00", "Z"),
                })
        return out


def emit_loop(profiler: "HostProfiler", diskq, beat, stop: threading.Event) -> None:
    """Pusht alle PROFILE_INTERVAL_S die aktuellen Host-Profile als
    host_profile-Frames in die DiskQueue (geht über den normalen _send_loop
    an den Master; Outage-Buffer greift wie bei Alerts/Metriken)."""
    # Erstes Intervall abwarten, damit das Reservoir nicht leer rausgeht.
    waited = 0.0
    while not stop.is_set():
        step = min(5.0, PROFILE_INTERVAL_S - waited) if waited < PROFILE_INTERVAL_S else 0.0
        if step > 0:
            stop.wait(step)
            waited += step
            if beat:
                beat()
            continue
        waited = 0.0
        try:
            frames = profiler.snapshot()
            for payload in frames:
                diskq.push(orjson.dumps({"type": "host_profile", "payload": payload}))
            if frames:
                log.info("Host-Profile gesendet: %d Hosts", len(frames))
        except Exception as exc:
            log.warning("Host-Profil-Emit fehlgeschlagen: %s", exc)
    log.info("Host-Profiler-Emit beendet")
