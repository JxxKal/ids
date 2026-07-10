"""
arpwatch-bridge  (Container ids-arpwatch / cyjan-tap-arpwatch)
==============================================================
Passive Layer-2-Überwachung des Mirror-Ports auf **Duplicate-IP / ARP-Spoof**.

Startet `arpwatch -d` (Vordergrund, keine Mails, Reports auf stderr) auf dem
Mirror-Interface und übersetzt dessen Events nach Kafka → alerts-raw, von wo
sie durch die normale Pipeline (alert-manager → DB → Enrichment → WS) laufen.

Event-Mapping (mit User abgestimmt):
  • flip flop / changed ethernet address  → CRITICAL  (IP von zwei MACs
    beansprucht = Duplicate-IP oder ARP-Spoofing)
  • new station / new activity            → LOW        (neue MAC taucht auf =
    evtl. Rogue-Device; im Warmup-Fenster unterdrückt gegen Cold-Start-Flut)
  • bogon                                 → unterdrückt (arpwatch -N)

Robustheit: arpwatch-Reports können je nach Version als **Einzeiler**
(`flip flop <ip> <mac> (<oldmac>)`) ODER als mehrzeiliger `label: value`-Block
auf stderr kommen. Der Parser versteht beide. Bei mehrzeiligen Blöcken ohne
verlässlichen Titel entscheidet die **Präsenz einer alten MAC** über
CRITICAL (Konflikt) vs. LOW (neu) — unabhängig vom exakten Titel-Format.

Umgebungsvariablen:
  KAFKA_BROKERS          Bootstrap (Standard: localhost:9094 — External Listener,
                         weil der Container network_mode:host läuft)
  ARPWATCH_IFACE         Interface (Standard: $MIRROR_IFACE)
  ARPWATCH_DATA          arp.dat-Pfad (Standard: /var/lib/arpwatch/arp.dat)
  NEW_STATION_WARMUP_S   new-station im Cold-Start unterdrücken (Standard: 120)
  TEST_MODE              true → is_test=true (Standard: false)
  LOG_LEVEL              DEBUG/INFO/WARNING (Standard: INFO)
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid

from confluent_kafka import Producer

# ── Konfiguration ────────────────────────────────────────────────────────────
KAFKA_BROKERS   = os.getenv("KAFKA_BROKERS", "localhost:9094")
ALERTS_TOPIC    = "alerts-raw"
IFACE           = os.getenv("ARPWATCH_IFACE") or os.getenv("MIRROR_IFACE") or ""
ARP_DATA        = os.getenv("ARPWATCH_DATA", "/var/lib/arpwatch/arp.dat")
WARMUP_S        = float(os.getenv("NEW_STATION_WARMUP_S", "120"))
TEST_MODE       = os.getenv("TEST_MODE", "false").lower() == "true"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [arpwatch-bridge] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Severity/Score ───────────────────────────────────────────────────────────
_CONFLICT = ("critical", 0.95, "ARP_DUP_001")
_NEW      = ("low",      0.30, "ARP_NEW_001")

# Einzeiler-Format (syslog-artig): "<titel> <ip> <mac> [(<altmac>)]"
_MAC = r"[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}"
_LINE_RX = re.compile(
    rf"^\s*(?P<title>flip flop|changed ethernet address|new station|new activity|"
    rf"reused old ethernet address|ethernet mismatch|bogon)\s+"
    rf"(?P<ip>\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s+"
    rf"(?P<mac>{_MAC})"
    rf"(?:\s+\((?P<old>{_MAC})\))?",
    re.IGNORECASE,
)
# Mehrzeiler-Block: "<label>: <value>"
_KV_RX = re.compile(
    r"^\s*(?P<label>ip address|ethernet address|old ethernet address)\s*:\s*(?P<val>.+?)\s*$",
    re.IGNORECASE,
)

# Titel, die einen Konflikt (Duplicate-IP) bedeuten:
_CONFLICT_TITLES = {"flip flop", "changed ethernet address", "ethernet mismatch"}
_NEW_TITLES      = {"new station", "new activity"}
_SKIP_TITLES     = {"bogon", "reused old ethernet address"}


def _norm_mac(mac: str | None) -> str | None:
    """0:1:2:a:b:c → 00:01:02:0a:0b:0c (für konsistente Anzeige/Dedup)."""
    if not mac:
        return None
    try:
        return ":".join(f"{int(o, 16):02x}" for o in mac.split(":"))
    except ValueError:
        return mac


class ArpwatchParser:
    """Zerlegt arpwatch-stderr in Events. Versteht Einzeiler UND Blöcke."""

    def __init__(self) -> None:
        self._cur: dict[str, str] = {}

    def feed(self, line: str) -> list[dict]:
        events: list[dict] = []

        m = _LINE_RX.match(line)
        if m:
            events.append(self._classify(
                title=m.group("title").lower(),
                ip=m.group("ip"),
                mac=m.group("mac"),
                old=m.group("old"),
            ))
            return [e for e in events if e]

        kv = _KV_RX.match(line)
        if kv:
            label = kv.group("label").lower()
            val   = kv.group("val").strip()
            if label == "ip address" and "ip" in self._cur:
                # neuer Block ohne Leerzeilen-Trenner — vorherigen flushen
                ev = self._flush_block()
                if ev:
                    events.append(ev)
            key = {"ip address": "ip", "ethernet address": "mac",
                   "old ethernet address": "old"}[label]
            self._cur[key] = val
            return events

        if not line.strip():
            ev = self._flush_block()
            if ev:
                events.append(ev)
        return events

    def _flush_block(self) -> dict | None:
        cur = self._cur
        self._cur = {}
        if "ip" not in cur or "mac" not in cur:
            return None
        # Ohne verlässlichen Titel: alte MAC vorhanden → Konflikt, sonst neu.
        title = "changed ethernet address" if cur.get("old") else "new station"
        return self._classify(title, cur["ip"], cur["mac"], cur.get("old"))

    def _classify(self, title: str, ip: str, mac: str, old: str | None) -> dict | None:
        if title in _SKIP_TITLES:
            return None
        if title in _CONFLICT_TITLES or (old and title not in _NEW_TITLES):
            kind = "conflict"
        else:
            kind = "new"
        return {"kind": kind, "title": title, "ip": ip,
                "mac": _norm_mac(mac), "old": _norm_mac(old)}


def _make_alert(ev: dict) -> dict:
    if ev["kind"] == "conflict":
        severity, score, rule_id = _CONFLICT
        desc = f"Duplicate IP {ev['ip']}: {ev['mac']}"
        if ev["old"]:
            desc += f" (vorher {ev['old']})"
        tags = ["arpwatch", "duplicate-ip", ev["mac"]]
        if ev["old"]:
            tags.append(ev["old"])
    else:
        severity, score, rule_id = _NEW
        desc = f"Neue Station {ev['ip']} @ {ev['mac']}"
        tags = ["arpwatch", "new-station", ev["mac"]]
    return {
        "alert_id":    str(uuid.uuid4()),
        "rule_id":     rule_id,
        "source":      "arpwatch",
        "severity":    severity,
        "score":       score,
        "description": desc,
        "src_ip":      ev["ip"],
        "dst_ip":      None,          # ARP ist L2 — kein Ziel-IP-Kontext
        "dst_port":    None,
        "proto":       "ARP",
        "ts":          time.time(),
        "tags":        tags,
        "is_test":     TEST_MODE,
    }


def _spawn_arpwatch() -> subprocess.Popen:
    # arp.dat muss existieren, sonst startet arpwatch nicht. arpwatch dropt per
    # Default auf User `arpwatch` und muss die Zustandsdatei schreiben können —
    # das per-Volume gemountete (root-owned) Verzeichnis dafür freigeben.
    data_dir = os.path.dirname(ARP_DATA)
    os.makedirs(data_dir, exist_ok=True)
    open(ARP_DATA, "a").close()
    try:
        os.chmod(data_dir, 0o777)
        os.chmod(ARP_DATA, 0o666)
    except OSError as exc:
        log.warning("chmod auf %s fehlgeschlagen: %s", data_dir, exc)
    cmd = ["arpwatch", "-d", "-N", "-i", IFACE, "-f", ARP_DATA]
    log.info("Starte: %s", " ".join(cmd))
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def main() -> None:
    if not IFACE:
        log.error("Kein Interface — ARPWATCH_IFACE/MIRROR_IFACE nicht gesetzt. Ende.")
        sys.exit(1)

    producer = Producer({
        "bootstrap.servers": KAFKA_BROKERS,
        "linger.ms": 20,
        "compression.type": "lz4",
    })
    parser = ArpwatchParser()
    started = time.monotonic()
    log.info("arpwatch-Bridge gestartet  →  %s @ %s  (iface=%s, warmup=%.0fs)",
             ALERTS_TOPIC, KAFKA_BROKERS, IFACE, WARMUP_S)

    proc = _spawn_arpwatch()
    assert proc.stderr is not None

    def _beat() -> None:
        try:
            open("/tmp/heartbeat", "w").close()
        except OSError:
            pass

    # Heartbeat NICHT an Events koppeln: ein ruhiges Segment liefert minutenlang
    # keine arpwatch-Zeile — der 120s-Healthcheck würde sonst fälschlich
    # unhealthy melden. Solange der arpwatch-Prozess lebt, beaten wir alle 30s.
    # Stirbt arpwatch, endet die stderr-Schleife → finally → Container-Neustart.
    def _heartbeat_loop() -> None:
        while proc.poll() is None:
            _beat()
            time.sleep(30)
    _beat()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    try:
        for line in proc.stderr:
            line = line.rstrip("\n")
            log.debug("arpwatch: %s", line)
            for ev in parser.feed(line):
                # Cold-Start: new-station im Warmup-Fenster unterdrücken.
                if ev["kind"] == "new" and (time.monotonic() - started) < WARMUP_S:
                    log.debug("new-station im Warmup unterdrückt: %s", ev["ip"])
                    continue
                alert = _make_alert(ev)
                producer.produce(ALERTS_TOPIC, json.dumps(alert, default=str).encode())
                producer.poll(0)
                log.info("Alert %s  %s  %s  [%s]",
                         alert["rule_id"], alert["src_ip"],
                         alert["description"], alert["severity"])
    finally:
        producer.flush(5)
        rc = proc.poll()
        log.error("arpwatch-Prozess beendet (rc=%s) — Container-Neustart folgt", rc)
        proc.terminate()
        sys.exit(1)


if __name__ == "__main__":
    main()
