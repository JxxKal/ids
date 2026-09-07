"""
Drossel für Suricata-Alerts, BEVOR sie nach Kafka gehen.

Hintergrund (OT-Vorfall 2026-09-04): eine einzige Stream-Engine-Regel
(SID 2210029 "STREAM ESTABLISHED invalid ack") feuerte auf jedes Paket einer
einseitig gespiegelten RDP-Session — 10.000 Alerts pro Sekunde, 88 GB in
alerts-raw, Platte voll, Kafka tot, Pipeline drei Tage blind. alert-manager
hat das per Dedup vollständig geschluckt, im Frontend war nichts zu sehen.
Die Flut muss deshalb VOR Kafka enden, nicht dahinter.

Drei Stufen, alle per ENV steuerbar:

  1. Engine-Events (SNORT_DROP_ENGINE_EVENTS, Default true)
     Suricatas eigene Decoder-/Stream-/App-Layer-Events (gid 1, SID
     2200000–2299999) feuern pro Paket bzw. Transaktion und beschreiben
     Parser-Zustände, keine Angriffe. Suricata liefert sie als Debug-
     Signaturen aus; in Produktion gehören sie abgeschaltet.

  2. Cooldown pro (SID, src, dst) (SNORT_BRIDGE_COOLDOWN_S, Default 60)
     Der erste Treffer geht durch, Wiederholungen derselben Regel auf
     derselben Verbindung werden bis zum Ablauf des Fensters verworfen.
     Entspricht dem `cooldown_s` der eigenen Heuristik-Rules — alert-manager
     würde sie ohnehin deduplizieren, nur eben erst hinter Kafka.

  3. Globale Rate (SNORT_BRIDGE_MAX_RATE, Default 50/s)
     Token-Bucket als letzte Bremse gegen alles, was Stufe 1 und 2 nicht
     fassen (z.B. ein Scanner, der pro Ziel eine neue Verbindung öffnet).
     50/s sind 4,3 Mio. Alerts am Tag — weit jenseits dessen, was ein
     Mensch triagiert, aber weit unter dem, was Kafka gefährdet.

Verworfene Alerts werden gezählt und einmal pro Minute als eine Log-Zeile
mit den Top-SIDs gemeldet — so bleibt die Flut sichtbar, ohne dass das Log
selbst zur Flut wird.
"""
from __future__ import annotations

import logging
import time
from collections import Counter

log = logging.getLogger(__name__)

# Suricata-interne Signaturen: decoder-events (2200xxx), stream-events
# (2210xxx), app-layer-events (222xxxx–229xxxx). Alle gid 1.
ENGINE_SID_MIN = 2_200_000
ENGINE_SID_MAX = 2_299_999

REPORT_INTERVAL_S = 60.0
# Cooldown-Map nicht unbegrenzt wachsen lassen: bei mehr Einträgen werden
# abgelaufene Schlüssel weggeräumt. Ein Scan über /16 erzeugt 65k Keys —
# das passt, aber ein Dauer-Scanner darf den RAM nicht auffressen.
_PURGE_AT = 200_000


def is_engine_event(gid: int, sid: int) -> bool:
    return gid == 1 and ENGINE_SID_MIN <= sid <= ENGINE_SID_MAX


class AlertThrottle:
    """Entscheidet pro Alert, ob er nach Kafka darf. Nicht threadsafe —
    snort-bridge hat genau einen Verarbeitungsthread."""

    def __init__(
        self,
        cooldown_s: float = 60.0,
        max_rate: float = 50.0,
        drop_engine_events: bool = True,
        now: callable = time.monotonic,
    ) -> None:
        self.cooldown_s = max(0.0, float(cooldown_s))
        self.max_rate = max(0.0, float(max_rate))
        self.drop_engine_events = bool(drop_engine_events)
        self._now = now

        self._last_seen: dict[tuple[int, str, str], float] = {}
        # Token-Bucket: Kapazität = max_rate (1 s Burst), Refill = max_rate/s.
        self._tokens = self.max_rate
        self._refill_ts = now()

        self._dropped: Counter[str] = Counter()      # Grund → Anzahl
        self._dropped_sid: Counter[int] = Counter()  # SID → Anzahl
        self._passed = 0
        self._last_report = now()

    # ── Entscheidung ────────────────────────────────────────────────────────

    def allow(self, gid: int, sid: int, src_ip: str | None, dst_ip: str | None) -> bool:
        now = self._now()

        if self.drop_engine_events and is_engine_event(gid, sid):
            self._drop("engine-event", sid)
            return False

        if self.cooldown_s > 0:
            key = (sid, src_ip or "", dst_ip or "")
            last = self._last_seen.get(key)
            if last is not None and now - last < self.cooldown_s:
                self._drop("cooldown", sid)
                return False
            if len(self._last_seen) >= _PURGE_AT:
                self._purge(now)
            self._last_seen[key] = now

        if self.max_rate > 0:
            elapsed = now - self._refill_ts
            self._refill_ts = now
            self._tokens = min(self.max_rate, self._tokens + elapsed * self.max_rate)
            if self._tokens < 1.0:
                self._drop("rate-limit", sid)
                return False
            self._tokens -= 1.0

        self._passed += 1
        return True

    # ── Reporting ───────────────────────────────────────────────────────────

    def maybe_report(self) -> None:
        """Einmal pro Minute eine Zusammenfassung loggen, wenn etwas verworfen
        wurde. Von der Hauptschleife nach jedem Event aufgerufen — billig."""
        now = self._now()
        if now - self._last_report < REPORT_INTERVAL_S:
            return
        self._last_report = now
        total = sum(self._dropped.values())
        if not total:
            self._passed = 0
            return
        reasons = ", ".join(f"{r}={n}" for r, n in self._dropped.most_common())
        top = ", ".join(f"sid {s}×{n}" for s, n in self._dropped_sid.most_common(3))
        log.warning(
            "Drossel: %d Alerts verworfen in %.0fs (%s) | durchgelassen=%d | Top: %s",
            total, REPORT_INTERVAL_S, reasons, self._passed, top,
        )
        self._dropped.clear()
        self._dropped_sid.clear()
        self._passed = 0

    # ── intern ──────────────────────────────────────────────────────────────

    def _drop(self, reason: str, sid: int) -> None:
        self._dropped[reason] += 1
        self._dropped_sid[sid] += 1

    def _purge(self, now: float) -> None:
        cutoff = now - self.cooldown_s
        self._last_seen = {k: t for k, t in self._last_seen.items() if t >= cutoff}
