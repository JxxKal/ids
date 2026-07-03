"""
Stateful Rule Context – Sliding-Window-Tracking für zeitbasierte Regeln.

Alle Sliding Windows basieren auf Flow-End-Timestamps.
Single-threaded: kein Locking nötig.

Verfügbare Funktionen in Regel-Bedingungen:
  ctx.unique_dst_ports(src_ip, window_s)  → int
  ctx.unique_dst_ips(src_ip, window_s)    → int
  ctx.flow_rate(src_ip, window_s)         → int
  ctx.syn_count(src_ip, window_s)         → int
"""
from __future__ import annotations

import time
from collections import defaultdict, deque


class RuleContext:
    # Maximales Zeitfenster das irgendeine Regel nutzen kann (für Cleanup-Cutoff)
    MAX_WINDOW_S = 300

    def __init__(self) -> None:
        # {src_ip: deque[(ts, dst_port)]}
        self._dst_ports: defaultdict[str, deque] = defaultdict(deque)
        # {src_ip: deque[(ts, dst_ip)]}
        self._dst_ips: defaultdict[str, deque]   = defaultdict(deque)
        # {src_ip: deque[ts]}
        self._flow_ts:  defaultdict[str, deque]  = defaultdict(deque)
        # {src_ip: deque[(ts, syn_count)]}
        self._syn:      defaultdict[str, deque]  = defaultdict(deque)

        self._last_cleanup = time.monotonic()

    def record(self, flow: dict) -> None:
        """
        Muss für jeden Flow VOR der Regel-Auswertung aufgerufen werden.
        Registriert den Flow in allen relevanten Sliding Windows.
        """
        ts       = float(flow.get("end_ts") or time.time())
        src_ip   = flow.get("src_ip", "")
        dst_port = flow.get("dst_port")
        dst_ip   = flow.get("dst_ip", "")
        syn_abs  = flow.get("tcp_flags_abs", {}).get("SYN", 0)

        if dst_port is not None:
            self._dst_ports[src_ip].append((ts, int(dst_port)))

        self._dst_ips[src_ip].append((ts, dst_ip))
        self._flow_ts[src_ip].append(ts)

        if syn_abs > 0:
            self._syn[src_ip].append((ts, int(syn_abs)))

        # Gelegentlicher Cleanup um Memory-Wachstum zu begrenzen
        now_mono = time.monotonic()
        if now_mono - self._last_cleanup > 60:
            self._cleanup()
            self._last_cleanup = now_mono

    # ── Abfrage-Funktionen (für Regelausdrücke) ───────────────────────────────

    def unique_dst_ports(self, src_ip: str, window_s: float) -> int:
        """Anzahl eindeutiger Ziel-Ports in den letzten window_s Sekunden."""
        entries = self._prune_tuple(self._dst_ports[src_ip], window_s)
        return len({port for _, port in entries})

    def unique_dst_ips(self, src_ip: str, window_s: float) -> int:
        """Anzahl eindeutiger Ziel-IPs in den letzten window_s Sekunden."""
        entries = self._prune_tuple(self._dst_ips[src_ip], window_s)
        return len({ip for _, ip in entries})

    def flow_rate(self, src_ip: str, window_s: float) -> int:
        """Anzahl Flows in den letzten window_s Sekunden."""
        dq = self._flow_ts[src_ip]
        cutoff = time.time() - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def syn_count(self, src_ip: str, window_s: float) -> int:
        """Summe aller SYN-Pakete in den letzten window_s Sekunden."""
        entries = self._prune_tuple(self._syn[src_ip], window_s)
        return sum(c for _, c in entries)

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────────

    @staticmethod
    def _prune_tuple(dq: deque, window_s: float) -> deque:
        """Entfernt Einträge die älter als window_s sind. Gibt bereinigtes Deque zurück."""
        cutoff = time.time() - window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return dq

    def _cleanup(self) -> None:
        """Entfernt alle Einträge die älter als MAX_WINDOW_S sind UND löscht
        anschließend leer gewordene per-src_ip-Keys aus den defaultdicts.

        Ohne das Key-Pruning wüchsen die Dicts bei vielen distinct Source-IPs
        (Internet-Uplink, gespoofte Scans) monoton bis zum OOM — die Query-
        Methoden vivifizieren über defaultdict-Zugriff sogar für reine
        Lookups leere Deques. Die Sliding-Window-Semantik bleibt unberührt:
        es werden nur Einträge älter als MAX_WINDOW_S entfernt (identisch zu
        vorher), zusätzlich verschwinden nur wirklich leere Keys."""
        cutoff = time.time() - self.MAX_WINDOW_S
        for storage in (self._dst_ports, self._dst_ips, self._syn):
            empty_keys = []
            for src_ip, dq in storage.items():
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    empty_keys.append(src_ip)
            for k in empty_keys:
                del storage[k]
        empty_keys = []
        for src_ip, dq in self._flow_ts.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                empty_keys.append(src_ip)
        for k in empty_keys:
            del self._flow_ts[k]
