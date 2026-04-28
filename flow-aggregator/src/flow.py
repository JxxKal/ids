"""
Flow-Aggregations-Engine.

Kernkonzepte:
- WelfordStats: Inkrementelle Berechnung von Mean/Std ohne alle Werte zu speichern
- IatHistogram: Logarithmisches Histogramm für Shannon-Entropie der Inter-Arrival-Times
- FlowState: Zustand eines aktiven Flows im Arbeitsspeicher
- FlowAggregator: Dict aller aktiven Flows + Timeout-Management
"""
from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from models import FlowRecord, PacketEvent

# Flow-Key: kanonisierter 5-Tupel-Schlüssel.
# Beide Richtungen einer Konversation hashen auf den gleichen Schlüssel:
# Endpunkte (ip,port) werden lexikographisch sortiert vor dem Tupel-Build.
# Damit kommt es pro Client-Server-Paar nur zu EINEM FlowState statt zwei.
type FlowKey = tuple[str, str, str, Optional[int], Optional[int]]


def _canonical_key(proto: str, src_ip: str, src_port: Optional[int],
                   dst_ip: str, dst_port: Optional[int]) -> FlowKey:
    """Sortiert die Endpunkte so, dass A→B und B→A denselben Key liefern."""
    a = (src_ip, src_port if src_port is not None else -1)
    b = (dst_ip, dst_port if dst_port is not None else -1)
    if a > b:
        a, b = b, a
    return (proto, a[0], b[0],
            a[1] if a[1] >= 0 else None,
            b[1] if b[1] >= 0 else None)

# ── Online-Statistiken (Welford-Algorithmus) ──────────────────────────────────

class WelfordStats:
    """
    Berechnet Mean und Standardabweichung inkrementell (O(1) pro Update, O(1) Speicher).
    Kein Speichern aller Werte nötig.
    """
    __slots__ = ("n", "mean", "_m2", "min_val", "max_val")

    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self._m2: float = 0.0
        self.min_val: float = float("inf")
        self.max_val: float = float("-inf")

    def update(self, v: float) -> None:
        self.n += 1
        delta = v - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (v - self.mean)
        if v < self.min_val:
            self.min_val = v
        if v > self.max_val:
            self.max_val = v

    @property
    def std(self) -> float:
        return math.sqrt(self._m2 / self.n) if self.n > 1 else 0.0

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 6),
            "std":  round(self.std, 6),
            "min":  self.min_val if self.n > 0 else 0.0,
            "max":  self.max_val if self.n > 0 else 0.0,
        }


# ── IAT-Histogramm für Shannon-Entropie ──────────────────────────────────────

# Logarithmische Bucket-Grenzen in Sekunden:
# [<1ms, 1-10ms, 10-100ms, 100ms-1s, 1-10s, 10-100s, >100s]
_IAT_EDGES = (0.001, 0.01, 0.1, 1.0, 10.0, 100.0)
_IAT_BUCKET_COUNT = len(_IAT_EDGES) + 1


def _iat_bucket(iat: float) -> int:
    for i, edge in enumerate(_IAT_EDGES):
        if iat < edge:
            return i
    return _IAT_BUCKET_COUNT - 1


def _shannon_entropy(hist: list[int]) -> float:
    total = sum(hist)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in hist:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ── Flow-Zustandsautomat ──────────────────────────────────────────────────────

# Mögliche Verbindungszustände
class ConnState:
    NEW         = "NEW"           # Erstes Paket gesehen
    SYN_ONLY    = "SYN_ONLY"      # TCP SYN ohne SYN-ACK (half-open)
    ESTABLISHED = "ESTABLISHED"   # TCP SYN+ACK oder UDP/ICMP aktiv
    FIN_WAIT    = "FIN_WAIT"      # TCP FIN gesehen
    RESET       = "RESET"         # TCP RST – sofort schließen
    CLOSED      = "CLOSED"        # TCP FIN+ACK vollständig


@dataclass
class FlowState:
    # Identität (Client/Server-Sichtweise; gesetzt beim ersten Paket).
    # src_ip/src_port = Client-Side, dst_ip/dst_port = Server-Side. Damit
    # entspricht das emittierte Tupel der konventionellen Verbindungs-Richtung,
    # auch wenn das physische erste Paket vom Server kam (mid-stream-Capture).
    flow_id: str           = field(default_factory=lambda: str(uuid.uuid4()))
    src_ip: str            = ""    # Client (Initiator)
    dst_ip: str            = ""    # Server (Responder)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: str             = "OTHER"
    ip_version: int        = 4
    direction_decided: bool = False   # erste Heuristik schon angewandt?

    # Zeitstempel
    start_ts: float        = 0.0
    last_seen: float       = 0.0
    last_pkt_ts: float     = 0.0

    # Volumen (kombiniert beide Richtungen)
    pkt_count: int         = 0
    byte_count: int        = 0
    pkt_size: WelfordStats = field(default_factory=WelfordStats)
    # Zusätzlich pro Richtung – nützlich für ML-Features (Up/Down-Ratio).
    pkt_count_fwd: int     = 0   # Client → Server
    byte_count_fwd: int    = 0
    pkt_count_rev: int     = 0   # Server → Client
    byte_count_rev: int    = 0

    # Timing / IAT
    iat: WelfordStats      = field(default_factory=WelfordStats)
    iat_hist: list[int]    = field(default_factory=lambda: [0] * _IAT_BUCKET_COUNT)

    # TCP-Flag-Zähler (absolut, aufsummiert über beide Richtungen)
    tcp_flags: dict[str, int] = field(default_factory=lambda: {
        "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0,
        "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
    })

    # Verbindungszustand
    conn_state: str        = ConnState.NEW
    should_flush: bool     = False   # True = sofort flushen (RST/FIN-Closed)

    def _decide_direction(self, pkt: PacketEvent) -> None:
        """Entscheidet beim ersten Paket wer Client und wer Server ist.

        Heuristik (in dieser Reihenfolge):
          1. TCP SYN-only      → src ist Client (klassischer 3WHS-Init)
          2. TCP SYN+ACK       → src ist Server (mid-capture, sehen Antwort)
          3. Port-Heuristik    → niedriger Port = Server, hoher Port = Client
          4. Fallback          → src bleibt Client (best guess)

        Wichtig für NAT-Setups: ohne diese Heuristik landeten Server-Antwort-
        Pakete in einem eigenen Flow mit "vertauschter" src/dst. Bidirektionale
        Aggregation + Initiator-Heuristik liefert pro Konversation EINEN Flow
        mit konventioneller Client→Server-Richtung.
        """
        sip   = pkt.ip.src
        dip   = pkt.ip.dst
        sport = pkt.transport.src_port if pkt.transport else None
        dport = pkt.transport.dst_port if pkt.transport else None

        client_first = True   # Default: src ist Client

        if pkt.transport and pkt.transport.tcp:
            flags = set(pkt.transport.tcp.flags)
            if "SYN" in flags and "ACK" not in flags:
                client_first = True              # echter SYN → src=Client
            elif "SYN" in flags and "ACK" in flags:
                client_first = False             # SYN-ACK → src=Server
            else:
                # Mid-stream ohne SYN: Port-Heuristik
                if sport is not None and dport is not None and sport < dport:
                    client_first = False         # niedrigerer Port = Server
        else:
            # UDP/ICMP: Port-Heuristik
            if sport is not None and dport is not None and sport < dport:
                client_first = False

        if client_first:
            self.src_ip, self.src_port = sip, sport
            self.dst_ip, self.dst_port = dip, dport
        else:
            self.src_ip, self.src_port = dip, dport
            self.dst_ip, self.dst_port = sip, sport
        self.direction_decided = True

    def add_packet(self, pkt: PacketEvent) -> None:
        now = pkt.ts

        if not self.direction_decided:
            self._decide_direction(pkt)

        if self.pkt_count == 0:
            self.start_ts = now

        # IAT: Zeitdifferenz zum vorherigen Paket
        if self.last_pkt_ts > 0.0:
            iat_val = max(0.0, now - self.last_pkt_ts)
            self.iat.update(iat_val)
            self.iat_hist[_iat_bucket(iat_val)] += 1

        self.last_pkt_ts = now
        self.last_seen   = now
        self.pkt_count  += 1
        self.byte_count += pkt.pkt_len
        self.pkt_size.update(float(pkt.pkt_len))

        # Per-Direction-Zähler (forward = Client→Server)
        pkt_src_port = pkt.transport.src_port if pkt.transport else None
        is_forward   = (pkt.ip.src == self.src_ip and pkt_src_port == self.src_port)
        if is_forward:
            self.pkt_count_fwd  += 1
            self.byte_count_fwd += pkt.pkt_len
        else:
            self.pkt_count_rev  += 1
            self.byte_count_rev += pkt.pkt_len

        # TCP: Flags zählen und Zustandsautomat
        if pkt.transport and pkt.transport.tcp:
            for flag in pkt.transport.tcp.flags:
                if flag in self.tcp_flags:
                    self.tcp_flags[flag] += 1

            flags = set(pkt.transport.tcp.flags)

            if "RST" in flags:
                self.conn_state = ConnState.RESET
                self.should_flush = True

            elif "FIN" in flags:
                if self.conn_state == ConnState.ESTABLISHED:
                    self.conn_state = ConnState.FIN_WAIT
                elif self.conn_state == ConnState.FIN_WAIT:
                    # Beide Seiten haben FIN gesendet
                    self.conn_state = ConnState.CLOSED
                    self.should_flush = True

            elif "SYN" in flags and "ACK" in flags:
                self.conn_state = ConnState.ESTABLISHED

            elif "SYN" in flags and self.conn_state == ConnState.NEW:
                self.conn_state = ConnState.SYN_ONLY

            elif "ACK" in flags and self.conn_state == ConnState.SYN_ONLY:
                self.conn_state = ConnState.ESTABLISHED

        elif pkt.transport and self.pkt_count >= 1:
            # UDP / ICMP: nach erstem Paket als established behandeln
            self.conn_state = ConnState.ESTABLISHED

    def to_record(self) -> FlowRecord:
        duration_s = max(self.last_seen - self.start_ts, 0.001)
        total       = max(self.pkt_count, 1)

        # TCP-Flag-Verhältnisse (0.0–1.0)
        tcp_flags_pct = {k: round(v / total, 4) for k, v in self.tcp_flags.items()}

        # Half-open: SYN gesehen, kein einziges ACK
        half_open = (
            self.proto == "TCP"
            and self.tcp_flags["SYN"] > 0
            and self.tcp_flags["ACK"] == 0
        )

        stats = {
            "duration_s":       round(duration_s, 4),
            "pps":              round(self.pkt_count / duration_s, 2),
            "bps":              round(self.byte_count / duration_s, 2),
            "pkt_size":         self.pkt_size.to_dict(),
            "iat":              self.iat.to_dict() if self.iat.n > 0
                                else {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0},
            "entropy_iat":      _shannon_entropy(self.iat_hist),
            "tcp_flags":        tcp_flags_pct,
            "tcp_flags_abs":    dict(self.tcp_flags),
            "connection_state": self.conn_state,
            "half_open":        half_open,
            # Per-Direction-Bilanz: Client→Server (fwd) vs Server→Client (rev).
            # Hilfreich für ML-Features (Upload/Download-Ratio) und für die
            # AlertFeed-Anzeige (PCAP-Vorschau zeigt beide Richtungen, aber der
            # Flow-Record meldet nur EINEN konventionellen src/dst – Client/
            # Server – ab diesem Commit).
            "pkt_count_fwd":    self.pkt_count_fwd,
            "pkt_count_rev":    self.pkt_count_rev,
            "byte_count_fwd":   self.byte_count_fwd,
            "byte_count_rev":   self.byte_count_rev,
        }

        return FlowRecord(
            flow_id=self.flow_id,
            start_ts=self.start_ts,
            end_ts=self.last_seen,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            proto=self.proto,
            ip_version=self.ip_version,
            pkt_count=self.pkt_count,
            byte_count=self.byte_count,
            stats=stats,
        )


# ── Flow-Aggregator ───────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Verwaltet alle aktiven Flows im Arbeitsspeicher.

    - add_packet(): Paket dem richtigen Flow zuordnen
    - flush_expired(): Abgelaufene Flows herausgeben (periodisch aufrufen)
    - flush_all(): Alle Flows herausgeben (beim Shutdown)
    """

    def __init__(self, timeout_s: int, max_duration_s: int) -> None:
        self.timeout_s = timeout_s
        self.max_duration_s = max_duration_s
        self._flows: dict[FlowKey, FlowState] = {}

    @staticmethod
    def _key(pkt: PacketEvent) -> Optional[FlowKey]:
        """Gibt einen kanonisierten Schlüssel zurück. None für Nicht-IP-Pakete.

        Beide Richtungen einer TCP/UDP/ICMP-Konversation hashen auf den
        gleichen Schlüssel (ip+port-Endpunkte sortiert) – damit landet jede
        Konversation in EINEM FlowState statt in zweien.
        """
        if not pkt.ip:
            return None
        proto     = pkt.transport.proto if pkt.transport else "OTHER"
        src_port  = pkt.transport.src_port if pkt.transport else None
        dst_port  = pkt.transport.dst_port if pkt.transport else None
        return _canonical_key(proto, pkt.ip.src, src_port, pkt.ip.dst, dst_port)

    def add_packet(self, pkt: PacketEvent) -> list[FlowRecord]:
        """
        Fügt ein Paket dem passenden Flow hinzu.
        Gibt sofort zu flushende Records zurück (TCP RST/Closed).
        """
        key = self._key(pkt)
        if key is None:
            return []

        if key not in self._flows:
            assert pkt.ip is not None  # guaranteed by _key check
            # FlowState.src_ip/dst_ip werden NICHT vom ersten Paket übernommen,
            # sondern in _decide_direction() beim ersten add_packet() anhand
            # der Initiator-Heuristik gesetzt (TCP-SYN-Erkennung + Port-
            # Heuristik). Damit ist src=Client, dst=Server pro Konversation –
            # konsistent über beide Richtungen.
            self._flows[key] = FlowState(
                proto=pkt.transport.proto if pkt.transport else "OTHER",
                ip_version=pkt.ip.version,
            )

        flow = self._flows[key]
        flow.add_packet(pkt)

        if flow.should_flush:
            del self._flows[key]
            return [flow.to_record()]

        return []

    def flush_expired(self, now: Optional[float] = None) -> list[FlowRecord]:
        """Gibt Records für alle abgelaufenen Flows zurück."""
        if now is None:
            now = time.time()

        expired = [
            key for key, flow in self._flows.items()
            if (now - flow.last_seen > self.timeout_s)
            or (now - flow.start_ts  > self.max_duration_s)
        ]

        records = []
        for key in expired:
            records.append(self._flows.pop(key).to_record())

        return records

    def flush_all(self) -> list[FlowRecord]:
        """Alle verbleibenden Flows flushen (Shutdown)."""
        records = [flow.to_record() for flow in self._flows.values()]
        self._flows.clear()
        return records

    @property
    def active_count(self) -> int:
        return len(self._flows)
