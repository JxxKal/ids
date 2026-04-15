"""
Pydantic-Modelle für eingehende PacketEvents (raw-packets Topic)
und ausgehende FlowRecords (flows Topic + TimescaleDB).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Eingehend: raw-packets ────────────────────────────────────────────────────

class TcpFields(BaseModel):
    flags: list[str] = []
    seq: int = 0
    ack: int = 0
    window: int = 0
    options: list[str] = []


class IcmpFields(BaseModel):
    # JSON-Key ist "type", Python-Attribut ist icmp_type um Builtin-Shadowing zu vermeiden
    model_config = ConfigDict(populate_by_name=True)
    icmp_type: int = Field(0, alias="type")
    code: int = 0


class TransportHeader(BaseModel):
    proto: str                              # TCP|UDP|ICMP|ICMPv6|OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp: Optional[TcpFields] = None
    icmp: Optional[IcmpFields] = None


class IpHeader(BaseModel):
    version: int = 4
    src: str
    dst: str
    ttl: int = 0
    proto: int = 0
    frag: bool = False
    dscp: int = 0
    flow_label: Optional[int] = None        # IPv6
    ext_headers: Optional[list[str]] = None # IPv6


class EthHeader(BaseModel):
    src_mac: str
    dst_mac: str
    ethertype: int


class PacketEvent(BaseModel):
    ts: float
    iface: str
    pkt_len: int
    eth: EthHeader
    ip: Optional[IpHeader] = None
    transport: Optional[TransportHeader] = None
    # raw_header_b64 wird für Aggregation nicht benötigt, daher ignoriert


# ── Ausgehend: flows Topic + TimescaleDB ─────────────────────────────────────

@dataclass
class FlowRecord:
    """Vollständig aggregierter Flow mit statistischen Features."""
    flow_id: str
    start_ts: float
    end_ts: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str
    ip_version: int
    pkt_count: int
    byte_count: int
    # Alle berechneten Features – geht als JSONB in die DB
    stats: dict

    def to_kafka_dict(self) -> dict:
        """
        Flaches Dict für das flows-Kafka-Topic.
        Stats werden auf Root-Ebene gemergt (entspricht dem definierten Schema).
        """
        d = {
            "flow_id": self.flow_id,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "ip_version": self.ip_version,
            "pkt_count": self.pkt_count,
            "byte_count": self.byte_count,
        }
        d.update(self.stats)
        return d
