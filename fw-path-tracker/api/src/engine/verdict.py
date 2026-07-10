"""Trace-Datenmodelle + Gesamt-Verdict-Aggregation."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

HopVerdict = Literal["ALLOW", "DENY", "UNKNOWN"]
TraceVerdict = Literal["ALLOW", "DENY", "DEGRADED"]


class Candidate(BaseModel):
    policyid: int | None = None
    name: str = ""
    action: str = "deny"
    srcintf: list[str] = Field(default_factory=list)
    dstintf: list[str] = Field(default_factory=list)
    srcaddr: list[str] = Field(default_factory=list)
    dstaddr: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    comments: str = ""
    hit: bool = False


class Endpoint(BaseModel):
    ip: str
    names: list[dict] = Field(default_factory=list)   # {name, provenance}
    provenance: str = "ip"


class Hop(BaseModel):
    index: int
    device: str
    vdom: str
    adom: str | None = None
    srcintf: str
    src_zone: str | None = None
    egress: str | None = None
    egress_zone: str | None = None
    egress_class: Literal["LOCAL", "VDOM_LINK", "OVERLAY", "DEFAULT", "UNKNOWN"] = "UNKNOWN"
    route: dict | None = None
    verdict: HopVerdict = "UNKNOWN"
    matched_policy: Candidate | None = None
    candidates: list[Candidate] = Field(default_factory=list)
    suggestion: dict | None = None
    warnings: list[str] = Field(default_factory=list)
    degraded: bool = False
    after_deny: bool = False


class TraceResult(BaseModel):
    verdict: TraceVerdict
    src: Endpoint
    dst: Endpoint
    protocol: str
    dst_port: int | None = None
    src_port: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    hops: list[Hop] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    vip: dict | None = None
    duration_ms: int = 0
    inventory_synced_at: str | None = None


def aggregate_verdict(hops: list[Hop]) -> TraceVerdict:
    """ALLOW nur wenn alle Hops ALLOW; DENY am ersten Deny;
    DEGRADED wenn ein Hop UNKNOWN ist (Gerät offline o.ä.)."""
    for hop in hops:
        if hop.verdict == "DENY":
            return "DENY"
        if hop.verdict == "UNKNOWN":
            return "DEGRADED"
    return "ALLOW"
