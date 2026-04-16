"""Pydantic-Schemas für Request- und Response-Objekte."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    alert_id:       UUID
    ts:             datetime
    flow_id:        UUID | None = None
    source:         str
    rule_id:        str | None = None
    severity:       str
    score:          float
    src_ip:         str | None = None
    dst_ip:         str | None = None
    src_port:       int | None = None
    dst_port:       int | None = None
    proto:          str | None = None
    description:    str | None = None
    tags:           list[str] = Field(default_factory=list)
    enrichment:     dict[str, Any] | None = None
    pcap_available: bool = False
    pcap_key:       str | None = None
    feedback:       str | None = None
    feedback_ts:    datetime | None = None
    feedback_note:  str | None = None
    is_test:        bool = False


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total:  int
    offset: int
    limit:  int


class FeedbackRequest(BaseModel):
    feedback: str = Field(..., pattern="^(fp|tp)$")
    note:     str | None = None


# ── Flows ─────────────────────────────────────────────────────────────────────

class FlowResponse(BaseModel):
    flow_id:    UUID
    start_ts:   datetime
    end_ts:     datetime | None = None
    src_ip:     str
    dst_ip:     str
    src_port:   int | None = None
    dst_port:   int | None = None
    proto:      str
    pkt_count:  int
    byte_count: int
    stats:      dict[str, Any] | None = None


class FlowListResponse(BaseModel):
    flows:  list[FlowResponse]
    total:  int
    offset: int
    limit:  int


# ── Hosts ─────────────────────────────────────────────────────────────────────

class HostResponse(BaseModel):
    ip:           str
    hostname:     str | None = None
    display_name: str | None = None
    trusted:      bool = False
    trust_source: str | None = None   # dns | csv | manual
    asn:          dict[str, Any] | None = None
    geo:          dict[str, Any] | None = None
    ping_ms:      float | None = None
    last_seen:    datetime | None = None
    updated_at:   datetime


class HostCreate(BaseModel):
    ip:           str
    display_name: str | None = None
    trusted:      bool = True
    trust_source: str = "manual"


class HostUpdate(BaseModel):
    display_name: str | None = None
    trusted:      bool | None = None


# ── Networks ──────────────────────────────────────────────────────────────────

class NetworkResponse(BaseModel):
    id:          UUID
    cidr:        str
    name:        str
    description: str | None = None
    color:       str | None = None


class NetworkCreate(BaseModel):
    cidr:        str
    name:        str
    description: str | None = None
    color:       str | None = None


# ── Stats ─────────────────────────────────────────────────────────────────────

class ThreatLevelResponse(BaseModel):
    level:      int = Field(..., ge=0, le=100)
    label:      str                             # green | yellow | orange | red
    alert_counts: dict[str, int]                # {severity: count} letzte 15 min
    window_min: int = 15


# ── System Config ─────────────────────────────────────────────────────────────

class ConfigResponse(BaseModel):
    key:   str
    value: dict[str, Any]


class ConfigUpdate(BaseModel):
    value: dict[str, Any]


# ── Test Runs ─────────────────────────────────────────────────────────────────

class TestRunRequest(BaseModel):
    scenario_id: str


class TestRunResponse(BaseModel):
    id:            UUID
    scenario_id:   str
    started_at:    datetime
    completed_at:  datetime | None = None
    status:        str
    expected_rule: str | None = None
    triggered:     bool | None = None
    alert_id:      UUID | None = None
    latency_ms:    int | None = None
    error:         str | None = None
