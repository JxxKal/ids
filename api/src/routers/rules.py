"""Rules Engine: Rule-Quellen verwalten, aktive Regeln lesen, Update anstoßen."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/rules", tags=["rules"])

RULES_DIR   = Path(os.getenv("RULES_DIR", "/rules"))
TRIGGER_FILE = RULES_DIR / "update.trigger"
SOURCES_FILE = RULES_DIR / "sources.json"


# ── Pydantic-Modelle ───────────────────────────────────────────────────────────

class RuleSource(BaseModel):
    id:      str
    name:    str
    url:     str
    enabled: bool
    builtin: bool = False
    tags:    list[str] = []

class RuleSourceCreate(BaseModel):
    name:    str
    url:     str
    enabled: bool = True

class RuleSourcePatch(BaseModel):
    enabled: bool | None = None
    name:    str | None  = None
    url:     str | None  = None

class Rule(BaseModel):
    sid:       int | None
    msg:       str
    action:    str
    classtype: str | None
    enabled:   bool
    file:      str

class RuleListResponse(BaseModel):
    rules:  list[Rule]
    total:  int

class UpdateStatus(BaseModel):
    requested:    bool
    requested_at: float | None
    last_updated: float | None


# ── Standardquellen (ET Open + OT/ICS-Fokus) ──────────────────────────────────

def _default_sources() -> list[dict]:
    return [
        {
            "id": "et-open",
            "name": "Emerging Threats Open (Vollpaket)",
            "url": "https://rules.emergingthreats.net/open/suricata-{version}/emerging.rules.tar.gz",
            "enabled": True,
            "builtin": True,
            "tags": ["IT", "Basis"],
        },
        {
            "id": "et-scada",
            "name": "ET SCADA / ICS Rules",
            "url": "https://rules.emergingthreats.net/open/suricata-{version}/rules/emerging-scada.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "SCADA", "ICS"],
        },
        {
            "id": "quickdraw-modbus",
            "name": "Digital Bond Quickdraw – Modbus TCP",
            "url": "https://raw.githubusercontent.com/digitalbond/Quickdraw-Suricata/master/modbus_master.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "Modbus", "ICS"],
        },
        {
            "id": "quickdraw-dnp3",
            "name": "Digital Bond Quickdraw – DNP3",
            "url": "https://raw.githubusercontent.com/digitalbond/Quickdraw-Suricata/master/dnp3_master.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "DNP3", "SCADA"],
        },
        {
            "id": "quickdraw-enip",
            "name": "Digital Bond Quickdraw – EtherNet/IP (CIP)",
            "url": "https://raw.githubusercontent.com/digitalbond/Quickdraw-Suricata/master/enip_master.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "EtherNet/IP", "Rockwell"],
        },
        {
            "id": "quickdraw-bacnet",
            "name": "Digital Bond Quickdraw – BACnet",
            "url": "https://raw.githubusercontent.com/digitalbond/Quickdraw-Suricata/master/bacnet_master.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "BACnet", "Gebäudeautomation"],
        },
        {
            "id": "pt-scada",
            "name": "Positive Technologies – SCADA Attack Detection",
            "url": "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/ics/ics.rules",
            "enabled": False,
            "builtin": True,
            "tags": ["OT", "ICS", "SCADA", "Angriffserkennung"],
        },
    ]


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _load_sources() -> list[dict]:
    if SOURCES_FILE.exists():
        try:
            return json.loads(SOURCES_FILE.read_text())
        except Exception:
            pass
    return _default_sources()


def _save_sources(sources: list[dict]) -> None:
    SOURCES_FILE.parent.mkdir(parents=True, exist_ok=True)
    SOURCES_FILE.write_text(json.dumps(sources, indent=2))


def _write_enabled_urls(sources: list[dict]) -> None:
    """Schreibt enabled-URLs in update-sources.txt für den Snort-Entrypoint."""
    urls = [s["url"] for s in sources if s.get("enabled")]
    url_file = RULES_DIR / "update-sources.txt"
    url_file.parent.mkdir(parents=True, exist_ok=True)
    url_file.write_text("\n".join(urls) + "\n")


_SID_RE = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
_MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]+)"\s*;')
_ACT_RE = re.compile(r'^#*\s*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+')
_CLS_RE = re.compile(r'\bclasstype\s*:\s*([^;]+)\s*;')


def _parse_rule_line(line: str, filename: str) -> Rule | None:
    raw = line.strip()
    if not raw:
        return None

    # Kommentare ignorieren, außer auskommentierte Rules
    enabled = not raw.startswith('#')
    text = raw.lstrip('#').lstrip()

    if not _ACT_RE.match(text):
        return None

    msg_m = _MSG_RE.search(text)
    if not msg_m:
        return None

    sid_m = _SID_RE.search(text)
    act_m = _ACT_RE.match(text)
    cls_m = _CLS_RE.search(text)

    return Rule(
        sid=int(sid_m.group(1)) if sid_m else None,
        msg=msg_m.group(1),
        action=act_m.group(1) if act_m else "alert",
        classtype=cls_m.group(1).strip() if cls_m else None,
        enabled=enabled,
        file=filename,
    )


def _read_all_rules(search: str, limit: int, offset: int) -> tuple[list[Rule], int]:
    all_rules: list[Rule] = []
    if not RULES_DIR.exists():
        return [], 0

    for path in sorted(RULES_DIR.glob("*.rules")):
        fname = path.name
        try:
            for line in path.read_text(errors="replace").splitlines():
                r = _parse_rule_line(line, fname)
                if r:
                    all_rules.append(r)
        except OSError:
            continue

    if search:
        s = search.lower()
        all_rules = [
            r for r in all_rules
            if s in r.msg.lower()
            or (r.classtype and s in r.classtype.lower())
            or (r.sid and s in str(r.sid))
            or s in r.file.lower()
        ]

    total = len(all_rules)
    return all_rules[offset : offset + limit], total


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/sources", response_model=list[RuleSource])
async def list_sources() -> list[RuleSource]:
    return [RuleSource(**s) for s in _load_sources()]


@router.post("/sources", response_model=RuleSource, status_code=201)
async def add_source(body: RuleSourceCreate) -> RuleSource:
    sources = _load_sources()
    new: dict[str, Any] = {
        "id":      str(uuid4()),
        "name":    body.name,
        "url":     body.url,
        "enabled": body.enabled,
        "builtin": False,
        "tags":    [],
    }
    sources.append(new)
    _save_sources(sources)
    return RuleSource(**new)


@router.patch("/sources/{source_id}", response_model=RuleSource)
async def update_source(source_id: str, body: RuleSourcePatch) -> RuleSource:
    sources = _load_sources()
    for s in sources:
        if s["id"] == source_id:
            if body.enabled is not None:
                s["enabled"] = body.enabled
            if body.name is not None and not s.get("builtin"):
                s["name"] = body.name
            if body.url is not None and not s.get("builtin"):
                s["url"] = body.url
            _save_sources(sources)
            return RuleSource(**s)
    raise HTTPException(status_code=404, detail="Quelle nicht gefunden")


@router.delete("/sources/{source_id}", status_code=204, response_model=None)
async def delete_source(source_id: str) -> None:
    sources = _load_sources()
    source = next((s for s in sources if s["id"] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Quelle nicht gefunden")
    if source.get("builtin"):
        raise HTTPException(status_code=400, detail="Eingebaute Quellen können nicht gelöscht werden")
    _save_sources([s for s in sources if s["id"] != source_id])


@router.get("", response_model=RuleListResponse)
async def list_rules(
    search: str = Query(default=""),
    limit:  int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RuleListResponse:
    rules, total = _read_all_rules(search=search, limit=limit, offset=offset)
    return RuleListResponse(rules=rules, total=total)


@router.post("/update", response_model=UpdateStatus)
async def trigger_update() -> UpdateStatus:
    """Schreibt Trigger-Datei und enabled-URLs → Snort-Entrypoint lädt neu."""
    sources = _load_sources()
    _write_enabled_urls(sources)
    TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    TRIGGER_FILE.write_text(str(now))
    return UpdateStatus(requested=True, requested_at=now, last_updated=None)


@router.get("/update/status", response_model=UpdateStatus)
async def update_status() -> UpdateStatus:
    requested    = TRIGGER_FILE.exists()
    requested_at = float(TRIGGER_FILE.read_text().strip()) if requested else None

    last_updated: float | None = None
    if RULES_DIR.exists():
        rule_files = list(RULES_DIR.glob("*.rules"))
        if rule_files:
            last_updated = max(f.stat().st_mtime for f in rule_files)

    return UpdateStatus(
        requested=requested,
        requested_at=requested_at,
        last_updated=last_updated,
    )
