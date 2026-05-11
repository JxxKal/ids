"""AI-authored Suricata-Rules — Write + Manage + Reload.

Rules leben in /rules/cyjan-ai.rules (snort-rules-Volume, gleicher Pfad
als /etc/suricata/rules/cyjan-ai.rules im snort-Container). Reload-Trigger
über Touch /rules/update.trigger — snort-entrypoint pollt das alle 30s
und ruft `suricatasc -c ruleset-reload-rules` über den unix-command-socket.

SID-Range 9000000-9999999 ist für AI-authored Rules reserviert (kollidiert
weder mit Suricata-internal 1.x noch mit ET-Open 2.x).

Sicherheits-Eigenschaften:
- SID-Range-Check: AI darf NICHT in ET-Open- oder Cyjan-Custom-Bereich
  schreiben — falls jemand sich SID 2068000 oder 12345 ausdenkt, reject.
- msg-Sanitierung: keine Quotes, Semikolons, Newlines (Suricata-rule-syntax-
  injection).
- proto-Whitelist: nur tcp/udp.
- content_hex Sanity: nur Hex-Chars + Whitespace + `|` (für `|aa bb|`-Form).
- Atomic Write: tmp + replace, niemals partial-write.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

RULES_FILE       = Path("/rules/cyjan-ai.rules")
RELOAD_TRIGGER   = Path("/rules/update.trigger")
MIN_AI_SID       = 9_000_000
MAX_AI_SID       = 9_999_999

_SID_RX     = re.compile(r"\bsid\s*:\s*(\d+)\b")
_MSG_RX     = re.compile(r'msg\s*:\s*"([^"]+)"')
_CLASS_RX   = re.compile(r"classtype\s*:\s*([a-z0-9_-]+)", re.IGNORECASE)
_HEX_OK_RX  = re.compile(r"^[0-9a-fA-F\s]+$")  # für reine hex-content-Args


class SuricataRuleError(Exception):
    pass


def _validate_sid(sid: int) -> None:
    if not isinstance(sid, int):
        raise SuricataRuleError(f"sid {sid!r} ist kein int")
    if not (MIN_AI_SID <= sid <= MAX_AI_SID):
        raise SuricataRuleError(
            f"sid {sid} außerhalb AI-Range [{MIN_AI_SID}, {MAX_AI_SID}]"
        )


def _validate_msg(msg: str) -> str:
    if not isinstance(msg, str) or not msg.strip():
        raise SuricataRuleError("msg muss non-empty string sein")
    if any(c in msg for c in '"\n\r;'):
        raise SuricataRuleError("msg darf keine \" ; oder Newlines enthalten")
    if len(msg) > 200:
        raise SuricataRuleError("msg > 200 chars")
    return msg.strip()


def _validate_content_hex(content_hex: str) -> str:
    """Sanitize content_hex zur Form `aa bb cc` (Space-separated lowercase).
    Akzeptiert Eingaben wie 'AABBCC', 'aa bb cc', '|aa bb|', '0xAA 0xBB'."""
    if not isinstance(content_hex, str):
        raise SuricataRuleError("content_hex muss string sein")
    # Strip `|`, `0x`-Präfixe, Whitespace; nur reine Hex-Chars + Spaces erlauben
    cleaned = re.sub(r"\|", "", content_hex)
    cleaned = re.sub(r"0[xX]", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not _HEX_OK_RX.match(cleaned):
        raise SuricataRuleError(f"content_hex enthält ungültige Chars: {content_hex!r}")
    # Auf gerade Byte-Anzahl prüfen (pro Byte 2 hex-chars)
    raw = re.sub(r"\s+", "", cleaned)
    if len(raw) % 2 != 0:
        raise SuricataRuleError(f"content_hex hat ungerade Anzahl hex-chars: {raw}")
    if len(raw) // 2 > 256:
        raise SuricataRuleError("content_hex > 256 bytes — Rule wird zu spezifisch")
    # Format als space-getrennte Pairs für lesbarkeit + Suricata-Spec
    pairs = " ".join(raw[i:i+2].lower() for i in range(0, len(raw), 2))
    return pairs


def _validate_proto(proto: str) -> str:
    proto = (proto or "").lower().strip()
    if proto not in ("tcp", "udp"):
        raise SuricataRuleError(f"proto {proto!r} nicht in (tcp, udp)")
    return proto


def _validate_port(dst_port: Any) -> str:
    """Akzeptiert int (1-65535) oder string "any" / "$VAR_NAME"."""
    if isinstance(dst_port, int):
        if not (1 <= dst_port <= 65535):
            raise SuricataRuleError(f"dst_port {dst_port} außerhalb 1-65535")
        return str(dst_port)
    if isinstance(dst_port, str):
        s = dst_port.strip()
        if s == "any" or re.match(r"^\$[A-Z_]+$", s):
            return s
        if s.isdigit():
            return _validate_port(int(s))
    raise SuricataRuleError(f"dst_port {dst_port!r} weder int noch 'any'/'$VAR'")


def _validate_classtype(classtype: str) -> str:
    if not classtype:
        return "misc-attack"
    if not re.match(r"^[a-z0-9_-]+$", classtype, re.IGNORECASE):
        raise SuricataRuleError(f"classtype {classtype!r} ungültig")
    return classtype


def build_rule(
    sid:          int,
    msg:          str,
    proto:        str,
    dst_port:     Any,
    content_hex:  str,
    classtype:    str = "misc-attack",
    flow_state:   bool = True,
) -> str:
    """Baut eine vollständige Suricata-Rule. Wirft SuricataRuleError bei
    jedem Validierungsfehler.

    Default-Form für tcp:
      alert tcp any any -> $HOME_NET <port> (msg:"Cyjan-AI: <msg>";
          flow:to_server,established; content:"|<hex>|"; offset:0;
          classtype:<classtype>; sid:<sid>; rev:1; metadata:author cyjan-ai;)
    """
    sid_ok    = sid          # _validate_sid wird ausgeführt → wirft bei Fehler
    _validate_sid(sid_ok)
    msg_ok    = _validate_msg(msg)
    proto_ok  = _validate_proto(proto)
    port_ok   = _validate_port(dst_port)
    hex_ok    = _validate_content_hex(content_hex)
    class_ok  = _validate_classtype(classtype)

    parts: list[str] = []
    parts.append(f'msg:"Cyjan-AI: {msg_ok}"')
    if proto_ok == "tcp" and flow_state:
        parts.append("flow:to_server,established")
    parts.append(f'content:"|{hex_ok}|"')
    parts.append("offset:0")
    parts.append(f"classtype:{class_ok}")
    parts.append(f"sid:{sid_ok}")
    parts.append("rev:1")
    parts.append("metadata:author cyjan-ai")
    body = "; ".join(parts) + ";"

    return f"alert {proto_ok} any any -> $HOME_NET {port_ok} ({body})"


def _read_rules_file() -> list[str]:
    if not RULES_FILE.is_file():
        return []
    return RULES_FILE.read_text().splitlines()


def _write_rules_file(lines: list[str]) -> None:
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = RULES_FILE.with_suffix(".rules.tmp")
    tmp.write_text("\n".join(lines) + "\n")
    tmp.replace(RULES_FILE)


def _trigger_reload() -> None:
    """Schreibt /rules/update.trigger — der snort-entrypoint-Polling-Loop
    erkennt das innerhalb von ~30s und ruft suricatasc reload."""
    RELOAD_TRIGGER.parent.mkdir(parents=True, exist_ok=True)
    RELOAD_TRIGGER.write_text("trigger\n")


def list_rules() -> list[dict[str, Any]]:
    """Parsed alle AI-Rules aus /rules/cyjan-ai.rules. Returns Liste von
    {sid, msg, classtype, raw}."""
    out: list[dict[str, Any]] = []
    for line in _read_rules_file():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m_sid = _SID_RX.search(line)
        if not m_sid:
            continue
        sid = int(m_sid.group(1))
        m_msg = _MSG_RX.search(line)
        m_cls = _CLASS_RX.search(line)
        out.append({
            "sid":       sid,
            "msg":       m_msg.group(1) if m_msg else "",
            "classtype": m_cls.group(1) if m_cls else "",
            "raw":       line,
        })
    return out


def upsert_rule(
    sid:         int,
    msg:         str,
    proto:       str,
    dst_port:    Any,
    content_hex: str,
    classtype:   str = "misc-attack",
) -> dict[str, Any]:
    """Schreibt eine Rule (ersetzt bei gleicher SID). Returns
    {sid, msg, path, reload_triggered, replaced_existing}."""
    rule = build_rule(sid, msg, proto, dst_port, content_hex, classtype)

    existing = _read_rules_file()
    replaced = False
    kept: list[str] = []
    for line in existing:
        m = _SID_RX.search(line)
        if m and int(m.group(1)) == sid:
            replaced = True
            continue
        kept.append(line)
    kept.append(rule)
    _write_rules_file(kept)
    _trigger_reload()
    log.info("Suricata-Rule sid=%d %s — %s",
             sid, "REPLACED" if replaced else "ADDED", msg)
    return {
        "sid":               sid,
        "msg":               msg,
        "path":              str(RULES_FILE),
        "reload_triggered":  True,
        "replaced_existing": replaced,
        "raw":               rule,
    }


def delete_rule(sid: int) -> bool:
    """Entfernt eine Rule by SID. Returns True wenn gefunden+entfernt."""
    _validate_sid(sid)
    existing = _read_rules_file()
    if not existing:
        return False
    removed = False
    kept: list[str] = []
    for line in existing:
        m = _SID_RX.search(line)
        if m and int(m.group(1)) == sid:
            removed = True
            continue
        kept.append(line)
    if removed:
        _write_rules_file(kept)
        _trigger_reload()
        log.info("Suricata-Rule sid=%d entfernt", sid)
    return removed
