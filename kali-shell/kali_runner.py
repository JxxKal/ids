#!/usr/bin/env python3
"""kali-shell Runner — wird via `docker exec -i ids-kali python3 ...`
vom redteam-orchestrator aufgerufen. Liest JSON-Command auf stdin,
validiert gegen allowed_tools.yml + RFC-5737-TEST-NETs, führt aus,
schreibt JSON-Result auf stdout.

Zwei Modi:
  - "tool" (default): vordefiniertes Pen-Test-Tool aus der allowed_tools-
    Whitelist (nmap, hydra, hping3, ncat, ping) mit args-Liste.
  - "payload": ncat --send-only mit base64-encoded bytes als stdin.
    Für Signatur-Detection-Tests (Modbus-PDU, HTTP-Header-Patterns, DNS-
    Tunnel-Frames). Validator: max 4 KB Decoded-Payload, TCP|UDP, beliebiger
    target_port, target_ip muss in TEST-NET liegen.

Sicherheits-Modell (Layer 4-5 aus REDTEAM_v1.3.0.md):
  - Tool-Whitelist greift VOR jeder String-Verarbeitung
  - subprocess mit shell=False + args-Liste (kein Shell-Inject möglich)
  - Forbidden-Flag-Check auf tokenisierte Args (nicht raw string)
  - Target-IP wird gegen RFC 5737 TEST-NET CIDRs validiert
  - Args werden zusätzlich nach Shell-Metachars gescannt (Defense in Depth)
  - Args werden auf IP-Smuggling gescannt: jeder Token der wie
    eine IP/CIDR aussieht muss ebenfalls in TEST-NET liegen
  - Payload-Mode: ncat-Aufruf hard-coded, kein -e/-l, payload nur als stdin

Invocation:
    docker exec -i ids-kali python3 /opt/cyjan/kali_runner.py < cmd.json

Returns JSON auf stdout (alle Modi):
    {exit_code, stdout, stderr, duration_ms, timed_out, ...}
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml


ALLOWED_TARGET_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
]

MAX_TIMEOUT_SEC  = 120
MAX_OUTPUT_BYTES = 1_048_576

# Payload-Mode: max 4 KB raw bytes nach base64-decode. Pakete größer als das
# wären auch nicht in einem einzelnen Frame transportierbar (Standard-MTU
# 1500), für L7-Signatur-Tests reicht 4 KB locker (Modbus-PDU ist 253 bytes,
# Suricata-Pattern matchen typisch erste paar 100 Bytes).
MAX_PAYLOAD_BYTES = 4096

ALLOWED_TOOLS_FILE = Path("/opt/cyjan/allowed_tools.yml")

# Shell-Metachars die im Token absolut nicht auftauchen dürfen. List-form
# subprocess macht eigentlich keinen Shell — aber Defense in Depth.
SHELL_METACHARS = (";", "|", "&", "$", "`", "\n", "\r", ">", "<", "*", "?")

# Erkennt IP-/CIDR-aussehende Tokens. Wird benutzt um IP-Smuggling über
# args zu blocken — z.B. `nmap -Pn 192.168.1.5` würde target_ip umgehen.
IP_PATTERN = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?\b")


def load_whitelist() -> dict[str, dict]:
    with open(ALLOWED_TOOLS_FILE) as f:
        return yaml.safe_load(f)["tools"]


def validate_ip_in_testnet(addr_or_cidr: str, context: str) -> None:
    """Wirft PermissionError wenn addr nicht in RFC-5737-TEST-NETs."""
    try:
        if "/" in addr_or_cidr:
            net = ipaddress.ip_network(addr_or_cidr, strict=False)
            if not any(net.subnet_of(t) for t in ALLOWED_TARGET_NETS):
                raise PermissionError(
                    f"{context}: CIDR '{addr_or_cidr}' nicht in TEST-NET"
                )
        else:
            addr = ipaddress.ip_address(addr_or_cidr)
            if not any(addr in net for net in ALLOWED_TARGET_NETS):
                raise PermissionError(
                    f"{context}: '{addr_or_cidr}' nicht in TEST-NET (192.0.2.0/24, "
                    f"198.51.100.0/24, 203.0.113.0/24)"
                )
    except ValueError as exc:
        raise PermissionError(f"{context}: ungültige IP/CIDR '{addr_or_cidr}': {exc}")


def validate_args(tool_name: str, tool_spec: dict, args: list[str]) -> None:
    """Reject if too many args / forbidden flag / shell metachar /
    IP-Smuggling außerhalb TEST-NET."""
    max_args = int(tool_spec.get("max_args", 20))
    if len(args) > max_args:
        raise PermissionError(
            f"{tool_name}: zu viele Args ({len(args)} > {max_args})"
        )

    forbidden = tool_spec.get("forbidden_flags") or []

    for token in args:
        # Shell-Metachar-Check
        for bad in SHELL_METACHARS:
            if bad in token:
                raise PermissionError(
                    f"{tool_name}: arg enthält verbotenes Zeichen {bad!r}: {token!r}"
                )
        # Forbidden-Flag-Check
        for flag in forbidden:
            if token == flag or token.startswith(flag + "="):
                raise PermissionError(
                    f"{tool_name}: verbotenes Flag {flag!r} im Args"
                )
        # IP-Smuggling-Check: wenn Token wie IP/CIDR aussieht, MUSS er
        # in einem TEST-NET liegen — sonst könnte target_ip über args
        # umgangen werden. finditer statt findall, weil regex Groups
        # enthält (findall würde Tuples liefern).
        for m in IP_PATTERN.finditer(token):
            validate_ip_in_testnet(m.group(0), f"{tool_name} arg")


def validate_command(cmd: dict) -> tuple[str, str, list[str], int]:
    """Returns (binary_path, target_ip, args, timeout_sec)."""
    whitelist = load_whitelist()

    tool_name = cmd.get("tool", "")
    if tool_name not in whitelist:
        raise PermissionError(
            f"Tool '{tool_name}' nicht in Whitelist. Erlaubt: {sorted(whitelist.keys())}"
        )

    tool_spec = whitelist[tool_name]
    binary = tool_spec["binary"]

    target_ip = cmd.get("target_ip", "")
    if tool_spec.get("require_target", False):
        if not target_ip:
            raise PermissionError(f"{tool_name}: target_ip ist erforderlich")
        validate_ip_in_testnet(target_ip, f"{tool_name} target_ip")

    args = cmd.get("args", [])
    if not isinstance(args, list):
        raise PermissionError("args muss Liste von Strings sein")
    if not all(isinstance(a, str) for a in args):
        raise PermissionError("alle args müssen Strings sein")
    validate_args(tool_name, tool_spec, args)

    timeout = min(int(cmd.get("timeout_sec", 30)), MAX_TIMEOUT_SEC)
    if timeout < 1:
        timeout = 30

    # Target an args anhängen, falls nicht schon drin
    final_args = list(args)
    if target_ip and not any(
        target_ip == a or target_ip in IP_PATTERN.findall(a) for a in args
    ):
        final_args.append(target_ip)

    return binary, target_ip, final_args, timeout


def execute(binary: str, args: list[str], timeout: int) -> dict[str, Any]:
    """Run validated command. shell=False, args als Liste — kein Shell-Inject."""
    start = time.time()
    try:
        proc = subprocess.run(
            [binary] + args,
            capture_output=True,
            timeout=timeout,
            text=True,
            check=False,
            shell=False,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:MAX_OUTPUT_BYTES],
            "stderr": proc.stderr[:MAX_OUTPUT_BYTES],
            "stdout_truncated": len(proc.stdout) > MAX_OUTPUT_BYTES,
            "stderr_truncated": len(proc.stderr) > MAX_OUTPUT_BYTES,
            "timed_out": False,
            "duration_ms": int((time.time() - start) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": -1,
            "stdout": (exc.stdout or b"").decode(errors="replace")[:MAX_OUTPUT_BYTES],
            "stderr": f"TIMEOUT after {timeout}s",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timed_out": True,
            "duration_ms": int((time.time() - start) * 1000),
        }
    except FileNotFoundError:
        return {
            "exit_code": -2,
            "stdout": "",
            "stderr": f"binary not found: {binary}",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timed_out": False,
            "duration_ms": int((time.time() - start) * 1000),
        }


# ──────────────────────────────────────────────────────────────────────
# Payload-Mode — ncat --send-only mit base64-encoded bytes als stdin
# ──────────────────────────────────────────────────────────────────────
def execute_payload(cmd: dict) -> dict[str, Any]:
    """Validiert + sendet einen Application-Layer-Payload. Genutzt für
    Signatur-Detection-Tests (Modbus-PDU, HTTP-Pattern, DNS-Tunnel-Frames).

    Required keys in cmd: target_ip, target_port, protocol (tcp|udp), payload_b64.
    Optional: timeout_sec.
    """
    target_ip = cmd.get("target_ip", "")
    if not target_ip:
        raise PermissionError("payload-mode: target_ip required")
    validate_ip_in_testnet(target_ip, "payload target_ip")

    port = cmd.get("target_port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise PermissionError(f"payload-mode: target_port {port!r} invalid (1-65535)")

    proto = (cmd.get("protocol") or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise PermissionError(f"payload-mode: protocol {proto!r} not in (tcp, udp)")

    payload_b64 = cmd.get("payload_b64", "")
    if not isinstance(payload_b64, str) or not payload_b64:
        raise PermissionError("payload-mode: payload_b64 (non-empty string) required")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise PermissionError(f"payload-mode: payload_b64 not valid base64: {exc}")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise PermissionError(
            f"payload-mode: {len(payload)} bytes > MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES})"
        )

    timeout = min(int(cmd.get("timeout_sec", 10)), MAX_TIMEOUT_SEC)
    if timeout < 1:
        timeout = 10

    # ncat --send-only: schickt stdin, schließt write-side, wartet je nach
    # Protokoll noch kurz auf Replies bevor ncat exit. -i 2 = idle-timeout 2s,
    # damit nach dem Send-Close ncat nicht ewig auf irgendwas wartet.
    cmd_args = ["/usr/bin/ncat", "--send-only", "-w", str(timeout), "-i", "2"]
    if proto == "udp":
        cmd_args.append("-u")
    cmd_args.extend([target_ip, str(port)])

    start = time.time()
    try:
        proc = subprocess.run(
            cmd_args, input=payload, capture_output=True,
            timeout=timeout, check=False, shell=False,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:MAX_OUTPUT_BYTES].decode(errors="replace"),
            "stderr": proc.stderr[:MAX_OUTPUT_BYTES].decode(errors="replace"),
            "stdout_truncated": len(proc.stdout) > MAX_OUTPUT_BYTES,
            "stderr_truncated": len(proc.stderr) > MAX_OUTPUT_BYTES,
            "timed_out": False,
            "duration_ms": int((time.time() - start) * 1000),
            "sent_bytes": len(payload),
            "target_port": port,
            "protocol": proto,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"TIMEOUT after {timeout}s",
            "stdout_truncated": False, "stderr_truncated": False,
            "timed_out": True,
            "duration_ms": int((time.time() - start) * 1000),
            "sent_bytes": 0,
            "target_port": port, "protocol": proto,
        }


def main() -> int:
    try:
        cmd = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"invalid JSON on stdin: {exc}"}), flush=True)
        return 2

    mode = cmd.get("mode", "tool")

    if mode == "payload":
        try:
            result = execute_payload(cmd)
        except PermissionError as exc:
            print(json.dumps({
                "error": "validation_failed",
                "message": str(exc),
                "mode": "payload",
            }), flush=True)
            return 3
        result["mode"] = "payload"
        result["target_ip"] = cmd.get("target_ip")
        print(json.dumps(result), flush=True)
        return 0

    # default tool-mode
    try:
        binary, target_ip, args, timeout = validate_command(cmd)
    except PermissionError as exc:
        print(json.dumps({
            "error": "validation_failed",
            "message": str(exc),
            "tool": cmd.get("tool"),
        }), flush=True)
        return 3

    result = execute(binary, args, timeout)
    result["tool"]      = cmd.get("tool")
    result["target_ip"] = target_ip
    result["args"]      = args

    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
