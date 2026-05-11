#!/bin/sh
# TCP-Sink-Listener für RedTeam-Payload-Scenarios.
#
# Bindet pro Ziel-Port einen ncat-Listener AUSSCHLIESSLICH auf 192.0.2.254
# (Host-Seite des cyjan-inject↔cy-inj-peer veth-Pairs). Andere Host-Services
# auf 0.0.0.0:<port> würden mit unserem IP-qualifizierten Bind kollidieren
# (Linux: 0.0.0.0:X reserviert <jede-IP>:X). Daher binden wir nur auf Ports
# die der Host nicht selbst belegt — Bind-Failures werden geloggt + skipped,
# Container stirbt deswegen nicht.
#
# Warum: Signatur-Detection-Tests aus kali brauchen TCP-Handshake-Vollendung,
# sonst kommt nur SYN auf die Leitung. Mit dem Listener wird der Payload
# (Modbus-PDU, S7Comm, NTLM-Bytes etc.) wirklich gesendet und vom Sniffer
# auf cy-inj-peer captured → flow-aggregator → signature-engine/Suricata.
#
# Listener ist passiv: --recv-only → schickt nichts zurück, kein Protokoll-
# Stack, nur byte-Sink. Realistische Service-Emulation ist hier NICHT das
# Ziel; der Detection-Trigger sitzt im REQUEST-Pattern.
set -eu

PEER_IP="${PEER_IP:-192.0.2.254}"
# Default-Port-Set: ICS- + Windows-Standard-Service-Ports, die typischerweise
# auf einem Linux-IDS-Host NICHT belegt sind. Bei kollidierenden Ports wird
# pro Port geloggt + skipped (siehe try_bind unten).
PORTS="${PORTS:-88 102 110 135 139 143 161 389 445 502 587 636 1433 1521 1947 2010 3268 3389 4840 5450}"
LOG_PREFIX="[redteam-listener]"

# Warte bis veth-Pair vom Orchestrator gesetzt + IP zugewiesen ist.
i=0
while ! ip -4 addr show 2>/dev/null | grep -qw "$PEER_IP"; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "$LOG_PREFIX FATAL: ${PEER_IP} nicht auf irgendeinem Host-Iface nach 120s" >&2
        exit 1
    fi
    echo "$LOG_PREFIX waiting for $PEER_IP on host interfaces... ($i/60)"
    sleep 2
done

echo "$LOG_PREFIX $PEER_IP sichtbar. Versuche Bind auf: $PORTS"

# Pro Port: ncat in den Hintergrund + 100ms warten + kill -0 prüfen ob noch
# am Leben. Wenn nicht (=Bind-Fehler), log + weiter. Sonst PID merken.
bound=0
failed=0
for port in $PORTS; do
    ncat -l -k -s "$PEER_IP" -p "$port" --recv-only >/dev/null 2>&1 &
    pid=$!
    sleep 0.1
    if kill -0 "$pid" 2>/dev/null; then
        bound=$((bound + 1))
    else
        failed=$((failed + 1))
        echo "$LOG_PREFIX :${port} BIND-FAIL (Port wohl Host-belegt) — skip"
    fi
done

echo "$LOG_PREFIX $bound Listener gebunden, $failed übersprungen. Bleibe aktiv."

# Trap für sauberen Shutdown
trap 'echo "$LOG_PREFIX SIGTERM — stoppe alle ncat-children"; kill $(jobs -p) 2>/dev/null; exit 0' TERM INT

# tail -f keeps the container alive unabhängig davon ob einzelne ncats
# später sterben. Healthcheck (ss -ltn auf 192.0.2.254 >= 5) deckt
# Gesamt-Funktionalität ab.
tail -f /dev/null &
wait $!
