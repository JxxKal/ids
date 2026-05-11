#!/bin/sh
# TCP-Sink-Listener für RedTeam-Payload-Scenarios.
#
# Bindet pro Ziel-Port einen ncat-Listener AUSSCHLIESSLICH auf 192.0.2.254
# (Host-Seite des cyjan-inject↔cy-inj-peer veth-Pairs). Andere Host-Services
# auf 0.0.0.0:<port> bleiben unberührt — wir teilen uns den Port-Namespace
# (network_mode: host), kollidieren aber nicht, weil unsere Binds IP-
# qualifiziert sind.
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
PORTS="${PORTS:-22 23 25 53 80 88 102 110 135 139 143 161 389 443 445 502 587 636 1433 1521 1947 2010 3268 3389 4840 5450}"
LOG_PREFIX="[redteam-listener]"

# Warte bis veth-Pair vom Orchestrator gesetzt + IP zugewiesen ist.
# Tries: 60×2s = 2 min. Wenn die Wartezeit reißt, ist der Orchestrator
# selbst nicht hochgekommen — der Listener stirbt und Docker restartet.
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

echo "$LOG_PREFIX $PEER_IP sichtbar. Binde Listener auf: $PORTS"

bound=0
for port in $PORTS; do
    # -l listen, -k keep-open (re-accept nach Disconnect), -s bind-addr,
    # --recv-only stille Senke, stdout → /dev/null
    ncat -l -k -s "$PEER_IP" -p "$port" --recv-only >/dev/null 2>&1 &
    bound=$((bound + 1))
done

echo "$LOG_PREFIX $bound Listener gestartet auf $PEER_IP. Warte auf SIGTERM..."

# Trap SIGTERM für sauberen Shutdown (kill child-ncats)
trap 'echo "$LOG_PREFIX SIGTERM — stoppe alle ncat-children"; kill $(jobs -p) 2>/dev/null; exit 0' TERM INT

# Bleib am Leben: wait blockiert bis irgendein Background-Job stirbt.
# Wenn einer stirbt — restart durch docker (unless-stopped).
wait -n
echo "$LOG_PREFIX ein Listener ist gestorben — Container exit für Restart"
exit 1
