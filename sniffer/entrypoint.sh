#!/bin/sh
# Bringt das Mirror-Interface hoch bevor der Sniffer startet.
# Nötig weil Linux-Interfaces nach dem Booten oft im DOWN-State sind.
if [ -n "${MIRROR_IFACE:-}" ]; then
    ip link set "$MIRROR_IFACE" up 2>/dev/null && echo "[ids] $MIRROR_IFACE up" || echo "[ids] ip link set $MIRROR_IFACE up fehlgeschlagen (ggf. schon up)"
fi
exec sniffer
