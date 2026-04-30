#!/bin/bash
#
# Proxmox Hookscript: Port Mirroring von einer VM auf eine Sniffer-VM
#
# Spiegelt den gesamten Netzwerkverkehr der überwachten VM (TARGET_VM)
# auf die an SNIFFER_BRIDGE angeschlossene NIC der Sniffer-VM (SNIFFER_VM).
#
# Installation:
#   cp proxmox-mirror.sh /var/lib/vz/snippets/mirror.sh
#   chmod +x /var/lib/vz/snippets/mirror.sh
#   qm set <TARGET_VM> --hookscript local:snippets/mirror.sh
#
# Logs anzeigen:
#   journalctl -t mirror-hook -f
#

set -u  # Undefined Variablen sind Fehler

# ============================================================
# KONFIGURATION
# ============================================================
TARGET_VM=109                 # Zu überwachende VM
SNIFFER_VM=108                # Sniffer-VM
SNIFFER_BRIDGE=vmbr99         # Bridge, an der das Sniffer-Mirror-Interface hängt
TARGET_NIC_INDEX=0            # Welche NIC der TARGET_VM spiegeln (0 = net0)
AUTO_START_SNIFFER=1          # 1 = Sniffer automatisch starten falls nicht aktiv
SNIFFER_WAIT_SECONDS=30       # Max. Wartezeit auf Sniffer-Tap

# ============================================================
# HELFER
# ============================================================
VMID=${1:-}
PHASE=${2:-}

log() {
    logger -t mirror-hook -- "[VM ${VMID:-?}/${PHASE:-?}] $*"
    echo "[mirror-hook] $*" >&2
}

# Tap-Name der überwachten VM
SRC_TAP="tap${TARGET_VM}i${TARGET_NIC_INDEX}"

# Findet das Tap-Device der Sniffer-VM, das an SNIFFER_BRIDGE hängt.
# Funktioniert mit und ohne aktivierte Proxmox-Firewall:
#   - ohne Firewall: tap<SNIFFER_VM>iN hängt direkt an SNIFFER_BRIDGE
#   - mit Firewall:  tap<SNIFFER_VM>iN hängt an fwbr<SNIFFER_VM>iN,
#                    fwpr<SNIFFER_VM>pN hängt an SNIFFER_BRIDGE
# Wir suchen das Tap, dessen Index zum fwpr passt, der an der Bridge hängt.
find_sniffer_tap() {
    local tap

    # Direkt an Bridge angeschlossenes Tap der Sniffer-VM (ohne Firewall)
    tap=$(bridge link show 2>/dev/null \
        | awk -v b="$SNIFFER_BRIDGE" '$0 ~ "master "b' \
        | grep -oE "tap${SNIFFER_VM}i[0-9]+" \
        | head -n1)
    if [ -n "$tap" ]; then
        echo "$tap"
        return 0
    fi

    # Mit Firewall: fwpr<SNIFFER_VM>p<N> hängt an Bridge → tap<SNIFFER_VM>i<N>
    local idx
    idx=$(bridge link show 2>/dev/null \
        | awk -v b="$SNIFFER_BRIDGE" '$0 ~ "master "b' \
        | grep -oE "fwpr${SNIFFER_VM}p[0-9]+" \
        | grep -oE "[0-9]+$" \
        | head -n1)
    if [ -n "$idx" ]; then
        tap="tap${SNIFFER_VM}i${idx}"
        if ip link show "$tap" >/dev/null 2>&1; then
            echo "$tap"
            return 0
        fi
    fi

    return 1
}

# Wartet bis zu N Sekunden auf das Sniffer-Tap
wait_for_sniffer_tap() {
    local i tap
    for i in $(seq 1 "$SNIFFER_WAIT_SECONDS"); do
        if tap=$(find_sniffer_tap); then
            echo "$tap"
            return 0
        fi
        sleep 1
    done
    return 1
}

# Entfernt vorhandene tc-Regeln auf dem Quell-Tap
cleanup_mirror() {
    tc qdisc del dev "$SRC_TAP" ingress 2>/dev/null && \
        log "ingress qdisc auf $SRC_TAP entfernt" || true
    tc qdisc del dev "$SRC_TAP" root 2>/dev/null && \
        log "root qdisc auf $SRC_TAP entfernt" || true
}

# Richtet Mirroring ein
setup_mirror() {
    local dst_tap="$1"

    # Sicherheitshalber alte Regeln weg
    cleanup_mirror

    # Ingress (Pakete von VM in Richtung Bridge)
    if ! tc qdisc add dev "$SRC_TAP" ingress 2>/dev/null; then
        log "FEHLER: ingress qdisc konnte nicht angelegt werden"
        return 1
    fi
    if ! tc filter add dev "$SRC_TAP" parent ffff: protocol all matchall \
            action mirred egress mirror dev "$dst_tap" 2>/dev/null; then
        log "FEHLER: ingress filter konnte nicht angelegt werden"
        return 1
    fi

    # Egress (Pakete von Bridge in Richtung VM)
    if ! tc qdisc add dev "$SRC_TAP" root handle 1: prio 2>/dev/null; then
        log "FEHLER: root qdisc konnte nicht angelegt werden"
        return 1
    fi
    if ! tc filter add dev "$SRC_TAP" parent 1: protocol all matchall \
            action mirred egress mirror dev "$dst_tap" 2>/dev/null; then
        log "FEHLER: egress filter konnte nicht angelegt werden"
        return 1
    fi

    log "Mirroring aktiv: $SRC_TAP -> $dst_tap"
    return 0
}

# ============================================================
# HAUPTLOGIK
# ============================================================

# Nur für die konfigurierte Target-VM aktiv werden
if [ "$VMID" != "$TARGET_VM" ]; then
    exit 0
fi

case "$PHASE" in

    pre-start)
        log "pre-start: prüfe Sniffer-VM $SNIFFER_VM"

        if ! qm status "$SNIFFER_VM" 2>/dev/null | grep -q "status: running"; then
            if [ "$AUTO_START_SNIFFER" = "1" ]; then
                log "Sniffer-VM $SNIFFER_VM nicht aktiv, starte sie..."
                if ! qm start "$SNIFFER_VM" >/dev/null 2>&1; then
                    log "WARNUNG: Sniffer-VM $SNIFFER_VM konnte nicht gestartet werden"
                fi
            else
                log "WARNUNG: Sniffer-VM $SNIFFER_VM läuft nicht (AUTO_START=0)"
            fi
        else
            log "Sniffer-VM $SNIFFER_VM läuft bereits"
        fi
        ;;

    post-start)
        log "post-start: richte Mirroring ein"

        # Quell-Tap muss existieren (sollte zu diesem Zeitpunkt der Fall sein)
        if ! ip link show "$SRC_TAP" >/dev/null 2>&1; then
            log "WARNUNG: Quell-Tap $SRC_TAP existiert nicht – breche ab"
            exit 0
        fi

        # Sniffer-Tap suchen (mit Wartezeit)
        DST_TAP=$(wait_for_sniffer_tap) || {
            log "WARNUNG: Sniffer-Tap an $SNIFFER_BRIDGE nach ${SNIFFER_WAIT_SECONDS}s nicht gefunden"
            exit 0
        }
        log "Sniffer-Tap gefunden: $DST_TAP"

        # Mirroring einrichten
        if ! setup_mirror "$DST_TAP"; then
            log "WARNUNG: Mirroring konnte nicht vollständig eingerichtet werden"
            cleanup_mirror
            exit 0
        fi
        ;;

    pre-stop)
        log "pre-stop: räume Mirror-Regeln auf"
        cleanup_mirror
        ;;

    post-stop)
        # Tap ist hier i.d.R. schon weg, qdiscs sterben mit dem Device.
        # Nur defensiv aufräumen, falls doch noch was übrig ist.
        if ip link show "$SRC_TAP" >/dev/null 2>&1; then
            cleanup_mirror
        fi
        ;;

    *)
        # Unbekannte Phase – ignorieren, nicht den Start blockieren
        :
        ;;
esac

# Hookscript-Konvention: Nur Exit-Code 0 lässt VM-Aktion fortfahren.
# Wir geben bewusst immer 0 zurück, damit Mirroring-Probleme
# niemals den Start der eigentlichen VM verhindern.
exit 0
