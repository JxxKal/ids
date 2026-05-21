#!/bin/bash
# /opt/ids/scripts/fix-network-interfaces.sh
#
# Repariert /etc/network/interfaces nach einem ids-setup-Lauf vor v2.5.22,
# der den static-Block angehängt hat ohne den DHCP-Default vorher zu
# entfernen. Symptom: ifup beim Boot failt ("Doppelte iface-Definition"),
# System fällt auf DHCP-Default zurück.
#
# Mechanik:
#   1. Backup von /etc/network/interfaces ziehen
#   2. ALLE auto/iface-Blöcke für das angegebene Iface aus der main-Datei
#      rauspatchen (Python-Regex über eingerückte Folgezeilen)
#   3. Den static-Block als drop-in in /etc/network/interfaces.d/
#      cyjan-mgmt-<iface> ablegen — wenn der user die Werte angibt
#   4. ifdown && ifup ausführen
#
# Idempotent: wiederholtes Ausführen ist sicher.
#
# Aufruf:
#   sudo /opt/ids/scripts/fix-network-interfaces.sh <iface> [<addr/cidr> <gateway>]
#
# Beispiele:
#   # Nur aufräumen, keine static-Config schreiben (Iface fällt auf DHCP):
#   sudo /opt/ids/scripts/fix-network-interfaces.sh eno1
#
#   # Aufräumen + static setzen:
#   sudo /opt/ids/scripts/fix-network-interfaces.sh eno1 10.180.42.10/25 10.180.42.129

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte mit sudo aufrufen." >&2
  exit 1
fi

IFC="${1:-}"
ADDR="${2:-}"
GW="${3:-}"

if [ -z "$IFC" ]; then
  echo "Usage: $0 <iface> [<addr/cidr> <gateway>]" >&2
  exit 2
fi

if ! [ -d "/sys/class/net/$IFC" ]; then
  echo "FEHLER: Iface '$IFC' existiert nicht. Vorhanden:" >&2
  ls /sys/class/net/ | grep -v '^lo$' >&2 || true
  exit 2
fi

BAK="/etc/network/interfaces.cyjan-bak-$(date +%Y%m%d-%H%M%S)"
cp /etc/network/interfaces "$BAK"
echo "[fix-net] Backup: $BAK"

# Alle Blöcke für das Iface aus der main-Datei rauspatchen
python3 - "$IFC" <<'PY'
import re, sys
ifc = sys.argv[1]
p = "/etc/network/interfaces"
with open(p) as f:
    src = f.read()
pat = re.compile(
    r"(?:^[ \t]*auto[ \t]+" + re.escape(ifc) + r"[ \t]*\n)?"
    r"^[ \t]*iface[ \t]+" + re.escape(ifc) + r"[ \t]+inet\b.*\n"
    r"(?:^[ \t]+\S.*\n)*",
    re.MULTILINE,
)
new = pat.sub("", src)
n_removed = len(pat.findall(src))
if new != src:
    with open(p, "w") as f:
        f.write(new)
print(f"[fix-net] {n_removed} Block(s) für '{ifc}' aus /etc/network/interfaces entfernt.")
PY

# Source-Statement im main file sicherstellen
if ! grep -q '^source[[:space:]].*interfaces\.d' /etc/network/interfaces 2>/dev/null; then
  printf '\nsource /etc/network/interfaces.d/*\n' >> /etc/network/interfaces
  echo "[fix-net] 'source /etc/network/interfaces.d/*' nachgezogen."
fi

# Drop-in schreiben wenn ADDR/GW gegeben — sonst Iface kommt auf DHCP-Default
mkdir -p /etc/network/interfaces.d
DROPIN="/etc/network/interfaces.d/cyjan-mgmt-${IFC}"

if [ -n "$ADDR" ]; then
  cat > "$DROPIN" <<EOF
auto ${IFC}
iface ${IFC} inet static
  address ${ADDR}
EOF
  if [ -n "$GW" ]; then
    echo "  gateway ${GW}" >> "$DROPIN"
  fi
  echo "[fix-net] Drop-in geschrieben: $DROPIN"
else
  # Kein static angegeben → DHCP-Block als drop-in (oder wenn schon existiert: lassen)
  if [ ! -e "$DROPIN" ]; then
    cat > "$DROPIN" <<EOF
auto ${IFC}
iface ${IFC} inet dhcp
EOF
    echo "[fix-net] Drop-in mit DHCP angelegt: $DROPIN"
  fi
fi

echo "[fix-net] Verify:"
echo "─── /etc/network/interfaces ───"
cat /etc/network/interfaces
echo "─── ${DROPIN} ───"
cat "$DROPIN"

echo
echo "[fix-net] Nun anwenden. ACHTUNG: ifdown/ifup kann SSH-Sessions kappen."
echo "  sudo ifdown ${IFC} && sudo ifup ${IFC}"
echo
echo "Oder beim nächsten Reboot zieht's auch — Backup liegt bei $BAK falls Rollback nötig."
