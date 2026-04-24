#!/bin/bash
# Login-Banner für Cyjan IDS
IDS_DIR="/opt/ids"
CYJAN_STATE="/etc/cyjan"

if [ -f "$CYJAN_STATE/FIRSTBOOT" ] && [ -t 0 ]; then
  # KEIN clear – sonst sieht man bei stillem Hängen nichts mehr.
  # Nutzer behält die Boot-Logs als Diagnose im Scrollback.
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║  Cyjan IDS – First-Boot Setup        ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
  echo "  Login als 'ids' (Autologin) erfolgreich."
  echo "  IP-Adresse: $(hostname -I | awk '{print $1}')"
  echo "  SSH: ssh ids@$(hostname -I | awk '{print $1}') (Passwort: ids)"
  echo ""
  echo "  Starte First-Boot-Wizard (sudo ids-setup)..."
  echo ""
  if ! sudo /usr/local/bin/ids-setup; then
    echo ""
    echo "  ⚠ ids-setup mit Fehler beendet (Exit $?)."
    echo "  Logs: sudo less /var/log/cyjan/setup.log"
    echo "  Manuell starten: sudo ids-setup"
    echo ""
  fi
  return
fi

# Stack-Status
cd "$IDS_DIR" 2>/dev/null || return
RUNNING=$(docker compose ps --services --filter status=running 2>/dev/null | wc -l)
TOTAL=$(docker compose ps --services 2>/dev/null | wc -l)
IP=$(hostname -I | awk '{print $1}')

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║            Cyjan IDS                     ║"
echo "  ╠══════════════════════════════════════════╣"
printf "  ║  Web-Interface: http://%-19s║\n" "${IP}:$(grep API_PORT $IDS_DIR/.env 2>/dev/null | cut -d= -f2 || echo 8001)"
printf "  ║  Dienste:       %-3s / %-3s laufen       ║\n" "$RUNNING" "$TOTAL"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║  ids-update   – System aktualisieren     ║"
echo "  ║  ids-setup    – Konfiguration ändern     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
