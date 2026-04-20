#!/bin/bash
# Login-Banner für Cyjan IDS
IDS_DIR="/opt/ids"
CYJAN_STATE="/etc/cyjan"

if [ -f "$CYJAN_STATE/FIRSTBOOT" ]; then
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║  Cyjan IDS – First-Boot Setup läuft  ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
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
