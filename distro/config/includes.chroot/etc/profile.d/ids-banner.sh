#!/bin/bash
# Login-Banner für Cyjan IDS – drei Modi:
#   Live-ISO        → Disk-Installer aufrufen
#   HDD, 1. Boot    → ids-setup (Konfig + Stack-Build) auf echtem ext4
#   HDD, danach     → Status-Anzeige
IDS_DIR="/opt/ids"
CYJAN_STATE="/etc/cyjan"

# Versionsinfo (vom CI in /etc/cyjan-version geschrieben)
VERSION=""
[ -r /etc/cyjan-version ] && VERSION=$(. /etc/cyjan-version 2>/dev/null && echo "${VERSION:-}")

# Live-Modus: root auf overlayfs (live-build) – verhindert Docker-Build-Crash
LIVE_MODE=0
if [ "$(findmnt -n -o FSTYPE / 2>/dev/null)" = "overlay" ] || [ -d /run/live/medium ]; then
  LIVE_MODE=1
fi

# ── Live-Modus: Installer anbieten ────────────────────────────────────────────
if [ "$LIVE_MODE" -eq 1 ] && [ -t 0 ]; then
  echo ""
  echo "  ╔══════════════════════════════════════════════╗"
  printf  "  ║  Cyjan IDS Live-System %-22s║\n" "${VERSION}"
  echo "  ╠══════════════════════════════════════════════╣"
  echo "  ║  Dies ist ein Live-System (RAM, ohne         ║"
  echo "  ║  Persistenz). Für den Produktivbetrieb       ║"
  echo "  ║  zuerst auf Festplatte installieren.         ║"
  echo "  ╚══════════════════════════════════════════════╝"
  echo ""
  echo "  IP-Adresse: $(hostname -I | awk '{print $1}')"
  echo "  SSH:         ssh ids@$(hostname -I | awk '{print $1}')  (Passwort: ids)"
  echo ""
  echo "  Starte Disk-Installer (sudo ids-installer)..."
  echo ""
  sudo /usr/local/bin/ids-installer
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo ""
    echo "  ⚠ ids-installer mit Fehler beendet (Exit $rc)."
    echo "  Logs: less /tmp/ids-install.log"
    echo "  Manuell starten: sudo ids-installer"
    echo ""
  fi
  return
fi

# ── HDD, erster Boot: Setup-Wizard ────────────────────────────────────────────
if [ -f "$CYJAN_STATE/FIRSTBOOT" ] && [ -t 0 ]; then
  echo ""
  echo "  ╔══════════════════════════════════════════════╗"
  printf  "  ║  Cyjan IDS First-Boot Setup %-17s║\n" "${VERSION}"
  echo "  ╚══════════════════════════════════════════════╝"
  echo ""
  echo "  Login als 'ids' (Autologin) erfolgreich."
  echo "  IP-Adresse: $(hostname -I | awk '{print $1}')"
  echo "  SSH:         ssh ids@$(hostname -I | awk '{print $1}')  (Passwort: ids)"
  echo ""
  echo "  Starte First-Boot-Wizard (sudo ids-setup)..."
  echo ""
  sudo /usr/local/bin/ids-setup
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo ""
    echo "  ⚠ ids-setup mit Fehler beendet (Exit $rc)."
    echo "  Logs: sudo less /var/log/cyjan/setup.log"
    echo "  Manuell starten: sudo ids-setup"
    echo ""
  fi
  return
fi

# ── Normaler HDD-Boot: Status-Anzeige ─────────────────────────────────────────
cd "$IDS_DIR" 2>/dev/null || return
RUNNING=$(docker compose ps --services --filter status=running 2>/dev/null | wc -l)
TOTAL=$(docker compose ps --services 2>/dev/null | wc -l)
IP=$(hostname -I | awk '{print $1}')

echo ""
echo "  ╔══════════════════════════════════════════════╗"
printf  "  ║  Cyjan IDS %-34s║\n" "${VERSION}"
echo "  ╠══════════════════════════════════════════════╣"
printf "  ║  Web-Interface: http://%-22s║\n" "${IP}/"
printf "  ║  API / Swagger: http://%-22s║\n" "${IP}:8001/api/docs"
printf "  ║  Dienste:       %-3s / %-3s laufen           ║\n" "$RUNNING" "$TOTAL"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║  ids-update   – System aktualisieren         ║"
echo "  ║  ids-setup    – Konfiguration ändern         ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
