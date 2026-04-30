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
  # `-n` damit fehlende NOPASSWD-Regel sofort als Fehler sichtbar wird statt
  # in einer stillen Passwort-Abfrage hängenzubleiben.
  sudo -n /usr/local/bin/ids-installer
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
# Trigger: FIRSTBOOT-Marker ODER fehlende .env. Letzteres als Fallback, weil
# der Marker durch einen abgebrochenen Wizard, manuelles `rm` oder einen Bug
# verloren gehen kann – dann bliebe das System ohne Auto-Setup hängen.
if { [ -f "$CYJAN_STATE/FIRSTBOOT" ] || [ ! -f "$IDS_DIR/.env" ]; } && [ -t 0 ]; then
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
  sudo -n /usr/local/bin/ids-setup
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
# Mode-aware: Master (Default) zeigt Web-Interface + API-Swagger, Tap zeigt
# Master-URL + Verbindungsstatus + cyjan-tap-Subkommandos. Compose-File
# wird je Mode korrekt mit -f tap.yml geladen, sonst zählt der Tap-Modus
# Service-Status falsch (default docker-compose.yml verlangt MIRROR_IFACE).
cd "$IDS_DIR" 2>/dev/null || return

MODE=$(cat "$CYJAN_STATE/mode" 2>/dev/null | tr -d '[:space:]')
[ -z "$MODE" ] && MODE="master"

if [ "$MODE" = "tap" ]; then
  COMPOSE_BASE_ARGS=(-f docker-compose.tap.yml)
else
  COMPOSE_BASE_ARGS=()
fi

RUNNING=$(docker compose "${COMPOSE_BASE_ARGS[@]}" ps --services --filter status=running 2>/dev/null | wc -l)
TOTAL=$(docker compose "${COMPOSE_BASE_ARGS[@]}" ps --services 2>/dev/null | wc -l)
IP=$(hostname -I | awk '{print $1}')

echo ""
echo "  ╔══════════════════════════════════════════════╗"
if [ "$MODE" = "tap" ]; then
  printf  "  ║  Cyjan IDS · Remote-Tap %-21s║\n" "${VERSION}"
  echo "  ╠══════════════════════════════════════════════╣"

  # Master-URL aus /etc/cyjan/profile (vom Wizard gesetzt). Reines
  # Host-Read — kein docker compose exec, sonst hängt jeder Login
  # 1-2s am Container-Status.
  MASTER_URL=$(grep -E '^MASTER_URL=' "$IDS_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' | head -c 29)
  [ -z "$MASTER_URL" ] && MASTER_URL=$(grep -E '^MASTER_URL=' "$CYJAN_STATE/profile" 2>/dev/null | cut -d= -f2- | tr -d '"' | head -c 29)
  [ -z "$MASTER_URL" ] && MASTER_URL="(nicht gepairt)"

  # Connection-Status: einfacher Container-Check statt state.json-Parse —
  # zeigt "ok" wenn tap-uplink läuft, "down" wenn nicht. Mehr Detail
  # liefert `cyjan-tap status` on demand.
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^cyjan-tap-uplink$'; then
    CONN="up"
  else
    CONN="down"
  fi

  printf "  ║  Master-URL:    %-29s║\n" "${MASTER_URL}"
  printf "  ║  Uplink:        %-29s║\n" "${CONN}"
  printf "  ║  IP-Adresse:    %-29s║\n" "${IP}"
  printf "  ║  Dienste:       %-3s / %-3s laufen           ║\n" "$RUNNING" "$TOTAL"
  echo "  ╠══════════════════════════════════════════════╣"
  echo "  ║  cyjan-tap status      – Tap-Status anzeigen ║"
  echo "  ║  cyjan-tap pair        – mit Master koppeln  ║"
  echo "  ║  cyjan-tap reconnect   – Reconnect erzwingen ║"
  echo "  ║  cyjan-tap logs follow – Live-Logs streamen  ║"
  echo "  ║  cyjan-tap test        – Test-Alert senden   ║"
  echo "  ║  ids-update            – System aktualisieren║"
  echo "  ║  ids-setup             – Setup neu starten   ║"
  echo "  ╚══════════════════════════════════════════════╝"
else
  printf  "  ║  Cyjan IDS %-34s║\n" "${VERSION}"
  echo "  ╠══════════════════════════════════════════════╣"
  printf "  ║  Web-Interface: http://%-22s║\n" "${IP}/"
  printf "  ║  API / Swagger: http://%-22s║\n" "${IP}:8001/api/docs"
  printf "  ║  Dienste:       %-3s / %-3s laufen           ║\n" "$RUNNING" "$TOTAL"
  echo "  ╠══════════════════════════════════════════════╣"
  echo "  ║  ids-update   – System aktualisieren         ║"
  echo "  ║  ids-setup    – Konfiguration ändern         ║"
  echo "  ╚══════════════════════════════════════════════╝"
fi
echo ""
