#!/bin/bash
# Cyjan IDS – Host-Wartung nach einem GUI-Update.
#
# Wird vom System-Update-ZIP nach /opt/ids/scripts/post-update.sh gelegt
# und einmal manuell mit sudo aufgerufen:
#
#   sudo bash /opt/ids/scripts/post-update.sh
#
# Idempotent — kann beliebig oft laufen. Greift auf Host-Pfade
# (/etc/docker, /etc/systemd) zu, die der API-Update-Container nicht
# selbst editieren kann.
#
# Was es macht:
#   1. /etc/docker/daemon.json mit Container-Log-Cap 50m × 5 versorgen
#      (verhindert dass Retry-Storms das Disk vollschreiben).
#   2. /usr/local/bin/cyjan-maintenance + systemd-Units installieren.
#   3. cyjan-maintenance.timer aktivieren (wöchentliches prune -f).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte als root ausführen: sudo bash $0" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[post-update] Quellverzeichnis: $SRC_DIR"

# ── 1) /etc/docker/daemon.json ───────────────────────────────────────────
# Wir mergen NICHT — wenn dort bereits eine User-Konfig liegt, wird sie
# nur überschrieben falls sie keine log-driver-Einstellung enthält oder
# explizit Default ist. Sonst Backup + Hinweis, kein blindes Überschreiben.
DAEMON_JSON="/etc/docker/daemon.json"
DAEMON_SRC="${SRC_DIR}/daemon.json"
mkdir -p /etc/docker
NEEDS_DOCKER_RESTART=0
if [ ! -f "$DAEMON_JSON" ]; then
  cp "$DAEMON_SRC" "$DAEMON_JSON"
  echo "[post-update] $DAEMON_JSON neu angelegt."
  NEEDS_DOCKER_RESTART=1
elif diff -q "$DAEMON_JSON" "$DAEMON_SRC" >/dev/null 2>&1; then
  echo "[post-update] $DAEMON_JSON bereits aktuell."
elif grep -q '"log-driver"\|"log-opts"' "$DAEMON_JSON" 2>/dev/null; then
  ts="$(date +%Y%m%d-%H%M%S)"
  cp "$DAEMON_JSON" "${DAEMON_JSON}.bak-${ts}"
  echo "[post-update] WARNUNG: vorhandene log-Konfig in $DAEMON_JSON gefunden — nicht überschrieben."
  echo "[post-update]            Vergleiche manuell: diff $DAEMON_JSON $DAEMON_SRC"
else
  ts="$(date +%Y%m%d-%H%M%S)"
  cp "$DAEMON_JSON" "${DAEMON_JSON}.bak-${ts}"
  cp "$DAEMON_SRC" "$DAEMON_JSON"
  echo "[post-update] $DAEMON_JSON ersetzt (Backup: ${DAEMON_JSON}.bak-${ts})."
  NEEDS_DOCKER_RESTART=1
fi

# ── 2) cyjan-maintenance Skript + systemd-Units ──────────────────────────
install -m 0755 "${SRC_DIR}/cyjan-maintenance"          /usr/local/bin/cyjan-maintenance
install -m 0644 "${SRC_DIR}/cyjan-maintenance.service"  /etc/systemd/system/cyjan-maintenance.service
install -m 0644 "${SRC_DIR}/cyjan-maintenance.timer"    /etc/systemd/system/cyjan-maintenance.timer
echo "[post-update] cyjan-maintenance Script + systemd-Units installiert."

systemctl daemon-reload
systemctl enable --now cyjan-maintenance.timer
echo "[post-update] cyjan-maintenance.timer aktiviert (nächster Lauf: $(systemctl show cyjan-maintenance.timer --property=NextElapseUSecRealtime --value 2>/dev/null || echo unbekannt))."

# ── 3) Docker-Daemon neu laden, falls daemon.json sich geändert hat ──────
# `systemctl reload docker` greift NUR den daemon.json-Wechsel ohne
# Container-Restart — das wir wollen, weil Container-Logs sonst kurz
# wegbrechen.
if [ "$NEEDS_DOCKER_RESTART" -eq 1 ]; then
  if systemctl reload docker 2>/dev/null; then
    echo "[post-update] dockerd reloaded (daemon.json aktiv)."
  else
    echo "[post-update] dockerd reload nicht unterstützt — full restart wäre nötig."
    echo "[post-update]   Manuell wenn gewünscht: sudo systemctl restart docker"
    echo "[post-update]   (Achtung: kurzer Container-Stop währenddessen.)"
  fi
fi

echo "[post-update] Fertig."
