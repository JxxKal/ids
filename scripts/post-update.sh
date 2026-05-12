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

# Helper: liefert den ersten existierenden Pfad einer Datei. Im Update-
# ZIP liegen alle Quell-Dateien direkt neben post-update.sh in
# /opt/ids/scripts/. Im git-Checkout sind sie in distro/config/
# includes.chroot/... Der Helper überprüft beide Pfade, damit das
# Script auch aus einem geclonten Repo direkt läuft (typisch beim
# Bootstrap eines Hosts der noch kein Update-ZIP gesehen hat).
REPO_ROOT="$(cd "$SRC_DIR/.." && pwd)"
locate_src() {
  local name="$1" subdir="$2"
  if [ -f "${SRC_DIR}/${name}" ]; then
    echo "${SRC_DIR}/${name}"
  elif [ -f "${REPO_ROOT}/distro/config/includes.chroot/${subdir}/${name}" ]; then
    echo "${REPO_ROOT}/distro/config/includes.chroot/${subdir}/${name}"
  fi
}

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
else
  # Targeted-Migration: log-driver=journald → json-file + live-restore,
  # ohne andere User-Settings (z.B. eigene "hosts": [...]) anzufassen.
  # Wirkt sich nur auf Hosts aus, die noch den alten ISO-Default
  # "journald" tragen — sonst no-op.
  MIGRATED=$(python3 - "$DAEMON_JSON" <<'PY' 2>/dev/null || true
import json, sys
p = sys.argv[1]
try:
    d = json.load(open(p))
except Exception:
    sys.exit(0)
changed = False
if d.get("log-driver") == "journald":
    d["log-driver"] = "json-file"
    d.setdefault("log-opts", {"max-size": "50m", "max-file": "5"})
    changed = True
if "log-driver" not in d:
    d["log-driver"] = "json-file"
    d.setdefault("log-opts", {"max-size": "50m", "max-file": "5"})
    changed = True
if d.get("live-restore") is not True:
    d["live-restore"] = True
    changed = True
if changed:
    json.dump(d, open(p, "w"), indent=2)
    open(p, "a").write("\n")
    print("migrated")
PY
)
  if [ "$MIGRATED" = "migrated" ]; then
    echo "[post-update] $DAEMON_JSON migriert (log-driver→json-file, live-restore=true, andere Felder unverändert)."
    NEEDS_DOCKER_RESTART=1
  else
    echo "[post-update] $DAEMON_JSON unverändert (Custom-log-driver oder schon json-file mit live-restore)."
  fi
fi

# ── 2) cyjan-maintenance Skript + systemd-Units ──────────────────────────
install -m 0755 "${SRC_DIR}/cyjan-maintenance"          /usr/local/bin/cyjan-maintenance
install -m 0644 "${SRC_DIR}/cyjan-maintenance.service"  /etc/systemd/system/cyjan-maintenance.service
install -m 0644 "${SRC_DIR}/cyjan-maintenance.timer"    /etc/systemd/system/cyjan-maintenance.timer
echo "[post-update] cyjan-maintenance Script + systemd-Units installiert."

# ── 3) cyjan-mirror-tune Skript + systemd-Service ────────────────────────
# Optional — Skript-Files sind nur dabei wenn das Update-ZIP sie liefert.
# Älter Update-ZIPs (vor v2.3.9) hatten sie nicht; in dem Fall kein-Op.
if [ -f "${SRC_DIR}/cyjan-mirror-tune" ]; then
  install -m 0755 "${SRC_DIR}/cyjan-mirror-tune"          /usr/local/bin/cyjan-mirror-tune
  install -m 0644 "${SRC_DIR}/cyjan-mirror-tune.service"  /etc/systemd/system/cyjan-mirror-tune.service
  echo "[post-update] cyjan-mirror-tune Script + systemd-Service installiert."
  if ! command -v ethtool >/dev/null 2>&1; then
    echo "[post-update] WARNUNG: ethtool fehlt — sudo apt install -y ethtool"
    echo "[post-update]            Mirror-tune-Service wird ohne ethtool nichts ändern (failsoft)."
  fi
fi

# ── 4) Tap-Update-Trigger (cyjan-tap-update.path + .service) ─────────────
# Greift nur auf Tap-Hosts. Wenn der Master via WebSocket "update_now"
# sendet, schreibt tap-uplink ein File nach /run/cyjan-update/trigger,
# der path-Watcher startet dann den Service der `cyjan-tap update --from-
# master -y` als root auf dem Host aufruft. /run/cyjan-update wird via
# tmpfiles.d bei jedem Boot angelegt.
TAP_PATH_SRC="$(locate_src cyjan-tap-update.path     etc/systemd/system)"
TAP_SVC_SRC="$(locate_src  cyjan-tap-update.service  etc/systemd/system)"
TAP_TMPFILES_SRC="$(locate_src cyjan-update.conf     etc/tmpfiles.d)"
# Fallback: im scripts-Verzeichnis heißt die Tmpfile-Datei
# cyjan-update.tmpfiles (per Konvention im Update-ZIP). Im git-Checkout
# heißt sie cyjan-update.conf.
[ -z "$TAP_TMPFILES_SRC" ] && [ -f "${SRC_DIR}/cyjan-update.tmpfiles" ] && TAP_TMPFILES_SRC="${SRC_DIR}/cyjan-update.tmpfiles"

if [ -n "$TAP_PATH_SRC" ] && [ -n "$TAP_SVC_SRC" ]; then
  install -m 0644 "$TAP_PATH_SRC"     /etc/systemd/system/cyjan-tap-update.path
  install -m 0644 "$TAP_SVC_SRC"      /etc/systemd/system/cyjan-tap-update.service
  if [ -n "$TAP_TMPFILES_SRC" ]; then
    install -m 0644 "$TAP_TMPFILES_SRC" /etc/tmpfiles.d/cyjan-update.conf 2>/dev/null \
      || cp "$TAP_TMPFILES_SRC" /etc/tmpfiles.d/cyjan-update.conf 2>/dev/null \
      || true
  fi
  # Verzeichnis sofort anlegen (vor systemctl restart, damit der bind-mount
  # des Containers nicht ins Leere greift).
  mkdir -p /run/cyjan-update
  chmod 0755 /run/cyjan-update
  echo "[post-update] cyjan-tap-update.path + .service + tmpfiles installiert."
else
  echo "[post-update] WARNUNG: cyjan-tap-update.path/service nicht gefunden — Tap-Push-Update bleibt deaktiviert."
fi

systemctl daemon-reload
systemctl enable --now cyjan-maintenance.timer
echo "[post-update] cyjan-maintenance.timer aktiviert (nächster Lauf: $(systemctl show cyjan-maintenance.timer --property=NextElapseUSecRealtime --value 2>/dev/null || echo unbekannt))."

if [ -f /etc/systemd/system/cyjan-mirror-tune.service ]; then
  systemctl enable cyjan-mirror-tune.service
  # Sofort ausführen — der Stack läuft schon, aber Sniffer würde den
  # neuen Ringbuffer erst bei Restart nutzen. Das macht der Service hier
  # vorbereitend; ein Sniffer-Restart kann der User danach selbst, wenn
  # er sofort die effektiven Drop-Reduktionen sehen will.
  systemctl start cyjan-mirror-tune.service || true
  echo "[post-update] cyjan-mirror-tune.service aktiviert + einmal ausgeführt."
fi

if [ -f /etc/systemd/system/cyjan-tap-update.path ]; then
  systemctl enable --now cyjan-tap-update.path
  echo "[post-update] cyjan-tap-update.path aktiviert (lauscht auf /run/cyjan-update/trigger)."
fi

# ── 5) Tap-Disk-Watch (Auto-Prune bei >85% Disk) ─────────────────────────
# Greift nur auf Tap-Hosts (Master-Hosts hat das cyjan-tap-CLI nicht;
# der Service wird also dort installiert aber nie effektiv).
WATCH_SVC_SRC="$(locate_src cyjan-tap-disk-watch.service etc/systemd/system)"
WATCH_TMR_SRC="$(locate_src cyjan-tap-disk-watch.timer   etc/systemd/system)"
if [ -n "$WATCH_SVC_SRC" ] && [ -n "$WATCH_TMR_SRC" ]; then
  install -m 0644 "$WATCH_SVC_SRC" /etc/systemd/system/cyjan-tap-disk-watch.service
  install -m 0644 "$WATCH_TMR_SRC" /etc/systemd/system/cyjan-tap-disk-watch.timer
  echo "[post-update] cyjan-tap-disk-watch installiert."
  if command -v cyjan-tap >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now cyjan-tap-disk-watch.timer
    echo "[post-update] cyjan-tap-disk-watch.timer aktiviert (15-Min-Check + Auto-Prune >85%)."
  else
    echo "[post-update] cyjan-tap-CLI nicht vorhanden — Timer-Aktivierung übersprungen (Master-Host?)."
  fi
fi

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
