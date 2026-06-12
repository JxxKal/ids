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
else
  # Targeted-Migration: log-driver=journald → json-file + live-restore,
  # ohne andere User-Settings (z.B. eigene "hosts": [...]) anzufassen.
  # Idempotent — wenn alles schon korrekt ist, kein Schreibvorgang.
  # Wir verlassen uns NICHT auf diff -q gegen DAEMON_SRC, weil ältere
  # ZIPs ein veraltetes scripts/daemon.json mitlieferten (ohne
  # live-restore=true); ein bitidentischer Match wäre dann ein
  # "alles ok"-Trugschluss.
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
    echo "[post-update] $DAEMON_JSON bereits aktuell (json-file + live-restore)."
  fi
fi

# ── 2) cyjan-maintenance Skript + systemd-Units ──────────────────────────
MAINT_BIN_SRC="$(locate_src cyjan-maintenance         usr/local/bin)"
MAINT_SVC_SRC="$(locate_src cyjan-maintenance.service etc/systemd/system)"
MAINT_TMR_SRC="$(locate_src cyjan-maintenance.timer   etc/systemd/system)"
if [ -n "$MAINT_BIN_SRC" ] && [ -n "$MAINT_SVC_SRC" ] && [ -n "$MAINT_TMR_SRC" ]; then
  install -m 0755 "$MAINT_BIN_SRC" /usr/local/bin/cyjan-maintenance
  install -m 0644 "$MAINT_SVC_SRC" /etc/systemd/system/cyjan-maintenance.service
  install -m 0644 "$MAINT_TMR_SRC" /etc/systemd/system/cyjan-maintenance.timer
  echo "[post-update] cyjan-maintenance Script + systemd-Units installiert."
else
  echo "[post-update] WARNUNG: cyjan-maintenance-Quellen nicht gefunden — übersprungen."
fi

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

# ── 5) cyjan-stack Boot-Unit (v2.5.28+) ──────────────────────────────────
# Bringt nach einem Reboot den VOLLEN Soll-Stack hoch (`docker compose
# --profile <prod|…> up -d`) statt sich auf die per-Container restart-Policy
# zu verlassen. Letztere startet nach einem Reboot NUR die Container, die
# vorher liefen — war ein Service (oder das halbe Stack) vorher gestoppt
# (z.B. nach einem `docker stop`, einem abgebrochenen Update oder einem
# `compose stop`), blieb er nach dem Reboot weg. Genau das hat auf
# Bestands-Hosts ohne diese Unit zum kompletten Web-Ausfall geführt.
#
# Diese Unit kam erst nach dem ersten ISO-Release dazu; Hosts die aus einem
# älteren ISO installiert und nur per `cyjan-update` aktuell gehalten wurden,
# haben sie nie bekommen (cyjan-update fasst die systemd-Layer nicht an).
# Hier wird sie idempotent nachgezogen.
STACK_BIN_SRC="$(locate_src cyjan-stack-up      usr/local/bin)"
STACK_SVC_SRC="$(locate_src cyjan-stack.service etc/systemd/system)"
if [ -n "$STACK_BIN_SRC" ] && [ -n "$STACK_SVC_SRC" ]; then
  install -m 0755 "$STACK_BIN_SRC" /usr/local/bin/cyjan-stack-up
  install -m 0644 "$STACK_SVC_SRC" /etc/systemd/system/cyjan-stack.service
  echo "[post-update] cyjan-stack-up + cyjan-stack.service installiert."
else
  echo "[post-update] WARNUNG: cyjan-stack-Quellen nicht gefunden — Boot-Stack-Unit übersprungen."
fi

# ── 5b) Boot-Health-Check + Alarm (v2.5.32+) ─────────────────────────────
# cyjan-stack.service galt bisher als "erfolgreich", sobald compose up -d
# exitete — ob die Container wirklich hochkamen, prüfte niemand (so blieb der
# halbe Stack nach dem OT-Reboot 22 h unbemerkt down). cyjan-stack-health wird
# per Wants= von cyjan-stack.service mitgezogen, pollt den Soll-Zustand und
# eskaliert bei Fehlschlag über cyjan-stack-alert (journal + wall + motd +
# Best-Effort-Alert in der DB). Keine [Install]-Section → kein enable nötig.
HEALTH_BIN_SRC="$(locate_src cyjan-stack-health         usr/local/bin)"
ALERT_BIN_SRC="$(locate_src cyjan-stack-alert           usr/local/bin)"
HEALTH_SVC_SRC="$(locate_src cyjan-stack-health.service etc/systemd/system)"
ALERT_SVC_SRC="$(locate_src cyjan-stack-alert.service   etc/systemd/system)"
if [ -n "$HEALTH_BIN_SRC" ] && [ -n "$ALERT_BIN_SRC" ] && [ -n "$HEALTH_SVC_SRC" ] && [ -n "$ALERT_SVC_SRC" ]; then
  install -m 0755 "$HEALTH_BIN_SRC" /usr/local/bin/cyjan-stack-health
  install -m 0755 "$ALERT_BIN_SRC"  /usr/local/bin/cyjan-stack-alert
  install -m 0644 "$HEALTH_SVC_SRC" /etc/systemd/system/cyjan-stack-health.service
  install -m 0644 "$ALERT_SVC_SRC"  /etc/systemd/system/cyjan-stack-alert.service
  echo "[post-update] cyjan-stack-health + cyjan-stack-alert installiert (greift beim nächsten Reboot)."
else
  echo "[post-update] WARNUNG: cyjan-stack-health/alert-Quellen nicht gefunden — Boot-Health-Check übersprungen."
fi

# ── 5c) cyjan-update Self-Update (v2.5.33+) ──────────────────────────────
# post-update.sh läuft typischerweise AUS cyjan-update heraus — ein direktes
# install/cp auf /usr/local/bin/cyjan-update würde in das gerade laufende
# Skript schreiben (bash liest inkrementell vom File → korrupte Reads).
# Deshalb atomar: in eine Temp-Datei daneben kopieren und per mv(1) drüber-
# renamen. Die laufende bash hält den ALTEN Inode und liest sauber zu Ende;
# ab dem nächsten Aufruf gilt die neue Fassung. (cyjan-tap bleibt bewusst
# manuell — siehe Kommentar im Release-Workflow.)
UPDATE_BIN_SRC="$(locate_src cyjan-update usr/local/bin)"
if [ -n "$UPDATE_BIN_SRC" ]; then
  if ! cmp -s "$UPDATE_BIN_SRC" /usr/local/bin/cyjan-update 2>/dev/null; then
    cp "$UPDATE_BIN_SRC" /usr/local/bin/.cyjan-update.new
    chmod 0755 /usr/local/bin/.cyjan-update.new
    mv -f /usr/local/bin/.cyjan-update.new /usr/local/bin/cyjan-update
    echo "[post-update] cyjan-update atomar aktualisiert (gilt ab dem nächsten Aufruf)."
  else
    echo "[post-update] cyjan-update bereits aktuell."
  fi
else
  echo "[post-update] WARNUNG: cyjan-update-Quelle nicht gefunden — Self-Update übersprungen."
fi

systemctl daemon-reload
systemctl enable --now cyjan-maintenance.timer

# cyjan-stack.service nur ARMIEREN (enable), NICHT --now starten: auf einem
# gesunden, laufenden Host würde `start` zwar nur ein idempotentes up -d
# auslösen, aber wir wollen während eines Routine-Updates bewusst nicht in
# den laufenden Stack greifen. Die Unit wird beim nächsten Reboot aktiv und
# erzwingt dann den vollen Soll-Zustand. Wer den vollen Stack sofort hochziehen
# will: `sudo systemctl start cyjan-stack.service` (== docker compose up -d).
if [ -f /etc/systemd/system/cyjan-stack.service ]; then
  if systemctl enable cyjan-stack.service 2>/dev/null; then
    echo "[post-update] cyjan-stack.service aktiviert (greift beim nächsten Reboot → voller Soll-Stack)."
  else
    echo "[post-update] WARNUNG: cyjan-stack.service konnte nicht enabled werden."
  fi
fi

# ── 6) Ctrl-Alt-Del-Hardening (v2.5.28+) ─────────────────────────────────
# Linux verlinkt ctrl-alt-del.target standardmäßig auf reboot.target. Auf
# einem Master-Host ist das brandgefährlich: ein angestöpselter IP-KVM
# (z.B. Raritan D2CIM-DVUSB) meldet sich als USB-Tastatur an und sendet beim
# Anstecken ein Ctrl-Alt-Del → die Box rebootet mitten im Produktivbetrieb.
# Genau das hat einen Komplett-Ausfall ausgelöst. Wir maskieren das Target,
# damit Strg-Alt-Entf an der Konsole nichts mehr auslöst (reversibel via
# `systemctl unmask ctrl-alt-del.target`). Idempotent — `mask` ist no-op,
# wenn der Symlink nach /dev/null schon steht.
if [ "$(readlink -f /etc/systemd/system/ctrl-alt-del.target 2>/dev/null)" = "/dev/null" ]; then
  echo "[post-update] ctrl-alt-del.target bereits maskiert."
else
  systemctl mask ctrl-alt-del.target >/dev/null 2>&1 \
    && echo "[post-update] ctrl-alt-del.target maskiert (KVM/Versehen kann nicht mehr rebooten)." \
    || echo "[post-update] WARNUNG: ctrl-alt-del.target konnte nicht maskiert werden."
fi

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
  # enable --now ist no-op wenn die Unit schon enabled ist — wenn sie
  # zwischenzeitlich auf "inactive (dead)" gekippt ist (z.B. nach dockerd-
  # Restart wegen daemon.json-Migration), kommt sie damit NICHT wieder
  # hoch. Daher explizit `restart` — idempotent, zwingt einen sauberen
  # Reset auch auf einem "dead"-State.
  systemctl enable cyjan-tap-update.path 2>/dev/null || true
  systemctl restart cyjan-tap-update.path
  STATE=$(systemctl is-active cyjan-tap-update.path 2>/dev/null || echo "?")
  echo "[post-update] cyjan-tap-update.path → $STATE (lauscht auf /run/cyjan-update/trigger)."
  if [ "$STATE" != "active" ]; then
    echo "[post-update] WARNUNG: Path-Watcher ist '$STATE' — Diagnose: sudo journalctl -u cyjan-tap-update.path -n 50"
  fi
fi

# ── 4.3) ids-banner.sh (Login-MOTD) ─────────────────────────────────────
# Bislang nur im frischen ISO eingebacken. Wenn neue Subkommandos
# (cyjan-update, neue Tap-Commands etc.) im Banner stehen, soll das auch
# auf Bestands-Hosts ankommen — sonst sieht der User beim SSH-Login
# weiter den Stand seiner Erst-Installation.
BANNER_SRC="$(locate_src ids-banner.sh etc/profile.d)"
if [ -n "$BANNER_SRC" ]; then
  install -m 0644 "$BANNER_SRC" /etc/profile.d/ids-banner.sh
  echo "[post-update] /etc/profile.d/ids-banner.sh aktualisiert."
fi

# ── 4.4) cyjan-update (Console-Updater für den Master) ──────────────────
# Bringt v2.5.10+ am Master einen klickfreien Update-Pfad: SSH rein →
# cyjan-update apply → fertig. Funktioniert symmetrisch zu cyjan-tap.
CYJUP_SRC="$(locate_src cyjan-update usr/local/bin)"
if [ -n "$CYJUP_SRC" ]; then
  install -m 0755 "$CYJUP_SRC" /usr/local/bin/cyjan-update
  echo "[post-update] cyjan-update installiert (Console-Updater)."
fi

# ── 4.5) cyjan-host-interfaces (NIC-Liste für Settings-Migration) ────────
# Schreibt /etc/cyjan/host-interfaces.json minütlich. Der api-Container
# mountet /etc/cyjan readonly und liest dort die echten Host-NICs für den
# Migration-Preview. Greift auf Master + Tap symmetrisch — am Tap ist es
# vorerst no-op, aber harmlos.
HIF_BIN_SRC="$(locate_src cyjan-host-interfaces           usr/local/bin)"
HIF_SVC_SRC="$(locate_src cyjan-host-interfaces.service   etc/systemd/system)"
HIF_TMR_SRC="$(locate_src cyjan-host-interfaces.timer     etc/systemd/system)"
if [ -n "$HIF_BIN_SRC" ] && [ -n "$HIF_SVC_SRC" ] && [ -n "$HIF_TMR_SRC" ]; then
  install -m 0755 "$HIF_BIN_SRC" /usr/local/bin/cyjan-host-interfaces
  install -m 0644 "$HIF_SVC_SRC" /etc/systemd/system/cyjan-host-interfaces.service
  install -m 0644 "$HIF_TMR_SRC" /etc/systemd/system/cyjan-host-interfaces.timer
  mkdir -p /etc/cyjan
  # Initial-Run einmalig, damit das File schon da ist wenn die api-
  # Container das erste Mal startet (sonst zeigt das Frontend "Iface-Liste
  # nicht verfügbar" bis der erste Timer-Tick durch ist).
  /usr/local/bin/cyjan-host-interfaces || true
  systemctl daemon-reload
  systemctl enable --now cyjan-host-interfaces.timer
  echo "[post-update] cyjan-host-interfaces installiert + Timer aktiviert (minütlicher NIC-Snapshot)."
else
  echo "[post-update] WARNUNG: cyjan-host-interfaces-Quellen nicht gefunden — Settings-Migration-Preview ohne Iface-Liste."
fi

# ── 5) Tap-Disk-Watch (Auto-Prune bei >85% Disk) ─────────────────────────
# Tap-only. Der Timer wird AUSSCHLIESSLICH auf Hosts mit /etc/cyjan/mode==tap
# aktiviert. Früherer Bug: das Gate war `command -v cyjan-tap` — auf Master-
# Hosts, die die cyjan-tap-CLI mitgebracht haben (aber kein mode-File), wurde
# der Timer fälschlich aktiv und failte alle 15 min (kaputtes inline-awk).
# Jetzt: auf Nicht-Tap-Hosts wird er aktiv DEAKTIVIERT (Cleanup für bestehende
# Fehl-Aktivierungen). Die Logik liegt im Skript cyjan-tap-disk-watch, das
# zusätzlich selbst auf mode==tap prüft (Defense in Depth).
WATCH_BIN_SRC="$(locate_src cyjan-tap-disk-watch         usr/local/bin)"
WATCH_SVC_SRC="$(locate_src cyjan-tap-disk-watch.service etc/systemd/system)"
WATCH_TMR_SRC="$(locate_src cyjan-tap-disk-watch.timer   etc/systemd/system)"
if [ -n "$WATCH_SVC_SRC" ] && [ -n "$WATCH_TMR_SRC" ]; then
  [ -n "$WATCH_BIN_SRC" ] && install -m 0755 "$WATCH_BIN_SRC" /usr/local/bin/cyjan-tap-disk-watch
  install -m 0644 "$WATCH_SVC_SRC" /etc/systemd/system/cyjan-tap-disk-watch.service
  install -m 0644 "$WATCH_TMR_SRC" /etc/systemd/system/cyjan-tap-disk-watch.timer
  echo "[post-update] cyjan-tap-disk-watch installiert."
  systemctl daemon-reload
  HOST_MODE="$(cat /etc/cyjan/mode 2>/dev/null | tr -d '[:space:]')"
  if [ "$HOST_MODE" = "tap" ]; then
    systemctl enable --now cyjan-tap-disk-watch.timer
    echo "[post-update] cyjan-tap-disk-watch.timer aktiviert (15-Min-Check + Auto-Prune >85%)."
  else
    systemctl disable --now cyjan-tap-disk-watch.timer 2>/dev/null || true
    echo "[post-update] cyjan-tap-disk-watch.timer deaktiviert (kein Tap-Host)."
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
