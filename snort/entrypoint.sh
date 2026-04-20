#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Suricata Entrypoint
#
# Umgebungsvariablen:
#   SNORT_IFACE          Interface für Paketerfassung  (Standard: eth0)
#   SNORT_RULESET        emerging-threats | none        (Standard: emerging-threats)
#   SNORT_UPDATE_RULES   true = Regeln beim Start laden (Standard: false)
#
# Laufzeit-Update (via Rules Engine UI):
#   - API schreibt /etc/suricata/rules/update-sources.txt  (eine URL pro Zeile)
#   - API schreibt /etc/suricata/rules/update.trigger
#   - Polling-Schleife erkennt Trigger, lädt Regeln, sendet SIGUSR2 (Live-Reload)
# ══════════════════════════════════════════════════════════════════════════════
set -e

IFACE="${SNORT_IFACE:-eth0}"
RULESET="${SNORT_RULESET:-emerging-threats}"
UPDATE="${SNORT_UPDATE_RULES:-false}"
RULES_DIR="/etc/suricata/rules"
LOG_DIR="/var/log/suricata"

mkdir -p "$LOG_DIR" "$RULES_DIR"

# ─── Suricata-Version ermitteln (für ET-Regel-URL) ────────────────────────────
SUR_MAJOR=$(suricata --build-info 2>/dev/null \
    | grep -oE 'version [0-9]+' | grep -oE '[0-9]+' | head -1 || echo "6")
[ -z "$SUR_MAJOR" ] && SUR_MAJOR="6" 
ET_BASE="https://rules.emergingthreats.net/open/suricata-${SUR_MAJOR}.0"

# ─── Hilfsfunktion: einzelne URL laden ────────────────────────────────────────
download_source() {
    local url="$1"
    url="${url//\{version\}/${SUR_MAJOR}.0}"

    if echo "$url" | grep -q '\.tar\.gz$'; then
        echo "[suricata] Lade Tarball: $url"
        if curl -sSL --max-time 300 "$url" | tar -xzC "$RULES_DIR" --strip-components=1 2>/dev/null; then
            echo "[suricata] Tarball entpackt"
        else
            echo "[suricata] WARNUNG: Tarball-Download fehlgeschlagen: $url"
        fi
    else
        local fname
        fname=$(basename "$url" | sed 's/[?#].*//')
        echo "[suricata] Lade Rules-Datei: $url → $fname"
        if curl -sSL --max-time 120 -o "${RULES_DIR}/${fname}" "$url"; then
            local cnt
            cnt=$(grep -c '^alert\|^drop' "${RULES_DIR}/${fname}" 2>/dev/null || echo '?')
            echo "[suricata] ${cnt} Regeln in ${fname}"
        else
            echo "[suricata] WARNUNG: Download fehlgeschlagen: $url"
        fi
    fi
}

# ─── Initiales Laden beim Start ────────────────────────────────────────────────
if [ -f "${RULES_DIR}/update-sources.txt" ]; then
    # Konfigurierte Quellen aus dem Rules-Engine-Volume
    if [ -z "$(ls -A "${RULES_DIR}"/*.rules 2>/dev/null)" ] || [ "$UPDATE" = "true" ]; then
        echo "[suricata] Lade Regeln aus konfigurierten Quellen..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            download_source "$url"
        done < "${RULES_DIR}/update-sources.txt"
    else
        COUNT=$(cat "$RULES_DIR"/*.rules 2>/dev/null | grep -c '^alert\|^drop' || echo '?')
        echo "[suricata] ${COUNT} Signaturen vorhanden (Cache)"
    fi
elif [ "$RULESET" != "none" ]; then
    # Fallback: ET Open Tarball
    if [ -z "$(ls -A "${RULES_DIR}"/*.rules 2>/dev/null)" ] || [ "$UPDATE" = "true" ]; then
        echo "[suricata] Lade Emerging Threats Open Regeln (Suricata ${SUR_MAJOR}.x)..."
        if curl -sSL --max-time 180 "${ET_BASE}/emerging.rules.tar.gz" \
            | tar -xzC "$RULES_DIR" --strip-components=1 2>/dev/null; then
            COUNT=$(cat "$RULES_DIR"/*.rules 2>/dev/null | grep -c '^alert\|^drop' || echo '?')
            echo "[suricata] ${COUNT} ET-Signaturen geladen"
        else
            echo "[suricata] WARNUNG: ET-Download fehlgeschlagen – starte ohne externe Regeln"
        fi
    else
        COUNT=$(cat "$RULES_DIR"/*.rules 2>/dev/null | grep -c '^alert\|^drop' || echo '?')
        echo "[suricata] ${COUNT} Signaturen vorhanden (Cache)"
    fi
fi

# ─── Minimale suricata.yaml generieren ────────────────────────────────────────
cat > /tmp/suricata.yaml << YAML
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8,::1]"
    EXTERNAL_NET: "!\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: 22
    FTP_PORTS: 21

default-log-dir: ${LOG_DIR}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - drop

af-packet:
  - interface: default
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

default-rule-path: ${RULES_DIR}
rule-files:
  - "*.rules"

detect:
  profile: low

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      enabled: yes

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
YAML

echo "[suricata] Starte auf Interface ${IFACE}"
echo "[suricata] Alerts → ${LOG_DIR}/eve.json"

# ─── Suricata im Hintergrund starten ──────────────────────────────────────────
suricata -c /tmp/suricata.yaml -i "$IFACE" -l "$LOG_DIR" &
SURICATA_PID=$!
echo "[suricata] PID ${SURICATA_PID}"

# ─── Trigger-Polling-Schleife (alle 30 s) ─────────────────────────────────────
while kill -0 "$SURICATA_PID" 2>/dev/null; do
    sleep 30

    TRIGGER="${RULES_DIR}/update.trigger"
    SOURCES="${RULES_DIR}/update-sources.txt"

    if [ -f "$TRIGGER" ]; then
        echo "[suricata] Update-Trigger erkannt – lade Regeln neu..."
        rm -f "$TRIGGER"

        if [ -f "$SOURCES" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                download_source "$url"
            done < "$SOURCES"
        else
            echo "[suricata] Keine Quellen-Datei – lade ET Open Fallback..."
            curl -sSL --max-time 180 "${ET_BASE}/emerging.rules.tar.gz" \
                | tar -xzC "$RULES_DIR" --strip-components=1 2>/dev/null || true
        fi

        COUNT=$(cat "$RULES_DIR"/*.rules 2>/dev/null | grep -c '^alert\|^drop' || echo '?')
        echo "[suricata] ${COUNT} Regeln geladen – sende SIGUSR2 für Live-Reload"
        kill -USR2 "$SURICATA_PID" 2>/dev/null || true
    fi
done

echo "[suricata] Suricata-Prozess beendet (PID ${SURICATA_PID})"
