#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Suricata Entrypoint  (ersetzt Snort 3 – kein offizielles Paket verfügbar)
#
# Umgebungsvariablen:
#   SNORT_IFACE          Interface für Paketerfassung  (Standard: eth0)
#   SNORT_RULESET        emerging-threats | none        (Standard: emerging-threats)
#   SNORT_UPDATE_RULES   true = Regeln neu laden        (Standard: false)
# ══════════════════════════════════════════════════════════════════════════════
set -e

IFACE="${SNORT_IFACE:-eth0}"
RULESET="${SNORT_RULESET:-emerging-threats}"
UPDATE="${SNORT_UPDATE_RULES:-false}"
RULES_DIR="/etc/suricata/rules"
LOG_DIR="/var/log/suricata"

mkdir -p "$LOG_DIR" "$RULES_DIR"

# ─── Suricata-Version ermitteln (für ET-Regel-URL) ───────────────────────────
SUR_MAJOR=$(suricata --build-info 2>/dev/null \
    | awk '/^Version:/{print $2}' \
    | cut -d. -f1 || echo "6")
ET_BASE="https://rules.emergingthreats.net/open/suricata-${SUR_MAJOR}.0"

# ─── Emerging Threats Open Rules ─────────────────────────────────────────────
if [ "$RULESET" != "none" ]; then
    if [ -z "$(ls -A "$RULES_DIR"/*.rules 2>/dev/null)" ] || [ "$UPDATE" = "true" ]; then
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
exec suricata -c /tmp/suricata.yaml -i "$IFACE" -l "$LOG_DIR"
