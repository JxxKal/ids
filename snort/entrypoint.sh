#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Snort 3 Entrypoint
#
# Umgebungsvariablen:
#   SNORT_IFACE          Interface für Paketerfassung (Standard: eth0)
#   SNORT_RULESET        community | emerging-threats | both  (Standard: community)
#   SNORT_UPDATE_RULES   true = Regeln immer neu laden        (Standard: false)
# ══════════════════════════════════════════════════════════════════════════════
set -e

IFACE="${SNORT_IFACE:-eth0}"
RULESET="${SNORT_RULESET:-community}"
UPDATE="${SNORT_UPDATE_RULES:-false}"
RULES_DIR="/etc/snort/rules"
LOG_DIR="/var/log/snort"

mkdir -p "$LOG_DIR" "$RULES_DIR"

# ─── Snort 3 Community Rules ──────────────────────────────────────────────────
if [ ! -f "$RULES_DIR/snort3-community.rules" ] || [ "$UPDATE" = "true" ]; then
    echo "[snort] Lade Snort 3 Community-Regeln..."
    if curl -sSL --max-time 90 \
        "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz" \
        | tar -xzO snort3-community-rules/snort3-community.rules \
        > "$RULES_DIR/snort3-community.rules"; then
        echo "[snort] Community-Regeln: $(grep -c '^alert\|^drop' "$RULES_DIR/snort3-community.rules" 2>/dev/null || echo '?') Signaturen"
    else
        echo "[snort] WARNUNG: Community-Download fehlgeschlagen – starte ohne Regeln."
        touch "$RULES_DIR/snort3-community.rules"
    fi
else
    echo "[snort] Community-Regeln vorhanden ($(grep -c '^alert\|^drop' "$RULES_DIR/snort3-community.rules" 2>/dev/null || echo '?') Signaturen)"
fi

# ─── Emerging Threats Open (optional) ────────────────────────────────────────
if [ "$RULESET" = "emerging-threats" ] || [ "$RULESET" = "both" ]; then
    if [ ! -f "$RULES_DIR/emerging-all.rules" ] || [ "$UPDATE" = "true" ]; then
        echo "[snort] Lade Emerging Threats Open-Regeln (Snort 2.9 Format)..."
        if curl -sSL --max-time 180 \
            "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules" \
            -o "$RULES_DIR/emerging-all.rules"; then
            echo "[snort] ET-Regeln: $(grep -c '^alert\|^drop' "$RULES_DIR/emerging-all.rules" 2>/dev/null || echo '?') Signaturen"
        else
            echo "[snort] WARNUNG: ET-Download fehlgeschlagen."
            rm -f "$RULES_DIR/emerging-all.rules"
        fi
    else
        echo "[snort] ET-Regeln vorhanden ($(grep -c '^alert\|^drop' "$RULES_DIR/emerging-all.rules" 2>/dev/null || echo '?') Signaturen)"
    fi
fi

# ─── snort.lua dynamisch generieren ──────────────────────────────────────────
INCLUDE_FILES="$RULES_DIR/snort3-community.rules"
if [ -f "$RULES_DIR/emerging-all.rules" ]; then
    INCLUDE_FILES="$INCLUDE_FILES $RULES_DIR/emerging-all.rules"
fi

RULE_COUNT=$(for f in $INCLUDE_FILES; do grep -c '^alert\|^drop' "$f" 2>/dev/null || echo 0; done | awk '{s+=$1} END{print s}')

cat > /tmp/snort.lua << EOF
-- IDS · Snort 3 Konfiguration  (generiert $(date '+%Y-%m-%dT%H:%M:%S'))
-- Interface: $IFACE  |  Regelsets: $RULESET  |  Signaturen: $RULE_COUNT

-- Stream-Reassembly
stream     = {}
stream_tcp = { policy = 'windows' }
stream_udp = {}
stream_icmp = {}

-- Applikations-Inspektoren
http_inspect = {}
dns  = {}
ssh  = {}
ssl  = {}
smtp = {}
ftp_server = {}
ftp_client = {}

-- IPS
ips = {
    enable_builtin_rules = true,
    include              = '$INCLUDE_FILES',
    action_override      = 'alert',
}

-- JSON-Output: eine Zeile pro Alert → $LOG_DIR/alert_json.txt
alert_json = { file = true }
EOF

echo "[snort] Konfiguration erstellt – $RULE_COUNT Signaturen auf Interface $IFACE"
echo "[snort] Alerts → $LOG_DIR/alert_json.txt"

exec snort \
    -c /tmp/snort.lua \
    -i "$IFACE" \
    -l "$LOG_DIR" \
    --warn-all
