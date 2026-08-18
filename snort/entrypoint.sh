#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Suricata Entrypoint
#
# Umgebungsvariablen:
#   SNORT_IFACE          Interfaces für Paketerfassung — SPACE-SEPARATED.
#                        Beispiel: "enp84s0 cy-inj-peer" capturet Mgmt-Mirror
#                        UND RedTeam-veth. (Standard: eth0)
#   SNORT_RULESET        emerging-threats | none        (Standard: emerging-threats)
#   SNORT_UPDATE_RULES   true = Regeln beim Start laden (Standard: false)
#
# Laufzeit-Update (via Rules Engine UI):
#   - API schreibt /etc/suricata/rules/update-sources.txt  (eine URL pro Zeile)
#   - API schreibt /etc/suricata/rules/update.trigger
#   - Polling-Schleife erkennt Trigger und triggert ruleset-reload-rules
#     über den Unix-Command-Socket (suricatasc).
# Hinweis: SIGUSR2 ist in Suricata nur für eve-Logfile-Rotation, NICHT
# für Rule-Reload — das war ein historisches Missverständnis.
# ══════════════════════════════════════════════════════════════════════════════
set -e

IFACE="${SNORT_IFACE:-eth0}"
RULESET="${SNORT_RULESET:-emerging-threats}"
UPDATE="${SNORT_UPDATE_RULES:-false}"
RULES_DIR="/etc/suricata/rules"
LOG_DIR="/var/log/suricata"

# ─── eve.json: Umfang und Größenbremse ────────────────────────────────────────
# Suricata schreibt in eve.json auf Wunsch die komplette Protokoll-Telemetrie
# (jede DNS-Abfrage, jede Modbus-Transaktion …). Für das RedTeam-Tooling ist
# das der Sinn der Sache; snort-bridge dagegen liest ausschließlich
# event_type alert/drop und verwirft den Rest sofort.
#
# Auf einem produktiven OT-Master wurde damit ein eve.json von 104 GB
# erzeugt, das nie jemand gelesen hat. Deshalb: Telemetrie folgt per Default
# dem Lab-Schalter und ist produktiv aus.
REDTEAM_ENABLED="${REDTEAM_ENABLED:-false}"
EVE_PROTO_LOGS="${SNORT_EVE_PROTOCOL_LOGS:-$REDTEAM_ENABLED}"
# Notbremse: Suricata rotiert nicht selbst. 0 schaltet sie ab.
# Auf der Platte liegen im schlimmsten Fall ~2× dieser Wert (aktuelle Datei
# plus eine aufgehobene Generation .1).
EVE_MAX_MB="${SNORT_EVE_MAX_MB:-2048}"

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

# ─── Iface-Availability — auf bis zu 60s warten ─────────────────────────────
# cy-inj-peer wird vom redteam-orchestrator zur Laufzeit angelegt. Wenn
# snort vor dem orchestrator startet, ist der veth noch nicht da → wir
# warten, skipen aber fehlende nach Timeout (graceful degrade: lieber
# auf Mgmt-Iface allein laufen als gar nicht).
AVAILABLE_IFACES=""
for one_iface in $IFACE; do
    deadline=$(( $(date +%s) + 60 ))
    while ! ip link show "$one_iface" >/dev/null 2>&1; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "[suricata] WARNUNG: Iface $one_iface nach 60s nicht da — skip"
            one_iface=""
            break
        fi
        echo "[suricata] warte auf Iface $one_iface ..."
        sleep 2
    done
    [ -n "$one_iface" ] && AVAILABLE_IFACES="$AVAILABLE_IFACES $one_iface"
done
AVAILABLE_IFACES=$(echo "$AVAILABLE_IFACES" | xargs)  # trim

if [ -z "$AVAILABLE_IFACES" ]; then
    echo "[suricata] FATAL: kein einziges Iface aus '$IFACE' verfügbar"
    exit 1
fi

# ─── af-packet-Blöcke pro Interface generieren ─────────────────────────────────
# Pro Iface eigener cluster-id (sonst rejected Suricata).
AF_PACKET_BLOCK=""
CLUSTER_ID=99
for one_iface in $AVAILABLE_IFACES; do
    AF_PACKET_BLOCK="${AF_PACKET_BLOCK}
  - interface: ${one_iface}
    cluster-id: ${CLUSTER_ID}
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes"
    CLUSTER_ID=$((CLUSTER_ID - 1))
done

# ─── suricata.yaml generieren ─────────────────────────────────────────────────
# ─── eve.json-Typen zusammenstellen ───────────────────────────────────────────
# snort-bridge braucht nur alert/drop. Alles andere ist Telemetrie fürs Lab.
if [ "$EVE_PROTO_LOGS" = "true" ]; then
  echo "[suricata] eve.json: Alarme + volle Protokoll-Telemetrie (Lab-Modus)"
  EVE_TYPES_BLOCK=$(cat <<'EVETYPES'
      types:
        - alert
        - drop
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - smb
        - krb5
        - dcerpc
        - dnp3
        - modbus
        - rdp
        - mqtt
        - quic
        - smtp
        - ssh
        - ftp
        - tftp
        - ike
        - sip
        - flow
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
EVETYPES
)
else
  echo "[suricata] eve.json: nur Alarme (SNORT_EVE_PROTOCOL_LOGS=true fuer Telemetrie)"
  EVE_TYPES_BLOCK=$(cat <<'EVETYPES'
      types:
        - alert
        - drop
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
EVETYPES
)
fi

cat > /tmp/suricata.yaml << YAML
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8,192.0.2.0/24,198.51.100.0/24,203.0.113.0/24]"
    EXTERNAL_NET: "!\$HOME_NET"
    # Server-Address-Groups — ET-Open-Rules referenzieren diese und failen
    # silent wenn nicht definiert. Default-Behavior: alle Server liegen
    # im HOME_NET (Lab-Setup). Bei Bedarf einzelne via .env-Override
    # eingrenzen, z.B. nur 192.168.1.0/24 für SQL_SERVERS.
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    SSH_SERVERS: "\$HOME_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
  port-groups:
    HTTP_PORTS: "[80,8080,8000,8008,8888,3128,8081,8181]"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
    FTP_PORTS: "21"
    SMTP_PORTS: "25"
    DNS_PORTS: "53"
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    MODBUS_PORTS: "502"
    KERBEROS_PORTS: "88"
    ORACLE_PORTS: "1521"

default-log-dir: ${LOG_DIR}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      # Suricata-7-Parser-Outputs: jeder Eintrag emittiert Protokoll-Telemetrie
      # auch ohne Alarm — wichtig damit das RedTeam-Tooling sehen kann was
      # erkannt wurde (z.B. KRB5-cname, OPC-UA-EndpointUrl, SMB-Dialect).
${EVE_TYPES_BLOCK}

af-packet:${AF_PACKET_BLOCK}

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
    # ICS/SCADA — wichtig für Modbus/DNP3/ENIP-Detection
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
    enip:
      enabled: yes
      detection-ports:
        dp: 44818
    # Windows-Auth — wichtig für Kerberos/SMB/NTLM
    smb:
      enabled: yes
      detection-ports:
        dp: 139,445
    krb5:
      enabled: yes
    dcerpc:
      enabled: yes
    nfs:
      enabled: yes
    ntp:
      enabled: yes
    rdp:
      enabled: yes
    snmp:
      enabled: yes
    # Suricata-7-additions — auf 6.x werden diese keys ignoriert (warning),
    # auf 7.x aktivieren sie die nativen Parser:
    http2:
      enabled: yes
    quic:
      enabled: yes
    mqtt:
      enabled: yes
    bittorrent-dht:
      enabled: yes
    tftp:
      enabled: yes
    ike:
      enabled: yes
    sip:
      enabled: yes
    pgsql:
      enabled: yes

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

unix-command:
  enabled: yes
  filename: /var/run/suricata-command.socket
YAML

echo "[suricata] Starte auf Interfaces: ${AVAILABLE_IFACES}"
echo "[suricata] Alerts → ${LOG_DIR}/eve.json"

# ─── Suricata im Hintergrund starten ──────────────────────────────────────────
# KEIN -i mehr (sonst überschreibt CLI alle af-packet-Blöcke aus der yaml).
# --af-packet aktiviert den Capture-Mode aus der yaml-Config.
suricata -c /tmp/suricata.yaml --af-packet -l "$LOG_DIR" &
SURICATA_PID=$!
echo "[suricata] PID ${SURICATA_PID}"

# ─── Trigger-Polling-Schleife (alle 30 s) ─────────────────────────────────────
while kill -0 "$SURICATA_PID" 2>/dev/null; do
    sleep 30

    # ── eve.json-Notbremse ────────────────────────────────────────────────
    # Suricata bringt keine eigene Rotation für filetype: regular mit. Ohne
    # diese Bremse läuft die Datei auf einem Langläufer bis zur vollen
    # Platte — auf einem OT-Master real mit 104 GB beobachtet.
    #
    # Wir rotieren per Umbenennen und lassen Suricata die Datei über den
    # Command-Socket neu öffnen; das ist der saubere Weg und hinterlässt
    # keine sparse-Datei, wie es ein blindes Truncate täte, falls Suricata
    # den Log nicht im Append-Modus hält. Klappt der Socket nicht, kürzen
    # wir als Rückfallebene.
    #
    # snort-bridge übersteht beides: es vergleicht Inode UND Dateigröße
    # gegen den eigenen Offset (siehe _tail() dort).
    EVE="${LOG_DIR}/eve.json"
    if [ "${EVE_MAX_MB:-0}" -gt 0 ] 2>/dev/null && [ -f "$EVE" ]; then
        EVE_MB=$(( $(stat -c %s "$EVE" 2>/dev/null || echo 0) / 1048576 ))
        if [ "$EVE_MB" -ge "$EVE_MAX_MB" ]; then
            echo "[suricata] eve.json ${EVE_MB} MB >= ${EVE_MAX_MB} MB - rotiere."
            if mv -f "$EVE" "${EVE}.1" 2>/dev/null \
               && suricatasc -c reopen-log-files >/dev/null 2>&1; then
                echo "[suricata] rotiert nach eve.json.1"
            else
                # Rückfall: Datei zurück und kürzen. Lieber ein Truncate als
                # ein Suricata, das in eine umbenannte Datei weiterschreibt.
                [ -f "${EVE}.1" ] && mv -f "${EVE}.1" "$EVE" 2>/dev/null
                : > "$EVE"
                echo "[suricata] WARNUNG: reopen-log-files ging nicht - gekuerzt."
            fi
        fi
    fi

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
        echo "[suricata] ${COUNT} Regeln geladen – triggere ruleset-reload-rules"
        if suricatasc -c ruleset-reload-rules >/dev/null 2>&1; then
            echo "[suricata] Live-Reload abgeschlossen"
        else
            echo "[suricata] WARNUNG: ruleset-reload-rules fehlgeschlagen – Socket nicht ready?"
        fi
    fi
done

echo "[suricata] Suricata-Prozess beendet (PID ${SURICATA_PID})"
