#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Kafka-Topic-Init für Remote-Tap-Stack
#
# Schmaler als der Master: nur die Topics die für die lokale Detection-Pipeline
# + den Uplink nötig sind. Keine alerts-enriched / feedback / etc.
#
# Pro-Topic-Retention ist hier KRITISCH: ein Offline-Tap (nicht zum Master
# verbunden) hat keinen Konsumenten für alerts-raw / rule-metrics, und der
# Sniffer pumpt raw-packets/flows trotzdem rein. Ohne explizite Retention
# greift Kafka-Default = 7 Tage und das Disk läuft bei echtem Traffic in
# kurzer Zeit voll. Real-World-Vorfall: 38 GB Disk durch Tap-Volume in
# wenigen Stunden.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

KAFKA=${KAFKA_BOOTSTRAP_SERVER:-kafka:9092}
TOPICS_BIN=/opt/kafka/bin/kafka-topics.sh
CONFIGS_BIN=/opt/kafka/bin/kafka-configs.sh

echo "[init-topics-tap] Warte auf Kafka..."
until "$TOPICS_BIN" --bootstrap-server "$KAFKA" --list &>/dev/null; do
  sleep 2
done
echo "[init-topics-tap] Kafka bereit."

# ──────────────────────────────────────────────────────────────────────────────
# ensure_topic: idempotent + heilend.
#   Topic existiert nicht → anlegen mit der gewünschten Retention.
#   Topic existiert       → kafka-configs.sh --alter, bestehende Topics
#                            werden auf die korrekten Retention/Segment-Werte
#                            migriert. Kein Daten-Loss, Kafka rolled neue
#                            Segmente entsprechend dem geänderten segment.ms.
#
#   $1 = Topic-Name
#   $2 = Partitionen (nur bei Neuanlage relevant)
#   $3 = Retention in Millisekunden
#   $4 = (optional) zusätzliche --config Argumente für --create (z.B.
#        max.message.bytes — wird hier auch bei --alter angewandt).
# ──────────────────────────────────────────────────────────────────────────────
ensure_topic() {
  local TOPIC=$1
  local PARTITIONS=$2
  local RETENTION_MS=$3
  local EXTRA_CONFIG=${4:-""}

  if "$TOPICS_BIN" --bootstrap-server "$KAFKA" --list 2>/dev/null | grep -qx "$TOPIC"; then
    # Existing topic — alter retention/segment configs
    local ALTER_ARGS="retention.ms=${RETENTION_MS},segment.ms=600000"
    # Extra-Configs (z.B. max.message.bytes) extrahieren und ans alter anhängen
    if [ -n "$EXTRA_CONFIG" ]; then
      # EXTRA_CONFIG hat Format "--config k=v --config k=v" — wir parsen die k=v
      local EXTRAS
      EXTRAS=$(echo "$EXTRA_CONFIG" | sed 's/--config //g' | tr ' ' ',' | sed 's/^,//;s/,$//')
      [ -n "$EXTRAS" ] && ALTER_ARGS="${ALTER_ARGS},${EXTRAS}"
    fi
    "$CONFIGS_BIN" --bootstrap-server "$KAFKA" --alter \
      --entity-type topics --entity-name "$TOPIC" \
      --add-config "$ALTER_ARGS" >/dev/null
    echo "[init-topics-tap] Topic '$TOPIC' aktualisiert: retention=${RETENTION_MS}ms"
    return
  fi
  "$TOPICS_BIN" --bootstrap-server "$KAFKA" --create \
    --topic "$TOPIC" \
    --partitions "$PARTITIONS" \
    --replication-factor 1 \
    --config retention.ms="$RETENTION_MS" \
    --config segment.ms=600000 \
    $EXTRA_CONFIG
  echo "[init-topics-tap] Topic erstellt: $TOPIC (${PARTITIONS}P, retention=${RETENTION_MS}ms)"
}

# ──────────────────────────────────────────────────────────────────────────────
# Topics
#
# raw-packets    Sniffer → Flow-Aggregator (lokal)
#                10 min — kurzlebig, hohe Schreiblast, der Konsument ist
#                im selben Container-Stack also lag-arm.
#
# flows          Flow-Aggregator → Signature-Engine
#                1h — Flows vollständig verarbeiten lassen.
#
# alerts-raw    Signature-Engine → tap-uplink (zum Master)
#                24h — bei Outage muss der Buffer den re-connect aushalten.
#                Längere Retention kostet zu viel Disk auf einer typischen
#                Tap-Appliance (32–64 GB SSD); 24h reicht praktisch immer,
#                weil tap-uplink zusätzlich einen SQLite-Outage-Buffer hat
#                (1 GB cap, persistent über Container-Restarts).
#
# rule-metrics   Signature-Engine → tap-uplink (Phase-2 Shadow-Metrik)
#                24h — niedriges Volumen wegen Sampling, aber gleicher
#                Outage-Reasoning wie alerts-raw.
#
# pcap-headers   Sniffer → tap-uplink (Mini-PCAP-Store, V1)
#                10 min — tap-uplink hält in-memory die letzten 60s und
#                baut PCAPs bei Tap-Alerts. Mehr Retention nutzt nichts.
#                segment.ms bewusst 2 min damit alte Segmente schnell
#                gedroppt werden.
#                Bei 18 kpps × 250 B/msg × 600 s = ~3 GB Kafka-Disk peak
#                im Worst-Case — der Default-1d-Wert würde 432 GB werden.
# ──────────────────────────────────────────────────────────────────────────────

ensure_topic "raw-packets"   2   600000     "--config max.message.bytes=1048576"
ensure_topic "flows"         2   3600000
ensure_topic "alerts-raw"    1   86400000
ensure_topic "rule-metrics"  1   86400000

# pcap-headers: kürzere segment.ms (2 min) damit retention.ms auch effektiv
# greift. Bei segment.ms = retention.ms (gleicher Wert) würde Kafka erst
# nach 10 min ein Segment rollen UND erst dann das vorherige droppen
# können — d.h. der Disk-Peak könnte 20 min dauern statt 10. Eigene
# Logic statt ensure_topic, weil dieser Topic einen abweichenden
# segment.ms braucht.
if "$TOPICS_BIN" --bootstrap-server "$KAFKA" --list 2>/dev/null | grep -qx pcap-headers; then
  "$CONFIGS_BIN" --bootstrap-server "$KAFKA" --alter \
    --entity-type topics --entity-name pcap-headers \
    --add-config "retention.ms=600000,segment.ms=120000,max.message.bytes=10485760" >/dev/null
  echo "[init-topics-tap] Topic 'pcap-headers' aktualisiert: retention=600000ms, segment=120000ms"
else
  "$TOPICS_BIN" --bootstrap-server "$KAFKA" --create \
    --topic pcap-headers \
    --partitions 2 \
    --replication-factor 1 \
    --config retention.ms=600000 \
    --config segment.ms=120000 \
    --config max.message.bytes=10485760
  echo "[init-topics-tap] Topic erstellt: pcap-headers (2P, retention=600000ms, segment=120000ms)"
fi

echo ""
echo "[init-topics-tap] Alle Topics angelegt:"
"$TOPICS_BIN" --bootstrap-server "$KAFKA" --list | sed 's/^/  /'
echo "[init-topics-tap] Fertig."
