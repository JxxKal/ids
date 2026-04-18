#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Kafka Topic Initialisierung
# Wird einmalig beim Stack-Start ausgeführt (kafka-init Service)
# ══════════════════════════════════════════════════════════════════════════════
set -e

KAFKA_BIN=/opt/kafka/bin
BOOTSTRAP=kafka:9092

echo "[kafka-init] Warte auf Kafka..."
until $KAFKA_BIN/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list &>/dev/null; do
  sleep 2
done
echo "[kafka-init] Kafka bereit."

# ──────────────────────────────────────────────────────────────────────────────
# Hilfsfunktion: Topic anlegen wenn nicht vorhanden
#   $1 = Topic-Name
#   $2 = Partitionen
#   $3 = Retention in Millisekunden
#   $4 = (optional) zusätzliche --config Argumente
# ──────────────────────────────────────────────────────────────────────────────
create_topic() {
  local TOPIC=$1
  local PARTITIONS=$2
  local RETENTION_MS=$3
  local EXTRA_CONFIG=${4:-""}

  if $KAFKA_BIN/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
      --describe --topic "$TOPIC" &>/dev/null; then
    echo "[kafka-init] Topic '$TOPIC' existiert bereits – übersprungen."
  else
    $KAFKA_BIN/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
      --create \
      --topic "$TOPIC" \
      --partitions "$PARTITIONS" \
      --replication-factor 1 \
      --config retention.ms="$RETENTION_MS" \
      $EXTRA_CONFIG
    echo "[kafka-init] Topic erstellt: $TOPIC (${PARTITIONS}P, ${RETENTION_MS}ms)"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Topics
#
# raw-packets       Sniffer → Flow-Aggregator + (optional) Signature-Engine
#                   4 Partitionen: parallele Verarbeitung nach src_ip Hash
#                   Retention 10 min: kurzlebig, hohe Schreiblast
#
# flows             Flow-Aggregator → ML-Engine + Signature-Engine
#                   4 Partitionen
#                   Retention 1h: Flows vollständig verarbeiten
#
# pcap-headers      Sniffer → PCAP-Store
#                   4 Partitionen (synchron mit raw-packets)
#                   Retention 30 min: nur solange wie PCAP-Window
#
# alerts-raw        Signature-Engine + ML-Engine → Alert-Manager
#                   2 Partitionen: geringeres Volumen
#                   Retention 24h
#
# alerts-enriched   Alert-Manager → API + TimescaleDB-Writer
#                   2 Partitionen
#                   Retention 7 Tage: Wiederherstellung nach Ausfall
#
# feedback          API → Training-Loop
#                   1 Partition: sequenzielle Verarbeitung wichtig
#                   Retention 30 Tage: vollständiger Feedback-Verlauf
#
# test-commands     API → Traffic-Generator (nur Test-Mode)
#                   1 Partition
#                   Retention 1h
# ──────────────────────────────────────────────────────────────────────────────

create_topic "raw-packets"          4   600000    "--config max.message.bytes=1048576"
create_topic "flows"                4   3600000
create_topic "pcap-headers"         4   1800000   "--config max.message.bytes=10485760"
create_topic "alerts-raw"           2   86400000
create_topic "alerts-enriched"      2   604800000
create_topic "alerts-enriched-push" 1   3600000
create_topic "feedback"             1   2592000000
create_topic "test-commands"        1   3600000

echo ""
echo "[kafka-init] Alle Topics angelegt:"
$KAFKA_BIN/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list | sed 's/^/  /'
echo "[kafka-init] Fertig."
