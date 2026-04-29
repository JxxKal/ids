#!/usr/bin/env bash
# Kafka-Topic-Init für Remote-Tap-Stack. Schmaler als der Master:
# nur die Topics die für die lokale Detection-Pipeline + den Uplink
# nötig sind. Keine alerts-enriched / pcap-headers etc.
set -euo pipefail

KAFKA=${KAFKA_BOOTSTRAP_SERVER:-kafka:9092}
TOPICS_BIN=/opt/kafka/bin/kafka-topics.sh

create() {
  local name="$1" parts="$2"
  if "$TOPICS_BIN" --bootstrap-server "$KAFKA" --list 2>/dev/null | grep -qx "$name"; then
    echo "topic $name existiert bereits"
    return
  fi
  "$TOPICS_BIN" --bootstrap-server "$KAFKA" --create \
    --topic "$name" --partitions "$parts" --replication-factor 1
  echo "topic $name angelegt"
}

create raw-packets   2
create flows         2
create alerts-raw    1
# Phase-2 Shadow-Metrik: signature-engine schreibt rein, tap-uplink konsumiert
# und forwarded zum Master. Lokal ohne Konsument läuft das Topic auf bis zur
# 24h-Retention voll — kein Issue, Volumen klein durch Sampling.
create rule-metrics  1

echo "[init-topics-tap] fertig"
