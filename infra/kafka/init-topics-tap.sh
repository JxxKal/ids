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

# pcap-headers: Sniffer schreibt JEDES Paket-Header-Sample (b64-encoded
# bis snaplen) hier rein. tap-uplink konsumiert es, hält ±60s ringbuf
# in-memory und baut bei Tap-Alarmen das PCAP für master-uplink-Upload.
# Retention bewusst sehr kurz (10 min): wir brauchen die Daten nur kurz
# bis tap-uplink sie konsumiert hat. Bei 18 kpps × 250 Bytes/msg ×
# 600s = ~3 GB Kafka-Disk peak — erträglich. Längere Retention würde
# nichts bringen weil tap-uplink eh nur in-memory die letzten 60s hält.
"$TOPICS_BIN" --bootstrap-server "$KAFKA" --list 2>/dev/null | grep -qx pcap-headers \
  && echo "topic pcap-headers existiert bereits" \
  || "$TOPICS_BIN" --bootstrap-server "$KAFKA" --create \
       --topic pcap-headers --partitions 2 --replication-factor 1 \
       --config retention.ms=600000 --config segment.ms=120000 \
  && echo "topic pcap-headers angelegt"

echo "[init-topics-tap] fertig"
