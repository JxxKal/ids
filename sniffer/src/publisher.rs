use std::time::Duration;
use std::sync::{atomic::Ordering, Arc};

use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError};
use rdkafka::{
    config::ClientConfig,
    producer::{BaseProducer, BaseRecord, Producer},
};

use crate::{capture::CapturedPacket, config::Config, stats::Stats};

const TOPIC_RAW_PACKETS: &str = "raw-packets";
const TOPIC_PCAP_HEADERS: &str = "pcap-headers";

pub fn create_producer(config: &Config) -> Result<BaseProducer> {
    let producer: BaseProducer = ClientConfig::new()
        .set("bootstrap.servers",              &config.kafka_brokers)
        // Wie lange rdkafka auf Ack wartet bevor Fehler
        .set("message.timeout.ms",             "5000")
        // Interner Puffer: max. Nachrichten in Queue
        .set("queue.buffering.max.messages",   "100000")
        // Batching-Delay: bis zu 5ms sammeln für höheren Throughput
        .set("queue.buffering.max.ms",         "5")
        .set("batch.num.messages",             "1000")
        // LZ4 ist schnell und hat gute Kompression für JSON
        .set("compression.codec",              "lz4")
        .set("socket.keepalive.enable",        "true")
        // Retry bei transienten Fehlern
        .set("retries",                        "3")
        .set("retry.backoff.ms",               "100")
        .create()?;

    Ok(producer)
}

/// Haupt-Publish-Schleife. Läuft auf dem Main-Thread.
/// Beendet sich wenn der Channel geschlossen wird (Capture-Thread beendet).
pub fn run(
    rx: Receiver<CapturedPacket>,
    producer: BaseProducer,
    stats: Arc<Stats>,
) -> Result<()> {
    tracing::info!("Publisher gestartet");

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(captured) => {
                // Partitionierungsschlüssel: Source-IP
                // → alle Pakete derselben Quelle landen in derselben Partition
                // → Flow-Aggregator sieht zusammenhängende Flows in einem Consumer
                let key: String = captured
                    .event
                    .ip
                    .as_ref()
                    .map(|ip| ip.src.clone())
                    .unwrap_or_else(|| "unknown".into());

                publish_raw(&producer, &key, &captured, &stats);
                publish_pcap(&producer, &key, &captured, &stats);

                // Delivery-Callbacks ohne Blockieren verarbeiten
                producer.poll(Duration::ZERO);
            }

            // Timeout: keine Pakete, aber noch am Leben → Callbacks flushen
            Err(RecvTimeoutError::Timeout) => {
                producer.poll(Duration::from_millis(10));
            }

            // Channel geschlossen → Capture-Thread fertig, sauber beenden
            Err(RecvTimeoutError::Disconnected) => {
                tracing::info!("Channel geschlossen, flushe Kafka...");
                break;
            }
        }
    }

    producer.flush(Duration::from_secs(10))?;
    tracing::info!("Publisher beendet");
    Ok(())
}

fn publish_raw(
    producer: &BaseProducer,
    key: &str,
    captured: &CapturedPacket,
    stats: &Stats,
) {
    match serde_json::to_vec(&captured.event) {
        Ok(json) => {
            let record = BaseRecord::to(TOPIC_RAW_PACKETS)
                .key(key)
                .payload(json.as_slice());

            match producer.send(record) {
                Ok(()) => {
                    stats.kafka_raw_ok.fetch_add(1, Ordering::Relaxed);
                }
                Err((e, _)) => {
                    tracing::warn!(error = %e, "Kafka raw-packets Fehler");
                    stats.kafka_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Serialisierungsfehler PacketEvent");
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn publish_pcap(
    producer: &BaseProducer,
    key: &str,
    captured: &CapturedPacket,
    stats: &Stats,
) {
    match serde_json::to_vec(&captured.pcap_record) {
        Ok(json) => {
            let record = BaseRecord::to(TOPIC_PCAP_HEADERS)
                .key(key)
                .payload(json.as_slice());

            match producer.send(record) {
                Ok(()) => {
                    stats.kafka_pcap_ok.fetch_add(1, Ordering::Relaxed);
                }
                Err((e, _)) => {
                    // pcap-headers ist weniger kritisch als raw-packets
                    tracing::debug!(error = %e, "Kafka pcap-headers Fehler");
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Serialisierungsfehler PcapRecord");
        }
    }
}
