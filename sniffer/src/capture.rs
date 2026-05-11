use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::Result;
use crossbeam_channel::Sender;
use pcap::Capture;

use crate::{
    config::Config,
    models::{PacketEvent, PcapRecord},
    parser,
    stats::Stats,
};

/// Gebündelte Ausgabe pro Paket: geht in den Channel zum Publisher.
pub struct CapturedPacket {
    pub event: PacketEvent,
    pub pcap_record: PcapRecord,
}

/// Blockierende Capture-Schleife für ein einzelnes Interface. Läuft in einem
/// eigenen Thread. Bricht ab wenn `shutdown` auf true gesetzt wird oder ein
/// fataler Fehler auftritt. Beim Beenden wird `tx` gedroppt → Publisher
/// erkennt Channel-Ende und flusht Kafka.
///
/// `iface_name` bestimmt das pcap-Device. Mehrere Threads können in den
/// gleichen `tx`-Channel schreiben — der Publisher serialisiert die Frames.
pub fn run(
    iface_name: &str,
    config: &Config,
    tx: Sender<CapturedPacket>,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    tracing::info!(
        iface      = %iface_name,
        snaplen    = config.snaplen,
        buffer_mb  = config.buffer_size / (1024 * 1024),
        test_mode  = config.test_mode,
        "Öffne Capture..."
    );

    let mut cap = Capture::from_device(iface_name)?
        .snaplen(config.snaplen)
        .promisc(true)
        // 1 Sekunde Timeout: erlaubt regelmäßige Shutdown-Checks
        .timeout(1000)
        .buffer_size(config.buffer_size)
        .open()?;

    tracing::info!(iface = %iface_name, "Capture aktiv");

    loop {
        // Shutdown-Check (atomar, kein Locking)
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("Shutdown-Signal empfangen, beende Capture");
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                stats.pkts_captured.fetch_add(1, Ordering::Relaxed);

                // Timestamp aus pcap-Header
                let ts_sec  = packet.header.ts.tv_sec  as u32;
                let ts_usec = packet.header.ts.tv_usec as u32;
                let ts      = ts_sec as f64 + ts_usec as f64 / 1_000_000.0;
                let orig_len = packet.header.len;
                let data     = packet.data;

                // Paket parsen — iface-Name kommt aus dem aktuellen Capture
                let event = match parser::parse(data, orig_len, ts, iface_name) {
                    Some(e) => e,
                    None => {
                        stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                // PcapRecord teilt sich die rohen Bytes mit event.raw_header_b64
                let pcap_record = PcapRecord {
                    ts_sec,
                    ts_usec,
                    orig_len,
                    data_b64: event.raw_header_b64.clone(),
                };

                let captured = CapturedPacket { event, pcap_record };

                // Non-blocking send: bei vollem Channel → Paket verwerfen
                // Besser ein Paket droppen als den Capture-Thread zu blockieren
                if tx.try_send(captured).is_err() {
                    stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Normaler Timeout (1s) – kein Fehler, nur keine Pakete
            Err(pcap::Error::TimeoutExpired) => continue,

            Err(e) => {
                tracing::error!(error = %e, "Fataler Capture-Fehler");
                return Err(e.into());
            }
        }
    }

    tracing::info!("Capture-Thread beendet");
    Ok(())
}
