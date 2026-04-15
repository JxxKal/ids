use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Stats {
    /// Pakete vom Interface erfasst
    pub pkts_captured: AtomicU64,
    /// Pakete verworfen (Channel-Backpressure: Publisher zu langsam)
    pub pkts_dropped: AtomicU64,
    /// Pakete die nicht geparst werden konnten (zu kurz, unbekanntes Format)
    pub parse_errors: AtomicU64,
    /// Erfolgreich an "raw-packets" Topic gesendet
    pub kafka_raw_ok: AtomicU64,
    /// Erfolgreich an "pcap-headers" Topic gesendet
    pub kafka_pcap_ok: AtomicU64,
    /// Kafka-Sendefehler (Queue voll, Verbindungsfehler, etc.)
    pub kafka_errors: AtomicU64,
}

/// Startet einen Background-Thread der alle `interval` Sekunden Metriken loggt.
pub fn spawn_reporter(stats: Arc<Stats>, interval: Duration) {
    std::thread::spawn(move || {
        let mut last_report = Instant::now();
        let mut prev_captured = 0u64;
        let mut prev_dropped = 0u64;
        let mut prev_kafka_ok = 0u64;

        loop {
            std::thread::sleep(interval);

            let elapsed = last_report.elapsed().as_secs_f64();
            last_report = Instant::now();

            let captured   = stats.pkts_captured.load(Ordering::Relaxed);
            let dropped    = stats.pkts_dropped.load(Ordering::Relaxed);
            let parse_err  = stats.parse_errors.load(Ordering::Relaxed);
            let kafka_ok   = stats.kafka_raw_ok.load(Ordering::Relaxed);
            let kafka_err  = stats.kafka_errors.load(Ordering::Relaxed);

            let delta_captured = captured.saturating_sub(prev_captured);
            let delta_dropped  = dropped.saturating_sub(prev_dropped);
            let delta_kafka    = kafka_ok.saturating_sub(prev_kafka_ok);

            let pps = delta_captured as f64 / elapsed;
            let drop_pct = if delta_captured > 0 {
                delta_dropped as f64 / delta_captured as f64 * 100.0
            } else {
                0.0
            };

            tracing::info!(
                pps          = format!("{pps:.0}"),
                drop_pct     = format!("{drop_pct:.2}%"),
                total_cap    = captured,
                total_drop   = dropped,
                delta_kafka  = delta_kafka,
                parse_errors = parse_err,
                kafka_errors = kafka_err,
                "sniffer stats"
            );

            prev_captured = captured;
            prev_dropped  = dropped;
            prev_kafka_ok = kafka_ok;
        }
    });
}
