use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::bounded;
use tracing_subscriber::EnvFilter;

mod capture;
mod config;
mod models;
mod parser;
mod publisher;
mod stats;

fn main() -> Result<()> {
    // ── Logging ──────────────────────────────────────────────────────────────
    // ANSI bewusst aus: `docker logs` zeigt die Subscriber-Ausgabe direkt,
    // und der API-Endpoint /system/stats parst die Felder per Regex. Mit ANSI
    // wären Sequenzen wie `\e[3mpps\e[0m\e[2m=\e[0m"11"` dazwischen und der
    // Match scheitert. Plain Text macht das Log gleichzeitig grep-bar.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_ansi(false)
        .init();

    // ── Konfiguration ────────────────────────────────────────────────────────
    let config = config::Config::from_env()?;

    tracing::info!(
        iface     = %config.mirror_iface,
        brokers   = %config.kafka_brokers,
        snaplen   = config.snaplen,
        test_mode = config.test_mode,
        "IDS Sniffer startet"
    );

    if config.test_mode {
        tracing::warn!(
            "TEST MODE aktiv – synthetischer Traffic, kein Produktionseinsatz"
        );
    }

    // ── Shared State ─────────────────────────────────────────────────────────
    let stats    = Arc::new(stats::Stats::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    // ── Signal-Handler (SIGTERM / SIGINT) ────────────────────────────────────
    let shutdown_signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        tracing::info!("Signal empfangen, starte Shutdown...");
        shutdown_signal.store(true, Ordering::SeqCst);
    })?;

    // ── Kafka Producer ───────────────────────────────────────────────────────
    let producer = publisher::create_producer(&config)?;
    tracing::info!(brokers = %config.kafka_brokers, "Kafka Producer bereit");

    // ── Channel zwischen Capture und Publisher ───────────────────────────────
    // Bounded: bei vollem Buffer werden Pakete im Capture-Thread verworfen,
    // anstatt den Capture zu blockieren (Packet Dropping >> Blocking)
    let (tx, rx) = bounded(config.channel_capacity);

    // ── Stats-Reporter (Background-Thread) ───────────────────────────────────
    stats::spawn_reporter(Arc::clone(&stats), Duration::from_secs(10));

    // ── Capture-Thread ───────────────────────────────────────────────────────
    let stats_cap   = Arc::clone(&stats);
    let shutdown_cap = Arc::clone(&shutdown);
    let config_cap  = config.clone();

    let capture_handle = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            if let Err(e) = capture::run(&config_cap, tx, stats_cap, shutdown_cap) {
                tracing::error!(error = %e, "Capture-Thread beendet sich mit Fehler");
            }
        })?;

    // ── Publisher (Main-Thread, blockiert bis Channel geschlossen) ───────────
    publisher::run(rx, producer, Arc::clone(&stats))?;

    // ── Cleanup ──────────────────────────────────────────────────────────────
    // Sicherstellen dass Capture-Thread sauber beendet ist
    if let Err(e) = capture_handle.join() {
        tracing::error!("Capture-Thread Panic: {:?}", e);
    }

    let captured = stats.pkts_captured.load(Ordering::Relaxed);
    let dropped  = stats.pkts_dropped.load(Ordering::Relaxed);
    let published = stats.kafka_raw_ok.load(Ordering::Relaxed);

    tracing::info!(
        captured, dropped, published,
        "Sniffer beendet"
    );

    Ok(())
}
