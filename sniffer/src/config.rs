use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Interface auf dem der Mirror-Traffic anliegt (AF_PACKET bind)
    pub mirror_iface: String,
    /// Kafka Bootstrap-Server, kommasepariert
    pub kafka_brokers: String,
    /// Bytes pro Paket (nur Header, kein Payload). Min 64, empfohlen 128.
    pub snaplen: i32,
    /// AF_PACKET Ring-Buffer in Bytes (pcap buffer_size)
    pub buffer_size: i32,
    /// Test-Mode: läuft auf Docker-Bridge ohne physisches Mirror-Interface
    pub test_mode: bool,
    /// Kapazität des internen Channels zwischen Capture- und Publisher-Thread
    pub channel_capacity: usize,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mirror_iface = std::env::var("MIRROR_IFACE")
            .context("MIRROR_IFACE ist nicht gesetzt")?;

        let kafka_brokers = std::env::var("KAFKA_BROKERS")
            .unwrap_or_else(|_| "localhost:9092".into());

        let snaplen = std::env::var("CAPTURE_SNAPLEN")
            .unwrap_or_else(|_| "128".into())
            .parse::<i32>()
            .context("CAPTURE_SNAPLEN muss eine ganze Zahl sein")?
            .max(64)      // Mindestgröße für vollständigen IPv6-Header
            .min(65535);

        let buffer_mb = std::env::var("CAPTURE_RING_BUFFER_MB")
            .unwrap_or_else(|_| "64".into())
            .parse::<i32>()
            .context("CAPTURE_RING_BUFFER_MB muss eine ganze Zahl sein")?
            .max(4)
            .min(4096);

        let test_mode = std::env::var("TEST_MODE")
            .unwrap_or_else(|_| "false".into())
            .eq_ignore_ascii_case("true");

        Ok(Self {
            mirror_iface,
            kafka_brokers,
            snaplen,
            buffer_size: buffer_mb * 1024 * 1024,
            test_mode,
            channel_capacity: 10_000,
        })
    }
}
