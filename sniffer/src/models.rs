use serde::Serialize;

/// Vollständig geparstes Paket-Ereignis → Kafka Topic "raw-packets"
/// Entspricht dem in der Architektur definierten Schema.
#[derive(Debug, Serialize)]
pub struct PacketEvent {
    /// Unix-Timestamp mit Mikrosekunden-Genauigkeit
    pub ts: f64,
    pub iface: String,
    /// Originale (ungekürzte) Paketlänge in Bytes
    pub pkt_len: u32,
    pub eth: EthHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportHeader>,
    /// Base64-kodierte rohe Header-Bytes (max snaplen, kein Payload)
    pub raw_header_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EthHeader {
    pub src_mac: String,
    pub dst_mac: String,
    /// EtherType als Dezimalzahl (2048=IPv4, 34525=IPv6, 2054=ARP)
    pub ethertype: u16,
}

#[derive(Debug, Serialize)]
pub struct IpHeader {
    /// 4 oder 6
    pub version: u8,
    pub src: String,
    pub dst: String,
    /// TTL (IPv4) oder Hop-Limit (IPv6)
    pub ttl: u8,
    /// IP-Protokollnummer des nächsten Headers (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
    pub proto: u8,
    /// Paket ist ein Fragment (oder hat MF-Bit gesetzt)
    pub frag: bool,
    /// DSCP (Differentiated Services Code Point)
    pub dscp: u8,
    /// IPv6: Flow-Label (20 Bit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_label: Option<u32>,
    /// IPv6: Liste der Extension-Header-Typen (z.B. ["HopByHop", "Routing"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_headers: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct TransportHeader {
    /// "TCP" | "UDP" | "ICMP" | "ICMPv6" | "OTHER"
    pub proto: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp: Option<IcmpFields>,
}

#[derive(Debug, Serialize)]
pub struct TcpFields {
    /// Aktive Flags: ["SYN"], ["SYN", "ACK"], etc.
    pub flags: Vec<String>,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    /// Geparste TCP-Optionen: ["MSS:1460", "SACK_PERM", "WScale:7", "Timestamps"]
    pub options: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IcmpFields {
    #[serde(rename = "type")]
    pub icmp_type: u8,
    pub code: u8,
}

/// Minimaler Datensatz für den PCAP-Store → Kafka Topic "pcap-headers"
/// Ermöglicht Rekonstruktion einer gültigen .pcap-Datei durch den pcap-store Service.
#[derive(Debug, Serialize)]
pub struct PcapRecord {
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Originale (ungekürzte) Paketlänge
    pub orig_len: u32,
    /// Base64-kodierte rohe Bytes (bis snaplen)
    pub data_b64: String,
}
