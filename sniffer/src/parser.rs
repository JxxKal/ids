use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use pnet::util::MacAddr;

use crate::models::*;

/// Parst rohe Paket-Bytes in ein vollständiges PacketEvent.
/// Gibt None zurück wenn das Paket zu kurz für einen Ethernet-Header ist.
pub fn parse(data: &[u8], orig_len: u32, ts: f64, iface: &str) -> Option<PacketEvent> {
    let eth = EthernetPacket::new(data)?;

    let eth_header = EthHeader {
        src_mac: format_mac(eth.get_source()),
        dst_mac: format_mac(eth.get_destination()),
        ethertype: eth.get_ethertype().0,
    };

    let (ip_header, transport_header) = match eth.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(eth.payload()),
        EtherTypes::Ipv6 => parse_ipv6(eth.payload()),
        // ARP, VLAN-tagged, etc.: kein IP-Header
        _ => (None, None),
    };

    Some(PacketEvent {
        ts,
        iface: iface.to_owned(),
        pkt_len: orig_len,
        eth: eth_header,
        ip: ip_header,
        transport: transport_header,
        raw_header_b64: BASE64.encode(data),
    })
}

// ── IPv4 ─────────────────────────────────────────────────────────────────────

fn parse_ipv4(payload: &[u8]) -> (Option<IpHeader>, Option<TransportHeader>) {
    let ipv4 = match Ipv4Packet::new(payload) {
        Some(p) => p,
        None => return (None, None),
    };

    let proto = ipv4.get_next_level_protocol();
    // MF-Bit (bit 0 des 3-bit flags-Felds) oder non-zero Fragment-Offset
    let frag = (ipv4.get_flags() & 0b001) != 0 || ipv4.get_fragment_offset() != 0;

    let ip = IpHeader {
        version: 4,
        src: ipv4.get_source().to_string(),
        dst: ipv4.get_destination().to_string(),
        ttl: ipv4.get_ttl(),
        proto: proto.0,
        frag,
        dscp: ipv4.get_dscp(),
        flow_label: None,
        ext_headers: None,
    };

    // Bei Fragmenten (außer dem ersten) ist kein vollständiger Transport-Header verfügbar
    let transport = if frag && ipv4.get_fragment_offset() != 0 {
        Some(TransportHeader {
            proto: "OTHER".into(),
            src_port: None,
            dst_port: None,
            tcp: None,
            icmp: None,
        })
    } else {
        parse_transport(proto, ipv4.payload())
    };

    (Some(ip), transport)
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

fn parse_ipv6(payload: &[u8]) -> (Option<IpHeader>, Option<TransportHeader>) {
    let ipv6 = match Ipv6Packet::new(payload) {
        Some(p) => p,
        None => return (None, None),
    };

    let (transport, ext_hdrs, effective_proto) = walk_ipv6_headers(&ipv6);

    let frag = ext_hdrs.iter().any(|h| h == "Fragment");

    let ip = IpHeader {
        version: 6,
        src: ipv6.get_source().to_string(),
        dst: ipv6.get_destination().to_string(),
        ttl: ipv6.get_hop_limit(),
        proto: effective_proto.0,
        frag,
        dscp: (ipv6.get_traffic_class() >> 2) & 0x3F,
        flow_label: Some(ipv6.get_flow_label()),
        ext_headers: if ext_hdrs.is_empty() { None } else { Some(ext_hdrs) },
    };

    (Some(ip), transport)
}

/// Läuft durch IPv6 Extension-Header-Kette bis zum Transport-Header.
/// Gibt (TransportHeader, Liste der Extension-Header-Namen, effektives Protokoll) zurück.
fn walk_ipv6_headers(
    ipv6: &Ipv6Packet,
) -> (Option<TransportHeader>, Vec<String>, IpNextHeaderProtocol) {
    let mut ext_headers: Vec<String> = Vec::new();
    let mut next_proto = ipv6.get_next_header();
    let mut payload = ipv6.payload();

    loop {
        match next_proto {
            // Hop-by-Hop Options (0)
            IpNextHeaderProtocols::Hopopt => {
                ext_headers.push("HopByHop".into());
                if let Some((np, rest)) = parse_ext_header_varlen(payload) {
                    next_proto = np;
                    payload = rest;
                } else {
                    break;
                }
            }
            // Routing Header (43)
            IpNextHeaderProtocols::Ipv6Route => {
                ext_headers.push("Routing".into());
                if let Some((np, rest)) = parse_ext_header_varlen(payload) {
                    next_proto = np;
                    payload = rest;
                } else {
                    break;
                }
            }
            // Fragment Header (44) – immer 8 Bytes, festes Format
            IpNextHeaderProtocols::Ipv6Frag => {
                ext_headers.push("Fragment".into());
                if payload.len() < 8 {
                    break;
                }
                next_proto = IpNextHeaderProtocol::new(payload[0]);
                payload = &payload[8..];
                // Nach Fragment-Header ist Transport normalerweise nicht mehr parsbar
                // (außer beim ersten Fragment, offset=0) – wir versuchen es trotzdem
                break;
            }
            // Destination Options (60)
            IpNextHeaderProtocols::Ipv6Opts => {
                ext_headers.push("Destination".into());
                if let Some((np, rest)) = parse_ext_header_varlen(payload) {
                    next_proto = np;
                    payload = rest;
                } else {
                    break;
                }
            }
            // Alles andere = Transport-Layer erreicht
            _ => break,
        }
    }

    let transport = parse_transport(next_proto, payload);
    (transport, ext_headers, next_proto)
}

/// Parst einen variabel-langen Extension-Header (Format: next_hdr | hdr_ext_len | ...).
/// hdr_ext_len ist in 8-Byte-Einheiten, exklusive der ersten 8 Bytes.
fn parse_ext_header_varlen(data: &[u8]) -> Option<(IpNextHeaderProtocol, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let next = IpNextHeaderProtocol::new(data[0]);
    let ext_len = (data[1] as usize + 1) * 8;
    if data.len() < ext_len {
        return None;
    }
    Some((next, &data[ext_len..]))
}

// ── Transport Layer ───────────────────────────────────────────────────────────

fn parse_transport(
    proto: IpNextHeaderProtocol,
    payload: &[u8],
) -> Option<TransportHeader> {
    match proto {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(payload)?;
            Some(TransportHeader {
                proto: "TCP".into(),
                src_port: Some(tcp.get_source()),
                dst_port: Some(tcp.get_destination()),
                tcp: Some(TcpFields {
                    flags: parse_tcp_flags(tcp.get_flags()),
                    seq: tcp.get_sequence(),
                    ack: tcp.get_acknowledgement(),
                    window: tcp.get_window(),
                    options: parse_tcp_options(&tcp),
                }),
                icmp: None,
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            Some(TransportHeader {
                proto: "UDP".into(),
                src_port: Some(udp.get_source()),
                dst_port: Some(udp.get_destination()),
                tcp: None,
                icmp: None,
            })
        }
        IpNextHeaderProtocols::Icmp => {
            let icmp = IcmpPacket::new(payload)?;
            Some(TransportHeader {
                proto: "ICMP".into(),
                src_port: None,
                dst_port: None,
                tcp: None,
                icmp: Some(IcmpFields {
                    icmp_type: icmp.get_icmp_type().0,
                    code: icmp.get_icmp_code().0,
                }),
            })
        }
        IpNextHeaderProtocols::Icmpv6 => {
            let icmp = Icmpv6Packet::new(payload)?;
            Some(TransportHeader {
                proto: "ICMPv6".into(),
                src_port: None,
                dst_port: None,
                tcp: None,
                icmp: Some(IcmpFields {
                    icmp_type: icmp.get_icmpv6_type().0,
                    code: icmp.get_icmpv6_code().0,
                }),
            })
        }
        _ => Some(TransportHeader {
            proto: "OTHER".into(),
            src_port: None,
            dst_port: None,
            tcp: None,
            icmp: None,
        }),
    }
}

// ── TCP Flags ─────────────────────────────────────────────────────────────────

fn parse_tcp_flags(flags: u16) -> Vec<String> {
    let mut result = Vec::with_capacity(4);
    // Reihenfolge: wichtigste zuerst
    if flags & TcpFlags::SYN != 0 { result.push("SYN".into()); }
    if flags & TcpFlags::ACK != 0 { result.push("ACK".into()); }
    if flags & TcpFlags::FIN != 0 { result.push("FIN".into()); }
    if flags & TcpFlags::RST != 0 { result.push("RST".into()); }
    if flags & TcpFlags::PSH != 0 { result.push("PSH".into()); }
    if flags & TcpFlags::URG != 0 { result.push("URG".into()); }
    if flags & TcpFlags::ECE != 0 { result.push("ECE".into()); }
    if flags & TcpFlags::CWR != 0 { result.push("CWR".into()); }
    result
}

// ── TCP Options ───────────────────────────────────────────────────────────────

fn parse_tcp_options(tcp: &TcpPacket) -> Vec<String> {
    let mut options = Vec::new();
    for opt in tcp.get_options_iter() {
        let name = match opt.get_number() {
            TcpOptionNumbers::MSS => {
                let d = opt.payload();
                if d.len() >= 2 {
                    format!("MSS:{}", u16::from_be_bytes([d[0], d[1]]))
                } else {
                    "MSS".into()
                }
            }
            TcpOptionNumbers::WSCALE => {
                let d = opt.payload();
                if !d.is_empty() {
                    format!("WScale:{}", d[0])
                } else {
                    "WScale".into()
                }
            }
            TcpOptionNumbers::SACK_PERMITTED => "SACK_PERM".into(),
            TcpOptionNumbers::SACK           => "SACK".into(),
            TcpOptionNumbers::TIMESTAMPS     => "Timestamps".into(),
            _                                => continue,
        };
        options.push(name);
    }
    options
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}
