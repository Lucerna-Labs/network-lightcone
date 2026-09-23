//! Structural wire observations for the passive network Lightcone.
#![no_std]

use kernel_lightcone::{embedded as node, set, NODE_WORDS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationKind {
    Decoded,
    Unknown,
    Malformed,
    Fragment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub kind: ObservationKind,
    pub seeds: [u64; NODE_WORDS],
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    sum
}

fn folded(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn valid_checksum(bytes: &[u8]) -> bool {
    folded(add_words(0, bytes)) == 0xffff
}

fn valid_ipv4_transport(ip: &[u8], data: &[u8], protocol: u8) -> bool {
    let mut sum = protocol as u32 + data.len() as u32;
    sum = add_words(sum, &ip[12..20]);
    folded(add_words(sum, data)) == 0xffff
}

fn valid_ipv6_transport(ip: &[u8], data: &[u8], protocol: u8) -> bool {
    let length = data.len() as u32;
    let mut sum = add_words(0, &ip[8..40]);
    sum += (length >> 16) + (length & 0xffff) + protocol as u32;
    folded(add_words(sum, data)) == 0xffff
}

fn malformed() -> Observation {
    Observation {
        kind: ObservationKind::Malformed,
        seeds: [0; NODE_WORDS],
    }
}

fn decode_udp(out: &mut Observation, ip: &[u8], data: &[u8], ipv6: bool) -> Result<(), ()> {
    if data.len() < 8 {
        return Err(());
    }
    let length = word(data, 4) as usize;
    if length < 8 || length != data.len() {
        return Err(());
    }
    let checksum = word(data, 6);
    if ipv6 {
        if checksum == 0 || !valid_ipv6_transport(ip, data, 17) {
            return Err(());
        }
    } else if checksum != 0 && !valid_ipv4_transport(ip, data, 17) {
        return Err(());
    }
    set(&mut out.seeds, node::UDP);
    set(&mut out.seeds, node::UDP_LENGTH);
    set(&mut out.seeds, node::UDP_PORTS);
    if word(data, 0) == 0 {
        set(&mut out.seeds, node::UDP_SOURCE_ZERO);
    }
    if checksum == 0 {
        set(&mut out.seeds, node::UDP_NO_CHECKSUM);
    } else {
        set(&mut out.seeds, node::UDP_CHECKSUM);
        set(&mut out.seeds, node::UDP_INTEGRITY);
    }
    Ok(())
}

fn decode_tcp(out: &mut Observation, ip: &[u8], data: &[u8], ipv6: bool) -> Result<(), ()> {
    if data.len() < 20 {
        return Err(());
    }
    let header = (data[12] >> 4) as usize * 4;
    if header < 20 || header > data.len() {
        return Err(());
    }
    let valid = if ipv6 {
        valid_ipv6_transport(ip, data, 6)
    } else {
        valid_ipv4_transport(ip, data, 6)
    };
    if !valid {
        return Err(());
    }
    set(&mut out.seeds, node::TCP);
    set(&mut out.seeds, node::TCP_PORTS);
    set(&mut out.seeds, node::TCP_CHECKSUM);
    if data.len() > header {
        set(&mut out.seeds, node::TCP_PAYLOAD);
    }
    for (flag, symbol) in [
        (0x02, node::TCP_SYN),
        (0x10, node::TCP_ACK),
        (0x01, node::TCP_FIN),
        (0x04, node::TCP_RST),
    ] {
        if data[13] & flag != 0 {
            set(&mut out.seeds, symbol);
        }
    }
    Ok(())
}

fn decode_icmpv4(out: &mut Observation, data: &[u8]) -> Result<(), ()> {
    if data.len() < 8 || !valid_checksum(data) {
        return Err(());
    }
    set(&mut out.seeds, node::ICMP_CHECKSUM);
    match (data[0], data[1]) {
        (8, 0) => set(&mut out.seeds, node::ICMP_REQUEST),
        (0, 0) => set(&mut out.seeds, node::ICMP_REPLY),
        (3, 0..=15) => set(&mut out.seeds, node::ICMP_UNREACHABLE),
        (11, 0..=1) => set(&mut out.seeds, node::ICMP_EXPIRED),
        (12, _) => set(&mut out.seeds, node::ICMP_PARAMETER_PROBLEM),
        (5, _) => set(&mut out.seeds, node::ICMP_REDIRECT),
        _ => return Ok(()),
    }
    Ok(())
}

fn decode_icmpv6(out: &mut Observation, ip: &[u8], data: &[u8]) -> Result<(), ()> {
    if data.len() < 8 || !valid_ipv6_transport(ip, data, 58) {
        return Err(());
    }
    set(&mut out.seeds, node::ICMPV6);
    set(&mut out.seeds, node::ICMPV6_CHECKSUM);
    match data[0] {
        1..=4 => set(&mut out.seeds, node::ICMPV6_ERROR),
        133 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::ROUTER_SOLICITATION);
        }
        134 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::ROUTER_ADVERTISEMENT);
        }
        135 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::NEIGHBOR_SOLICITATION);
        }
        136 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::NEIGHBOR_ADVERTISEMENT);
        }
        _ => {}
    }
    Ok(())
}

fn decode_ipv4(out: &mut Observation, packet: &[u8]) -> Result<(), ()> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err(());
    }
    let header = (packet[0] & 0x0f) as usize * 4;
    let total = word(packet, 2) as usize;
    if header < 20
        || header > packet.len()
        || total < header
        || total > packet.len()
        || !valid_checksum(&packet[..header])
    {
        return Err(());
    }
    set(&mut out.seeds, node::IPV4);
    set(&mut out.seeds, node::IP_HEADER);
    set(&mut out.seeds, node::IP_LENGTH);
    set(&mut out.seeds, node::IP_CHECKSUM);
    set(&mut out.seeds, node::IP_PROTOCOL);
    set(&mut out.seeds, node::ENDPOINT_ADDRESSES);
    if packet[8] > 0 {
        set(&mut out.seeds, node::IP_TTL);
    }
    if word(packet, 6) & 0x3fff != 0 {
        set(&mut out.seeds, node::IP_FRAGMENT);
        out.kind = ObservationKind::Fragment;
        return Ok(());
    }
    let data = &packet[header..total];
    match packet[9] {
        17 => decode_udp(out, packet, data, false),
        6 => decode_tcp(out, packet, data, false),
        1 => decode_icmpv4(out, data),
        _ => Ok(()),
    }
}

fn decode_ipv6(out: &mut Observation, packet: &[u8]) -> Result<(), ()> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Err(());
    }
    let payload = word(packet, 4) as usize;
    if 40 + payload > packet.len() {
        return Err(());
    }
    set(&mut out.seeds, node::IPV6);
    set(&mut out.seeds, node::IPV6_PAYLOAD_LENGTH);
    set(&mut out.seeds, node::IPV6_NEXT_HEADER);
    set(&mut out.seeds, node::IPV6_HOP_LIMIT);
    set(&mut out.seeds, node::IPV6_SOURCE);
    set(&mut out.seeds, node::IPV6_DESTINATION);
    let mut next = packet[6];
    let mut offset = 40usize;
    let end = 40 + payload;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if offset + 2 > end {
                    return Err(());
                }
                set(&mut out.seeds, node::IPV6_EXTENSION);
                let length = (packet[offset + 1] as usize + 1) * 8;
                if length < 8 || offset + length > end {
                    return Err(());
                }
                next = packet[offset];
                offset += length;
            }
            44 => {
                if offset + 8 > end {
                    return Err(());
                }
                set(&mut out.seeds, node::IPV6_FRAGMENT);
                out.kind = ObservationKind::Fragment;
                return Ok(());
            }
            _ => break,
        }
    }
    let data = &packet[offset..end];
    match next {
        17 => decode_udp(out, packet, data, true),
        6 => decode_tcp(out, packet, data, true),
        58 => decode_icmpv6(out, packet, data),
        _ => Ok(()),
    }
}

/// Decode only bounded wire structure. Payload text cannot select node IDs.
pub fn decode(frame: &[u8]) -> Observation {
    let mut out = Observation {
        kind: ObservationKind::Unknown,
        seeds: [0; NODE_WORDS],
    };
    if frame.len() < 14 {
        return malformed();
    }
    let ether_type = word(frame, 12);
    let packet = &frame[14..];
    let result = match ether_type {
        0x0806 => {
            if packet.len() < 28
                || word(packet, 0) != 1
                || word(packet, 2) != 0x0800
                || packet[4] != 6
                || packet[5] != 4
            {
                Err(())
            } else {
                match word(packet, 6) {
                    1 => set(&mut out.seeds, node::ARP_REQUEST),
                    2 => set(&mut out.seeds, node::ARP_REPLY),
                    _ => return out,
                }
                Ok(())
            }
        }
        0x0800 => decode_ipv4(&mut out, packet),
        0x86dd => decode_ipv6(&mut out, packet),
        _ => return out,
    };
    if result.is_err() {
        return malformed();
    }
    if out.kind != ObservationKind::Fragment {
        out.kind = ObservationKind::Decoded;
    }
    out
}

/// Add context only after a trusted host parser validates that symbol.
/// Raw packet payloads must never call this boundary directly.
pub fn add_host_validated_symbol(observation: &mut Observation, symbol: usize) -> bool {
    if symbol >= kernel_lightcone::MAX_NODES {
        return false;
    }
    set(&mut observation.seeds, symbol);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_lightcone::bit;

    fn finish_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset + 1] = 0;
        let value = !folded(add_words(0, bytes));
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn udp_frame(payload: &[u8]) -> ([u8; 256], usize) {
        let mut frame = [0u8; 256];
        let length = 14 + 20 + 8 + payload.len();
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..length];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        finish_checksum(&mut ip[..20], 10);
        let udp = &mut ip[20..];
        udp[0..2].copy_from_slice(&12000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp[8..8 + payload.len()].copy_from_slice(payload);
        (frame, length)
    }

    fn ipv6_neighbor_solicitation() -> ([u8; 128], usize) {
        let mut frame = [0u8; 128];
        let length = 14 + 40 + 24;
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&24u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 255;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 2]);
        packet[40] = 135;
        packet[41] = 0;
        packet[48..64].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut sum = add_words(0, &packet[8..40]);
        sum += 24 + 58;
        let checksum = !folded(add_words(sum, &packet[40..64]));
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        (frame, length)
    }

    #[test]
    fn malformed_and_unknown_observations_have_no_seeds() {
        for length in 0..14 {
            let observation = decode(&[0u8; 14][..length]);
            assert_eq!(observation.kind, ObservationKind::Malformed);
            assert_eq!(observation.seeds, [0; NODE_WORDS]);
        }
        let mut frame = [0u8; 14];
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Unknown);
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn payload_text_cannot_select_nodes() {
        let (ordinary, ordinary_len) = udp_frame(b"ordinary");
        let (text, text_len) = udp_frame(b"node=export;authorize=true;probe");
        assert_eq!(
            decode(&ordinary[..ordinary_len]).seeds,
            decode(&text[..text_len]).seeds
        );
    }

    #[test]
    fn structurally_valid_udp_seeds_only_protocol_context() {
        let (frame, length) = udp_frame(b"context");
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert!(bit(&observation.seeds, node::IPV4));
        assert!(bit(&observation.seeds, node::UDP));
        assert!(bit(&observation.seeds, node::UDP_PORTS));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
        assert!(!bit(&observation.seeds, node::POLICY_DECISION));
    }

    #[test]
    fn shared_protocol_symbol_can_enter_without_host_authority() {
        let (frame, length) = udp_frame(b"context");
        let mut observation = decode(&frame[..length]);
        assert!(add_host_validated_symbol(&mut observation, node::DNS_QUERY));
        assert!(bit(&observation.seeds, node::DNS_QUERY));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
    }

    #[test]
    fn ipv6_neighbor_discovery_is_structurally_seeded() {
        let (frame, length) = ipv6_neighbor_solicitation();
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert!(bit(&observation.seeds, node::IPV6));
        assert!(bit(&observation.seeds, node::ICMPV6));
        assert!(bit(&observation.seeds, node::NDP));
        assert!(bit(&observation.seeds, node::NEIGHBOR_SOLICITATION));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
    }
}
