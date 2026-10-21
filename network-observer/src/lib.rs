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
    /// Stable diagnostic reason for this exact structural observation.
    pub reason: &'static str,
}

/// Actual parser events, containing structural metadata but no payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverStep {
    Enter {
        stage: &'static str,
        offset: usize,
        length: usize,
    },
    Field {
        name: &'static str,
        value: u64,
    },
    Check {
        rejection_reason: &'static str,
        passed: bool,
    },
    Seed {
        node: usize,
    },
    Discard {
        reason: &'static str,
        seeds: [u64; NODE_WORDS],
    },
    Finish {
        kind: ObservationKind,
        reason: &'static str,
        seeds: [u64; NODE_WORDS],
    },
}
fn rejected(bad: bool, reason: &'static str, trace: &mut impl FnMut(ObserverStep)) -> bool {
    trace(ObserverStep::Check {
        rejection_reason: reason,
        passed: !bad,
    });
    bad
}
fn traced_set(mask: &mut [u64; NODE_WORDS], node: usize, trace: &mut impl FnMut(ObserverStep)) {
    set(mask, node);
    trace(ObserverStep::Seed { node });
}
fn field(trace: &mut impl FnMut(ObserverStep), name: &'static str, value: usize) {
    trace(ObserverStep::Field {
        name,
        value: value as u64,
    });
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

fn malformed(reason: &'static str) -> Observation {
    Observation {
        kind: ObservationKind::Malformed,
        seeds: [0; NODE_WORDS],
        reason,
    }
}

fn decode_udp(
    out: &mut Observation,
    ip: &[u8],
    data: &[u8],
    ipv6: bool,
    offset: usize,
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "udp",
        offset,
        length: data.len(),
    });
    if rejected(data.len() < 8, "udp_short_header", trace) {
        return Err("udp_short_header");
    }
    field(trace, "udp_source_port", word(data, 0) as usize);
    field(trace, "udp_destination_port", word(data, 2) as usize);
    let length = word(data, 4) as usize;
    field(trace, "udp_length", length);
    if rejected(
        length < 8 || length != data.len(),
        "udp_length_mismatch",
        trace,
    ) {
        return Err("udp_length_mismatch");
    }
    let checksum = word(data, 6);
    field(trace, "udp_checksum", checksum as usize);
    if ipv6 {
        if rejected(checksum == 0, "udp_ipv6_zero_checksum", trace) {
            return Err("udp_ipv6_zero_checksum");
        }
        if rejected(
            !valid_ipv6_transport(ip, data, 17),
            "udp_ipv6_bad_checksum",
            trace,
        ) {
            return Err("udp_ipv6_bad_checksum");
        }
    } else if rejected(
        checksum != 0 && !valid_ipv4_transport(ip, data, 17),
        "udp_ipv4_bad_checksum",
        trace,
    ) {
        return Err("udp_ipv4_bad_checksum");
    }
    traced_set(&mut out.seeds, node::UDP, trace);
    traced_set(&mut out.seeds, node::UDP_LENGTH, trace);
    traced_set(&mut out.seeds, node::UDP_PORTS, trace);
    if word(data, 0) == 0 {
        traced_set(&mut out.seeds, node::UDP_SOURCE_ZERO, trace);
    }
    if checksum == 0 {
        traced_set(&mut out.seeds, node::UDP_NO_CHECKSUM, trace);
        out.reason = "ipv4_udp_no_checksum";
    } else {
        traced_set(&mut out.seeds, node::UDP_CHECKSUM, trace);
        traced_set(&mut out.seeds, node::UDP_INTEGRITY, trace);
        out.reason = if ipv6 {
            "ipv6_udp_valid"
        } else {
            "ipv4_udp_valid"
        };
    }
    Ok(())
}

fn decode_tcp(
    out: &mut Observation,
    ip: &[u8],
    data: &[u8],
    ipv6: bool,
    offset: usize,
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "tcp",
        offset,
        length: data.len(),
    });
    if rejected(data.len() < 20, "tcp_short_header", trace) {
        return Err("tcp_short_header");
    }
    field(trace, "tcp_source_port", word(data, 0) as usize);
    field(trace, "tcp_destination_port", word(data, 2) as usize);
    field(
        trace,
        "tcp_sequence",
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize,
    );
    field(
        trace,
        "tcp_acknowledgment",
        u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize,
    );
    field(trace, "tcp_flags", data[13] as usize);
    field(trace, "tcp_window", word(data, 14) as usize);
    let header = (data[12] >> 4) as usize * 4;
    field(trace, "tcp_header_length", header);
    if rejected(
        header < 20 || header > data.len(),
        "tcp_header_length_invalid",
        trace,
    ) {
        return Err("tcp_header_length_invalid");
    }
    field(trace, "tcp_payload_length", data.len() - header);
    let valid = if ipv6 {
        valid_ipv6_transport(ip, data, 6)
    } else {
        valid_ipv4_transport(ip, data, 6)
    };
    if rejected(!valid, "tcp_bad_checksum", trace) {
        return Err("tcp_bad_checksum");
    }
    traced_set(&mut out.seeds, node::TCP, trace);
    traced_set(&mut out.seeds, node::TCP_PORTS, trace);
    traced_set(&mut out.seeds, node::TCP_CHECKSUM, trace);
    if data.len() > header {
        traced_set(&mut out.seeds, node::TCP_PAYLOAD, trace);
    }
    for (flag, symbol) in [
        (0x02, node::TCP_SYN),
        (0x10, node::TCP_ACK),
        (0x01, node::TCP_FIN),
        (0x04, node::TCP_RST),
    ] {
        if data[13] & flag != 0 {
            traced_set(&mut out.seeds, symbol, trace);
        }
    }
    out.reason = if ipv6 {
        "ipv6_tcp_valid"
    } else {
        "ipv4_tcp_valid"
    };
    Ok(())
}

fn decode_icmpv4(
    out: &mut Observation,
    data: &[u8],
    offset: usize,
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "icmpv4",
        offset,
        length: data.len(),
    });
    if rejected(data.len() < 8, "icmpv4_short_message", trace) {
        return Err("icmpv4_short_message");
    }
    field(trace, "icmpv4_type", data[0] as usize);
    field(trace, "icmpv4_code", data[1] as usize);
    if rejected(!valid_checksum(data), "icmpv4_bad_checksum", trace) {
        return Err("icmpv4_bad_checksum");
    }
    traced_set(&mut out.seeds, node::ICMP_CHECKSUM, trace);
    match (data[0], data[1]) {
        (8, 0) => traced_set(&mut out.seeds, node::ICMP_REQUEST, trace),
        (0, 0) => traced_set(&mut out.seeds, node::ICMP_REPLY, trace),
        (3, 0..=15) => traced_set(&mut out.seeds, node::ICMP_UNREACHABLE, trace),
        (11, 0..=1) => traced_set(&mut out.seeds, node::ICMP_EXPIRED, trace),
        (12, _) => traced_set(&mut out.seeds, node::ICMP_PARAMETER_PROBLEM, trace),
        (5, _) => traced_set(&mut out.seeds, node::ICMP_REDIRECT, trace),
        _ => {
            out.reason = "icmpv4_unrepresented_type";
            return Ok(());
        }
    }
    out.reason = "icmpv4_valid";
    Ok(())
}

fn ndp_has_source_link_option(
    data: &[u8],
    mut offset: usize,
    absolute: usize,
    trace: &mut impl FnMut(ObserverStep),
) -> Result<bool, &'static str> {
    let mut found = false;
    while offset < data.len() {
        trace(ObserverStep::Enter {
            stage: "ndp_option",
            offset: absolute + offset,
            length: data.len() - offset,
        });
        if rejected(offset + 2 > data.len(), "ndp_option_length_invalid", trace) {
            return Err("ndp_option_length_invalid");
        }
        let length = data[offset + 1] as usize * 8;
        field(trace, "ndp_option_type", data[offset] as usize);
        field(trace, "ndp_option_length", length);
        if rejected(
            length == 0 || offset + length > data.len(),
            "ndp_option_length_invalid",
            trace,
        ) {
            return Err("ndp_option_length_invalid");
        }
        found |= data[offset] == 1;
        offset += length;
    }
    Ok(found)
}

fn unspecified_ipv6(address: &[u8]) -> bool {
    address.iter().all(|&byte| byte == 0)
}

fn solicited_node_multicast(address: &[u8]) -> bool {
    address[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
}

fn link_local_ipv6(address: &[u8]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

fn decode_icmpv6(
    out: &mut Observation,
    ip: &[u8],
    data: &[u8],
    offset: usize,
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "icmpv6",
        offset,
        length: data.len(),
    });
    if rejected(data.len() < 8, "icmpv6_short_message", trace) {
        return Err("icmpv6_short_message");
    }
    field(trace, "icmpv6_type", data[0] as usize);
    field(trace, "icmpv6_code", data[1] as usize);
    if rejected(
        !valid_ipv6_transport(ip, data, 58),
        "icmpv6_bad_checksum",
        trace,
    ) {
        return Err("icmpv6_bad_checksum");
    }
    // Neighbor Discovery has stricter wire validity than generic ICMPv6.
    // Validate it before any IPv6 or NDP seed can reach the Lightcone.
    if (133..=136).contains(&data[0]) {
        if rejected(ip[7] != 255, "ndp_hop_limit_invalid", trace) {
            return Err("ndp_hop_limit_invalid");
        }
        if rejected(data[1] != 0, "ndp_code_invalid", trace) {
            return Err("ndp_code_invalid");
        }
        let minimum_length = if data[0] == 133 {
            8
        } else if data[0] == 134 {
            16
        } else {
            24
        };
        if rejected(data.len() < minimum_length, "ndp_short_message", trace) {
            return Err("ndp_short_message");
        }
        let source = &ip[8..24];
        let destination = &ip[24..40];
        let source_link_option = ndp_has_source_link_option(data, minimum_length, offset, trace)?;
        match data[0] {
            133 if rejected(
                unspecified_ipv6(source) && source_link_option,
                "ndp_unspecified_source_link_option",
                trace,
            ) =>
            {
                return Err("ndp_unspecified_source_link_option");
            }
            134 if rejected(
                !link_local_ipv6(source),
                "ndp_router_source_not_link_local",
                trace,
            ) =>
            {
                return Err("ndp_router_source_not_link_local");
            }
            135 => {
                if rejected(data[8] == 0xff, "ndp_multicast_target", trace) {
                    return Err("ndp_multicast_target");
                }
                if unspecified_ipv6(source) {
                    if rejected(
                        !solicited_node_multicast(destination),
                        "ndp_unspecified_source_destination_invalid",
                        trace,
                    ) {
                        return Err("ndp_unspecified_source_destination_invalid");
                    }
                    if rejected(
                        source_link_option,
                        "ndp_unspecified_source_link_option",
                        trace,
                    ) {
                        return Err("ndp_unspecified_source_link_option");
                    }
                }
            }
            136 => {
                if rejected(data[8] == 0xff, "ndp_multicast_target", trace) {
                    return Err("ndp_multicast_target");
                }
                if rejected(
                    destination[0] == 0xff && data[4] & 0x40 != 0,
                    "ndp_solicited_multicast_advertisement",
                    trace,
                ) {
                    return Err("ndp_solicited_multicast_advertisement");
                }
            }
            _ => {}
        }
    }
    traced_set(&mut out.seeds, node::ICMPV6, trace);
    traced_set(&mut out.seeds, node::ICMPV6_CHECKSUM, trace);
    match data[0] {
        1..=4 => traced_set(&mut out.seeds, node::ICMPV6_ERROR, trace),
        133 => {
            traced_set(&mut out.seeds, node::NDP, trace);
            traced_set(&mut out.seeds, node::ROUTER_SOLICITATION, trace);
        }
        134 => {
            traced_set(&mut out.seeds, node::NDP, trace);
            traced_set(&mut out.seeds, node::ROUTER_ADVERTISEMENT, trace);
        }
        135 => {
            traced_set(&mut out.seeds, node::NDP, trace);
            traced_set(&mut out.seeds, node::NEIGHBOR_SOLICITATION, trace);
        }
        136 => {
            traced_set(&mut out.seeds, node::NDP, trace);
            traced_set(&mut out.seeds, node::NEIGHBOR_ADVERTISEMENT, trace);
        }
        _ => {
            out.reason = "icmpv6_unrepresented_type";
            return Ok(());
        }
    }
    out.reason = "icmpv6_valid";
    Ok(())
}

fn decode_ipv4(
    out: &mut Observation,
    packet: &[u8],
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "ipv4",
        offset: 14,
        length: packet.len(),
    });
    if rejected(packet.len() < 20, "ipv4_short_header", trace) {
        return Err("ipv4_short_header");
    }
    if rejected(packet[0] >> 4 != 4, "ipv4_bad_version", trace) {
        return Err("ipv4_bad_version");
    }
    field(trace, "ipv4_ttl", packet[8] as usize);
    field(trace, "ipv4_protocol", packet[9] as usize);
    field(trace, "ipv4_fragment_field", word(packet, 6) as usize);
    let header = (packet[0] & 0x0f) as usize * 4;
    field(trace, "ipv4_header_length", header);
    let total = word(packet, 2) as usize;
    field(trace, "ipv4_total_length", total);
    if rejected(
        header < 20 || header > packet.len(),
        "ipv4_header_length_invalid",
        trace,
    ) {
        return Err("ipv4_header_length_invalid");
    }
    if rejected(
        total < header || total > packet.len(),
        "ipv4_total_length_invalid",
        trace,
    ) {
        return Err("ipv4_total_length_invalid");
    }
    if rejected(
        !valid_checksum(&packet[..header]),
        "ipv4_bad_header_checksum",
        trace,
    ) {
        return Err("ipv4_bad_header_checksum");
    }
    traced_set(&mut out.seeds, node::IPV4, trace);
    traced_set(&mut out.seeds, node::IP_HEADER, trace);
    traced_set(&mut out.seeds, node::IP_LENGTH, trace);
    traced_set(&mut out.seeds, node::IP_CHECKSUM, trace);
    traced_set(&mut out.seeds, node::IP_PROTOCOL, trace);
    traced_set(&mut out.seeds, node::ENDPOINT_ADDRESSES, trace);
    if packet[8] > 0 {
        traced_set(&mut out.seeds, node::IP_TTL, trace);
    }
    if word(packet, 6) & 0x3fff != 0 {
        traced_set(&mut out.seeds, node::IP_FRAGMENT, trace);
        out.kind = ObservationKind::Fragment;
        out.reason = "ipv4_fragment_requires_reassembly";
        return Ok(());
    }
    let data = &packet[header..total];
    match packet[9] {
        17 => decode_udp(out, packet, data, false, 14 + header, trace),
        6 => decode_tcp(out, packet, data, false, 14 + header, trace),
        1 => decode_icmpv4(out, data, 14 + header, trace),
        _ => {
            out.reason = "ipv4_header_only_unrepresented_transport";
            Ok(())
        }
    }
}

fn decode_ipv6(
    out: &mut Observation,
    packet: &[u8],
    trace: &mut impl FnMut(ObserverStep),
) -> Result<(), &'static str> {
    trace(ObserverStep::Enter {
        stage: "ipv6",
        offset: 14,
        length: packet.len(),
    });
    if rejected(packet.len() < 40, "ipv6_short_header", trace) {
        return Err("ipv6_short_header");
    }
    if rejected(packet[0] >> 4 != 6, "ipv6_bad_version", trace) {
        return Err("ipv6_bad_version");
    }
    let payload = word(packet, 4) as usize;
    field(trace, "ipv6_payload_length", payload);
    field(trace, "ipv6_hop_limit", packet[7] as usize);
    if rejected(
        40 + payload > packet.len(),
        "ipv6_payload_length_invalid",
        trace,
    ) {
        return Err("ipv6_payload_length_invalid");
    }
    traced_set(&mut out.seeds, node::IPV6, trace);
    traced_set(&mut out.seeds, node::IPV6_PAYLOAD_LENGTH, trace);
    traced_set(&mut out.seeds, node::IPV6_NEXT_HEADER, trace);
    traced_set(&mut out.seeds, node::IPV6_HOP_LIMIT, trace);
    traced_set(&mut out.seeds, node::IPV6_SOURCE, trace);
    traced_set(&mut out.seeds, node::IPV6_DESTINATION, trace);
    let mut next = packet[6];
    let mut offset = 40usize;
    let end = 40 + payload;
    // Each recognized extension consumes at least eight bytes, so the
    // declared payload bounds this walk without an arbitrary header count.
    loop {
        field(trace, "ipv6_next_header", next as usize);
        field(trace, "ipv6_next_offset", 14 + offset);
        match next {
            0 | 43 | 60 => {
                if rejected(
                    next == 0 && offset != 40,
                    "ipv6_hop_by_hop_not_first",
                    trace,
                ) {
                    return Err("ipv6_hop_by_hop_not_first");
                }
                if rejected(offset + 2 > end, "ipv6_extension_short_header", trace) {
                    return Err("ipv6_extension_short_header");
                }
                traced_set(&mut out.seeds, node::IPV6_EXTENSION, trace);
                let length = (packet[offset + 1] as usize + 1) * 8;
                field(trace, "ipv6_extension_length", length);
                if rejected(
                    length < 8 || offset + length > end,
                    "ipv6_extension_length_invalid",
                    trace,
                ) {
                    return Err("ipv6_extension_length_invalid");
                }
                next = packet[offset];
                offset += length;
            }
            44 => {
                if rejected(offset + 8 > end, "ipv6_fragment_short_header", trace) {
                    return Err("ipv6_fragment_short_header");
                }
                traced_set(&mut out.seeds, node::IPV6_FRAGMENT, trace);
                out.kind = ObservationKind::Fragment;
                out.reason = "ipv6_fragment_requires_reassembly";
                return Ok(());
            }
            _ => break,
        }
    }
    let data = &packet[offset..end];
    match next {
        17 => decode_udp(out, packet, data, true, 14 + offset, trace),
        6 => decode_tcp(out, packet, data, true, 14 + offset, trace),
        58 => decode_icmpv6(out, packet, data, 14 + offset, trace),
        _ => {
            out.reason = "ipv6_header_only_unrepresented_transport";
            Ok(())
        }
    }
}

/// Decode only bounded wire structure. Payload text cannot select node IDs.
pub fn decode(frame: &[u8]) -> Observation {
    decode_traced(frame, &mut |_| {})
}

pub fn decode_traced(frame: &[u8], trace: &mut impl FnMut(ObserverStep)) -> Observation {
    trace(ObserverStep::Enter {
        stage: "ethernet",
        offset: 0,
        length: frame.len(),
    });
    let result = decode_inner(frame, trace);
    trace(ObserverStep::Finish {
        kind: result.kind,
        reason: result.reason,
        seeds: result.seeds,
    });
    result
}
fn decode_inner(frame: &[u8], trace: &mut impl FnMut(ObserverStep)) -> Observation {
    let mut out = Observation {
        kind: ObservationKind::Unknown,
        seeds: [0; NODE_WORDS],
        reason: "unparsed",
    };
    if rejected(frame.len() < 14, "ethernet_short_frame", trace) {
        return malformed("ethernet_short_frame");
    }
    let ether_type = word(frame, 12);
    field(trace, "ether_type", ether_type as usize);
    let packet = &frame[14..];
    let result = match ether_type {
        0x0806 => {
            trace(ObserverStep::Enter {
                stage: "arp",
                offset: 14,
                length: packet.len(),
            });
            if rejected(
                packet.len() < 28
                    || word(packet, 0) != 1
                    || word(packet, 2) != 0x0800
                    || packet[4] != 6
                    || packet[5] != 4,
                "arp_structure_invalid",
                trace,
            ) {
                Err("arp_structure_invalid")
            } else {
                field(trace, "arp_operation", word(packet, 6) as usize);
                match word(packet, 6) {
                    1 => {
                        traced_set(&mut out.seeds, node::ARP_REQUEST, trace);
                        out.reason = "arp_request_valid";
                    }
                    2 => {
                        traced_set(&mut out.seeds, node::ARP_REPLY, trace);
                        out.reason = "arp_reply_valid";
                    }
                    _ => {
                        out.reason = "arp_unrepresented_operation";
                        return out;
                    }
                }
                Ok(())
            }
        }
        0x0800 => decode_ipv4(&mut out, packet, trace),
        0x86dd => decode_ipv6(&mut out, packet, trace),
        _ => {
            out.reason = "ethernet_unrepresented_ethertype";
            return out;
        }
    };
    if let Err(reason) = result {
        trace(ObserverStep::Discard {
            reason,
            seeds: out.seeds,
        });
        return malformed(reason);
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

    #[test]
    fn trace_returns_identical_observation_and_records_seed_discard() {
        let (mut frame, length) = udp_frame(b"trace-fixture");
        for count in 0..=length {
            let mut last = None;
            let got = decode_traced(&frame[..count], &mut |event| {
                if let ObserverStep::Finish {
                    kind,
                    reason,
                    seeds,
                } = event
                {
                    last = Some(Observation {
                        kind,
                        reason,
                        seeds,
                    });
                }
            });
            assert_eq!(got, decode(&frame[..count]));
            assert_eq!(last, Some(got));
        }
        // IP validates and contributes seeds before invalid UDP length clears them.
        frame[14 + 20 + 4] = 1;
        let mut discarded = false;
        let got = decode_traced(&frame[..length], &mut |event| {
            if let ObserverStep::Discard { seeds, .. } = event {
                discarded = seeds.iter().any(|word| *word != 0);
            }
        });
        assert!(discarded);
        assert_eq!(got.kind, ObservationKind::Malformed);
        assert_eq!(got.seeds, [0; NODE_WORDS]);
    }

    fn finish_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset + 1] = 0;
        let value = !folded(add_words(0, bytes));
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn finish_icmpv6_checksum(packet: &mut [u8]) {
        let length = word(packet, 4) as usize;
        packet[42..44].fill(0);
        let mut sum = add_words(0, &packet[8..40]);
        sum += length as u32 + 58;
        let checksum = !folded(add_words(sum, &packet[40..40 + length]));
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
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
        finish_icmpv6_checksum(packet);
        (frame, length)
    }

    #[test]
    fn malformed_and_unknown_observations_have_no_seeds() {
        for length in 0..14 {
            let observation = decode(&[0u8; 14][..length]);
            assert_eq!(observation.kind, ObservationKind::Malformed);
            assert_eq!(observation.seeds, [0; NODE_WORDS]);
            assert_eq!(observation.reason, "ethernet_short_frame");
        }
        let mut frame = [0u8; 14];
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Unknown);
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
        assert_eq!(observation.reason, "ethernet_unrepresented_ethertype");
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
        assert_eq!(observation.reason, "ipv4_udp_no_checksum");
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
        assert_eq!(observation.reason, "icmpv6_valid");
        assert!(bit(&observation.seeds, node::IPV6));
        assert!(bit(&observation.seeds, node::ICMPV6));
        assert!(bit(&observation.seeds, node::NDP));
        assert!(bit(&observation.seeds, node::NEIGHBOR_SOLICITATION));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
    }

    #[test]
    fn neighbor_discovery_requires_hop_limit_255() {
        let (mut frame, length) = ipv6_neighbor_solicitation();
        frame[14 + 7] = 64;
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_hop_limit_invalid");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn neighbor_discovery_requires_code_zero_and_complete_message() {
        let (mut frame, length) = ipv6_neighbor_solicitation();
        let packet = &mut frame[14..length];
        packet[41] = 1;
        finish_icmpv6_checksum(packet);
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_code_invalid");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);

        let (mut frame, _) = ipv6_neighbor_solicitation();
        let packet = &mut frame[14..14 + 40 + 8];
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        finish_icmpv6_checksum(packet);
        let observation = decode(&frame[..14 + 40 + 8]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_short_message");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn unresolved_ipv6_extension_chain_has_no_context() {
        let mut frame = [0u8; 14 + 40 + 64];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&64u16.to_be_bytes());
        packet[6] = 60;
        for extension in packet[40..].chunks_exact_mut(8) {
            extension[0] = 60;
        }
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ipv6_extension_short_header");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn complete_ipv6_extension_chain_can_exceed_eight_headers() {
        let mut frame = [0u8; 14 + 40 + 72];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&72u16.to_be_bytes());
        packet[6] = 60;
        for extension in packet[40..].chunks_exact_mut(8) {
            extension[0] = 60;
        }
        packet[40 + 64] = 59;
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert_eq!(
            observation.reason,
            "ipv6_header_only_unrepresented_transport"
        );
        assert!(bit(&observation.seeds, node::IPV6));
        assert!(bit(&observation.seeds, node::IPV6_EXTENSION));
    }

    #[test]
    fn hop_by_hop_extension_must_be_first() {
        let mut frame = [0u8; 14 + 40 + 16];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 60;
        packet[40] = 0;
        packet[48] = 59;
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ipv6_hop_by_hop_not_first");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn deterministic_wire_stress_keeps_unrecognized_inputs_empty() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        let mut frame = [0u8; 300];
        for trial in 0..20_000usize {
            let length = 14 + trial % (frame.len() - 13);
            for byte in &mut frame[..length] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            frame[12..14].copy_from_slice(
                &match trial % 3 {
                    0 => 0x86ddu16,
                    1 => 0x0800u16,
                    _ => 0x0806u16,
                }
                .to_be_bytes(),
            );
            if trial % 3 == 0 && length >= 54 {
                frame[14] = 0x60;
                frame[18..20].copy_from_slice(&((length - 54) as u16).to_be_bytes());
                frame[20] = [0, 43, 44, 60, 58, 17, 6, 59][trial % 8];
            }
            let observation = decode(&frame[..length]);
            if matches!(
                observation.kind,
                ObservationKind::Malformed | ObservationKind::Unknown
            ) {
                assert_eq!(observation.seeds, [0; NODE_WORDS], "trial {trial}");
            }
        }
    }
}
