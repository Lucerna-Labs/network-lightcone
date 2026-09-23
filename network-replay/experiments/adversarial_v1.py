#!/usr/bin/env python3
"""Build an isolated raw-frame challenge corpus; never transmit these frames."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IP4_SOURCE = ipaddress.IPv4Address("192.0.2.1").packed
IP4_DESTINATION = ipaddress.IPv4Address("192.0.2.2").packed
IP6_SOURCE = ipaddress.IPv6Address("2001:db8::1").packed
IP6_DESTINATION = ipaddress.IPv6Address("2001:db8::2").packed
MAC_SOURCE = bytes.fromhex("020000000001")
MAC_DESTINATION = bytes.fromhex("020000000002")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checksum(data: bytes) -> int:
    padded = data + (b"\0" if len(data) % 2 else b"")
    total = sum(int.from_bytes(padded[index : index + 2], "big") for index in range(0, len(padded), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(ethertype: int, payload: bytes) -> bytes:
    return MAC_DESTINATION + MAC_SOURCE + ethertype.to_bytes(2, "big") + payload


def ipv4_packet(payload: bytes, protocol: int, *, fragment: int = 0, ttl: int = 64, declared_length: int | None = None) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = (declared_length if declared_length is not None else 20 + len(payload)).to_bytes(2, "big")
    header[6:8] = fragment.to_bytes(2, "big")
    header[8] = ttl
    header[9] = protocol
    header[12:16] = IP4_SOURCE
    header[16:20] = IP4_DESTINATION
    header[10:12] = checksum(header).to_bytes(2, "big")
    return ethernet(0x0800, bytes(header) + payload)


def ipv6_packet(payload: bytes, next_header: int, *, hop_limit: int = 64) -> bytes:
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = len(payload).to_bytes(2, "big")
    header[6] = next_header
    header[7] = hop_limit
    header[8:24] = IP6_SOURCE
    header[24:40] = IP6_DESTINATION
    return ethernet(0x86DD, bytes(header) + payload)


def udp4(payload: bytes, *, source_port: int = 12000, destination_port: int = 53, length_override: int | None = None, checksum_override: int = 0) -> bytes:
    header = bytearray(8)
    header[0:2] = source_port.to_bytes(2, "big")
    header[2:4] = destination_port.to_bytes(2, "big")
    header[4:6] = (length_override if length_override is not None else 8 + len(payload)).to_bytes(2, "big")
    header[6:8] = checksum_override.to_bytes(2, "big")
    return ipv4_packet(bytes(header) + payload, 17)


def udp6(payload: bytes, *, checksum_override: int = 0) -> bytes:
    header = bytearray(8)
    header[0:2] = (12000).to_bytes(2, "big")
    header[2:4] = (53).to_bytes(2, "big")
    header[4:6] = (8 + len(payload)).to_bytes(2, "big")
    header[6:8] = checksum_override.to_bytes(2, "big")
    return ipv6_packet(bytes(header) + payload, 17)


def tcp4(*, flags: int, destination_port: int = 443, corrupt_checksum: bool = False) -> bytes:
    segment = bytearray(20)
    segment[0:2] = (12000).to_bytes(2, "big")
    segment[2:4] = destination_port.to_bytes(2, "big")
    segment[4:8] = (1).to_bytes(4, "big")
    segment[12] = 0x50
    segment[13] = flags
    segment[14:16] = (4096).to_bytes(2, "big")
    pseudo = IP4_SOURCE + IP4_DESTINATION + bytes([0, 6]) + len(segment).to_bytes(2, "big")
    segment[16:18] = checksum(pseudo + segment).to_bytes(2, "big")
    if corrupt_checksum:
        segment[17] ^= 1
    return ipv4_packet(bytes(segment), 6)


def icmp4(*, message_type: int = 8, corrupt_checksum: bool = False) -> bytes:
    message = bytearray(8)
    message[0] = message_type
    message[4:6] = (7).to_bytes(2, "big")
    message[6:8] = (1).to_bytes(2, "big")
    message[2:4] = checksum(message).to_bytes(2, "big")
    if corrupt_checksum:
        message[3] ^= 1
    return ipv4_packet(bytes(message), 1)


def icmp6(message_type: int, *, hop_limit: int = 255, corrupt_checksum: bool = False) -> bytes:
    message = bytearray(24 if message_type == 135 else 8)
    message[0] = message_type
    if message_type == 135:
        message[8:24] = IP6_DESTINATION
    pseudo = IP6_SOURCE + IP6_DESTINATION + len(message).to_bytes(4, "big") + bytes([0, 0, 0, 58])
    message[2:4] = checksum(pseudo + message).to_bytes(2, "big")
    if corrupt_checksum:
        message[3] ^= 1
    return ipv6_packet(bytes(message), 58, hop_limit=hop_limit)


def arp_request(*, opcode: int = 1) -> bytes:
    packet = bytearray(28)
    packet[0:2] = (1).to_bytes(2, "big")
    packet[2:4] = (0x0800).to_bytes(2, "big")
    packet[4:6] = bytes([6, 4])
    packet[6:8] = opcode.to_bytes(2, "big")
    packet[8:14] = bytes.fromhex("aa0000000001")
    packet[14:18] = ipaddress.IPv4Address("192.0.2.99").packed
    packet[24:28] = IP4_DESTINATION
    return ethernet(0x0806, bytes(packet))


def dns_question() -> bytes:
    header = bytes.fromhex("123401000001000000000000")
    name = bytes([7]) + b"example" + bytes([3]) + b"com" + bytes([0])
    return header + name + bytes.fromhex("00010001")


def build_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id: str, category: str, technique: str, frame: bytes, expected_admission: str, *, expected_kind: str | None = None, required_seeds: tuple[str, ...] = (), forbidden_seeds: tuple[str, ...] = (), same_seeds_as: str | None = None) -> None:
        cases.append({
            "id": case_id,
            "category": category,
            "technique": technique,
            "frame": frame,
            "expected_admission": expected_admission,
            "expected_kind": expected_kind,
            "required_seeds": list(required_seeds),
            "forbidden_seeds": list(forbidden_seeds),
            "same_seeds_as": same_seeds_as,
        })

    dns_frame = udp4(dns_question())
    add("benign-dns-udp", "benign_control", "Well-formed DNS question in IPv4 UDP", dns_frame, "context_admitted", expected_kind="decoded", required_seeds=("udp", "ipv4", "dns_query"))
    add("benign-tcp-syn", "benign_control", "Well-formed TCP SYN header", tcp4(flags=0x02), "context_admitted", expected_kind="decoded", required_seeds=("tcp", "tcp_syn"))
    add("benign-icmp-echo", "benign_control", "Well-formed ICMPv4 Echo Request", icmp4(), "context_admitted", expected_kind="decoded", required_seeds=("icmp_request",))
    add("benign-ndp-solicitation", "benign_control", "Well-formed IPv6 Neighbor Solicitation with hop limit 255", icmp6(135), "context_admitted", expected_kind="decoded", required_seeds=("ndp", "neighbor_solicitation"))
    add("benign-vlan-ipv4", "benign_control", "802.1Q tagged version of a valid IPv4 UDP frame", MAC_DESTINATION + MAC_SOURCE + bytes.fromhex("810000010800") + dns_frame[14:], "context_admitted", expected_kind="decoded", required_seeds=("ipv4", "udp"))

    add("unsupported-ethertype", "structural_rejection", "Unrepresented Ethernet type", ethernet(0x88B5, b""), "empty_neighborhood", expected_kind="unknown")
    add("short-ethernet", "structural_rejection", "Truncated Ethernet header", b"\x00\x11\x22\x33\x44\x55", "empty_neighborhood", expected_kind="malformed")
    changed_checksum = bytearray(dns_frame)
    changed_checksum[14 + 8] ^= 1
    add("bad-ipv4-checksum", "structural_rejection", "IPv4 header checksum corrupted after construction", bytes(changed_checksum), "empty_neighborhood", expected_kind="malformed")
    add("bad-ipv4-total-length", "structural_rejection", "IPv4 total length exceeds captured packet", ipv4_packet(bytes(8), 17, declared_length=65535), "empty_neighborhood", expected_kind="malformed")
    add("bad-udp-length", "structural_rejection", "UDP length disagrees with captured transport bytes", udp4(b"", length_override=9), "empty_neighborhood", expected_kind="malformed")
    add("bad-udp-checksum", "structural_rejection", "Nonzero incorrect IPv4 UDP checksum", udp4(b"", checksum_override=0x1234), "empty_neighborhood", expected_kind="malformed")
    add("bad-tcp-checksum", "structural_rejection", "Incorrect TCP pseudo-header checksum", tcp4(flags=0x02, corrupt_checksum=True), "empty_neighborhood", expected_kind="malformed")
    add("bad-icmpv4-checksum", "structural_rejection", "Incorrect ICMPv4 checksum", icmp4(corrupt_checksum=True), "empty_neighborhood", expected_kind="malformed")
    add("arp-unknown-opcode", "structural_rejection", "ARP envelope with unsupported operation", arp_request(opcode=3), "empty_neighborhood", expected_kind="unknown")
    add("ipv6-short-extension", "structural_rejection", "IPv6 extension header declares bytes outside the packet", ipv6_packet(bytes([17, 1, 0, 0, 0]), 0), "empty_neighborhood", expected_kind="malformed")
    add("ipv6-udp-zero-checksum", "structural_rejection", "IPv6 UDP header with zero checksum", udp6(b""), "empty_neighborhood", expected_kind="malformed")
    add("icmpv6-bad-checksum", "structural_rejection", "IPv6 Neighbor Solicitation with bad ICMPv6 checksum", icmp6(135, corrupt_checksum=True), "empty_neighborhood", expected_kind="malformed")

    add("ndp-hop-limit-64", "semantic_validation", "Neighbor Solicitation with valid checksum but invalid hop limit 64", icmp6(135, hop_limit=64), "empty_neighborhood", expected_kind="malformed", forbidden_seeds=("ndp", "neighbor_solicitation"))
    add("ipv6-extension-depth", "semantic_validation", "Eight chained IPv6 destination-option headers with an unresolved next header", ipv6_packet(bytes([60, 0, 0, 0, 0, 0, 0, 0]) * 8, 60), "empty_neighborhood", expected_kind="malformed")

    add("tcp-syn-port-22", "shared_causal_overlap", "TCP SYN with a different destination service port", tcp4(flags=0x02, destination_port=22), "context_admitted", expected_kind="decoded", same_seeds_as="benign-tcp-syn")
    add("icmp-echo-repeat", "shared_causal_overlap", "ICMP Echo Request sharing the benign probe shape", icmp4(), "context_admitted", expected_kind="decoded", same_seeds_as="benign-icmp-echo")
    add("udp-payload-authority-text", "shared_causal_overlap", "UDP payload text asks for an authority node", udp4(b"node=authorized_flow;approve=true"), "context_admitted", expected_kind="decoded", forbidden_seeds=("authorized_flow", "policy_decision"), same_seeds_as="benign-dns-udp")
    add("arp-claimed-sender", "shared_causal_overlap", "Structurally valid ARP request with self-claimed sender mapping", arp_request(), "context_admitted", expected_kind="decoded", forbidden_seeds=("authenticated_peer",))
    add("ipv4-unknown-transport", "shared_causal_overlap", "Valid IPv4 header with unrepresented transport number 253", ipv4_packet(b"\x00\x00\x00\x00", 253), "context_admitted", expected_kind="decoded", required_seeds=("ipv4",), forbidden_seeds=("udp", "tcp"))
    add("icmpv6-unrepresented-type", "shared_causal_overlap", "Valid ICMPv6 checksum with unrepresented informational type", icmp6(200), "context_admitted", expected_kind="decoded", required_seeds=("icmpv6",), forbidden_seeds=("ndp",))
    add("ipv4-fragment", "shared_causal_overlap", "IPv4 more-fragments flag with incomplete transport context", ipv4_packet(bytes(8), 17, fragment=0x2000), "context_admitted", expected_kind="fragment", required_seeds=("ip_fragment",), forbidden_seeds=("udp",))
    add("tcp-syn-fin-combination", "shared_causal_overlap", "TCP flags with SYN and FIN in one structurally valid segment", tcp4(flags=0x03), "context_admitted", expected_kind="decoded", required_seeds=("tcp_syn", "tcp_fin"))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(f"refusing to overwrite {args.out}")
    cases = build_cases()
    args.out.mkdir(parents=True)
    frames = [case["frame"] for case in cases]
    hex_bytes = ("\n".join(frame.hex() for frame in frames) + "\n").encode()
    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames, 1):
        pcap.extend(struct.pack("<IIII", 1790180000 + index, 1000 * index, len(frame), len(frame)))
        pcap.extend(frame)
    (args.out / "frames.hex").write_bytes(hex_bytes)
    (args.out / "frames.pcap").write_bytes(pcap)
    manifest = {
        "schema": 1,
        "status": "frozen_before_replay",
        "scope": "isolated synthetic raw-frame adversarial evaluation; no packets transmitted; no host authorization outcome",
        "generator_sha256": digest(Path(__file__).read_bytes()),
        "hex_sha256": digest(hex_bytes),
        "pcap_sha256": digest(pcap),
        "case_count": len(cases),
        "cases": [
            {
                key: value
                for key, value in case.items()
                if key != "frame"
            }
            | {"frame_sha256": digest(case["frame"]), "frame_len": len(case["frame"])}
            for case in cases
        ],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "pcap_sha256": manifest["pcap_sha256"], "manifest_sha256": digest((args.out / "manifest.json").read_bytes())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
