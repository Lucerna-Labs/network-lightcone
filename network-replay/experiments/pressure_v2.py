#!/usr/bin/env python3
"""Freeze a second offline raw-frame challenge; never transmit its frames."""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
from pathlib import Path

from adversarial_v1 import checksum, digest, ethernet, icmp4, ipv4_packet, tcp4, udp4


SOURCE = ipaddress.IPv6Address("2001:db8::1").packed
TARGET = ipaddress.IPv6Address("2001:db8::2").packed
LINK_LOCAL = ipaddress.IPv6Address("fe80::1").packed
MULTICAST = ipaddress.IPv6Address("ff02::1").packed
SOLICITED = ipaddress.IPv6Address("ff02::1:ff00:2").packed
UNSPECIFIED = bytes(16)
SOURCE_LL = bytes.fromhex("0101020000000001")
ZERO_LENGTH_LL = bytes.fromhex("0100020000000001")
TRUNCATED_LL = bytes.fromhex("0102020000000001")


def icmp6(message_type: int, body: bytes, *, source: bytes = SOURCE,
          destination: bytes = TARGET, code: int = 0, hop_limit: int = 255,
          options: bytes = b"") -> bytes:
    message = bytearray(bytes([message_type, code, 0, 0]) + body + options)
    pseudo = source + destination + len(message).to_bytes(4, "big") + bytes([0, 0, 0, 58])
    message[2:4] = checksum(pseudo + message).to_bytes(2, "big")
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = len(message).to_bytes(2, "big")
    header[6] = 58
    header[7] = hop_limit
    header[8:24] = source
    header[24:40] = destination
    return ethernet(0x86DD, bytes(header) + message)


def ipv6_extension(chain: list[int], terminal: int = 59) -> bytes:
    """Each item is an extension type; all have the minimum eight-byte size."""
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = (8 * len(chain)).to_bytes(2, "big")
    header[6] = chain[0]
    header[7] = 64
    header[8:24] = SOURCE
    header[24:40] = TARGET
    extensions = bytearray(8 * len(chain))
    for index in range(len(chain)):
        extensions[index * 8] = chain[index + 1] if index + 1 < len(chain) else terminal
    return ethernet(0x86DD, bytes(header) + extensions)


def build_cases() -> list[dict]:
    cases: list[dict] = []

    def add(case_id: str, category: str, frame: bytes, admitted: bool,
            *, seed: str | None = None) -> None:
        cases.append({
            "id": case_id,
            "category": category,
            "technique": case_id.replace("-", " "),
            "frame": frame,
            "expected_admission": "context_admitted" if admitted else "empty_neighborhood",
            "expected_kind": "decoded" if admitted else "malformed",
            "required_seeds": [seed] if seed else [],
            "forbidden_seeds": [] if admitted else ["ndp"],
            "same_seeds_as": None,
        })

    rs = bytes(4)
    ra = bytes(12)
    ns = bytes(4) + TARGET
    na = bytes(4) + TARGET

    add("valid-neighbor-solicitation", "valid_nd_control", icmp6(135, ns), True,
        seed="neighbor_solicitation")
    add("valid-router-solicitation", "valid_nd_control", icmp6(133, rs), True,
        seed="router_solicitation")
    add("valid-router-advertisement", "valid_nd_control",
        icmp6(134, ra, source=LINK_LOCAL, destination=MULTICAST), True,
        seed="router_advertisement")
    add("valid-neighbor-advertisement", "valid_nd_control", icmp6(136, na), True,
        seed="neighbor_advertisement")
    add("valid-dad-solicitation", "valid_nd_control",
        icmp6(135, ns, source=UNSPECIFIED, destination=SOLICITED), True,
        seed="neighbor_solicitation")
    add("valid-ns-source-link-option", "valid_nd_control",
        icmp6(135, ns, options=SOURCE_LL), True, seed="neighbor_solicitation")

    add("ns-multicast-target", "invalid_nd", icmp6(135, bytes(4) + MULTICAST), False)
    add("ns-zero-length-option", "invalid_nd", icmp6(135, ns, options=ZERO_LENGTH_LL), False)
    add("ns-truncated-option", "invalid_nd", icmp6(135, ns, options=TRUNCATED_LL), False)
    add("ns-unspecified-source-unicast-destination", "invalid_nd",
        icmp6(135, ns, source=UNSPECIFIED), False)
    add("ns-unspecified-source-with-link-option", "invalid_nd",
        icmp6(135, ns, source=UNSPECIFIED, destination=SOLICITED, options=SOURCE_LL), False)
    add("ra-global-source", "invalid_nd", icmp6(134, ra), False)
    add("ra-zero-length-option", "invalid_nd",
        icmp6(134, ra, source=LINK_LOCAL, destination=MULTICAST,
              options=ZERO_LENGTH_LL), False)
    add("rs-unspecified-source-with-link-option", "invalid_nd",
        icmp6(133, rs, source=UNSPECIFIED, destination=MULTICAST,
              options=SOURCE_LL), False)
    add("rs-zero-length-option", "invalid_nd",
        icmp6(133, rs, options=ZERO_LENGTH_LL), False)
    add("na-multicast-target", "invalid_nd", icmp6(136, bytes(4) + MULTICAST), False)
    add("na-solicited-to-multicast", "invalid_nd",
        icmp6(136, bytes([0x40, 0, 0, 0]) + TARGET, destination=MULTICAST), False)
    add("na-zero-length-option", "invalid_nd", icmp6(136, na, options=ZERO_LENGTH_LL), False)
    add("nd-bad-code", "invalid_nd", icmp6(135, ns, code=1), False)
    add("nd-bad-hop-limit", "invalid_nd", icmp6(135, ns, hop_limit=64), False)
    add("nd-short-message", "invalid_nd", icmp6(135, bytes(4)), False)

    add("valid-nine-extension-chain", "valid_ipv6_control",
        ipv6_extension([60] * 9), True, seed="ipv6_extension")
    add("valid-hop-by-hop-then-destination", "valid_ipv6_control",
        ipv6_extension([0, 60]), True, seed="ipv6_extension")
    add("unresolved-extension-chain", "invalid_ipv6_extension",
        ipv6_extension([60] * 8, terminal=60), False)
    add("hop-by-hop-not-first", "invalid_ipv6_extension",
        ipv6_extension([60, 0]), False)
    add("bad-extension-declared-length", "invalid_ipv6_extension",
        ethernet(0x86DD, ipv6_extension([60])[14:40 + 14] + b"\x3b\x01" + bytes(6)), False)

    add("valid-ipv4-udp-context", "cross_protocol_control", udp4(b"context"), True,
        seed="udp")
    add("bad-ipv4-header-checksum", "cross_protocol_control",
        bytes(bytearray(ipv4_packet(bytes(8), 17))[:22] +
              bytes([ipv4_packet(bytes(8), 17)[22] ^ 1]) +
              ipv4_packet(bytes(8), 17)[23:]), False)
    add("valid-ipv4-tcp-context", "cross_protocol_control", tcp4(flags=0x02), True,
        seed="tcp")
    add("bad-ipv4-tcp-checksum", "cross_protocol_control",
        tcp4(flags=0x02, corrupt_checksum=True), False)
    add("valid-icmpv4-context", "cross_protocol_control", icmp4(), True,
        seed="icmp_request")
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
        pcap.extend(struct.pack("<IIII", 1790181000 + index, 1000 * index, len(frame), len(frame)))
        pcap.extend(frame)
    (args.out / "frames.hex").write_bytes(hex_bytes)
    (args.out / "frames.pcap").write_bytes(pcap)
    manifest = {
        "schema": 1,
        "status": "frozen_before_replay",
        "scope": "isolated synthetic network observation challenge; no transmission or enforcement",
        "generator_sha256": digest(Path(__file__).read_bytes()),
        "hex_sha256": digest(hex_bytes),
        "pcap_sha256": digest(pcap),
        "case_count": len(cases),
        "cases": [
            {key: value for key, value in case.items() if key != "frame"}
            | {"frame_sha256": digest(case["frame"]), "frame_len": len(case["frame"])}
            for case in cases
        ],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "pcap_sha256": manifest["pcap_sha256"],
                      "manifest_sha256": digest((args.out / "manifest.json").read_bytes())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
