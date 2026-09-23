#!/usr/bin/env python3
"""Transmit and capture a bounded TCP sequence inside an isolated net namespace.

Run only with `unshare -Urn`; no packet is addressed outside 127.0.0.1.
Captured PCAPs are evaluation artifacts, never Lightcone training inputs.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

from adversarial_v1 import checksum, digest


LOOPBACK = socket.inet_aton("127.0.0.1")
RAW_SOURCE_PORT = 42000
ORDINARY_SOURCE_PORT = 42001


def raw_tcp(destination_port: int, flags: int, sequence: int,
            acknowledgment: int = 0, payload: bytes = b"") -> bytes:
    segment = bytearray(20 + len(payload))
    segment[0:2] = RAW_SOURCE_PORT.to_bytes(2, "big")
    segment[2:4] = destination_port.to_bytes(2, "big")
    segment[4:8] = sequence.to_bytes(4, "big")
    segment[8:12] = acknowledgment.to_bytes(4, "big")
    segment[12] = 0x50
    segment[13] = flags
    segment[14:16] = (4096).to_bytes(2, "big")
    segment[20:] = payload
    pseudo = LOOPBACK + LOOPBACK + bytes([0, 6]) + len(segment).to_bytes(2, "big")
    segment[16:18] = checksum(pseudo + segment).to_bytes(2, "big")

    packet = bytearray(20 + len(segment))
    packet[0] = 0x45
    packet[2:4] = len(packet).to_bytes(2, "big")
    packet[4:6] = (0x4C43).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = 6
    packet[12:16] = LOOPBACK
    packet[16:20] = LOOPBACK
    packet[10:12] = checksum(packet[:20]).to_bytes(2, "big")
    packet[20:] = segment
    return bytes(packet)


def serve_one(listener: socket.socket, result: dict) -> None:
    try:
        connection, _ = listener.accept()
        with connection:
            result["request_received"] = bool(connection.recv(1024))
            connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except OSError as error:
        result["server_error"] = str(error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    uid_map = Path("/proc/self/uid_map").read_text().split()
    isolated_interfaces = sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if (
        os.geteuid() != 0
        or len(uid_map) != 3
        or uid_map[0] != "0"
        or uid_map[2] != "1"
        or not isolated_interfaces
    ):
        raise RuntimeError("run only in an isolated user and network namespace with unshare -Urn")
    if args.out.exists():
        raise FileExistsError(f"refusing to overwrite {args.out}")
    args.out.mkdir(parents=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(5)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port = listener.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        closed_port = reserve.getsockname()[1]
    if closed_port == open_port:
        raise RuntimeError("open and closed controls chose the same port")

    data = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    planned = {
        "schema": 1,
        "status": "frozen_before_transmission",
        "scope": "real packets on isolated 127.0.0.1 namespace only; passive offline Lightcone replay follows capture",
        "generator_sha256": digest(Path(__file__).read_bytes()),
        "open_port": open_port,
        "closed_port": closed_port,
        "raw_source_port": RAW_SOURCE_PORT,
        "ordinary_source_port": ORDINARY_SOURCE_PORT,
        "steps": [
            "ordinary SYN to closed port and kernel RST response",
            "raw SYN to open port from one source port",
            "raw out-of-state ACK with application-like bytes on the same tuple",
            "raw FIN+ACK on the same tuple",
            "raw ACK with deliberately incorrect checksum on the same tuple",
            "ordinary completed handshake, request, response, and close",
        ],
        "hypotheses": [
            "A structurally valid SYN will admit TCP context.",
            "A valid-checksum ACK or data packet will also admit generic TCP context even without observed connection state.",
            "The deliberately bad-checksum TCP packet will admit no context.",
            "A completed ordinary connection will admit TCP context for its follow-up packets.",
        ],
    }
    (args.out / "plan.json").write_text(json.dumps(planned, indent=2) + "\n")

    capture = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-U", "-s", "0", "-nn", "-Z", "root",
         "-w", str(args.out / "capture.pcap")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    server_result: dict = {}
    server = threading.Thread(target=serve_one, args=(listener, server_result), daemon=True)
    server.start()
    sent: list[str] = []
    try:
        time.sleep(0.3)
        if capture.poll() is not None:
            raise RuntimeError(f"capture exited early: {capture.communicate()[1]}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_probe:
            closed_probe.settimeout(1)
            closed_result = closed_probe.connect_ex(("127.0.0.1", closed_port))
        sent.append(f"closed_port_connect_ex={closed_result}")

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
            raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            for label, packet in [
                ("raw_syn", raw_tcp(open_port, 0x02, 1000)),
                ("raw_ack_data", raw_tcp(open_port, 0x10, 1001, 1, data)),
                ("raw_fin_ack", raw_tcp(open_port, 0x11, 1001 + len(data), 1)),
            ]:
                raw.sendto(packet, ("127.0.0.1", open_port))
                sent.append(label)
                time.sleep(0.08)
            corrupt = bytearray(raw_tcp(open_port, 0x10, 1002, 1))
            corrupt[20 + 16] ^= 1
            raw.sendto(corrupt, ("127.0.0.1", open_port))
            sent.append("raw_bad_checksum_ack")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ordinary:
            ordinary.settimeout(3)
            ordinary.bind(("127.0.0.1", ORDINARY_SOURCE_PORT))
            ordinary.connect(("127.0.0.1", open_port))
            ordinary.sendall(data)
            response = ordinary.recv(1024)
            sent.append(f"ordinary_response_bytes={len(response)}")
        server.join(timeout=3)
        if server_result.get("server_error") or not server_result.get("request_received"):
            raise RuntimeError(f"ordinary server exchange incomplete: {server_result}")
        # AF_PACKET capture may retain a partially filled ring block until
        # its timeout; allow it to hand the final packets to tcpdump.
        time.sleep(2.0)
    finally:
        listener.close()
        if capture.poll() is None:
            try:
                capture.send_signal(signal.SIGINT)
            except PermissionError:
                # AppArmor confines tcpdump separately and may deny signals
                # from the parent even in the same disposable namespace.
                subprocess.run(
                    ["aa-exec", "-p", "tcpdump", "--", "kill", "-INT", str(capture.pid)],
                    check=True,
                )
        _, capture_stderr = capture.communicate(timeout=5)

    pcap = args.out / "capture.pcap"
    if capture.returncode != 0 or not pcap.is_file() or pcap.stat().st_size <= 24:
        raise RuntimeError(f"capture failed: {capture_stderr}")
    outcome = {
        "schema": 1,
        "status": "captured",
        "plan_sha256": digest((args.out / "plan.json").read_bytes()),
        "pcap_sha256": digest(pcap.read_bytes()),
        "pcap_bytes": pcap.stat().st_size,
        "steps_sent": sent,
        "capture_stderr": capture_stderr.strip(),
        "server": server_result,
    }
    (args.out / "capture.json").write_text(json.dumps(outcome, indent=2) + "\n")
    print(json.dumps(outcome, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
