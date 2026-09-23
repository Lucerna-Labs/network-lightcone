#!/usr/bin/env python3
"""Bind the fake-secret attack result to exact captured Lightcone admissions."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from local_malicious_http import FAKE_SECRET


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def pcap_frames(data: bytes) -> list[bytes]:
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("classic PCAP magic required")
    require(len(data) >= 24, "PCAP global header short")
    require(struct.unpack_from(endian + "I", data, 20)[0] == 1, "Ethernet PCAP required")
    offset = 24
    frames = []
    while offset < len(data):
        require(offset + 16 <= len(data), "PCAP record header short")
        _, _, captured, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        require(offset + captured <= len(data), "PCAP record bytes short")
        frames.append(data[offset:offset + captured])
        offset += captured
    return frames


def tcp_payload(frame: bytes) -> bytes:
    if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00":
        return b""
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return b""
    ihl = (ip[0] & 0x0F) * 4
    total = int.from_bytes(ip[2:4], "big")
    if total > len(ip) or total < ihl + 20:
        return b""
    tcp = ip[ihl:total]
    header = (tcp[12] >> 4) * 4
    if header < 20 or header > len(tcp):
        return b""
    return tcp[header:]


def label(payload: bytes) -> str | None:
    if payload.startswith(b"GET /file/hello.txt HTTP/1.0"):
        return "benign_public_request"
    if payload.startswith(b"GET /secret.txt HTTP/1.0"):
        return "denied_direct_request"
    if payload.startswith(b"GET /file/../secret.txt HTTP/1.0"):
        return "unauthorized_traversal_request"
    if payload.startswith(b"HTTP/1.0") and FAKE_SECRET in payload:
        return "fake_secret_response"
    if payload.startswith(b"POST /collect HTTP/1.0") and FAKE_SECRET in payload:
        return "fake_secret_transfer"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "refusing to overwrite evaluated results")

    plan_path = args.capture / "plan.json"
    pcap_path = args.capture / "capture.pcap"
    capture_path = args.capture / "capture.json"
    service_path = args.capture / "service_result.json"
    events_path = args.replay / "events.jsonl"
    summary_path = args.replay / "summary.json"
    plan = json.loads(plan_path.read_bytes())
    capture = json.loads(capture_path.read_bytes())
    service = json.loads(service_path.read_bytes())
    summary = json.loads(summary_path.read_bytes())
    pcap = pcap_path.read_bytes()
    events_bytes = events_path.read_bytes()
    events = [json.loads(line) for line in events_bytes.splitlines() if line]
    frames = pcap_frames(pcap)

    require(plan["status"] == "frozen_before_attack", "attack plan was not predeclared")
    require(plan["fake_secret_sha256"] == digest(FAKE_SECRET), "fake secret binding differs")
    require(capture["plan_sha256"] == digest(plan_path.read_bytes()), "capture plan binding differs")
    require(capture["pcap_sha256"] == digest(pcap), "capture PCAP binding differs")
    require(capture["service_result_sha256"] == digest(service_path.read_bytes()), "service result binding differs")
    require(service["complete"] is True, "local service did not complete")
    require(service["collector"]["received_fake_secret"] is True, "local fake secret was not transferred")
    require(capture["direct_secret_status"] == 404, "direct secret access was not denied")
    require(capture["traversal_status"] == 200 and capture["traversal_returned_fake_secret"], "traversal did not retrieve fake secret")
    require(summary["status"] == "completed" and summary["sealed"] is False, "unsealed replay did not complete")
    require(summary["input_hash_stable"] and summary["input_sha256"] == digest(pcap), "replay input differs")
    require(summary["events_sha256"] == digest(events_bytes), "event log hash differs")
    require(len(events) == len(frames) == summary["frames"], "event count differs")

    selected: dict[str, list[dict]] = {}
    for index, (frame, event) in enumerate(zip(frames, events), 1):
        require(event["sequence"] == index, "event order differs")
        require(event["frame_sha256"] == digest(frame), "captured frame differs from replay")
        name = label(tcp_payload(frame))
        if name is None:
            continue
        seeds = sorted(node["record"]["id"] for node in event["observer"]["seeds"])
        topology = {
            "nodes": sorted(node["record"]["id"] for node in event["admission"]["nodes"]),
            "edges": sorted(edge["record"]["id"] for edge in event["admission"]["edges"]),
        }
        row = {
            "frame": index,
            "admission": event["admission"]["status"],
            "observer_reason": event["observer"]["reason"],
            "direct_seeds": seeds,
            "admitted_nodes": len(event["admission"]["nodes"]),
            "admitted_topology_sha256": digest(json.dumps(topology, sort_keys=True).encode()),
            "frame_sha256": event["frame_sha256"],
        }
        selected.setdefault(name, []).append(row)

    names = [
        "benign_public_request",
        "denied_direct_request",
        "unauthorized_traversal_request",
        "fake_secret_response",
        "fake_secret_transfer",
    ]
    for name in names:
        require(len(selected.get(name, [])) == 1, f"expected one captured {name}")
        row = selected[name][0]
        require(row["admission"] == "context_admitted", f"{name} did not admit context")
        require("tcp_payload" in row["direct_seeds"], f"{name} lacked TCP payload seed")
    ordinary = selected["benign_public_request"][0]["direct_seeds"]
    require(all(selected[name][0]["direct_seeds"] == ordinary for name in names),
            "payload-bearing cases did not share the same direct seed set")
    ordinary_topology = selected["benign_public_request"][0]["admitted_topology_sha256"]
    require(all(selected[name][0]["admitted_topology_sha256"] == ordinary_topology for name in names),
            "payload-bearing cases did not share the same admitted topology")

    result = {
        "schema": 1,
        "status": "verified_diagnostic",
        "scope": "real isolated fake-secret attack sequence, captured on veth and replayed through passive unsealed Lightcone",
        "plan_sha256": digest(plan_path.read_bytes()),
        "pcap_sha256": digest(pcap),
        "events_sha256": digest(events_bytes),
        "replay_summary_sha256": digest(summary_path.read_bytes()),
        "service_result_sha256": digest(service_path.read_bytes()),
        "world_pack_sha256": summary["world_pack_sha256"],
        "sealed": summary["sealed"],
        "frames": len(frames),
        "admission_statuses": summary["admission_statuses"],
        "all_selected_payload_cases_same_direct_seeds": True,
        "all_selected_payload_cases_same_admitted_topology": True,
        "selected": {name: selected[name][0] for name in names},
        "limitations": [
            "The intentionally vulnerable service and retrieved token were disposable and fake.",
            "The result proves admission on this represented TCP path, not all possible malicious traffic.",
            "No Lightcone or host packet blocking was tested; the Lightcone is passive.",
        ],
    }
    args.out.mkdir(parents=True)
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "frames": len(frames),
                      "selected": result["selected"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
