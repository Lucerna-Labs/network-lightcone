#!/usr/bin/env python3
"""Verify replay input, log integrity, actual step coverage and receipt semantics."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def input_frames(path):
    if path.suffix.lower() == ".hex":
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            cleaned = "".join(text.split()).replace(":", "").removeprefix("0x")
            require(len(cleaned) % 2 == 0, "odd input hex length")
            yield bytes.fromhex(cleaned), False, {"line": line_number, "format": "hex"}
    else:
        data = path.read_bytes()
        require(len(data) >= 24, "short PCAP header")
        magic = {b"\xd4\xc3\xb2\xa1": ("<", "microseconds"), b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
                 b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"), b"\xa1\xb2\x3c\x4d": (">", "nanoseconds")}
        require(data[:4] in magic, "unsupported PCAP")
        endian, resolution = magic[data[:4]]
        snaplen, link = struct.unpack_from(endian + "II", data, 16)
        require(link == 1 and 0 < snaplen <= 1048576, "invalid PCAP linktype/snaplen")
        at = 24
        while at < len(data):
            require(at + 16 <= len(data), "partial PCAP record header")
            seconds, fraction, length, original = struct.unpack_from(endian + "IIII", data, at)
            at += 16
            require(length <= min(snaplen, original, 1048576) and at + length <= len(data), "partial/invalid PCAP frame")
            yield data[at:at+length], length < original, {
                "format": "pcap", "timestamp_seconds": seconds, "timestamp_fraction": fraction,
                "timestamp_unit": resolution, "captured_len": length, "original_len": original}
            at += length


def words(indices, count):
    result = [0] * count
    for i in indices:
        require(0 <= i < count * 64, "mask index overflow")
        result[i // 64] |= 1 << (i % 64)
    return result


def graph_replay(world, seeds, policy):
    """Independent state reconstruction from serialized exact graph/policy."""
    trace = []
    def event(action, node=None, edge=None, neighbor=None, depth=None):
        trace.append(dict(action=action, node=node, edge=edge, neighbor=neighbor, depth=depth))
    event("policy_accepted")
    admitted, excluded, frontier, queue = set(), set(), set(), []
    for node in sorted(seeds):
        if len(queue) < policy["max_nodes"]:
            admitted.add(node); queue.append((node, 0)); event("seed_enqueued", node, depth=0)
        else:
            excluded.add(node); event("seed_node_cap", node, depth=0)
    def eligible(edge):
        return policy["relation_mask"] & (1 << edge["relation"]) and policy["polarity"] in (0, edge["polarity"])
    at = 0
    while at < len(queue):
        node, depth = queue[at]; at += 1
        event("visit", node, depth=depth)
        for edge in world["edges"]:
            i = edge["index"]
            if not eligible(edge):
                action = "walk_relation_filtered" if not policy["relation_mask"] & (1 << edge["relation"]) else "walk_polarity_filtered"
                event(action, node, i, depth=depth); continue
            neighbor = None
            if edge["source"] == node and policy["direction"] != "past": neighbor = edge["target"]
            elif edge["target"] == node and policy["direction"] != "future": neighbor = edge["source"]
            if neighbor is None:
                action = "walk_direction_filtered" if node in (edge["source"], edge["target"]) else "walk_not_incident"
            elif neighbor in admitted: action = "walk_already_admitted"
            elif depth >= policy["max_hops"]:
                frontier.add(neighbor); action = "walk_hop_limit"
            elif len(queue) >= policy["max_nodes"]:
                excluded.add(neighbor); action = "walk_node_cap"
            else:
                admitted.add(neighbor); queue.append((neighbor, depth + 1)); action = "walk_enqueued"
            event(action, node, i, neighbor, depth)
    retained = set()
    for edge in world["edges"]:
        if eligible(edge) and edge["source"] in admitted and edge["target"] in admitted:
            retained.add(edge["index"]); action = "final_edge_retained"
        else: action = "final_edge_policy_filtered" if not eligible(edge) else "final_edge_endpoint_absent"
        event(action, edge=edge["index"])
    excluded -= admitted; frontier -= admitted
    for node in range(len(world["nodes"])):
        action = "final_node_admitted" if node in admitted else "final_node_cap" if node in excluded else "final_node_hop_limit" if node in frontier else "final_node_not_reached"
        event(action, node)
    event("receipt_complete")
    return admitted, retained, excluded, frontier, trace


def verify(directory, input_path, allow_incomplete=False, pack_path=None):
    summary = json.loads((directory / "summary.json").read_text())
    require(summary["status"] == "completed" or allow_incomplete, "run is incomplete/failed; use --allow-incomplete to inspect its prefix")
    for name, key in [("events.jsonl", "events_sha256"), ("world.json", "world_snapshot_sha256"), ("lifecycle.jsonl", "lifecycle_sha256")]:
        require(digest((directory / name).read_bytes()) == summary[key], f"{name} hash mismatch")
    require(digest(input_path.read_bytes()) == summary["input_sha256"] == summary["input_sha256_after_replay"], "input hash mismatch")
    lifecycle = [json.loads(line) for line in (directory / "lifecycle.jsonl").read_text().splitlines()]
    require([e["sequence"] for e in lifecycle] == list(range(len(lifecycle))), "lifecycle sequence gap")
    require(lifecycle[0]["stage"] == "run_started" and lifecycle[-1]["stage"] == ("run_completed" if summary["status"] == "completed" else "run_failed"), "lifecycle terminal mismatch")
    world = json.loads((directory / "world.json").read_text())
    require(world["pack_sha256"] == summary["world_pack_sha256"], "world pack identity mismatch")
    pack_path = pack_path or Path(__file__).resolve().parents[2] / "kernel-lightcone/src/world.bin"
    raw = pack_path.read_bytes()
    require(digest(raw) == world["pack_sha256"], "trusted pack hash mismatch")
    magic,n,e,d,version,size = struct.unpack_from('<8sHHHHI',raw)
    require(magic==b'ATLCNET2' and d==48 and n==len(world['nodes']) and e==len(world['edges']), 'pack dimensions differ')
    strings=1044+n*216+e*16
    require(strings+size==len(raw),'pack length differs')
    def metadata(offset):
        start,length=struct.unpack_from('<II',raw,offset)
        return json.loads(raw[strings+start:strings+start+length])
    for i,node in enumerate(world['nodes']):
        offset=1044+i*216
        require(node['record']==metadata(offset),'snapshot node differs from trusted pack')
        require(node['full_48d_quantized']+node['observer_4d_quantized']==list(struct.unpack_from('<52i',raw,offset+8)),'snapshot coordinates differ from trusted pack')
    for i,edge in enumerate(world['edges']):
        offset=1044+n*216+i*16
        src,dst,relation,polarity=struct.unpack_from('<HHBb',raw,offset)
        require(edge['record']==metadata(offset+8) and (edge['source'],edge['target'],edge['relation'],edge['polarity'])==(src,dst,relation,polarity),'snapshot edge differs from trusted pack')
    require([n["index"] for n in world["nodes"]] == list(range(len(world["nodes"]))) and [e["index"] for e in world["edges"]] == list(range(len(world["edges"]))), "world index gap")
    events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
    require(len(events) == summary["frames"], "event count mismatch")
    frames = input_frames(input_path); previous = None; step_count = 0
    for index, logged in enumerate(events, 1):
        frame, truncated, capture = next(frames)
        require(logged["sequence"] == index and logged["event_id"] == f"{summary['run_id']}:{index}" and logged["run_id"] == summary["run_id"], "event identity mismatch")
        require(logged["capture"] == capture and logged["frame_sha256"] == digest(frame) and logged["frame_len"] == len(frame), "input/frame mismatch")
        if summary["payload_bytes_logged"]: require(bytes.fromhex(logged["frame_hex"]) == frame, "logged bytes differ from source frame")
        else: require(logged["frame_hex"] is None, "unexpected payload bytes")
        record = dict(logged); claimed = record.pop("event_sha256")
        require(record["previous_event_sha256"] == previous and digest(canonical(record)) == claimed, "event hash chain mismatch")
        previous = claimed
        observation, admission = logged["observer"], logged["admission"]
        seeds = {x["index"] for x in observation["seeds"]}
        for n in observation["seeds"]: require(n["record"] == world["nodes"][n["index"]]["record"], "seed metadata mismatch")
        timeline = logged["trace"]; graph_steps = []; observer_steps = []
        require(logged["trace_enabled"] == summary["trace_enabled"], "trace mode mismatch")
        if logged["trace_enabled"]:
            require([t["ordinal"] for t in timeline] == list(range(len(timeline))), "trace sequence gap")
            require([t["elapsed_us"] for t in timeline] == sorted(t["elapsed_us"] for t in timeline), "trace time inversion")
            require(timeline[0]["detail"]["action"] == "input_received" and timeline[-1]["detail"]["action"] == "output_ready", "pipeline endpoints missing")
            tentative = set()
            for t in timeline:
                d = t["detail"]
                if t["actor"] == "admission": graph_steps.append(d)
                if t["actor"] != "observer": continue
                observer_steps.append(d)
                if d["action"] == "enter": require(0 <= d["offset"] <= len(frame) and d["offset"]+d["length"] <= len(frame), "parser slice outside frame")
                elif d["action"] == "seed_added": tentative.add(d["node"])
                elif d["action"] == "seeds_discarded":
                    require(d["seed_mask"] == words(tentative, 4), "discarded seeds mismatch"); tentative.clear()
            require(observer_steps[-1]["action"] == "complete" and observer_steps[-1]["seed_mask"] == words(seeds, 4), "observer return/seed mismatch")
            require(tentative == seeds and observer_steps[-1]["reason"] == observation["reason"] and observer_steps[-1]["kind"] == observation["kind"], "observer trace disagrees with result")
            require(observation["kind"] == "malformed" or all(d.get("passed",True) for d in observer_steps if d["action"] == "check"), "failed check returned non-malformed observation")
        else: require(not timeline, "disabled trace emitted steps")
        if truncated:
            require(admission["status"] == "capture_truncated" and not admission["attempted"] and not graph_steps, "truncated capture was admitted")
        else:
            require(admission["attempted"] and admission["policy"] == world["policy"] == summary["policy"], "admission policy mismatch")
            nodes, edges, excluded, frontier, expected_trace = graph_replay(world,seeds,admission["policy"])
            for field, expected, records in [("nodes",nodes,world["nodes"]),("edges",edges,world["edges"]),("excluded",excluded,world["nodes"]),("hop_frontier",frontier,world["nodes"])]:
                require({r["index"] for r in admission[field]} == expected, f"receipt {field} mismatch")
                for r in admission[field]: require(r["record"] == records[r["index"]]["record"], f"{field} evidence mismatch")
            if logged["trace_enabled"]: require(graph_steps == expected_trace, "actual admission trace incomplete or semantically wrong")
            p=admission["policy"]
            material=b"ATOM-NETWORK-ADMISSION-2"+bytes.fromhex(world["pack_sha256"])+bytes.fromhex(logged["frame_sha256"])
            material+=bytes([{"past":0,"future":1,"both":2}[p["direction"]],p["max_hops"],p["relation_mask"],p["polarity"] & 255])+struct.pack("<H",p["max_nodes"])
            for indices,width in [(seeds,4),(nodes,4),(edges,8),(excluded,4),(frontier,4)]:
                material+=b"".join(struct.pack("<Q",v) for v in words(indices,width))
            require(digest(material)==admission["receipt_sha256"],"independently recomputed receipt mismatch")
        step_count+=len(timeline)
    require(previous==summary["last_event_sha256"],"final chain hash mismatch")
    if summary["status"]=="completed": require(next(frames,None) is None,"successful run omitted input frames")
    return {"verified":True,"complete":summary["status"]=="completed","frames":len(events),"trace_steps":step_count,
            "exact_frame_bytes_logged":summary["payload_bytes_logged"],"scope":"integrity and execution trace; not security effectiveness"}


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument('--logs',type=Path,required=True);parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--allow-incomplete',action='store_true');parser.add_argument('--pack',type=Path);args=parser.parse_args()
    print(json.dumps(verify(args.logs,args.input,args.allow_incomplete,args.pack),indent=2))
