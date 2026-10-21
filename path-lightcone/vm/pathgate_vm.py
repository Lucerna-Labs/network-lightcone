"""PATHGATE-3 (path-lightcone/PATHGATE-1-PRECOMMIT.md): the trained-path gate in Imperium's
three-VM lab with live traffic. Imperium's lab, traffic servers, mesh nodes, captures and packet
exporter are imported unchanged from outside; this driver adds the gate, the live negatives and
the kill/restart arms. Every setting is here.

Usage: python3 pathgate_vm.py PATHGATE_BINARY [--imperium DIR]
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("pathgate", type=Path)
parser.add_argument("--imperium", type=Path, default=Path("~/Desktop/Projects/imperium-main/imperium-main").expanduser())
args = parser.parse_args()
IMP = args.imperium.resolve()
sys.path.insert(0, str(IMP / "scripts/lightcone-vm"))

from lab import CACHE, Lab, atomic_json, execute  # noqa: E402
from packet_io import (CASES_PER_ARM, captures, case_probe, case_summary, nodes,  # noqa: E402
                       save_interfaces, server_health, set_phase, start_servers)
from packet_log import export_packet_logs  # noqa: E402
from phase1 import required  # noqa: E402
import traffic_guest  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from neg_guest import NEGATIVES  # noqa: E402  (also registers them in traffic_guest.CASES)

ROLES = ("hub", "source", "receiver")
GATE_SECONDS = 1500
EVIDENCE_FILES = [f"{arm}-{role}-packets.jsonl" for arm in ("healthy", "quarantined", "kernel_recovered") for role in ROLES]
TABLE = """table inet pathgate {
  chain in { type filter hook prerouting priority -300; policy accept; iifname != "lo" queue to 11; }
  chain out { type filter hook output priority -300; policy accept; oifname != "lo" queue to 11; }
}"""
NEGATIVE_ADDRESS = "192.0.2.77/24"
SOURCE_MAC = "52:54:00:77:00:02"


def add_runtime(lab, name, original):
    """Copy a host executable and its libraries into the read-only share, with a loader wrapper (lab.py's method)."""
    runtime = lab.input / "runtime"
    destination = runtime / str(original).lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, destination)
    for library in re.findall(r"(/[^\s()]+)", execute(["ldd", str(original)]).stdout):
        dest = runtime / library.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, dest)
    wrapper = lab.input / name
    wrapper.write_text("#!/bin/sh\nexec /lab/runtime/lib64/ld-linux-x86-64.so.2 --library-path "
                       "/lab/runtime/lib/x86_64-linux-gnu:/lab/runtime/usr/lib/x86_64-linux-gnu "
                       f"/lab/runtime/{str(original).lstrip('/')} \"$@\"\n")
    wrapper.chmod(0o755)


def gate_start(lab, role, log):
    required(lab, role, f"PATHGATE_LAB=vm PATHGATE_LOG_BYTES=1 /lab/pathgate gate /lab/evidence {role} 11 {GATE_SECONDS} "
                        f">/control/{log} 2>&1 </dev/null & echo $! >/control/gate.pid")
    required(lab, role, f"for i in $(seq 1 200); do grep -q READY /control/{log} && exit 0; sleep .1; done; cat /control/{log}; exit 1", 40)


def arm(lab, name, cases):
    set_phase(lab, name)
    print(f"Arm {name}", flush=True)
    captures(lab, name, True)
    save_interfaces(lab, name)
    results = {}
    for case in cases:
        server_health(lab)
        if case in NEGATIVES:
            print(f"  {name}: {case}", flush=True)
            results[case] = json.loads(required(lab, "source", f"python3 /lab/neg_guest.py probe {case}", 60)["stdout"])
            print(f"    attempted={results[case]['attempted']} echoes={results[case]['echoed']}", flush=True)
        else:
            results[case] = case_probe(lab, name, case)
    for role in ROLES:
        required(lab, role, f"cp /control/node.log /control/{name}-node.log")
    capture_stats = captures(lab, name, False)
    export_packet_logs(lab.path, name)
    rows = [case_summary(lab, name, case, value) for case, value in results.items()]
    return {"cases": results, "rows": rows, "capture_stats": {r: {k: v for k, v in s.items() if k != "log"} for r, s in capture_stats.items()}}


def verdict_stats(path):
    ns = sorted(int(l.split()[3]) for l in Path(path).read_text().splitlines() if l.startswith("V "))
    passed = sum(1 for l in Path(path).read_text().splitlines() if l.startswith("V ") and l.split()[2] == "1")
    return {"verdicts": len(ns), "passed": passed, "median_ns": ns[len(ns) // 2] if ns else None,
            "p99_ns": ns[len(ns) * 99 // 100] if ns else None}


def main():
    run_dir = CACHE / "pathgate-runs" / time.strftime("%Y%m%d-%H%M%S")
    lab = Lab(run_dir)
    lab.manifest["pathgate_enforced_in_lab_guests"] = True
    report = {"experiment": "PATHGATE-3", "imperium_filter_enforced": False}
    print(f"Run directory: {lab.path}", flush=True)
    try:
        lab.prepare()
        shutil.copy2(IMP / "scripts/lightcone-vm/traffic_guest.py", lab.input / "traffic_guest.py")
        shutil.copy2(HERE / "neg_guest.py", lab.input / "neg_guest.py")
        add_runtime(lab, "pathgate", args.pathgate.resolve())
        ev = lab.input / "evidence/lightcone-vm-io-20261001"
        ev.mkdir(parents=True)
        for name in EVIDENCE_FILES:
            shutil.copy2(IMP / "evidence/lightcone-vm-io-20261001" / name, ev / name)
        lab.manifest["pathgate_sha256"] = execute(["sha256sum", str(args.pathgate)]).stdout.split()[0]
        atomic_json(lab.path / "manifest.json", lab.manifest)
        lab.start()
        start_servers(lab)
        required(lab, "receiver", "python3 /lab/neg_guest.py serve >/control/neg-server.log 2>&1 </dev/null & echo $! >/control/neg.pid")
        required(lab, "receiver", "for i in $(seq 1 50); do test -e /control/neg-ready && exit 0; sleep .1; done; cat /control/neg-server.log; exit 1")
        required(lab, "source", f"ip addr add {NEGATIVE_ADDRESS} dev $(ip -br link | awk 'tolower($3)==\"{SOURCE_MAC}\"{{print $1}}')")
        set_phase(lab, "mesh")
        report["mesh"] = nodes(lab, "healthy")
        report["open"] = arm(lab, "open", CASES_PER_ARM + list(NEGATIVES))
        for role in ROLES:
            gate_start(lab, role, "gate.log")
        for role in ROLES:
            required(lab, role, f"/lab/nft -f - <<'NFT'\n{TABLE}\nNFT")
        report["gated"] = arm(lab, "gated", CASES_PER_ARM + list(NEGATIVES))
        required(lab, "receiver", "kill $(cat /control/gate.pid); sleep .5")
        report["gate_killed"] = arm(lab, "gate_killed", ["direct_udp4"])
        gate_start(lab, "receiver", "gate2.log")
        report["gate_restarted"] = arm(lab, "gate_restarted", ["direct_udp4"])
        report["gate_tables"] = {role: json.loads(required(lab, role, "/lab/nft -j list table inet pathgate")["stdout"]) for role in ROLES}
    except Exception as error:
        report["execution_error"] = str(error)
        print(f"Experiment error: {error}", flush=True)
    finally:
        lab.close()
        report["owned_vms_stopped"] = all(p.poll() is not None for p in lab.processes.values())
    # Host-side re-judgement and latency from the byte-logged verdicts.
    report["verdicts"] = {}
    for role in ROLES:
        for log in ("gate.log", "gate2.log"):
            path = lab.path / role / "control" / log
            if path.exists():
                rj = execute([str(args.pathgate), "rejudge", str(IMP / "evidence"), role, str(path)]).stdout.strip()
                report["verdicts"][f"{role}/{log}"] = {"rejudge": rj, **verdict_stats(path)}
    atomic_json(lab.path / "pathgate-report.json", report)
    print(json.dumps({k: v for k, v in report.items() if k in ("execution_error", "owned_vms_stopped", "verdicts")}, indent=1), flush=True)
    for name in ("open", "gated", "gate_killed", "gate_restarted"):
        for row in report.get(name, {}).get("rows", []):
            print(f"{name:15} {row['case']:16} attempts {row['attempted']:2} echoes {row['client_echoes']} "
                  f"server {row['server_unique_received']} src_out {row['source_capture_out']} hub_in {row['hub_capture_in']} "
                  f"hub_out {row['hub_capture_out']} recv_in {row['receiver_capture_in']}", flush=True)
    return 0 if "execution_error" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
