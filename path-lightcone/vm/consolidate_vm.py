"""CONSOLIDATE-1 (path-lightcone/CONSOLIDATE-1-PRECOMMIT.md), door two, live arm.

Imperium's three-VM lab (imported unchanged). Four episodes, each a fresh mesh bring-up (fresh TUN
link-local addresses). In every episode a LOG-ONLY gate (PATHGATE_RELEASE_ALL=1: judge and
byte-log, always release — exactly Imperium's passive door one) runs in each guest while the 8
trained cases flow. The brain (`brain1`, on the host) then classifies the drops by cause and
consolidates the self-caused ones into candidate packs; episode 4 re-runs with those packs.

Usage: python3 consolidate_vm.py PATHGATE_BIN BRAIN_BIN PACK_DIR [--imperium DIR]
"""

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("pathgate", type=Path)
ap.add_argument("brain", type=Path)
ap.add_argument("pack_dir", type=Path)
ap.add_argument("--imperium", type=Path, default=Path("~/Desktop/Projects/imperium-main/imperium-main").expanduser())
args = ap.parse_args()
IMP = args.imperium.resolve()
sys.path.insert(0, str(IMP / "scripts/lightcone-vm"))

from lab import CACHE, Lab, atomic_json, execute  # noqa: E402
from packet_io import CASES_PER_ARM, nodes, set_phase, start_servers, stop_nodes  # noqa: E402
from phase1 import required  # noqa: E402

ROLES = ("hub", "source", "receiver")
LEARN = (1, 2, 3)
EVAL = 4
GATE_SECONDS = 220
TABLE = ('table inet pathgate {\n'
         '  chain inn { type filter hook prerouting priority -300; policy accept; iifname != "lo" queue flags bypass to 11; }\n'
         '  chain out { type filter hook output priority -300; policy accept; oifname != "lo" queue flags bypass to 11; }\n}')


def addr_value(text):
    a = ipaddress.ip_address(text)
    return format(int(a), "x")


def self_readings(lab, role, ep):
    ctrl = lab.path / role / "control"
    addrs = json.loads(required(lab, role, "ip -j addr")["stdout"])
    links = json.loads(required(lab, role, "ip -d -j link")["stdout"])
    lines = []
    for iface in addrs:
        for info in iface.get("addr_info", []):
            if info.get("local"):
                lines.append(f"addr {addr_value(info['local'])}")
    for link in links:
        if (link.get("linkinfo") or {}).get("info_kind") == "tun":
            lines.append(f"tun {link['ifindex']}")
    (ctrl / f"ep{ep}-self.txt").write_text("\n".join(sorted(set(lines))) + "\n")


def ready(path):
    for _ in range(400):
        if path.exists() and "READY" in path.read_text():
            return
        time.sleep(0.05)
    raise RuntimeError(f"no READY in {path}")


def episode(lab, ep, packfile):
    name = f"ep{ep}"
    set_phase(lab, name)
    print(f"-- episode {ep} (pack {packfile})", flush=True)
    for role in ROLES:
        # Reader binds the queue and prints READY *before* the rule exists, so every queued
        # packet always has a reader (log-only: it releases everything).
        required(lab, role, f"PATHGATE_LAB=vm PATHGATE_LOG_BYTES=1 PATHGATE_RELEASE_ALL=1 "
                            f"/lab/pathgate gate-pack /control/{packfile} - 11 {GATE_SECONDS} "
                            f">/control/{name}-gate.log 2>&1 </dev/null & echo $! >/control/gate.pid")
        ready(lab.path / role / "control" / f"{name}-gate.log")
        required(lab, role, f"/lab/nft -f - <<'NFT'\n{TABLE}\nNFT")
    nodes(lab, "healthy")
    for role in ROLES:
        self_readings(lab, role, ep)
    echoes = {}
    for case in CASES_PER_ARM:
        if case == "tunnel_icmp4":
            continue
        role = "hub" if case.startswith("loopback") else "source"
        r = json.loads(required(lab, role, f"python3 /lab/traffic_guest.py probe {case}", 30)["stdout"])
        echoes[case] = (r["echoed"], r["attempted"])
    stop_nodes(lab, name)
    for role in ROLES:
        required(lab, role, "kill $(cat /control/gate.pid) 2>/dev/null; /lab/nft delete table inet pathgate 2>/dev/null; true")
    print(f"   echoes: {echoes}", flush=True)
    return echoes


def main():
    lab = Lab(CACHE / "consolidate-runs" / time.strftime("%Y%m%d-%H%M%S"))
    report = {"experiment": "CONSOLIDATE-1", "imperium_filter_enforced": False, "episodes": {}}
    print(f"Run directory: {lab.path}", flush=True)
    try:
        lab.prepare()
        shutil.copy2(IMP / "scripts/lightcone-vm/traffic_guest.py", lab.input / "traffic_guest.py")
        # Vendor the pathgate binary + libraries into the read-only share, like lab.py does.
        runtime = lab.input / "runtime"
        dest = runtime / str(args.pathgate.resolve()).lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.pathgate.resolve(), dest)
        import re
        for lib in re.findall(r"(/[^\s()]+)", execute(["ldd", str(args.pathgate.resolve())]).stdout):
            d = runtime / lib.lstrip("/")
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(lib, d)
        wrapper = lab.input / "pathgate"
        wrapper.write_text("#!/bin/sh\nexec /lab/runtime/lib64/ld-linux-x86-64.so.2 --library-path "
                           "/lab/runtime/lib/x86_64-linux-gnu:/lab/runtime/usr/lib/x86_64-linux-gnu "
                           f"/lab/runtime/{str(args.pathgate.resolve()).lstrip('/')} \"$@\"\n")
        wrapper.chmod(0o755)
        lab.start()
        start_servers(lab)
        for role in ROLES:
            shutil.copy2(args.pack_dir / f"{role}.pathpack", lab.path / role / "control" / "role.pathpack")
        for ep in LEARN:
            report["episodes"][ep] = episode(lab, ep, "role.pathpack")
        # Assemble the brain's input and consolidate (host side).
        brain_in = lab.path / "brain"
        for role in ROLES:
            (brain_in / role).mkdir(parents=True, exist_ok=True)
            for ep in LEARN:
                shutil.copy2(lab.path / role / "control" / f"ep{ep}-gate.log", brain_in / role / f"ep{ep}-gate.log")
                shutil.copy2(lab.path / role / "control" / f"ep{ep}-self.txt", brain_in / role / f"ep{ep}-self.txt")
        out_dir = lab.path / "candidate"
        # Episode 4 needs ep4 logs too; run it first with the ORIGINAL packs is wrong — ep4 uses
        # candidates. So consolidate from 1-3, write candidates, then run ep4 with candidates.
        cand_report = execute([str(args.brain), str(brain_in), str(args.pack_dir), str(out_dir)]).stdout
        print(cand_report, flush=True)
        (lab.path / "brain-report.txt").write_text(cand_report)
        for role in ROLES:
            shutil.copy2(out_dir / f"{role}.pathpack", lab.path / role / "control" / "candidate.pathpack")
        report["episodes"][EVAL] = episode(lab, EVAL, "candidate.pathpack")
        # Re-run the brain with ep4 included, for the final C1-C6 verdicts.
        for role in ROLES:
            shutil.copy2(lab.path / role / "control" / f"ep{EVAL}-gate.log", brain_in / role / f"ep{EVAL}-gate.log")
            shutil.copy2(lab.path / role / "control" / f"ep{EVAL}-self.txt", brain_in / role / f"ep{EVAL}-self.txt")
        final = execute([str(args.brain), str(brain_in), str(args.pack_dir), str(out_dir)]).stdout
        print(final, flush=True)
        (lab.path / "brain-report-final.txt").write_text(final)
    except Exception as error:
        report["execution_error"] = str(error)
        print(f"Experiment error: {error}", flush=True)
    finally:
        lab.close()
        report["owned_vms_stopped"] = all(p.poll() is not None for p in lab.processes.values())
        atomic_json(lab.path / "consolidate-report.json", report)
    return 0 if "execution_error" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
