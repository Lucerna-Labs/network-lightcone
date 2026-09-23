#!/usr/bin/env python3
"""Compare predeclared raw-frame expectations with actual replay events."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


CONTEXT_WORDS = {"authorized_flow", "policy_decision", "export", "authenticated_peer"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    required(not args.out.exists(), "refusing to overwrite an existing report")

    manifest = json.loads(args.manifest.read_bytes())
    summary_path = args.replay / "summary.json"
    events_path = args.replay / "events.jsonl"
    summary = json.loads(summary_path.read_bytes())
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line]
    cases = manifest["cases"]
    required(manifest["status"] == "frozen_before_replay", "challenge expectations were not frozen")
    required(summary["status"] == "completed", "replay did not complete")
    required(summary["input_hash_stable"] is True, "replay input changed during the run")
    required(summary["input_sha256"] == manifest["pcap_sha256"], "replay used a different PCAP")
    required(summary["events_sha256"] == digest(events_path), "event log hash differs")
    required(len(events) == len(cases) == manifest["case_count"], "frame/case count differs")
    required(summary["sealed"] is False, "this diagnostic expects an unsealed pack")

    seed_sets: dict[str, set[str]] = {}
    for case, event in zip(cases, events):
        required(event["sequence"] == len(seed_sets) + 1, "event sequence differs")
        required(event["frame_sha256"] == case["frame_sha256"], f"frame bytes differ for {case['id']}")
        seed_sets[case["id"]] = {row["record"]["id"] for row in event["observer"]["seeds"]}

    rows = []
    categories: dict[str, Counter] = {}
    for case, event in zip(cases, events):
        actual_kind = event["observer"]["kind"]
        actual_reason = event["observer"]["reason"]
        actual_admission = event["admission"]["status"]
        direct_seeds = seed_sets[case["id"]]
        admitted = {row["record"]["id"] for row in event["admission"].get("nodes", [])}
        required(event["admission"].get("authorization_verdict") is None, "host verdict was attributed to passive admission")

        checks = {
            "observer_kind": case["expected_kind"] is None or actual_kind == case["expected_kind"],
            "admission": actual_admission == case["expected_admission"],
            "required_seeds": set(case["required_seeds"]) <= direct_seeds,
            "forbidden_seeds": not (set(case["forbidden_seeds"]) & direct_seeds),
            "same_seed_set": case["same_seeds_as"] is None or direct_seeds == seed_sets[case["same_seeds_as"]],
        }
        category = case["category"]
        counts = categories.setdefault(category, Counter())
        counts["total"] += 1
        counts[actual_admission] += 1
        counts["expectation_passed" if all(checks.values()) else "expectation_failed"] += 1
        rows.append(
            {
                "id": case["id"],
                "category": category,
                "technique": case["technique"],
                "expected_kind": case["expected_kind"],
                "actual_kind": actual_kind,
                "reason": actual_reason,
                "expected_admission": case["expected_admission"],
                "actual_admission": actual_admission,
                "checks": checks,
                "expectation_passed": all(checks.values()),
                "direct_seed_ids": sorted(direct_seeds),
                "admitted_node_count": len(admitted),
                "admitted_edge_count": len(event["admission"].get("edges", [])),
                "policy_named_nodes_in_context": sorted(admitted & CONTEXT_WORDS),
                "receipt_sha256": event["admission"].get("receipt_sha256"),
                "runtime_admission_us": event["timing_us"]["runtime_admission"],
            }
        )

    outcome = {
        "schema": 1,
        "status": "diagnostic_complete",
        "scope": "synthetic offline raw Ethernet replay through the real observer and passive Rust Lightcone; no live traffic or packet enforcement",
        "manifest_sha256": digest(args.manifest),
        "pcap_sha256": manifest["pcap_sha256"],
        "events_sha256": summary["events_sha256"],
        "replay_summary_sha256": digest(summary_path),
        "world_pack_sha256": summary["world_pack_sha256"],
        "world_source_sha256": summary["world_source_sha256"],
        "sealed": summary["sealed"],
        "case_count": len(rows),
        "predeclared_expectations_met": sum(row["expectation_passed"] for row in rows),
        "predeclared_expectations_failed": sum(not row["expectation_passed"] for row in rows),
        "categories": {name: dict(counts) for name, counts in sorted(categories.items())},
        "cases": rows,
        "limitations": [
            "A nonempty causal receipt is context, not an authorization or network pass.",
            "The corpus is synthetic and small; it does not estimate production attack reduction.",
            "No host enforcement or application-level parser participated in this experiment.",
            "Intent cannot be inferred from a packet when benign and adversarial uses share the same observable structure.",
        ],
    }
    args.out.mkdir(parents=True)
    (args.out / "results.json").write_text(json.dumps(outcome, indent=2) + "\n")

    lines = [
        "# Network Lightcone adversarial replay v1",
        "",
        f"Status: `{outcome['status']}`. Pack sealed: `{outcome['sealed']}`.",
        "",
        "This is an isolated synthetic raw-frame test. No packets were transmitted and no host policy blocked or allowed traffic.",
        "",
        f"- Cases: {outcome['case_count']}",
        f"- Predeclared observations met: {outcome['predeclared_expectations_met']}",
        f"- Predeclared observations failed: {outcome['predeclared_expectations_failed']}",
        f"- Pack SHA-256: `{outcome['world_pack_sha256']}`",
        f"- Input PCAP SHA-256: `{outcome['pcap_sha256']}`",
        f"- Event log SHA-256: `{outcome['events_sha256']}`",
        "",
        "| Case | Category | Expected admission | Observed admission | Parser reason | Direct seeds | Context nodes | Checks |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            f"| `{row['id']}` | {row['category']} | {row['expected_admission']} | {row['actual_admission']} | `{row['reason']}` | {len(row['direct_seed_ids'])} | {row['admitted_node_count']} | {'pass' if row['expectation_passed'] else 'FAIL'} |"
        )
    lines += [
        "",
        "## How to read this",
        "",
        "A zero-seed, empty-neighborhood result means this world supplied no causal context for that observation. A context-admitted result can include protocol or host-policy concepts without proving a packet is legitimate. Look at direct seeds separately from the broader admitted neighborhood in `results.json` and the replay `events.jsonl`.",
        "",
        "## Open boundary",
        "",
        "This report does not measure prevented attacks or justify sealing. The next step is a matched evaluation with independently labeled benign traffic, adversarial traffic, and a separately enforced host policy.",
        "",
    ]
    (args.out / "report.md").write_text("\n".join(lines))
    print(json.dumps({"status": outcome["status"], "cases": len(rows), "expectation_failures": outcome["predeclared_expectations_failed"], "report": str(args.out / 'report.md')}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
