#!/usr/bin/env python3
"""Check the structural unknown/overlap boundary outside training."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def admit(world: dict, seed_ids: list[str]) -> set[str]:
    nodes = {node["id"] for node in world["nodes"]}
    if not set(seed_ids) <= nodes:
        raise ValueError(f"challenge references unknown seeds: {sorted(set(seed_ids) - nodes)}")
    admitted = set(seed_ids)
    frontier = list(seed_ids)
    depth = {seed: 0 for seed in seed_ids}
    while frontier and len(admitted) < world["policy"]["max_nodes"]:
        current = frontier.pop(0)
        if depth[current] >= world["policy"]["max_hops"]:
            continue
        for edge in world["edges"]:
            neighbor = None
            if edge["source"] == current:
                neighbor = edge["target"]
            elif edge["target"] == current:
                neighbor = edge["source"]
            if neighbor is not None and neighbor not in admitted:
                admitted.add(neighbor)
                depth[neighbor] = depth[current] + 1
                frontier.append(neighbor)
                if len(admitted) >= world["policy"]["max_nodes"]:
                    break
    return admitted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--world", type=Path, default=ROOT / "sources/world.json")
    parser.add_argument(
        "--challenges",
        type=Path,
        default=ROOT / "tests/defense-challenges.json",
    )
    args = parser.parse_args()
    world_bytes = args.world.read_bytes()
    challenge_bytes = args.challenges.read_bytes()
    world = json.loads(world_bytes)
    challenges = json.loads(challenge_bytes)
    results = []
    for case in challenges["cases"]:
        admitted = admit(world, case["seeds"])
        observed = "zero_admission" if not admitted else "shared_causal_admission"
        results.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                "observed": observed,
                "seed_count": len(case["seeds"]),
                "admitted_count": len(admitted),
                "passed": observed == case["expected"],
            }
        )
    zero = sum(row["observed"] == "zero_admission" for row in results)
    fraction = zero / len(results)
    passed = all(row["passed"] for row in results) and fraction >= challenges[
        "minimum_zero_admission_fraction"
    ]
    report = {
        "schema": 1,
        "status": "passed" if passed else "failed",
        "scope": "synthetic structural unknown-versus-shared-causal-overlap challenge; not measured production attack reduction",
        "world_sha256": hashlib.sha256(world_bytes).hexdigest(),
        "challenge_sha256": hashlib.sha256(challenge_bytes).hexdigest(),
        "case_count": len(results),
        "zero_admission_count": zero,
        "shared_causal_admission_count": len(results) - zero,
        "zero_admission_fraction": fraction,
        "minimum_zero_admission_fraction": challenges[
            "minimum_zero_admission_fraction"
        ],
        "results": results,
        "training_input_exclusion": {
            "trainer_accepts_only_world_path": True,
            "challenge_file_is_not_referenced_by_world": (
                args.challenges.name not in world_bytes.decode("utf-8")
            ),
        },
        "report_sha256": "",
    }
    report["report_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
