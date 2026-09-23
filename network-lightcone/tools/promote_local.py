#!/usr/bin/env python3
"""Promote one verified local diagnostic without creating a seal."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--world", type=Path, required=True)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--challenge-receipt", type=Path, required=True)
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("network_train", ROOT / "tools/train.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    world = json.loads(args.world.read_bytes())
    module.validate(world)
    world_hash = sha256(args.world)
    manifest_path = args.pack / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    training_path = args.pack / "training.json"
    training = json.loads(training_path.read_bytes())
    challenge = json.loads(args.challenge_receipt.read_bytes())
    coverage = json.loads(args.coverage.read_bytes())

    require(manifest.get("status") == "local_diagnostic", "pack is not local diagnostic")
    require(manifest.get("sealed") is False, "local promotion cannot accept a sealed pack")
    require(manifest.get("source_sha256") == world_hash, "pack source differs from current world")
    require(training.get("world_sha256") == world_hash, "training source differs from current world")
    require(training.get("platform") == "local_diagnostic", "training platform is not local diagnostic")
    require(training.get("passed") is True, "local training did not pass")
    require(
        training.get("required_gates") == list(module.REQUIRED_GATES),
        "required gate manifest differs",
    )
    require(
        set(training.get("gates", {})) == set(module.REQUIRED_GATES)
        and all(training["gates"].values()),
        "one or more local gates failed",
    )
    for name, expected in manifest["files"].items():
        require(sha256(args.pack / name) == expected, f"pack file hash differs: {name}")
    require(challenge.get("status") == "passed", "structural challenge receipt failed")
    require(challenge.get("world_sha256") == world_hash, "challenge receipt covers another world")
    require(
        challenge.get("training_input_exclusion", {}).get("challenge_file_is_not_referenced_by_world") is True,
        "challenge corpus is not isolated from the world",
    )

    coverage["status"] = "locally_validated"
    coverage["local_validation"] = {
        "pack": str(args.pack.relative_to(ROOT)),
        "manifest_sha256": sha256(manifest_path),
        "training_sha256": sha256(training_path),
        "world_sha256": world_hash,
        "platform": training["platform"],
        "devices": training["devices"],
        "gates": training["gates"],
        "metrics": training["metrics"],
    }
    coverage["structural_challenge"] = {
        "receipt": str(args.challenge_receipt.relative_to(ROOT)),
        "receipt_sha256": sha256(args.challenge_receipt),
        "case_count": challenge["case_count"],
        "zero_admission_fraction": challenge["zero_admission_fraction"],
        "scope": challenge["scope"],
    }
    coverage["accelerator_acceptance"] = False
    coverage["sealed"] = False
    args.coverage.write_text(json.dumps(coverage, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": coverage["status"],
                "world_sha256": world_hash,
                "sealed": coverage["sealed"],
                "accelerator_acceptance": coverage["accelerator_acceptance"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
