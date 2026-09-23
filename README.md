# Network Lightcone standalone project

This project is the standalone network-specific Lightcone derived from Atom OS
source snapshot `db5f6624ac35ebe040d769511555f41fa2923c14`.

The current revision-4 world contains 208 source-bound network and defensive
control concepts, 188 typed causal relationships and 29 pinned sources. Its
active artifact is a local RTX diagnostic pack. It is deliberately unsealed.

## Components

- `network-lightcone/` — world source, frozen mechanism splits, trainer,
  finalizer, validators, coverage ledger, diagnostic packs and receipts.
- `kernel-lightcone/` — passive `no_std` Rust runtime with exact graph
  admission, a hash-bound 48D pack and observer-only spatial `(x,y,z,w)`
  coordinates.
- `network-observer/` — standalone structural Ethernet, ARP, IPv4, IPv6, UDP,
  TCP, ICMPv4, ICMPv6 and Neighbor Discovery observation adapter. Payload text
  cannot select Lightcone nodes.
- `network-replay/` — offline hex or classic Ethernet PCAP replay with detailed
  per-frame JSONL logs and an integrity-bound summary.
- `integration/atom-os/` — retained Atom OS adapter source for later host
  integration work.

## Inspect the current revision

```sh
cargo test --workspace --offline
python3 network-lightcone/tools/verify.py
python3 network-lightcone/tests/evaluate_defense_challenges.py
```

The active pack reports `platform=local_diagnostic` and `sealed=false`.
The synthetic structural challenge records a 60% zero-admission fraction for
unrepresented observations and explicitly records the remaining 40% as probes
that share represented causal protocol symbols. That challenge checks the
architecture boundary; it is not a measured production attack-reduction claim.

Current evidence and known gaps are recorded in
`network-lightcone/coverage.json` and
`network-lightcone/receipts/v4-local-validation-20260923.md`.

## Detailed observation logs

```sh
cargo run -p network-lightcone-replay --offline -- \
  --input network-replay/fixtures/demo.hex \
  --out artifacts/logs/my-first-replay
```

The output directory contains `events.jsonl` and `summary.json`. Each event
records the parser reason, exact seed nodes, admitted nodes and edges with
their source evidence, excluded and hop-frontier nodes, receipt hashes, and
timing. The summary hashes the input and event log. Classic Ethernet `.pcap`
files use the same command. See `network-replay/README.md` for the fields and
capture limitations.
