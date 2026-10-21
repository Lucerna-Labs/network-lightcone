# Detailed network replay logs

Run the real structural observer and embedded Rust Lightcone against raw
Ethernet frames stored as one hex frame per line or in a classic Ethernet
PCAP. This is an offline diagnostic; it does not capture a live interface or
authorize or block traffic.

```sh
cargo run -p network-lightcone-replay --offline -- \
  --input network-replay/fixtures/demo.hex \
  --out artifacts/logs/demo-run

cargo run -p network-lightcone-replay --offline -- \
  --input /path/to/capture.pcap \
  --out artifacts/logs/capture-run
```

Each output directory must be new; the command refuses to overwrite a prior
run. `.hex` input accepts whitespace and `#` comments. `.pcap` input must use
classic Ethernet linktype 1; PCAPNG and other linktypes are rejected with a
failure summary. A truncated capture record is logged and receives no
admission attempt.

The default limit is 1,000 frames because full node and edge evidence can make
large logs. Use `--max-frames N` to set a larger bound (up to 1,000,000). If a
capture exceeds the bound, the saved summary says `failed` and explains that
the log is incomplete; earlier events remain available.

`events.jsonl` has one schema-2 JSON object per frame:

- capture line or timestamp, length, frame SHA-256 and untrusted wire hints;
- observation kind and a specific parser reason;
- seed nodes resolved from validated structure;
- the exact policy, admitted nodes and typed edges with provenance,
  conditions and exceptions;
- excluded nodes, hop frontier, query and receipt hashes; and
- separate parse, runtime admission, explanation and total processing times.

Detailed tracing is now on by default. The actual observer and admission engine
emit callbacks for layer entry, structural fields/checks, tentative seeds and
discard, every edge scan/filter, queue visits, caps/frontiers and final membership.
Each event has a run ID, sequence, event hash and previous-event hash. The trace
contains ordered timestamps and refers to node/edge indices in `world.json`.
Tracing is observation-only: `--no-trace` runs the same admission path without
collecting detailed steps. It is useful for latency comparisons and compact logs.

`world.json` is a hash-bound snapshot of exact node/edge metadata, full quantized
48D coordinates and observer-only spatial `(x,y,z,w)` coordinates. This runtime
validates those coordinates at load; **admission itself uses exact graph/policy**.
It does not score coordinate distance, evaluate prose edge conditions, interpret
payload semantics, or maintain TCP connection state.

`lifecycle.jsonl` records run start, pack-file verification, runtime pack loading,
input identification, replay and its completed/failed outcome. Startup and partial
input failures retain a failure summary. The summary binds the lifecycle, world
snapshot and event log, and records hashes of the source bytes embedded at compile
time plus whether the current source tree matches that build. Events are flushed
after each frame; this is not a power-loss durability or signed-log guarantee.

`summary.json` records the active world, pack, manifest and training receipt
hashes, pack status, input
hash before and after replay, event-log hash, executable/source hashes,
kind/reason/admission counts, and p95 processing time.
It preserves a `failed` status and the error if parsing stops after earlier
events. Verify the event log with `sha256sum events.jsonl` against the summary.

Payload bytes and IP addresses are omitted by default. `--include-frame-bytes`
explicitly writes exact frame hex, including payload and addresses, for complete
reconstruction; `--include-addresses` adds address hints without copying payload.
Ports and protocol
numbers are untrusted wire hints until the observer validates the packet.
Generated logs belong under ignored `artifacts/logs/` and must never become
world-training inputs.

The event status `context_admitted` means a bounded causal neighborhood was
returned. It is not an authorization or attack classification. Effectiveness
claims require independently labeled traffic and a separate host enforcement
evaluation.

## Verify and inspect a trace

```sh
python3 network-replay/tools/verify_trace.py \
  --logs artifacts/logs/demo-run --input network-replay/fixtures/demo.hex

python3 network-replay/tools/trace_report.py \
  --logs artifacts/logs/demo-run --sequence 1 --out artifacts/logs/frame-1.md
```

The verifier binds source input frames, optional logged bytes, event/hash-chain
ordering, parser seed transitions, every admission decision and independently
recomputed receipt digests to the trusted `kernel-lightcone/src/world.bin`.
Use `--pack PATH` for another explicitly trusted copy. `--allow-incomplete` verifies
the available replay prefix while reporting `complete=false`; it does not turn a
failed run into a complete capture. A failure before pack loading has only startup
diagnostics, not a verifiable admission trace.

Full traces are intentionally verbose. The acceptance corpus produced about
16 MB for 27 frames; trace callbacks materially increase debug-build processing
time. Bound capture size with `--max-frames` and use `--no-trace` for comparisons.
No live host-interface capture starts automatically. Existing isolated capture
experiments can create PCAP inputs; replay then exercises the actual Rust parser
and runtime. See [the logging results](../TRACE-RESULTS.md) for measured scope.

## Reproduce the isolated adversarial replay

The adversarial corpus generator creates raw synthetic Ethernet frames and
freezes expected observations before replay. It never opens a network socket.
Use new output directory names for each run:

```sh
python3 network-replay/experiments/adversarial_v1.py \
  --out artifacts/experiments/adversarial-v1-new

cargo run -p network-lightcone-replay --offline -- \
  --input artifacts/experiments/adversarial-v1-new/frames.pcap \
  --out artifacts/logs/adversarial-v1-new

python3 network-replay/experiments/evaluate_adversarial_v1.py \
  --manifest artifacts/experiments/adversarial-v1-new/manifest.json \
  --replay artifacts/logs/adversarial-v1-new \
  --out artifacts/experiments/adversarial-v1-results-new
```

The evaluator verifies the PCAP, frame and event hashes before comparing
predeclared expectations with the actual observer and runtime outputs. The
first run and its failed expectations are retained in
`network-lightcone/receipts/adversarial-v1-20260923.*`.
