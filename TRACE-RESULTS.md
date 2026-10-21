# Input-to-receipt logging — implementation and measured results

Detailed logging is implemented in this independent copy. The observer and native
admission runtime now emit their actual internal decisions, and a separate verifier
checks the resulting trace against the input frames and trusted world pack.
**Logging correctness passed. Defensive usefulness remains unestablished.**

## Recorded path

```text
run/pack verification -> exact input identity -> parser layers and fields
-> validation checks -> tentative seeds / failed-parse discard
-> returned seeds -> policy checks -> queue and every edge decision
-> admitted / capped / frontier nodes -> exact edges -> receipt -> output hashes
```

Each run writes:

- `lifecycle.jsonl`: startup, individual pack-file hash checks, runtime pack
  validation, input identity, replay start/end and completed/failed outcome.
- `world.json`: exact node and edge records, provenance, 48D coordinates, 4D
  observer coordinates and policy. Frame traces reference its indices.
- `events.jsonl`: run/event IDs, frame length/hash and capture location, parser
  checks/fields/seed transitions, ordered graph steps, all final evidence and
  receipt hashes. Each event is linked to the previous event by hash.
- `summary.json`: counts, times, source/executable identity, pack identity and
  file hashes. Source hashes are embedded at compilation, with a separate check
  of whether the current working source still matches the running executable.

Detailed traces are on by default. Payload bytes and addresses are omitted by
default. `--include-frame-bytes` opts into exact frame hex, including addresses
and payload. The controlled live test used that option and verified every logged
byte against its input capture. `--no-trace` leaves the existing compact logging
path available for comparison; admission is unchanged.

## What the runtime actually does

The current implementation admits via exact graph reachability and the configured
direction, relation, polarity, hop and node bounds. It verifies the 48D geometry
and observer projection when loading the pack. Coordinate distance does **not**
participate in this packet admission function. The 4D view is observer-only.

It records conditional mechanisms but does not evaluate prose edge conditions
against observed connection state. It does not maintain TCP flow state, interpret
application payloads, or authorize packet release. Logs and snapshots expose
these boundaries explicitly. No artificial geometry-scoring stage was added.

## Verification

The final acceptance run is
`artifacts/experiments/trace-acceptance-final-20261001/result.json`.

| Check | Result |
|---|---|
| End-to-end logging checks | **42/42 passed** |
| Rust workspace tests | **17 passed** |
| Synthetic replay corpus | 27 frames; **108,024 trace records verified** |
| Real isolated TCP capture | 20 frames; **86,314 trace records verified** |
| Pre-change versus traced versus untraced | Identical observations and admission receipts |
| Exact-byte logging | Reconstructed bytes match each input frame |
| Truncated capture record | Recorded, with admission explicitly skipped |
| Partial PCAP, malformed hex, frame limit | Failed summary; retained prefix verifies as incomplete |
| Unsupported input format | Retained lifecycle and startup failure summary |
| Changed log bytes | Rejected |
| Deleted internal step with outer hashes recomputed | Rejected by semantic trace replay |
| Changed frame bytes with outer hashes recomputed | Rejected against the source capture |
| Existing output directory | Refused, prior logs preserved |

The verifier independently recomputes graph traversal, caps/frontiers, retained
edges and the runtime receipt digest. It also checks parser seed additions,
discard and returned seeds, ordering, source-frame identity and optional raw bytes.
The world snapshot is checked against `kernel-lightcone/src/world.bin`, including
all metadata and 52 stored coordinate values per node. These checks use trusted
input/pack files; hashes are not digital signatures or proof against replacement
of the whole trust source. The verifier is not a second full protocol parser.

`cargo fmt --all -- --check`, `git diff --check`, Python compilation and the
independent world-pack verifier passed. Clippy passed with warnings denied except
two pre-existing style-lint categories introduced by the installed toolchain:
`chunks_exact_to_as_chunks` and `manual_is_multiple_of`. No blanket code-level
lint suppression was added. During implementation, a generated match-guard syntax
error and an initially missing direction-filter test case were repaired before
the final passing runs; no runtime policy or world threshold was changed.

## Actual captured traffic and useful findings

The existing capture experiment ran under `unshare -Urn`, using a disposable
user/network namespace and loopback only. It exercised a closed-port connection,
raw TCP control segments, an intentionally incorrect checksum, and a completed
ordinary request/response. The server received the request, the client received
40 response bytes, and tcpdump reported **20 packets captured, zero kernel drops**.
The parser/runtime then replayed those exact captured bytes. This is captured
traffic followed by offline replay; it is not a background tap on the user's
normal host traffic.

Seven frames produced `ipv4_tcp_valid`; thirteen produced `tcp_bad_checksum`.
The trace shows that tentative IP seeds are discarded on those checksum failures
and the runtime receives no seeds. Some failures belong to the successful ordinary
connection. Their origin was not diagnosed in this task: captured-byte checksum
failure alone does not establish on-wire corruption or harmful intent. The classic
PCAP input does not give this parser a separate checksum-validation status.

An out-of-state raw ACK with application bytes still admits generic TCP context.
That matches the pre-change executable: this observer has no connection-state
validation and a neighborhood is not permission. It is now directly inspectable
through the parsed flags, checksum result, seeds and edge decisions.

The pre-existing 27-case challenge also retains **two unmet expectations**:

- A valid UDP DNS question yields UDP/IP seeds, without the expected DNS-specific
  seed. Payload application semantics are not decoded here.
- A VLAN-tagged IPv4 frame is reported as an unrepresented EtherType and admits
  nothing.

Those results were not changed to make the logging tests green. Log equivalence
to the baseline confirms they predate this instrumentation. They remain relevant
to coverage and usefulness work, separately from whether logging works.

## Overhead and preservation

In the debug acceptance run, corpus p95 processing was about **29.1 ms traced**
versus **2.89 ms untraced**. The live capture was about **29.8 ms versus 2.98 ms**.
These figures include callback collection but exclude event JSON serialization
and disk writes. Full trace event logs were about **16.3 MB for 27 frames** and
**13.0 MB for 20 frames**. This is diagnostic instrumentation, with substantial
cost; no production throughput claim is made. Events flush per frame, without a
power-loss durability guarantee.

The original `/home/jesse/Desktop/Projects/network-lightcone-standalone` matches
its complete pre-copy snapshot. In the experiment copy, **88 protected world,
pack, trainer, receipt and ledger files** also match their copied hashes. The
active pack remains `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`,
with 208 nodes, 188 edges, 48 dimensions, `platform=local_diagnostic` and
`sealed=false`. No world retraining, sealing or original-project change occurred.

## Use the logs

From this copied project:

```sh
cargo run -p network-lightcone-replay --offline -- \
  --input /path/to/capture.pcap --out artifacts/logs/new-run

# Include exact bytes only when wanted:
cargo run -p network-lightcone-replay --offline -- \
  --input /path/to/capture.pcap --out artifacts/logs/new-full-run \
  --include-frame-bytes

python3 network-replay/tools/verify_trace.py \
  --logs artifacts/logs/new-run --input /path/to/capture.pcap

python3 network-replay/tools/trace_report.py \
  --logs artifacts/logs/new-run --sequence 1 --out artifacts/logs/frame-1.md
```

Start with these recorded artifacts:

- [Readable live ACK trace](artifacts/experiments/trace-acceptance-final-20261001/live-frame-6.md)
- [Readable checksum-failure trace](artifacts/experiments/trace-acceptance-final-20261001/live-frame-1.md)
- [Acceptance checks and measurements](artifacts/experiments/trace-acceptance-final-20261001/result.json)
- [Live trace summary](artifacts/experiments/trace-acceptance-final-20261001/live-traced/summary.json)
- [Capture provenance and outcome](artifacts/experiments/trace-live-20261001/capture.json)
- [Original/world preservation audit](artifacts/experiments/trace-original-and-world-audit-20261001.json)

The next usefulness evaluation can now correlate observed traffic, exact admitted
evidence and independently labeled outcomes. Creating correct logs is evidence
about execution, not by itself evidence of defensive effectiveness.
