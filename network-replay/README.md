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

`events.jsonl` has one JSON object per frame:

- capture line or timestamp, length, frame SHA-256 and untrusted wire hints;
- observation kind and a specific parser reason;
- seed nodes resolved from validated structure;
- the exact policy, admitted nodes and typed edges with provenance,
  conditions and exceptions;
- excluded nodes, hop frontier, query and receipt hashes; and
- separate parse, runtime admission, explanation and total processing times.

`summary.json` records the active world, pack, manifest and training receipt
hashes, pack status, input
hash before and after replay, event-log hash, executable/source hashes,
kind/reason/admission counts, and p95 processing time.
It preserves a `failed` status and the error if parsing stops after earlier
events. Verify the event log with `sha256sum events.jsonl` against the summary.

Payload bytes are never written to logs. IP addresses are omitted by default;
use `--include-addresses` only when that detail is needed. Ports and protocol
numbers are untrusted wire hints until the observer validates the packet.
Generated logs belong under ignored `artifacts/logs/` and must never become
world-training inputs.

The event status `context_admitted` means a bounded causal neighborhood was
returned. It is not an authorization or attack classification. Effectiveness
claims require independently labeled traffic and a separate host enforcement
evaluation.
