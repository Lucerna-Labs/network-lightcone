# Complete-path logging acceptance

2026-10-01. Scope: this independent experiment copy only. Preserve the original
checkout, world sources, trained packs, coverage ledger and `sealed=false`.

The existing replay logger has input hashes and final observations/receipts.
Extend the actual observer and runtime with optional no-allocation callbacks;
their existing public APIs use the same implementation with no-op callbacks.
Tracing must never become admission policy or change a receipt.

Required evidence:

- Run lifecycle: start, world/pack validation, input identity, replay, completion
  or explicit failure. Preserve incomplete runs and never overwrite an output.
- Per-frame identity: run ID plus sequence, capture location/timestamp, exact
  byte length/hash, parser and admission times, and an ordered internal trace.
- Real parser stages: layer entry/extent, parsed structural fields, actual
  validation checks, tentative seed additions, failed-parse seed discard, and
  the returned observation. Do not infer successful checks from a final label.
- Real admission stages: policy checks, seed-cap decisions, queue visits, every
  edge scan/filter, direction/visited/hop/node-cap choices, final edge inclusion,
  final node states, and unchanged receipt hash.
- A hash-bound world snapshot exposing full 48D coordinates, observer-only 4D
  coordinates and exact node/edge metadata. State clearly that this admission
  implementation consults exact graph/policy, not coordinate distance, and does
  not evaluate the prose conditions or maintain TCP connection state.
- Default logs omit payload bytes and addresses. Explicit `--include-frame-bytes`
  records exact bytes, including addresses/payload, for reconstruction. Detailed
  trace is enabled by default; `--no-trace` provides an uninstrumented comparison.
- A separate verifier checks source input identity, individual frame hashes,
  optional logged bytes, ordered stages and seeds, graph decisions against the
  pack/policy, final receipts, and file-level hashes. Integrity failure is visible.

Acceptance: existing tests pass; traced/untraced APIs and baseline/new executables
give identical observations and receipt digests on the declared replay corpus;
unknown, malformed, truncated, capped and incomplete inputs have complete or
explicitly failed logs; tampering is detected; logging leaves input bytes and
trained world unchanged. Exercise actual captured packets on a disposable local
network namespace if available, with no host-network reconfiguration. Document
which live boundary was tested, trace overhead and limits. Logging proves what
ran; usefulness/security effectiveness still requires outcome labels and matched
tests. Do not claim those from log creation alone.
