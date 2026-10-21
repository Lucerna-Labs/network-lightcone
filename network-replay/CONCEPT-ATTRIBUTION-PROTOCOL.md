# C02 — isolate the mechanism, holding world content fixed

2026-10-01. Jesse asked to set training gaps aside and establish whether the
concept works. Do not curate/retrain the current world or treat its coverage
defects as the target. Future world rebuilding is the user's separate plan.

This test isolates the current packet-admission implementation. Its primary
bounded claim is that represented symbols select an exact causal neighborhood
while no represented symbols produce no neighborhood. Separately determine
whether learned coordinate values contribute to those admission outputs.
Neither claim is equivalent to distinguishing all benign/malicious behavior.

Freeze input and source hashes before execution. Use every represented node as
a singleton input, the empty input, and every distinct observer seed set in the
already verified C01 synthetic/live captures. Those captures are regression
evidence; this is a new controlled ablation, not a fresh unseen-traffic benchmark.
Retain the mapping from all source frames to their normalized seed sets.

For each normalized input, run the actual Rust admission API with:

1. The unchanged active pack and active policy.
2. The same graph/metadata with all 48D coordinates and 4D projections erased.
   Reset the projection center and supply a valid orthonormal reference basis.
3. The same graph/metadata with paired 48D/4D rows reassigned to different node
   IDs, preserving the original projection basis and center.
4. The active pack with all relation types disabled (direct seeds only).
5. The active pack with past-only traversal.
6. The active pack with future-only traversal.

The coordinate changes exist only as in-memory synthetic counterfactual buffers.
Their test hashes are explicitly supplied to the low-level loader. They are not
trained packs, do not describe the original training receipt, are not accepted
through the deployment manifest gate, and must never replace active files.
If a control fails the loader, record it rather than weakening validation.

Save exact nodes, edges, exclusions, frontier, policy, query/pack/receipt hashes
and all admission steps for each case/control. Compare membership/edge outcomes
separately from receipts: pack or policy changes must change identity hashes even
when admitted content is identical.

Predeclared interpretation:

- All baseline and policy-control outputs must agree with independent exact
  graph replay and receipt reconstruction. Empty inputs must remain empty.
- If erased/shuffled coordinates leave all admission content and decision steps
  unchanged, learned-coordinate contribution is **not exercised by this path**;
  do not call that proof of learned-geometric value or failure of the abstract
  Lightcone architecture.
- Relation removal should change outcomes wherever the baseline expanded beyond
  its direct seeds/retained edges. Past/future differences quantify directionality.
- Same normalized seed sets and policy must produce identical admitted content,
  even for different packet bytes. Different query hashes still distinguish the
  receipts. This identifies the observation boundary; it does not establish
  identical application meaning or whether a packet is legitimate.
- Report functional contribution and remaining untested value separately. A
  benefit to downstream decisions would require a separately defined outcome
  and matched comparison; no such improvement may be inferred from counts alone.

Keep runtime code, world, trained files, coverage ledger and original checkout
unchanged. No sealing, training, GPU work, or world rebuild is part of C02.
