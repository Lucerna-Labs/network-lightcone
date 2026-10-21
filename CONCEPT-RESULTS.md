# Concept tests — all three claims evaluated with the world held fixed

Jesse asked to stop focusing on training coverage and test the concept itself.
All three requested comparisons were executed. No world curation, training,
runtime repair or sealing was performed.

| Claim | Measured result |
|---|---|
| Represented versus unrepresented admission | **Works at the observed-symbol boundary** |
| Learned geometry contributes beyond the exact graph | **Not exercised by this packet-admission implementation** |
| Returned context improves a downstream task | **No accuracy gain on this test; 77.29% fewer input tokens than supplying the full world** |

The positive evidence is for bounded, reproducible causal-graph admission and
context scoping. These results do not establish a learned-geometric advantage or
a general network-security effect. That distinction concerns the running mechanism,
independently of missing world coverage.

## 1. Represented/unrepresented admission

The input set contains every one of the 208 represented singleton symbols, an
explicit empty input, and all 35 distinct seed sets produced by the already
verified C01 captures: 162 constructed frames and 42 real captured frames.
The mapping from all 204 source frames to their seed sets was frozen before
the new controls. This reuses evaluated traffic as regression evidence.

Across **244 normalized inputs**, the original runtime returned exact bounded
neighborhoods matching independent graph replay. All empty inputs remained empty.
The earlier frame-boundary checks show that malformed or wholly unrepresented
frames produced no seeds and no admitted context. This validates the represented-
symbol admission contract.

All 35 packet-seed groups contain different frame byte hashes, yet members of each
group receive identical admitted nodes and edges. Their receipt hashes still bind
the different frame bytes. Thus input identity is recorded, while context selection
depends on the represented symbols.

This is a specific boundary: unknown application meaning inside otherwise
recognized TCP/UDP structure can share the same observation symbols. The result
does not imply that arbitrary unknown behavior, intent, identity or maliciousness
is distinguished. A returned neighborhood remains context, not packet permission.

## 2. What actually drives the result

Each normalized input was evaluated through the actual Rust admission API under
six controls. The independent evaluator checked all node/edge/cap/frontier results,
all **3,063,453 admission steps**, and every recomputed receipt across **1,464 runs**.

| Control | Inputs whose admitted content changed |
|---|---:|
| Erase all learned 48D coordinates and 4D projections | **0 / 244** |
| Reassign coordinate rows to different node IDs | **0 / 244** |
| Disable all graph relations | **242 / 244** |
| Past-only traversal instead of active both-directions policy | **226 / 244** |
| Future-only traversal instead of active both-directions policy | **221 / 244** |

Past versus future differed on 242 inputs. The two unchanged inputs under relation
removal were the two empty-input representations. Every nonempty tested input
therefore depended on graph relations for its expanded result.

The coordinate controls actually changed the representation: erasure changed
37,451 bytes; row reassignment changed all 208 node-coordinate associations.
Both coordinate controls left **every admission decision trace unchanged**.
All 244 receipt hashes changed in each coordinate control because the pack identity
changed, even though admitted content did not. This confirms provenance binding
without confusing it with a change in selection behavior.

These are in-memory synthetic counterfactual buffers, with explicit diagnostic
hashes passed to the low-level loader. Erasure resets the projection center/basis
so its structural projection checks remain defined. Neither counterfactual is a
trained world or an accepted deployment pack. Neither was written over active
artifacts or passed through the original manifest/promotion gate.

The result agrees with the code: the packet observer selects exact symbols;
`World::admit` follows exact typed edges and policy. Coordinates are checked at
load time but are not consulted during this admission. Consequently this path
cannot demonstrate the value of learned 48D geometry. This is an implementation-
boundary finding, not a proof that the abstract Lightcone architecture cannot work.

## 3. Actual downstream model comparison

A real local model, `qwen3.5-2b-cybersec@q8_0`, was loaded as the separate instance
`lightcone-c03-eval`. The load requested `--gpu off`, context 16,384 and one
prediction at a time. GPU weight offload was disabled; the installed CUDA backend
still initialized a GPU context, so this is not a claim of zero GPU allocation.
No GPU-performance experiment or training was performed. Only the experiment's
model instance was unloaded afterward; the model server was left running.

The task had **16 predeclared protocol-interpretation questions**, with two fixed
answer-option permutations: 32 trials per arm, not 32 independent questions.
All questions concern represented source-supported mechanisms. Gold answers were
kept out of model requests. The model could use prior knowledge in every arm.

The four arms held the model, questions, observations, system prompt, options,
temperature and token maximum fixed:

1. No supplemental world context.
2. Direct seed-node descriptions only.
3. Actual admitted node/edge context from verified runtime receipts.
4. The complete unchanged world.

The renderer retained node statements, typed relation/polarity, provenance IDs,
conditions and exceptions. Repeated conditions/exceptions were dictionary-encoded
without removing their content. Requests were stateless, with reasoning off and no
tools or integrations. All observed reasoning-token counts were zero.

### Initial run: an output-format confound

C03's frozen task required a JSON `choice`. Its results are preserved:

| Context | Correct machine-readable answers | Non-JSON/invalid responses |
|---|---:|---:|
| None | 12 / 32 | 20 |
| Seed descriptions | 18 / 32 | 14 |
| Admitted context | 3 / 32 | 29 |
| Full world | 1 / 32 | 31 |

Many responses were bare letters or answer text rather than the required JSON.
This is a real structured-consumer integration failure, but it confounds answer
format with protocol knowledge. These scores were not repaired or discarded.

### Format-constrained replication

A separate C03b protocol was declared before further scored calls. It kept the
same questions, gold labels, option order, context strings, model and generation
limits, while enforcing a JSON schema permitting any of A/B/C. The schema contains
no correct-answer information. It uses the local server's documented
[structured-output interface](https://lmstudio.ai/docs/developer/openai-compat/structured-output).
This is a replication on already evaluated regression questions, not a fresh holdout.

| Context | Correct answers | Invalid responses | Total input tokens |
|---|---:|---:|---:|
| None | **32 / 32** | 0 | 6,578 |
| Seed descriptions | **32 / 32** | 0 | 14,092 |
| Admitted context | **32 / 32** | 0 | 99,396 |
| Full world | **32 / 32** | 0 | 437,682 |

There were zero paired accuracy wins or losses for admitted context against any
other arm. The task hit a baseline ceiling: the model already knew these protocol
answers. **No accuracy improvement is established by this test.**

Admitted context used **77.29% fewer input tokens than the full world** with equal
observed correctness. That is a real reduction in supplied context, conditional
on choosing to provide world evidence. No-context was cheaper still on these
already-known questions. Do not present the token reduction as an accuracy gain,
latency improvement, evidence that all context is necessary, or general reasoning
superiority. Requests were grouped by arm for prefix reuse, so wall-time comparison
is not an acceptance metric.

The audit independently recomputed all 256 response scores and hashes. It verified
that system/user strings and gold labels were unchanged between C03 and C03b,
and that the same model instance produced every response.

## What can be concluded now

- The represented-symbol boundary and exact causal-context selection operate
  reproducibly and respond to relation/direction changes.
- This packet path does not exercise learned coordinates in selecting context.
  A larger or better curated world alone cannot demonstrate a coordinate-based
  contribution in a function that never consults those coordinates.
- Context scoping reduces the amount of world information supplied to a consumer.
  The tested model/task showed no extra answer accuracy once formatting was
  controlled. This small, model-specific ceiling result does not show that context
  could never help a different task.

The stronger geometric/security claim remains unestablished by this implementation.
The missing evidence is about the mechanism's exercised role and downstream
outcomes, rather than another list of world-coverage defects. No world rebuild or
curation work was done; Jesse's planned Claude rebuild remains separate.

## Evidence and preservation

- [C02 protocol](network-replay/CONCEPT-ATTRIBUTION-PROTOCOL.md)
- [C02 controls and independently verified results](artifacts/experiments/concept-attribution-input-20261001/summary.json)
- [C03 protocol](network-replay/CONCEPT-DOWNSTREAM-PROTOCOL.md)
- [Initial downstream results, including failures](artifacts/experiments/concept-downstream-20261001/summary.json)
- [C03b format-control protocol](network-replay/CONCEPT-DOWNSTREAM-FORMAT-CONTROL.md)
- [Format-controlled results](artifacts/experiments/concept-downstream-format-20261001/summary.json)
- [Independent final audit](artifacts/experiments/concept-final-audit-20261001.json)
- [Temporary model cleanup](artifacts/experiments/concept-model-cleanup-20261001.json)

The original checkout, 88 protected world/pack/training/ledger files and the
runtime/observer/replay implementation hashes remain unchanged. The world remains
`sealed=false`. All 17 existing Rust tests passed. Only new diagnostic examples,
protocols, evaluation scripts and reports were added for these tests.
