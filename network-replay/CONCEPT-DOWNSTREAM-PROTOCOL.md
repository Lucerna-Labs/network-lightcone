# C03 — matched downstream task, all three concept tests authorized

2026-10-01. Jesse explicitly requested all three tests without further questions.
C01/C02 cover represented/unrepresented admission and mechanism attribution.
C03 measures whether admitted context improves a real downstream model's answers,
with the existing world held fixed. Do not repair training gaps or rebuild worlds.

Task: sixteen predeclared multiple-choice protocol-interpretation questions on
represented, source-supported mechanisms. Gold choices are authored separately
from the model prompt using RFC field/meaning definitions. No unsupported feature
is scored as a world failure. Questions/gold, rendering, arm order and settings
are frozen before scored calls. A non-network JSON readiness call is preflight only.

Use the existing local `qwen3.5-2b-cybersec@q8_0` model, loaded as the separate
`lightcone-c03-eval` instance, with GPU weight offload disabled, context 16384,
one prediction at a time, reasoning off, temperature zero, maximum 64 output
tokens, no tools/integrations, and stateless requests (`store=false`). Record actual
runtime identity/settings. This is inference, not training or a GPU benchmark.
Unload only the instance created for this experiment when finished.

Four arms use the identical model, question, options, observation description and
system instructions:

1. No supplemental world context (model may use prior protocol knowledge).
2. Only the direct seed-node descriptions.
3. The actual admitted node/edge context from verified C01 runtime receipts.
4. The full unchanged world.

The common context renderer retains node statements, typed relation/polarity,
source IDs, conditions and exceptions. Repeated condition/exception strings may
be dictionary-encoded without dropping their content. Do not put gold choices or
test judgments in prompts. The same neutral system prompt applies to all arms.

Run two fixed option-order permutations per question: 32 trials per arm, 128
total. These remain sixteen unique questions, not 32 independent tasks. Reverse
arm order on the second pass and use fresh stateless messages. Group by arm to
allow local prefix reuse; do not infer a runtime-speed benefit from these timings.

Scoring: require a parseable JSON `choice` from A/B/C; accept an enclosing Markdown
code fence but no answer repair, retries after seeing a wrong answer or discarded
outputs. Count malformed/truncated outputs as incorrect and report them separately.
Infrastructure errors are retained; one same-argument retry is permitted only for
transport failures, never for content quality. Save complete requests, responses,
model identity, token counts, prompt hashes and elapsed times.

Report correctness per arm, paired wins/losses of admitted context against no
context and seed descriptions, option-order consistency, and token volume versus
full world. A positive accuracy difference is only descriptive evidence on this
small set. Equal performance/ceiling effects do not establish improvement; losses
count against it. Compare full-world performance to distinguish scoping value from
simply adding more text. No claim of general reasoning improvement, attack
prevention, original-concept proof or production readiness follows automatically.

The two coordinate counterfactuals in C02 are not deployed or passed to the model.
Keep the active world, runtime, receipts and original checkout unchanged. Preserve
negative results. User's future plan for Claude to rebuild the world is separate.
