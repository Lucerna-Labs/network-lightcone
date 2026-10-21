# C03b — remove answer-format adherence as a confound

Declared after preserving C03 and before C03b scored calls, 2026-10-01.

C03 is complete and remains negative under its frozen structured-task criteria.
Malformed/non-JSON responses dominated: none20/32, seed-only14/32,
admitted29/32, full-world31/32. Do not regrade or replace that run.

Run the same 16 questions, two option permutations, four arms, gold answers,
context text, system prompt, model instance, temperature and 64-token maximum.
The only experimental change is output-channel enforcement through LM Studio's
documented JSON-schema sampling endpoint `/v1/chat/completions`. The schema permits
any of A/B/C; it contains no correct-answer information. Request no reasoning via
the compatibility parameters and record observed reasoning-token counts.

This is a controlled replication on **already evaluated regression questions**,
not a fresh held-out test. It diagnoses the format confound and separately measures
protocol choice accuracy. Do not add questions, change a gold label, increase
context, switch models, or retry incorrect responses.

Convert each frozen C03 request mechanically to system/user messages, preserving
the strings byte-for-byte. Use the same reversed arm order on repetition2. Save
all transformed requests and their hash before calls, then every raw response,
choice, format status and token count. Compare accuracy and paired wins/losses;
report ceiling effects and the limited sixteen-question population.

Keep C03 and C03b results separate in the report. No inference of general model
improvement or architecture-wide security is permitted from this small diagnostic.
