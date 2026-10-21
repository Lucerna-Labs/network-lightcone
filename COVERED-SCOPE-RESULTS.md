# C01 — covered mechanisms pass; IPv6 context needs a curation correction

The covered structural parser, exact graph admission and selected evidence
retrieval passed their tests. The evaluation also found a **world-content scope
defect**: IPv6 TCP/UDP observations expose three generic transport relationships
that impose IPv4-specific prerequisites without an explicit IPv4-only guard.
Those failures remain recorded; no world or runtime correction was made here.

## Results

| Boundary | Observed result |
|---|---|
| Fresh wire fixtures | **162/162** exact seed/kind/reason expectations passed |
| Invalid/unrepresented input | All **57 malformed and 6 unknown** cases admitted no context |
| Valid structural/fragment observations | All **93 decoded and 6 fragment** cases matched expected seeds |
| Selected sourced relationships | **156/156** required relation occurrences retained with original evidence/polarity |
| Native catalog API | All **208 represented concepts**, plus **4 empty/error controls**, passed |
| Live covered traffic | All **42 captured frames** independently checked and correctly observed |
| Live application outcomes | Four exact TCP/UDP echoes and IPv4/IPv6 pings succeeded |
| Semantic scope | **24 IPv6 cases failed**, exposing three existing relationships |
| Existing Rust tests | **17 passed** |
| Trained pack/ranking verifier | Passed existing local-diagnostic gates; remains unsealed |

## What “covered” means in this test

The wire score covers the existing adapter's supported Ethernet/ARP, IPv4/IPv6
framing, ordinary UDP/TCP structural fields/checksums, mapped ICMPv4 types,
generic ICMPv6/error context, supported RS/RA/NS/NA validation, extension-chain
framing and fragment context. It does not claim full protocol semantics.

Three variants change ports, addresses/lifetime and payload lengths/content.
The frames and expected seed sets were frozen before replay. Payload text naming
authority/application concepts did not create corresponding direct seeds. Correct
fragment recognition did not invent complete TCP/UDP observations.

DNS semantic decoding, VLAN, full NDP option semantics/Redirect, arbitrary extension
semantics, TCP flow-state tracking, application parsing and enforcement were
excluded **before testing**, as documented gaps. Previous failures in those areas
were neither repaired nor counted as passes. Higher-level catalog concepts were
queried only through the explicitly seeded native API; that is not wire recognition.

Protocol expectations use the world’s cited standards, including
[UDP](https://www.rfc-editor.org/rfc/rfc768.html),
[IPv6](https://www.rfc-editor.org/rfc/rfc8200.html),
[Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861.html), and
[TCP](https://www.rfc-editor.org/rfc/rfc9293.html).
These are fresh packet fixtures for represented mechanisms, not a new unseen
mechanism benchmark or an external production workload.

## Useful information supplied by the world

The selected questions required actual typed relationships, not just protocol
names: ARP mapping and identity limits; checksum/error-detection and absent-checksum
limits; UDP delivery limits; TCP sequencing/state and identity prerequisites;
ICMP echo/error association; fragmentation/reassembly; and NDP neighbor/cache/DAD
relationships. All 156 requested relation occurrences were present with the source
metadata and polarity intact.

For represented wire observations, median output was **50 nodes and 54 edges**,
compared with **208 nodes and 188 edges** in the complete catalog. Thus the current
bounded lookup supplied the selected evidence while returning about 24% of catalog
nodes and 29% of its edges at the median. Direct-seeds-only has no expanded edges
by construction; the full catalog contains all selected edges but supplies the
entire world. This comparison measures scoped evidence retrieval, not better LLM
answers, relevance of every extra returned fact, or prevented attacks.

The 208 native tests used the real Rust `add_host_validated_symbol` and
`World::admit_traced` APIs. An independent check compared exact membership,
edges, caps/frontiers, ordered decisions and recomputed receipt hashes. All
represented indices were exercised exactly once. Empty input, an out-of-world
index, an out-of-capacity symbol and invalid policy were checked separately.
The API supports access to these represented concepts; this does not certify the
truth or completeness of every catalog relationship.

## The specific curation defect

The decoder correctly produces IPv6 and UDP/TCP seeds. Expansion then includes:

| Existing edge | Unqualified relationship | Observed occurrences |
|---|---|---:|
| `e014` | `udp requires ipv4` | 9 IPv6 UDP cases |
| `e019` | `udp_checksum depends_on ipv4` | 9 IPv6 UDP cases |
| `e039` | `tcp requires ipv4` | 15 IPv6 TCP cases |

The UDP pair occurs in the same nine cases; there are **24 affected cases**, not
33 independent failures. These are three relationships exhibiting one scope issue.
Their conditions and scope prose do not supply an explicit IPv4-only guard. Mere
presence of an IPv4 node elsewhere in a contextual neighborhood is not the failure;
the problem is the positive, unqualified prerequisite evidence attached to generic
transport concepts.

IPv6 carries TCP/UDP with IPv6 pseudo-header checksum rules; IPv4 is not a universal
prerequisite for those transports. See [RFC 8200 §8.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1)
and [RFC 9293 §3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1).

This concern was identified from source inspection and explicitly placed in the
frozen protocol before replay. The logs confirm that it reaches actual IPv6
context output. It is therefore an in-scope data-curation failure, even though
packet recognition and faithful graph execution pass. The next correction belongs
in version-specific transport relationships/scopes, with fresh validation and these
cases retained as regressions. No corrective training or pack promotion occurred.

## Live boundary with checksum-complete inputs

The live harness ran only inside a disposable user/network namespace and a second
private veth peer namespace. TX checksum offload was disabled on both private
interfaces, and the settings were saved before transmission. Host network settings
and unrelated services were not changed.

All four known-payload exchanges succeeded: IPv4 TCP and UDP each returned 72
bytes; IPv6 TCP and UDP each returned 73 bytes. Both pings succeeded. Capture
reported **42 packets captured, 43 received by the filter, 0 kernel drops**.
That is the reported capture interval, not a guarantee that every possible packet
at shutdown was retained.

Independent parsing of captured bytes checked IP/transport lengths and checksums
before comparing expected direct seeds with the Rust observer. All 42 recorded
frames passed, with no checksum failures or malformed observations:

| Covered family | Captured frames |
|---|---:|
| ARP | 2 |
| IPv4 TCP | 11 |
| IPv6 TCP | 10 |
| IPv4 UDP | 2 |
| IPv6 UDP | 2 |
| ICMPv4 | 2 |
| Generic ICMPv6 informational context | 7 |
| NDP | 6 |

This avoids the earlier loopback capture ambiguity for this lab. It is not a
diagnosis of every prior checksum failure, a production deployment test, or a
claim that the runtime itself now understands checksum-offload metadata.

## Reproducibility and preservation

Protocol: [COVERED-SCOPE-PROTOCOL.md](network-replay/COVERED-SCOPE-PROTOCOL.md),
SHA-256 `c5e8eb27cc48622d2541a5cdc868f28fd4ef2e74fc31195454ce2c176023f58c`.
Input manifest SHA-256:
`3ec9d733a301a7750ef71b795800ee71ac884b39ef08bca5ac7b0c8884e06ccf`.

The checks examined 842,133 synthetic-wire trace records, 339,400 live trace
records and 468,217 native catalog steps. Native replay after formatting the
example produced byte-identical JSONL. No expected outcome or threshold was
changed after results.

Independent audit confirms:

- The original checkout still matches its full pre-copy snapshot.
- All 88 protected world, trainer, pack, receipt and coverage files in the copy
  retain their hashes.
- Runtime, observer, replay, trace and Cargo.lock hashes match the previous
  logging build; only new test/diagnostic files and documentation were added.
- Fixture generator, input capture, offload receipt and compiled diagnostic
  identities are recorded.
- The pack remains `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`,
  `local_diagnostic`, `sealed=false`. Existing ranking verification is a regression
  rerun on previously evaluated splits, not new accelerator/seal acceptance.

## Inspect and rerun

- [Full per-case results](artifacts/experiments/covered-scope-results-20261001/result.json)
- [Concrete IPv6 scope failure](artifacts/experiments/covered-scope-results-20261001/ipv6-scope-failure.json)
- [Readable IPv6 UDP trace](artifacts/experiments/covered-scope-results-20261001/ipv6-udp-trace.md)
- [Live application/capture results](artifacts/experiments/covered-live-20261001/capture.json)
- [Independent preservation/identity audit](artifacts/experiments/covered-scope-results-20261001/independent-audit.json)

Use new output directories:

```sh
python3 network-replay/experiments/covered_scope.py --out artifacts/experiments/C01-input-new
unshare -Urn -- python3 network-replay/experiments/covered_live.py --out artifacts/experiments/C01-live-new
CARGO_TARGET_DIR=target/trace-dev cargo build -p network-lightcone-replay --example covered_catalog --offline
python3 network-replay/experiments/evaluate_covered.py \
  --inputs artifacts/experiments/C01-input-new \
  --live artifacts/experiments/C01-live-new \
  --out artifacts/experiments/C01-results-new
```

The evaluator reports wire, evidence, native-catalog, live-capture and semantic-scope
outcomes separately. Successful execution does not erase a failing semantic gate.
