# Network Lightcone revision-4 local validation

Status: `locally_validated`

Seal status: `false`

Accelerator acceptance: `false`

## Bound artifacts

- World: `atom-network-causal-v4`
- World SHA-256: `06dd1dbe35847a1e13146a0d8dfc2bc70bc9f27f44b07354ceba83d077fb9ff2`
- Split-manifest SHA-256: `c5efcc65e8f3de71e14927915cf21906c275bafeba48e2a468fadcfcd12eae86`
- Diagnostic pack SHA-256: `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`
- Training receipt SHA-256: `73a46bc6dfe95a33a0b096e9a21e9f533ce1966000459a9846a82cdd1106fd79`
- Pack manifest SHA-256: `3df4aa6cd3fca92708462a5a83027f07a0d8658714eae8b32cf5e9ca3f3af7af`
- Device: NVIDIA GeForce RTX 5070 Ti
- JAX: 0.11.2

## World population

- 208 nodes
- 188 edges
- 29 pinned sources
- 99 train edges
- 25 validation edges
- 22 sealed-test edges
- 24 cross-composition edges
- 18 retained regression edges

The authored and compiled world contains no named probe, attack, malware,
exploit, flood, beacon or exfiltration exemplar. Those terms may occur only in
separately labelled challenge evidence that the trainer does not read.

## Passing local gates

- Train: pairwise ranking 1.000; top-1 1.000
- Validation: pairwise ranking 0.965; top-10 0.760; worst edge 0.621
- Sealed test: pairwise ranking 0.907; top-10 0.545; worst edge 0.361
- Cross composition: pairwise ranking 0.874; top-10 0.583; worst edge 0.354
- Held-out split population: passed
- Finite full geometry: passed
- Orthonormal spatial observer: passed
- Non-expansion: passed
- Observer versus random-basis placebo: passed
- Rust pack verification: passed
- Exact graph/runtime tests: passed
- Structural observation adapter tests: passed

## Retained failures

- `failed-v4-local-001`: held-out top-10 and individual-floor failures.
- `failed-v4-local-002`: top-10 improved; individual-floor failures remained.
- `failed-v4-local-003`: DNSSEC floor corrected; the evaluated multicast edge
  remained a failure and was moved to regression before a fresh holdout was
  authored.

No threshold was reduced after observing these failures.

## Structural defense challenge

Receipt: `v4-defense-challenges-20260923.json`

The 20-case synthetic challenge produced 12 zero-admission cases and eight
shared-causal-overlap cases, a zero-admission fraction of 0.60 against a frozen
minimum of 0.50. The challenge corpus is outside the world and outside trainer
inputs. This is an architecture-boundary check, not measured production attack
reduction.

## Open gates

- Real Kaggle TPU training and independent receipt verification
- Complete application and routing-protocol observation adapters
- Environment-specific asset, service and policy inventories
- Independent long-duration and external network evaluation
- Measured effectiveness on a representative, contamination-controlled corpus
- Explicit future sealing authorization after the above gates close
