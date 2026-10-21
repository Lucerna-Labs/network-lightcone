# PATHCONE-1: the restrained path world (allow) and its reverse (deny)

Status: PRECOMMITTED (2026-10-21), before any code.

## Jesse's design (the authority)

- "if it's causal then a lot can make it through". So not relatedness or proximity.
- A **restrained world:** "only paths trained can pass".
- "a reverse version in addition, a trained world of what not to let pass through".
- "maybe the light cone is built wrong if it's not working as a static filter".
- The rejected-v6 correction (git `7e18418`) still holds: **no hand-written allowlist, CIDR or
  service rules.** Paths are *learned from traffic*.
- **Work autonomously** and borrow concepts from his other projects, **except the thermo memory**
  (too slow for line rate).

## Relation to the existing Lightcone (composed from outside)

The passive knowledge Lightcone (`kernel-lightcone`, the v4 world) is untouched, and so is
`AGENTS.md`'s clean-world rule. The path filter is a **separate component** in `path-lightcone/`, and
its deny world is its own artifact, never mixed into the clean world.

## The stack (one function per crate, zero dependencies)

| crate | its one job (Atom role) |
|---|---|
| `path-sense` | **sense:** a captured frame (Linux SLL2 header, then ARP, IPv4 or IPv6, then TCP, UDP, ICMP or ICMPv6) plus its direction → its **path**, the ordered structural symbols: direction, link type, L3 version, L4 protocol, source address, destination address, source port, destination port, TCP flag set, ICMP type and code. ARP gives operation, sender and target. Payload bytes are never read. Anything unparsable gives *no path* |
| `path-world` | **the world:** a trie of trained paths. **Learned folding** (the FOLD concept): after training, a trie position whose values are *volatile* (≥ 3 distinct, none holding more than half of the visits) folds into a wildcard child. Ephemeral ports and ICMP IDs are generalised by the data, never by a hand list. Matching walks the trie: an exact child, else the wildcard child, else no match. A path matches only at a trained terminal |
| `path-admit` | **the gate law:** pass ⇔ the allow world matches **and** the deny world does not. No path, no pass (fail-closed) |
| `pathcone1` | **the orchestrator:** loads the evidence, trains one allow world per host role (hub, source, receiver), and runs the checks. The settings live here |

**The fold settings** (orchestrator, labelled as settings): distinct ≥ 3, max share ≤ 0.5.

## Data (Imperium `evidence/`)

- **Train:** the `lightcone-vm-io-20261001` healthy arm. Case packets with attempt index < 6, plus
  every packet with no case (the host's own background: ARP, ND, mDNS). Per role.
- **Held-out legitimate:**
  - the healthy arm's attempts ≥ 6;
  - all of the **quarantined** and **kernel_recovered** arms (different runs of the same services);
  - per role.
- **The real negative:** the phase-1 undeclared UDP probe to port 45999
  (`lightcone-vm-20260930-phase1/receiver/control/mesh.pcap`), judged by the receiver world.
- **Synthetic negatives** (deterministic mutations of every held-out legitimate packet):
  - (a) destination port changed to one never trained;
  - (b) source address changed to one never trained;
  - (c) the L4 protocol swapped (UDP ↔ TCP);
  - (d) the direction flipped.

## Predictions

1. **P1, trained paths pass:** held-out legitimate traffic passes at ≥ 0.98 for every role.
2. **P2, the real negative is stopped:** the UDP 45999 probe is dropped.
3. **P3, untrained paths are stopped:** each mutation class is dropped at ≥ 0.99 for every role.
4. **P4, fail-closed:** an empty allow world passes nothing, and malformed or truncated frames are
   dropped.
5. **P5, learned folding is load-bearing:** without folding, held-out legitimate traffic drops by
   ≥ 0.2 (ephemeral ports). With it, P3 still holds, so no service port or address is
   over-generalised.
6. **P6, the reverse world:**
   - a deny world trained on mutation class (a) from the *training* packets blocks class (a) on
     held-out packets when the allow world is deliberately widened (destination port folded);
   - with the plain allow world, the deny world's added drops are reported. The prediction is **0
     on this data**, because a strict allow world already stops them.
7. **P7, no lag:** ≥ 1,000,000 admissions per second on one CPU thread.

**Chaos, heat and amplification:** excluded at this rung. The gate is a deterministic exact matcher,
and the fold thresholds get their chaos round in PATHCONE-2. The thermo memory is excluded by
Jesse's direction.

## Run 1: results (2026-10-21, `evidence/pathcone-1/results.txt`)

| role | trained paths (folds) | held-out legitimate pass | without folding | mutation drops: dst port / src address / protocol swap / direction flip |
|---|---|---|---|---|
| hub | 777 (76) | **0.9863** | 0.3174 | 0.344 / 0.309 / 1.000 / 0.249 |
| source | 468 (36) | **0.9904** | 0.2668 | 0.311 / 0.455 / 1.000 / 0.831 |
| receiver | 472 (39) | **0.9904** | 0.2841 | 0.249 / 0.454 / 1.000 / 0.830 |

- The real phase-1 probe (10.77.0.1:60675 → 10.99.0.1:45999) **passed**.
- Speed: **6.0 million admissions per second** on one thread.

| # | Result |
|---|---|
| P1 trained paths pass | MEASURED |
| P2 real negative stopped | **FAILED** |
| P3 untrained paths stopped | **FAILED** (25–83%) |
| P4 fail-closed | MEASURED |
| P5 folding load-bearing | MEASURED (+0.67 to +0.72) |
| P6 deny under widened allow | **FAILED** (0.37–0.40) |
| P6b deny adds 0 | **FAILED** (241–388 added drops) |
| P7 speed | MEASURED |

**4 of 8 hold.**

### Diagnosis (`evidence/pathcone-1/diagnostic-folds.txt`; after the run)

**Over-folding.** The rule "≥ 3 distinct values, none above half" folded stable structure as well
as the ephemeral values. The wildcards per field at the hub were: source address 5, destination
address 4, source port 8, **destination port 13**, **TCP flags 8**, ICMP 1. A host's handful of real
services, peers and flag sets *are* several distinct values with no majority, so the rule cannot
tell them from random ephemeral ports. Mutation (a) passed for 359 of 536 UDP packets that were not
reply-shaped at the hub.

**Two of my tests were also invalid:**
- **The direction flip is no negative at the hub,** which forwards each packet in *and* out.
- **Mutating a port the data legitimately folded** (an ephemeral reply port) is no negative either.

P6's deny world inherits both problems.

## Run 2: PRECOMMITTED (2026-10-21), before any run-2 code

**The change, recurrence folding:** a position folds only when its values are mostly
**one-burst**, meaning each value is seen within a single time window and never recurs.
- Service ports, peer addresses and flag sets recur across flows over time, so they stay exact.
- Ephemeral ports live in one flow, so they fold.
- **The rule:** ≥ 3 distinct values, and ≥ 80% of them one-burst. A value is one-burst when its
  last sighting is ≤ 1 s after its first. The window and fraction are orchestrator settings, and
  training uses each packet's capture time.

**The corrected tests (declared now):**
- **Mutations (a) and (b)** change only a position the packet matched **exactly** (not through a
  wildcard), to a value never trained, preferring the destination port and then the source port
  for (a).
- **The direction flip** applies to the end hosts (source and receiver) only.
- **P6's deny world** is trained on the corrected class (a) of the training paths. It is tested on
  held-out class (a) under the plain allow world, where a "widened" arm is no longer meaningful.
  Its added drops are reported.

**Predictions** (otherwise as run 1):
- P1 ≥ 0.98;
- P2 the probe dropped;
- P3 each class ≥ 0.99;
- P4 fail-closed;
- P5 folding gains ≥ 0.2;
- P7 ≥ 1 M/s.
- **P8, recurrence folding repairs over-folding:** no destination-port, address or TCP-flag
  wildcards remain, except where a position's values really are one-burst.
