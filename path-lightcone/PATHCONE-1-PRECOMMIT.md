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

## Run 2: results (2026-10-21, `evidence/pathcone-1-run2/`)

| role | held-out pass | exact port | exact address | protocol swap | direction flip | wildcards per field |
|---|---|---|---|---|---|---|
| hub | 0.9522 | 0.957 | 1.000 | 1.000 | (n/a: hub) | src 1, dst 1, sport 12, dport 13, **tcpf 8** |
| source | 0.9443 | **1.000** | **1.000** | **1.000** | **1.000** | src 1, sport 6, dport 6, **tcpf 4** |
| receiver | 0.9463 | **1.000** | **1.000** | **1.000** | **1.000** | src 1, sport 6, dport 6, **tcpf 4** |

Also:
- **The deny world wrongly drops 0 legitimate packets.** It catches 122–244 of the held-out
  class (a) on its own.
- Speed: **6.7 million per second**.

| # | Result |
|---|---|
| P1 | FAILED (0.94–0.95) |
| P2 | **FAILED, and invalid** (below) |
| P3 | FAILED at the hub only (0.957 exact port) |
| P4 | MEASURED |
| P5 | MEASURED |
| P6 | MEASURED |
| P7 | MEASURED |
| P8 | FAILED (TCP-flag wildcards remain) |

**4 of 8 hold.**

### Diagnoses (after the run)

- **P2 was an invalid negative** (`diagnostic-probe.txt`). The probe (10.77.0.1:60675 →
  10.99.0.1:45999) matched with destination port **45999 exact**. In the io-20261001 experiment UDP
  45999 is a *legitimate trained service* at the receiver, so phase 1's "undeclared" label does not
  transfer. It got through only because its source-address position had folded. My precommit
  error.
- **The TCP flags still fold because folding ran at every depth at once.** Under each individual
  flow's branch, its flags (SYN, ACK, FIN) are all within one flow, so they look one-burst there.
  **The fix is top-down:** fold the shallowest eligible positions first, then rebuild.
- **The held-out misses are genuinely untrained traffic** (`diagnostic-misses.txt`):
  - about 20 packets per role on **UDP port 41000**, a service present only in the later arms;
  - IPv6 hop-by-hop/MLD and neighbour-discovery packets from **new link-local addresses** (each
    VM boot has new interface IDs).
  - A trained-path filter *should* drop the first. The second calls for learning *which part* of
    an address varies.

## Run 3: PRECOMMITTED (2026-10-21), before any run-3 code

**The two changes:**
1. **Top-down recurrence folding:** each pass folds only the shallowest eligible positions, then
   rebuilds, until none remain. The rule is otherwise run 2's.
2. **Learned prefix folding** (a new crate, `path-nibble`): every address and port value is expanded
   into its 4-bit nibbles, most significant first, each its own trie position. Recurrence folding
   then learns *which nibbles* are volatile (the interface half of a link-local address, the low
   nibbles of ephemeral ports) while stable prefixes and service ports stay exact. This is
   CIDR-like generalisation **learned from traffic, never written**.

**The tests:**
- **The mutations** apply only where *every* nibble of the field matched exactly.
- **P2 is withdrawn** (no valid real negative exists in this data).
- **"Untrained service"** packets are those whose (L4, port) pair never appears in training,
  computed from the data.

**Predictions:**
- **P1:** held-out pass ≥ 0.97 overall, and ≥ 0.99 excluding untrained-service packets.
- **P1b:** the UDP-41000 packets (an untrained service) are dropped.
- **P3:** each exact-field mutation class is dropped at ≥ 0.99.
- **P4:** fail-closed.
- **P5:** folding is load-bearing.
- **P6:** the deny world wrongly drops nothing.
- **P7:** ≥ 1 M admissions per second (paths grow to about 76 symbols).
- **P8:** no TCP-flag wildcards, and no wildcard on an address's first 8 nibbles (prefixes stay
  exact).

## Run 3: results (2026-10-21, `evidence/pathcone-1-run3/`)

| role | held-out pass | exact port | exact address | protocol swap | direction flip | deny wrongly drops |
|---|---|---|---|---|---|---|
| hub | 0.9454 | 1.000 | 1.000 | 1.000 | (n/a) | 0 |
| source | 0.9443 | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| receiver | 0.9463 | 1.000 | 1.000 | 1.000 | 1.000 | 0 |

- Speed: **1.25 M/s**, down from 6.7 M/s: the expanded paths are about 4 to 9 times longer.
- **5 of 9 hold:** P3, P4, P5, P6 and P7.
- **P1, P1x, P1b and P8 FAIL.**

### Diagnoses (after the run)

**P1b's premise was wrong.** UDP 41000 is the Imperium **tunnel port**: a heavily trained service.
- The 20 misses per role are one **loopback control flow** per arm (interface `lo`, one ephemeral
  source port per arm → 41000).
- Training holds exactly one example of it, so nothing can be learned to fold it. The "untrained
  service" set is empty in this data.

**Nibble expansion learned no prefix.**
- The new link-local addresses are the tunnel interfaces' (`impa`, `impb`, `impc`) random interface
  IDs, recreated at each arm's start.
- Training holds 1 to 2 of them per trie node, which is below min_distinct 3.
- No address nibble folded. The cost was a 5× slowdown, with no gain.

**Top-down did not stop the TCP-flag wildcards, and the reason is the data, not the depth**
(`diagnostic-flag-wildcards.txt`):
- every remaining flag wildcard sits under a *service* port (46000 or 46001), after the flows had
  merged;
- the whole TCP case set of an arm lasts about **10 ms**, so every flag set there is "one-burst";
- **time recurrence cannot tell structure from ephemera in a capture this short.** The run-2/3 law
  is the wrong signal for this data.

(The top-down unit test still shows the depth effect on synthetic data.)

## Run 4: PRECOMMITTED (2026-10-21), before any run-4 code

**The law changes from time to context.** Borrowed from linguistics, the *continuation count*
(Kneser–Ney): a word seen in many different contexts is part of the language, and a word seen in
one context is incidental.

- **The context count:** for each (field, value), the number of distinct raw training prefixes it
  directly follows.
- **Ephemeral:** a value with a context count of exactly 1.
  - A throwaway port belongs to one conversation, so it is ephemeral.
  - A service port follows many client ports, and a flag set follows many flows, so neither is.
- **The fold rule:** a node folds when it has ≥ 3 non-wild children (min_distinct) and ≥ 0.8 of
  them are ephemeral.
- **Context counts come from the raw (unfolded) paths, so they stay stable as folding merges
  branches.** Folding is iterated top-down, as in run 3. There is no time window, and no value is
  ever written by hand.
- **Paths are raw again** (nibbles dropped: no gain, 5× cost).
- **The tests are run 3's.** P1b becomes "the loopback control flow is reported, not predicted":
  it has one training example.

**Predictions:**
- **P1:** held-out pass ≥ 0.95 on every role (run 3: 0.944–0.946). About 4% of the held-out
  packets are one-example paths: the loopback flow, and the new tunnel IDs' MLD/RS packets.
- **P3:** each exact-field mutation class is dropped at ≥ 0.99.
- **P4:** fail-closed.
- **P5:** folding is load-bearing (≥ 0.2 gain).
- **P6:** the deny world harms 0 legitimate packets.
- **P7:** ≥ 5 M/s.
- **P8:** **no TCP-flag wildcard and no address wildcard.**

## Run 4: results (2026-10-21, `evidence/pathcone-1-run4/`)

| role | held-out pass | wildcards | mutations dropped | deny wrongly drops |
|---|---|---|---|---|
| hub | **0.5074** (no folding 0.3174) | src 1, sport 1, dport 3 | 1.000 every class | 0 |
| source | 0.9443 | sport 6, dport 6 | 1.000 every class | 0 |
| receiver | 0.9463 | sport 6, dport 6 | 1.000 every class | 0 |

- Speed: 5.7 M/s.
- **4 of 7 hold:** P3, P4, P6 and P7.
- **P1, P5 and P8 FAIL, all at the hub.**

**What worked:** on both end hosts the context law gives the same pass as run 2/3, but with **no
TCP-flag wildcard and no address wildcard**. That is the structurally clean world P8 asked for.

**Diagnosis of the hub (after the run):** the hub forwards.
- Each forwarded packet is captured twice: in on one link, out on the other, with a different
  direction symbol.
- So a throwaway port follows **2** raw contexts, never 1. The ports fail to fold, and the whole
  hub world stays nearly strict.
- The single address wildcard is a node where 3 of the hub's own one-context addresses met.

## Run 5: PRECOMMITTED (2026-10-21), before any run-5 code

**One change:** a value is ephemeral when its context count is **below min_distinct** (fewer than
3), instead of exactly 1.
- One setting now says both "many values" and "few contexts", so the law is symmetric: a position
  is volatile when it takes ≥ m values that each follow < m contexts.
- Everything else is run 4's.

**Predictions:**
- **P1:** held-out pass ≥ 0.94 on every role.
- **P3:** each exact-field mutation class is dropped at ≥ 0.99.
- **P4:** fail-closed.
- **P5:** folding is load-bearing (≥ 0.2 gain on every role).
- **P6:** the deny world harms 0 legitimate packets.
- **P7:** ≥ 5 M/s.
- **P8:** no TCP-flag wildcard and no address wildcard, **on every role, the hub included**.
