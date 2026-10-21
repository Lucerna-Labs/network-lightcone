# CONSOLIDATE-1: door two's first experiment — the brain learns self-caused new normal and hands it to door one

**Status: PRECOMMITTED, 2026-10-21, before any CONSOLIDATE-1 code.**

## Jesse's design (2026-10-21)

- **Door one** is the sealed path lightcone. **Door two** is the brain behind it. The brain must be
  able to *read* door one, and *"wouldn't it be great if what gets learned the brain could transfer
  that new knowledge to lightcone"*.
- **The transfer is consolidation** (the hippocampus → cortex analogy):
  - the brain hands over **observed paths (evidence), never rules**;
  - door one **relearns them with its own law** (context folding, run 6), from its old training
    plus the evidence, into a **new pack**;
  - that pack is tested, then sealed, then swapped in at the single loading point. The sealed
    world is never edited in place.
- **Self versus non-self** (the immune system's law):
  - the brain consolidates a dropped path automatically **only when its cause is the machine itself,
    linked by identity, never by timing**;
  - unexplained novelty is watched, and waits for Jesse;
  - Jesse: *"Yes, but only if you concur that it likely would work well."* This experiment is the
    measurement that earns that.

## The causes the brain can check from inside (readings, labelled)

- **`own_address`:** an outbound packet whose source address is one of this host's own interface
  addresses in the same episode's snapshot (`ip -j addr`). It is identity, read from the kernel.
- **`authenticated_tunnel`:** an inbound packet that arrived on a tunnel (TUN) interface (`ip -d -j
  link`, `info_kind: tun`).
  - Only the mesh daemon writes to it, after the frozen AEAD authenticates the peer, so an outsider
    on a link cannot place a packet there.
  - **The labelled limit:** an authenticated but compromised peer *is* trusted by this law.
- **Everything else is `non_self`:** for example a packet arriving on a physical link from an
  address the host does not own. **This includes a spoofed copy of the host's own address arriving
  from outside.**

## The composition (one function per crate; the orchestrator holds every setting)

- **`path-self`:** classify one judged packet (path, hook, interface, the episode's self readings)
  into a cause. It is a reading; it decides nothing.
- **`path-consolidate`:** from the dropped packets and their causes, build the candidate pack. The
  rules:
  - **add-only:** the old pack's paths are all kept;
  - **only `own_address` or `authenticated_tunnel` paths** join;
  - **never a path the deny world matches;**
  - de-duplicated.
- **`pathgate`** gains:
  - the interface index and the time in each byte-logged verdict;
  - a `gate-pack` mode that judges with a world built from a pack file (the same law and the same
    deny construction as Imperium's `imperium-net-pathworld`).
- **`brain1`** (orchestrator, run on the host over the run's evidence) produces:
  - the causes of every drop;
  - the candidate packs;
  - the offline checks.
- **`vm/consolidate_vm.py`** (Imperium's three-VM lab, imported unchanged):
  - **episodes 1–3:** gates on, using the 2026-10-01 role packs. Each episode starts the Imperium
    nodes (fresh TUNs, so fresh tunnel link-local IDs), snapshots each guest's addresses and links,
    runs the 8 trained cases, then stops the nodes.
  - **in every episode, the attacker arm.** The hub injects raw frames with an `AF_PACKET` socket
    (which bypasses its own gate) onto the receiver's physical link, timed **inside the restart
    window**:
    - MLD reports (ICMPv6 143 → ff02::16) and router solicitations (133 → ff02::2) from fake
      link-local addresses;
    - the same from a **spoof of the receiver's own fresh tunnel link-local address**;
    - UDP to the trained service 45998 from a fake address.
  - the brain then builds candidate packs from episodes 1–3;
  - **episode 4:** the gates restart with the candidate packs. A fresh restart, the attacker arm,
    the 8 trained cases, and PATHGATE-3's 5 live negatives.

## Predictions

- **C1:** every attacker frame is classified `non_self`, including the spoof of the receiver's own
  tunnel address.
- **C2:** the candidate packs contain **0** attacker paths, and contain every `own_address` and
  `authenticated_tunnel` drop of episodes 1–3.
- **C3:** add-only. Each candidate pack contains every path of its old pack.
- **C4:** offline, the candidate world admits 100% of episodes 1–3's self-caused drops, and admits
  0 of the attacker paths.
- **C5:** in episode 4, every attempt of the 8 trained cases echoes, all 5 live negatives are
  stopped (0 echoes, 0 receipts), and 0 attacker frames pass the receiver's gate.
- **C6:** the episode-4 self-caused drops are fewer than episode 1's on every role.

**Measured, not predicted:** whether the context law folds the tunnel link-local position after
three episodes, so that episode 4's *fresh* IDs pass. If it does, and widens nothing else, door one
learned the class itself. Where any widening appears, it is recorded exactly.

**Settings:** `min_distinct 3`, `ephemeral_fraction 0.8` (run 6); 3 learning episodes; attacker
frames 5 per kind per episode.

## Correction (2026-10-21, before any `path-self` or `path-consolidate` code)

**The hole:** as first written, `own_address` would make nearly every outbound packet "self". That
includes a compromised process on the host sending to a new port, which would then be learned
automatically: the exfiltration case.

**Corrected law: a cause must explain the novelty itself.** A dropped path is self-caused only when
it **matches a trained path everywhere except its source address**, and that source is self:
- **`own_address`:** outbound, and the source is one of this host's own addresses in the episode's
  snapshot.
- **`authenticated_tunnel`:** inbound on a TUN interface. The source is then a peer that the mesh
  has authenticated.

**Everything else is `unexplained`** and is never consolidated automatically. That covers a novel
port, a novel destination, a novel protocol, and anything arriving on a physical link.

This needs one new, read-only world function, `World::matches_except(path, free_positions)`: a
match that accepts any value at the given positions. The world's law is unchanged.

The predictions stand, with `own_address` and `authenticated_tunnel` read in this corrected sense.
**C2's "every self-caused drop" means every *explained* one.** Self-sourced drops whose novelty is
elsewhere are reported as `unexplained`.

## Method change (2026-10-21, before the run): the adversary is tested offline, not injected live

The attacker arm as first written needed a live packet-spoofing injector in the lab. That is not
what CONSOLIDATE-1 is testing, and building a spoofing tool is not warranted: **PATHGATE-3 already
proved, live in VMs, that door one drops and stops exactly these shapes** (untrained ports,
untrained addresses, protocol swaps, and the fail-closed arms). The only new claim here is about
**classification and consolidation**: attacker novelty must never be read as self, so it can never
enter the next pack.

That claim is a property of the `path-self` law and the `path-consolidate` law. It is tested
offline, which is stronger (exhaustive, deterministic) than a handful of live injections:

- **The adversarial set is derived by `brain1` from each role's own trained paths and the
  episode's self readings**, by field substitution only (no live traffic):
  - **A1, spoofed self source on a physical link:** a trained inbound path with its source replaced
    by the receiver's own fresh tunnel address, arriving on a physical interface (not a TUN).
  - **A2, fabricated link-local novelty:** an MLD/RS path from a link-local address the host does
    not own, inbound on a physical interface.
  - **A3, novel service from a spoofed self source:** source = one of the host's own addresses, but
    destination port untrained (novelty is not in the address).
  - **A4, outbound exfiltration:** source = the host's own address, destination and port untrained.
- `path-self`'s unit test already pins the core case: the host's own address **arriving on a
  physical link is a spoof** (`Unexplained`), and novelty beyond the address is `Unexplained`.

**Revised predictions:**
- **C1:** every adversarial path A1–A4 classifies `Unexplained`.
- **C2:** the candidate packs contain 0 adversarial paths and every self-caused drop (that the deny
  world does not refuse).
- **C3:** add-only.
- **C4:** offline, the candidate world admits 100% of the self-caused drops and **0** of A1–A4.
- **C5 (revised):** in the live episode 4, every trained case still echoes and the 5 live negatives
  are still stopped — i.e. consolidation did not loosen door one. (The negatives are PATHGATE-3's,
  already-proven shapes; no new injector.)
- **C6:** episode 4 has fewer self-caused drops than episode 1 on every role.

The live VM lab now runs **legitimate restarts only** (fresh TUNs each episode), which is what
produces the real self-caused drops the brain learns from.

## Second method note (2026-10-21, before the run): the lab gate is log-only, C5 is offline

To *learn*, the brain needs door one's **verdict** on live traffic. Imperium's door one is passive:
it judges and records, it does not block (`filter_enforced=false`). So the lab gate runs **log-only**
— it computes and byte-logs the true pass/drop verdict for every packet, and always releases — via
`PATHGATE_RELEASE_ALL=1`. This matches Imperium exactly and cannot break the live mesh bring-up or
the cases (so the fresh tunnels actually come up, which is what produces the drops to learn from).

**C5 becomes offline, and widens to the full negative set.** "Consolidation did not loosen door
one" is proven by evaluating the candidate world against the adversarial/negative shapes offline:
A1–A4 above, plus **A5 (protocol swap on a trained service)** and **A6 (trained service from an
untrained source address)** — the PATHGATE-3 live negatives, in path form. C4/C5: the candidate
world admits every self-caused drop and **0** of A1–A6. The live episode 4 instead measures C6
directly: with the candidate pack, the fresh-restart housekeeping that episode 1 dropped is now
admitted (fewer self-caused drops), proving the gap closed end to end.

## Results (2026-10-21, `evidence/consolidate-1/`): all predictions hold

Imperium's three-VM lab, four episodes, each a fresh mesh bring-up (fresh TUN link-local
addresses), the gate log-only in every guest. (A first run had a harness bug — one self-readings
file per guest overwritten each episode — so episodes 1–2 drops looked unexplained; fixed to
per-episode readings and re-run. The bug and fix are in `run.log`.)

| # | Prediction | Result |
|---|---|---|
| C1 | every adversarial path A1–A6 is `Unexplained` | **HOLDS** |
| C2 | 0 adversarial paths in packs; every self-caused drop consolidated | **HOLDS** |
| C3 | add-only (every old path kept) | **HOLDS** |
| C4 | candidate admits 100% of self-caused drops, 0 of A1–A6 | **HOLDS** (hub 48/48, source 19/19, receiver 18/18; adversarial 0/6 each) |
| C5 | consolidation did not loosen door one (A5/A6 = PATHGATE-3 negatives still denied) | **HOLDS** (folded into C4's 0/6) |
| C6 | episode 4 has fewer self-caused drops than episode 1, every role | **HOLDS** |

**The measured question — did door one's own law fold the tunnel link-local address? — is YES.**
- Candidate wildcards per field: hub `{3: 1→4}`, source `{3: 0→2}`, receiver `{3: 0→2}`. Only the
  **source-address** position folded, and only under the IPv6 ND/MLD contexts (link `86dd`, L4 `0`
  or `3a`). Service ports (5, 6) were untouched.
- So in episode 4, the tunnels' **brand-new** link-local addresses (never trained, never in the
  evidence) were admitted. **Self-caused drops: episode 1 = 16/6/6, episode 4 = 0/0/0.** The gap
  door one left at the end of PATHGATE-3 is closed.
- Packs grew add-only: hub 777→792 (+15), source 468→475 (+7), receiver 472→478 (+6). The deny
  world refused 0 (none of the self-caused evidence is a denied shape).

**The guard that makes it safe** (`path-self`): a drop is consolidated only when the machine
explains the novelty by **identity** — an `own_address` source (outbound) or an
`authenticated_tunnel` (inbound on a TUN, behind the frozen AEAD), **and** the path matches a
trained path everywhere except that source. Everything else, including a spoof of the host's own
address arriving on a physical link, is `Unexplained` and is never consolidated automatically. A
small `unexplained` residue remained in some episodes and was correctly left for Jesse, not
learned.

**Conclusion.** Door two reads door one, learns self-caused new normal, and hands it back as
evidence; door one relearns it with its own immutable law and generalises. The adversary cannot
ride the channel in. With the identity guard and the offline adversarial check measured, **I concur
this works well** — within the stated limit that an *authenticated but compromised peer* is trusted
by `authenticated_tunnel` (recorded in `path-self`).

**The seam to door two's autonomy:** self-caused consolidation can build a candidate pack without
Jesse; the reseal (deny-check, VM test, TPU seal, swap) is still a gated ceremony, and unexplained
novelty waits for him.
