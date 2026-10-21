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
