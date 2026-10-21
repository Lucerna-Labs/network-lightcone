# PATHGATE-1: the trained-path world in the kernel packet path (namespace lab)

**Status: PRECOMMITTED, 2026-10-21, before any rung-2 code.**

## Goal

PATHCONE-1 run 6 showed the allow + deny worlds judge recorded packets correctly offline. Rung 2
puts the same verdict where packets actually pass: a fail-closed kernel queue. A packet crosses
only if the gate releases it.

**Isolation:**
- All of it runs inside `unshare -Urn` (a private user and network namespace).
- There is no change to the host's firewall, routes or interfaces, and no fail-open path.
- The kernel may load its standard `nft_queue` / `nfnetlink_queue` modules on demand. That is the
  only host-visible effect.

## The composition (each crate does one job; the orchestrator holds every setting)

- **`path-queue`:** the fail-closed NFQUEUE transport, recovered from Imperium `2bb1e8c`
  (`imperium-net-host/src/queue.rs`, `queue_wire.rs`, deleted by `1d58c98`). It is the same codec
  and checks (FAIL_OPEN cleared, truncation and duplicate-attribute refusal, owned packet IDs),
  with the `libc` crate replaced by a handful of declared syscalls (zero dependencies). It is
  mechanism only, with no judgment.
- **`path-frame`:** an adapter from a kernel-held IP packet plus its hook to the path `path-sense`
  reads (an SLL2 shim header; outbound = the OUTPUT/POSTROUTING hooks).
- **`pathgate`,** the orchestrator:
  - trains the receiver's allow world (run 6 settings) and deny world from the evidence;
  - binds the **gate queue** and the **observer queue**;
  - for each held packet: frame → sense → `admit` → release or discard;
  - **on any error, discard**;
  - also an `inject` mode that sends recorded frames on a veth with a packet socket.

**The lab:**
- one namespace, with a veth pair `pg0` ↔ `pg1`;
- the nft table `pathgate`, with two chains on `pg1`'s ingress path (prerouting):
  - priority −300: `queue num 11` (no bypass);
  - priority −200: `queue num 12 bypass`, **the observer**, which records and releases every packet
    the gate let through.

  The observer's record is the receipt of passage, made by the kernel and not by the gate.
- **The positives:** the receiver role's held-out inbound IP frames from the non-loopback
  interfaces, not truncated, and replayed byte-exact.
  - ARP and loopback-interface packets are excluded: NFQUEUE carries IP only, and loopback packets
    never cross a link.
- **The negatives:** the same frames with run 3's exact-field mutations:
  - (a) an untrained port;
  - (b) an untrained address, with the IPv4 header checksum recomputed;
  - (c) the UDP/TCP protocol swap.

## Predictions

- **G1, agreement:** for every injected frame, the kernel outcome (seen or not seen by the observer)
  equals the offline verdict `admit(allow, deny, sense(frame))`: **100% agreement.**
- **G2, positives:** passage ≥ 0.94, run 6's offline rate on this subset.
- **G3, negatives:** each mutation class ≥ 0.99 dropped.
- **G4, fail-closed:** with the queue rule installed and **no gate reader**, 0 frames reach the
  observer. After the gate exits mid-lab, 0 frames pass.
- **G5, baseline:** with the gate chain removed, every frame reaches the observer, which proves the
  injection path itself works.
- **G6, latency:** the median verdict time (receive → finish) is below 100 µs.

## Results (2026-10-21, `evidence/pathgate-1/`): 6 of 6 hold

**Command:** `unshare -Urn sh scripts/pathgate-lab.sh <pathgate> <imperium evidence> evidence/pathgate-1`.
- It ran in a private user + network namespace, with no host firewall, route or interface touched.
- The kernel loaded its standard `nft_queue` module on demand (the first namespace test).

| phase | frames injected | reached the observer | expected |
|---|---|---|---|
| no gate reader (queue rule, no bypass) | 176 positives | **0** | 0 (G4) |
| gate running | 176 positives | **175 (0.9943)** | ≥ 0.94 (G2) |
| | 164 port mutations | **0** | ≥ 0.99 dropped (G3) |
| | 175 address mutations | **0** | |
| | 164 protocol swaps | **0** | |
| gate exited (rule kept) | 176 positives | **0** | 0 (G4) |
| gate chain removed | 176 positives | **176** | all (G5) |

- **G1, agreement:** in the gate phase, the kernel outcome equals the offline verdict for **679 of
  679** frames. The one positive the world drops offline is the one the kernel dropped.
- **G6, latency:** the median verdict (receive → finish, including the kernel acknowledgement) is
  **16.0 µs**, and the p99 is 47.9 µs, over 680 verdicts.
  - The 680th was the veth's own IPv6 autoconfiguration packet. It is untrained, so it was
    discarded.

### A defect found and fixed in the recovered transport

The first lab run passed nothing, even with the gate removed, because both readers refused every
packet.

**The cause:**
- The kernel sets `nlmsg_len` to the unpadded length, so the last netlink message and its final
  attribute (the packet payload) end without alignment padding whenever the packet's length is
  not a multiple of 4.
- The Imperium transport required that padding.
- Its 2026-10-01 lab sent only 84-byte pings, which are aligned, so it never met the case.

**The fix,** an in-place change to code that had never worked for that case:
- padding is required only where bytes follow;
- a length past the end is still refused;
- a new unit test pins the kernel's unpadded format;
- the three original adversarial codec tests still pass.

### What this does not yet cover

- **IP only:** ARP and other L2 frames don't pass through NFQUEUE.
- **Inbound only:** at prerouting, for one role (the receiver).
- **Replayed frames, not live connections:** checksum offload, GSO and real TUN/mesh passage are
  untested.
- The hub's forwarding role and the outbound direction come next, then the VM matrix. The Imperium
  constraints stand until that matrix passes.

---

# PATHGATE-2: every role, both directions (namespace lab)

**Status: PRECOMMITTED, 2026-10-21, before any PATHGATE-2 code.**

## Changes

- **The role is an argument:** hub, source or receiver. Each role gets its own run-6 allow and deny
  worlds.
- **Outbound:** recorded outbound IP packets are sent from inside the namespace by a raw IP socket
  (header included, bound to `pg0`), so they cross the kernel's **OUTPUT** hook.
  - The gate's queue sits at OUTPUT (priority −300, `oifname "pg0"`, no bypass).
  - The observer's queue sits at POSTROUTING (priority −200, with bypass).
  - The gate judges with hook 3, so the direction is outbound.
- **Inbound** is as in PATHGATE-1, at PREROUTING.
  - At the hub, forwarded packets are judged once, at entry: the hub's world holds both captured
    copies.
- **The packet identity hash ignores the IPv4 ID and header checksum,** which the kernel may fill
  in for a header-included send.

## Predictions, per role and direction

- **G1:** the kernel outcome equals the offline verdict on 100% of frames.
- **G2:** positives pass at ≥ 0.94.
- **G3:** each mutation class is dropped at ≥ 0.99.
- **G4:** no reader → 0 pass; reader exited → 0 pass.
- **G5:** with the gate chain removed, all positives reach the observer.
- **G6:** the median verdict is < 100 µs.

A positive the raw socket cannot send (the kernel refuses it) is counted and reported, not
dropped silently.

## PATHGATE-2 results (2026-10-21, `evidence/pathgate-2/`): all hold, every role and direction

**Command:** `unshare -Urn sh scripts/pathgate2-lab.sh <pathgate> <imperium evidence> evidence/pathgate-2`.
The raw sender refused 0 packets.

| role, direction | positives passed (gate) | mutations passed (port / address / protocol) | kernel = offline | no reader / reader exited | baseline | median / p99 verdict |
|---|---|---|---|---|---|---|
| hub, in | 312/327 **0.9541** | 0/305 · 0/312 · 0/305 | 1249/1249 | 0 / 0 | 327/327 | 26.6 / 61.5 µs |
| hub, out | 348/354 **0.9831** | 0/325 · 0/348 · 0/325 | 1352/1352 | 0 / 0 | 354/354 | 26.1 / 89.3 µs |
| source, in | 171/172 **0.9942** | 0/161 · 0/171 · 0/161 | 665/665 | 0 / 0 | 172/172 | 18.9 / 56.5 µs |
| source, out | 157/165 **0.9515** | 0/154 · 0/157 · 0/154 | 630/630 | 0 / 0 | 165/165 | 16.2 / 52.5 µs |
| receiver, in | 175/176 **0.9943** | 0/164 · 0/175 · 0/164 | 679/679 | 0 / 0 | 176/176 | 15.6 / 63.0 µs |
| receiver, out | 156/163 **0.9571** | 0/151 · 0/156 · 0/151 | 621/621 | 0 / 0 | 163/163 | 28.2 / 76.3 µs |

**Every prediction holds:**
- **G1:** the kernel outcome equals the offline verdict on **5196 of 5196** frames.
- **G2:** positives pass at ≥ 0.94 everywhere (0.9515–0.9943).
- **G3:** **0 of 2984 mutated packets passed.**
- **G4:** fail-closed in all 12 fail-closed tests.
- **G5:** the baseline passes everything, so the injection path itself works.
- **G6:** the medians are 15.6–28.2 µs.

The extra gate verdicts in some phases come from the namespace's own IPv6 autoconfiguration
packets. They are untrained, so they were discarded.

**The positives the gate drops** are the packets the run-6 world drops offline: one-example paths,
and the new tunnel interface IDs' MLD/RS packets (see PATHCONE-1 run 6).

**Still outside this lab:**
- live connections (checksum offload, GSO), real TUN and mesh passage;
- L2/ARP.

That is the VM matrix's job. Imperium keeps `filter_enforced=false` until it passes.
