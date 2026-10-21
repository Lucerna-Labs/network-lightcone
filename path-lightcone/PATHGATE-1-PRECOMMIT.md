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
