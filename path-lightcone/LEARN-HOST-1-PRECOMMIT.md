# LEARN-HOST-1: passive learning on Jesse's real machine

**Status: PRECOMMITTED, 2026-10-23, before the learner code.** Jesse: "Start learning."

## What runs on the host (passive, read-only)

- **A capture started by Jesse himself** (it needs root, and the password is his to type):
  - `systemd-run --unit=lightcone-learn tcpdump -i any -s 128 -n -U -Z jesse -G 3600 ... 'ip or ip6'`;
  - only the first 128 bytes of each packet (the headers door one reads);
  - root is dropped after opening the interface;
  - output goes to a private `0700` folder (`~/.local/share/lightcone-learn/`), rotating hourly.
- **No rule is installed and nothing is blocked.** The wifi, USB Ethernet, Tailscale and Docker
  links are untouched.

## The learner, `pathlearn` (unprivileged, runs over the finished hourly files)

- reads SLL / SLL2 captures and senses each packet into its path. Direction comes from the SLL
  packet type; loopback is skipped, since door one does not gate it;
- keeps **only de-duplicated paths**, which does not change the context law: counts are over
  distinct prefixes. It adds them to a host training pack, `host.pathpack`;
- **deletes each hourly capture once read.** The current file is left alone;
- reports which of the paths enforcement depends on are already present: DHCP (UDP 67/68), DNS
  (53), IPv6 router and neighbour discovery (ICMPv6 133–136).

## Predictions

- **H1:** after at least one hour, `host.pathpack` holds the machine's paths, and the readiness
  report lists DHCP, DNS and IPv6 ND/RA as present or absent, honestly.
- **H2:** no capture file outlives its conversion. Only paths remain on disk.
- **H3:** nothing on the host is blocked or slowed. The service is read-only, and the learner runs
  unprivileged.

**Switching to enforcement is a separate, explicit yes from Jesse, after he reviews the report.**
