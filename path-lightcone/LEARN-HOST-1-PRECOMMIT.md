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

## Running (2026-10-23)

**Two setup fixes before it ran:**
1. **AppArmor's tcpdump profile denies hidden home folders** (`audit deny @{HOME}/.*/**`) and gives
   root no DAC override into Jesse's folders, so the first start failed with `Permission denied`.
   **AppArmor was not changed.** The capture now runs **as Jesse** with only `CAP_NET_RAW` and
   `CAP_NET_ADMIN` (`systemd-run -p User=jesse -p AmbientCapabilities=...`, no `-Z`), and writes to
   a plain private folder, `~/lightcone-learn` (`0700`).
2. **The file name came out as a literal `cap-%Y%m%d-%H%M%S.pcap`.** Newer `systemd-run` already
   escapes `%`, so my doubled `%%` reached tcpdump, whose `strftime` turned it into a literal `%`.
   Every hourly rotation would have overwritten the same file. Fixed with single `%`; the first
   minutes of capture were kept by renaming.

**The service now:** `sudo systemd-run --unit=lightcone-learn -p User=jesse -p
AmbientCapabilities="CAP_NET_RAW CAP_NET_ADMIN" tcpdump -i any -s 128 -n -U -G 3600 -w
'/home/jesse/lightcone-learn/cap-%Y%m%d-%H%M%S.pcap' 'ip or ip6'`. Stop it with
`sudo systemctl stop lightcone-learn`.

**First learner run (6½ minutes of real traffic):**
- 24,518 packets, every one with a path, giving **1,440 distinct paths** in `host.pathpack`;
- the capture was deleted after reading, and the live file was left alone (H2 holds so far).

**Readiness:** DNS, IPv6 RS/RA and NA are present. **DHCP is missing**, as expected: no renewal
yet. **IPv6 NS is missing** so far. Learning continues for at least a day.

## Browsing and the hourly learner (2026-10-23)

**Browsing, Jesse's idea:** about 25 ordinary sites in the built-in browser. It only read pages: no
logins, forms, downloads or consent clicks, and a bot challenge was left alone. The traffic covered
HTTPS over TCP and QUIC, plain HTTP, video, maps, search, CDNs and raw GitHub.
- In about 26 minutes: **514,755 packets, giving 7,572 distinct paths** (was 1,440).
- **DHCP is now present.** IPv6 NS is still missing, as expected: it is rare when neighbours are
  cached.

**The hourly learner (Jesse: "Hourly timer"):** a user-level systemd timer with no root,
`~/.config/systemd/user/lightcone-pathlearn.{service,timer}`.
- It runs `~/.local/bin/pathlearn ~/lightcone-learn ~/lightcone-learn/host.pathpack` at :25 every
  hour, after the capture rotates at :18. `Persistent=true` catches up on missed runs.
- Each finished hour (about 170 MB) is read and deleted, so only paths stay on disk.
- Tested: the live hour is left alone and the pack is kept.
- It is a user timer, so it runs while Jesse is logged in. To remove it:
  `systemctl --user disable --now lightcone-pathlearn.timer`.
