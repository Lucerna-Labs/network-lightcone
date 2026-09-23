# IPv6 observation boundary regression

The source world and local diagnostic pack were not changed or resealed. The
observer was corrected so an IPv6 Neighbor Discovery message with a hop limit
other than 255 yields zero seeds, and an extension chain that still points to
another header after its declared payload ends yields zero seeds. Neighbor
Discovery Code and minimum fixed-message length are also checked before
admission. A Hop-by-Hop Options header after the first extension is rejected.
The parser now walks each recognized extension until a terminal Next Header
instead of stopping after an arbitrary count of eight.

These checks implement bounded parts of [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
and [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html). They do not
constitute complete IPv6 or Neighbor Discovery validation. The remaining
address, option, and unsupported-extension semantics are open in the coverage
ledger.

## Replayed evidence

- Frozen manifest SHA-256: `3fc50f2a13296815e60b5442524f14f39f39672ce3047554b761688440b68195`.
- Unchanged input PCAP SHA-256: `6eb6db053c6635a7e9571a6de84205340d2fc40a256c8b60eb91a0b530753502`.
- Unchanged world pack SHA-256: `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
- Observer source SHA-256: `371f218f3d1c68b3cb175a1d902e298a77f8adad37753f9cf494072eb2ae2437`.
- New event log SHA-256: `b900091f73eea718cd97eb32de3fb008df0b9e79c52cc2e6979bca93bd9ea80b`.
- New summary SHA-256: `09244cdc5c14e05bd6ba6ba4126b776c3605e989f35d8f7c8dbf5003327be79c`.
- New evaluated results SHA-256: `13890608b4a409bb56c244bc6d3daac158dab30499aae30832da58d3c6c05f95`.

The previous replay admitted context for 14 of 27 frames and returned an empty
neighborhood for 13. The same frames through the corrected observer admitted
context for 12 and returned empty for 15. Specifically,
`ndp-hop-limit-64` now has reason `ndp_hop_limit_invalid` and zero seeds;
`ipv6-extension-depth` now has reason `ipv6_extension_short_header` and zero
seeds. The valid Neighbor Solicitation control still admits context. The
predeclared expectation count improved from 23/27 to 25/27. The two remaining
failures are the missing direct DNS observation and a valid VLAN-tagged frame
that the observer does not yet recognize.

Verification: `cargo test --workspace --offline` passed (4 Lightcone runtime
tests, 10 observer tests), and `python3 network-lightcone/tools/verify.py`
reported a valid local diagnostic pack with `sealed=false`. The new replay
completed offline without transmitting frames. Detailed logs remain under
`artifacts/logs/adversarial-v1-ipv6-regression-20260923/`; evaluated results
are under `artifacts/experiments/adversarial-v1-results-ipv6-regression-20260923/`.

This is a repair of two measured IPv6 false admissions, not proof that all
IPv6 probes are excluded. Valid observed fields that share represented IPv6
causal symbols can still admit a neighborhood. No packet decision or host
enforcement is implied.
