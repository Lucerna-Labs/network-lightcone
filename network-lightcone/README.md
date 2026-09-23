# Network Lightcone

This is a passive causal-geometry defense component. It admits exact structural
network and host-context symbols into a bounded typed graph and emits a
reproducible receipt. The host owns any policy decision or packet action.

## Revision 4

Revision 4 contains:

- 208 source-bound concepts and 188 typed relationships;
- 29 pinned protocol and defensive-guidance sources;
- Ethernet, ARP, IPv4, IPv6, ICMPv4, ICMPv6, Neighbor Discovery, UDP, TCP,
  QUIC, NAT, DNS, DNSSEC, DHCP, TLS, HTTP, SSH, NTP, SNMP, IPsec, BGP, OSPF
  and multicast context;
- firewall, segmentation, source validation, egress, telemetry, identity,
  configuration and host-policy prerequisites;
- 99 training edges, 25 validation edges, 22 sealed-test edges, 24 fresh
  cross-composition edges and 18 retained regression edges; and
- 48D authoritative geometry plus an observer-only train-fitted spatial
  `(x,y,z,w)` projection.

Every relation has a relation-specific warrant, scoped conditions, exceptions
and source IDs. The authoring and compiler gates reject endpoint-statement
concatenation, duplicate evidence, isolated nodes, split leakage, forbidden
rights, missing provenance, polarity errors and insufficient held-out
populations.

Named probes, attacks and behavior shapes are excluded from the authored and
compiled world. They live only in the separate synthetic challenge corpus.
Unknown observations with no represented seed admit nothing. A probe sharing a
legitimate protocol symbol can enter that protocol neighborhood; the receipt
does not convert the overlap into authorization.

## Current evidence

The active pack is `worlds/v4-local-rtx-diagnostic`. It was trained locally on
an NVIDIA GeForce RTX 5070 Ti with JAX 0.11.2 and passed every predeclared local
gate:

- validation: 25 edges, 0.965 mean pairwise ranking, 0.76 top-10;
- sealed-test: 22 edges, 0.907 mean pairwise ranking, 0.545 top-10;
- cross-composition: 24 edges, 0.874 mean pairwise ranking, 0.583 top-10;
- every fresh held-out relation exceeded the 0.20 individual pairwise floor;
- full geometry was finite; and
- the spatial observer was orthonormal, non-expansive and at least as faithful
  as the registered random-basis placebo.

Three earlier revision-4 local attempts are retained under `receipts/failed-*`.
Their failed gates were not hidden or weakened.

This status is `locally_validated`. It is not Kaggle TPU acceptance and is not a
seal. `coverage.json` keeps production effectiveness, long-duration external
evaluation and remaining protocol coverage open.

## Reproduce and verify

Author the canonical world and verify the pinned public source hashes:

```sh
python3 network-lightcone/tools/author_world_v4.py --verify-sources
```

Run an unsealed local diagnostic in an environment with NumPy and JAX:

```sh
LIGHTCONE_SOURCE_REVISION=standalone-v4-draft \
LIGHTCONE_SOURCE_DIRTY=true \
LIGHTCONE_JOB=local-v4-diagnostic \
python3 network-lightcone/tools/train.py \
  --world network-lightcone/sources/world.json \
  --out target/network-lightcone/v4-local-diagnostic
```

Finalize only as a diagnostic:

```sh
python3 network-lightcone/tools/finalize.py \
  --world network-lightcone/sources/world.json \
  --training target/network-lightcone/v4-local-diagnostic \
  --out network-lightcone/worlds/NEW_DIAGNOSTIC_VERSION \
  --kernel kernel-lightcone/src \
  --diagnostic
```

Verify the pack, exact runtime, observation boundary and structural challenge:

```sh
python3 network-lightcone/tools/verify.py
cargo test --workspace --offline
python3 network-lightcone/tests/evaluate_defense_challenges.py
```

The default finalizer still requires real TPU evidence when `--diagnostic` is
absent. A future TPU result will remain accelerator evidence only until the
coverage and production-effectiveness gates are closed and a separate seal is
explicitly authorized.
