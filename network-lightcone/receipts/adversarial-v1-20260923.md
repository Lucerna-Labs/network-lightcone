# Adversarial network replay: findings

This was an isolated synthetic raw-frame test of the standalone Network
Lightcone. The generator produced a classic Ethernet PCAP before replay, and
the real structural observer and Rust Lightcone processed its 27 frames. No
packet was sent to a network. No host policy permitted or blocked traffic.

The unsealed diagnostic pack was
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
The frozen challenge manifest was
`3fc50f2a13296815e60b5442524f14f39f39672ce3047554b761688440b68195`;
the input PCAP was
`6eb6db053c6635a7e9571a6de84205340d2fc40a256c8b60eb91a0b530753502`;
the detailed event log was
`e3edc09cc4f862368b5eedf12c63313a0c62e86ed63560c82b52f874efeb6a86`.
The machine-readable results were
`8ab496135b7e600299a3bc67f1e163df38d81e9bd694408e95274410845acb56`.
The replay summary binds those hashes and records `sealed=false`.

## Outcomes

| Group | Cases | Result |
| --- | ---: | --- |
| Structurally malformed or unsupported | 12 | 12 produced empty causal neighborhoods. |
| Valid shared-shape probe-like inputs | 8 | All 8 entered represented protocol context, as expected. |
| Semantically invalid IPv6 inputs | 2 | Both entered context despite predeclared expectations of no admission. |
| Benign controls | 5 | Four entered context; one valid tagged frame was excluded. One admitted DNS query lacked a direct DNS seed. |

Across all categories, 23 of 27 predeclared observations matched and four did
not. An empty neighborhood is **not** a packet drop or a prevented attack.

### Techniques that failed to obtain context

Bad IPv4, UDP, TCP, ICMPv4 and ICMPv6 checksums; inconsistent IPv4 and UDP
lengths; a short Ethernet frame; an unsupported EtherType; an unknown ARP
operation; a truncated IPv6 extension; and an IPv6 UDP packet with a zero
checksum all produced zero direct seeds and zero admitted nodes. These are
real observer-to-runtime replay results, not preassigned seed lists.

The IPv6 UDP zero-checksum case tests the default protocol path. [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.txt)
permits explicitly configured tunnel exceptions, which this observer does
not model; treating every zero-checksum packet as malicious would create a
coverage error in such an environment.

### Inputs that entered shared causal context

A TCP SYN to another destination port, a repeated ICMP Echo Request, UDP
payload text naming an authority node, an ARP sender claim, an IPv4 packet
with an unrepresented transport number, an unrepresented ICMPv6 type, an IPv4
fragment, and a TCP SYN+FIN combination all returned nonempty causal
neighborhoods. That is expected whenever valid observed fields share nodes
already represented in the world. None received an authorization verdict.

The UDP payload text did not inject `authorized_flow` or `policy_decision` as
direct seeds. Its direct seed set matched the benign UDP control. This
technique failed to select nodes through payload words.

## Four failed expectations

| Case | Expected | Observed | Owner |
| --- | --- | --- | --- |
| `benign-dns-udp` | Direct `dns_query` seed | Only IPv4 and UDP structural seeds; 50 nodes admitted | Missing bounded DNS observation adapter |
| `benign-vlan-ipv4` | Valid tagged IPv4 context | Unknown EtherType; empty neighborhood | Missing 802.1Q link parser |
| `ndp-hop-limit-64` | Reject invalid Neighbor Solicitation | `icmpv6_valid`, ten seeds, 18 nodes admitted | Neighbor Discovery validation; [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.txt) requires hop limit 255 |
| `ipv6-extension-depth` | Stop on unresolved extension chain | Generic IPv6 context admitted with seven seeds and 11 nodes | IPv6 extension-chain completion check |

## Important context boundary

Nine IPv4 cases admitted an `export` node into the neighborhood. For the
benign UDP frame the shortest path was:

```text
udp --describes (+1)--> opaque --does_not_establish (-1)--> export
```

This is a *negative* relation, not an export permission. The runtime's edge
selection currently filters relation type and polarity; it serializes edge
conditions and exceptions but does not evaluate them against host identity,
service, session or policy state. A downstream consumer must not turn a node
name or graph membership into authority. The host enforcement layer is still
an open project boundary.

## Priorities before effectiveness claims

1. Validate Neighbor Discovery hop limits and complete IPv6 extension chains
   before emitting protocol-specific seeds; preserve these failures as
   regression fixtures.
2. Ensure any receipt consumer respects negative polarity, conditions and
   separate host authorization. Keep the Lightcone passive.
3. Add 802.1Q parsing and a bounded DNS parser or explicit host-validated DNS
   context, then retest legitimate false exclusions.
4. Evaluate an independent, labeled traffic corpus with matched legitimate
   lookalikes. Compare a host policy with and without Lightcone context in an
   isolated network before estimating attack reduction or false block rates.

The sample p95 runtime admission time was 398 microseconds; p95 total replay
processing, including full JSON explanations, was 2,858 microseconds. Twenty-
seven synthetic frames do not establish throughput or long-duration
reliability. The pack remains `local_diagnostic` and unsealed.
