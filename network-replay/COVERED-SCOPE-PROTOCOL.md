# C01 — test the currently covered scope

Frozen before executing the new cases, 2026-10-01. Test the copied project only;
do not retrain, change runtime behavior, repair world contents, or seal anything.
Preserve the original checkout and existing failures. Local CPU diagnostics only.

## Boundaries

Wire coverage: ordinary Ethernet/ARP; IPv4/IPv6 framing and supported extension
chains; UDP/TCP structural headers and checksums; ICMPv4 types already mapped;
ICMPv6 generic/error context; supported RS/RA/NS/NA structural validation;
fragment context without reassembly. Test only the already supported portions of
these mechanisms. Also check malformed/unrepresented input boundaries.

DNS semantic decoding, VLAN, full NDP option semantics/Redirect, arbitrary IPv6
extension semantics, TCP connection-state tracking, payload/application parsing,
identity/authorization decisions and host enforcement remain outside the wire
score. This boundary comes from coverage.json and the observer, not from deleting
new failed results. Higher-layer concepts still get native catalog-query tests
when supplied as explicitly trusted host symbols; those are not wire recognition.

## Fresh packet cases

Author a new standard-library packet corpus and freeze frame hashes and expected
results before replay. Use three declared variants of ports, payload length,
addresses/lifetime where appropriate. Do not obtain expectations from runtime
outputs. Keep corpus/expectations in ignored experiment artifacts, outside worlds.
Use RFC 768/791/792/826/4443/4861/8200/9293 for protocol field/checksum expectations.

Positive forms: ARP request/reply; IPv4 UDP with/without checksum, optional zero
source port, IPv4 options; IPv6 UDP including valid extension chains; IPv4 and
IPv6 TCP SYN/ACK/data/FIN/RST; ICMPv4 echo request/reply, unreachable and expired;
ICMPv6 error and generic informational context; RS/RA/NS/NA; IPv4/IPv6 fragments;
IP framing with an unrepresented upper-layer protocol.

Negative forms: bad IP/transport/ICMP checksums, invalid lengths, invalid TCP
header size, prohibited IPv6 UDP zero checksum, invalid supported NDP hop-limit/
code/source/target/option-length cases, malformed extension chains, short Ethernet
and an unknown EtherType. Fragment observations must not invent complete transport
seeds. Payload/port changes must not create host-authority or application seeds.

## Assertions and useful context

Check exact expected direct seed sets, observation kinds and stable parser
reasons; malformed/unrepresented frames with no seeds must yield empty context.
For represented observations, require the applicable sourced relation:
ARP mapping/non-identity, UDP delivery limits and checksum/non-checksum evidence,
TCP sequence/state/non-identity prerequisites, ICMP association/quote, IPv6
reassembly, and NDP neighbor/cache/DAD relationships. Check relation polarity and
evidence metadata; mere presence of a node is not an asserted consequence.

Source inspection exposed a specific covered-scope concern: generic UDP/TCP
relations e014/e019/e039 express IPv4-specific prerequisites without an explicit
IPv4-only guard, while IPv6 is supported. Predeclare a separate semantic-scope
gate: an IPv6-only transport observation must not expose those as unqualified
requirements. Their presence is a context correctness failure even if seed and
graph-execution tests pass. Do not repair the world during this evaluation.

Compare required relation retrieval with direct-seeds-only (no expanded edges)
and the full 188-edge catalog. Report required-evidence recall and context size;
this measures availability of scoped evidence, not LLM answers or prevented harm.

## Native catalog boundary

Exercise all 208 represented node IDs through the real Rust host-symbol/admission
API under the active policy. Save trace steps and receipts, and compare membership,
caps/frontiers, edges and hashes against the independent verifier/source graph.
Include empty input, invalid node indices and invalid policy. This establishes
mechanical access to represented knowledge, not truth of all 208 records.
Independently re-run existing pack/ranking verification; report its exact scope.

## Fresh live covered traffic

Use only a disposable user/network namespace and a private veth peer namespace.
Configure IPv4/IPv6 addresses, disable TX checksum offload on those two virtual
interfaces, save the settings, and capture complete Ethernet frames. No changes
to host interfaces, routes, firewall or unrelated services.

Run known-payload TCP and UDP echo exchanges over IPv4 and IPv6 plus ICMP echo
in both families. Capture ARP/NDP resolution naturally. Freeze the test plan before
transmission and verify each application exchange separately. Independently check
captured IP/transport checksums before using the capture as a wire-validity test;
never rewrite captured bytes to make checksums pass. Replay with full logs.

## Acceptance

- 100% declared wire seed/kind/reason expectations and zero false authority seeds.
- 100% selected required-relation recall and source/polarity retention, with
  median returned context smaller than the full catalog. Report semantic-scope
  violations independently; do not label overall context correctness green if
  the IPv6 prerequisite gate fails.
- All 208 valid native queries and explicit error/empty controls behave as
  specified and their traces/receipts verify.
- Live application echoes/pings succeed; capture reports zero kernel drops;
  independently verified well-formed covered frames have expected direct seeds
  and are not rejected as malformed. Capture-boundary failures stay visible.
- Input, runtime implementation, world/pack/ledger and original checkout hashes
  remain unchanged by the tests. No production effectiveness or seal claim.

Preserve all failures; fix test-harness defects only with a documented rerun and
unchanged gates/expected protocol outcomes. New evaluated cases become regression
evidence after this run. No post-result threshold tuning or scope narrowing.
