# Real local TCP sequence through the unsealed Network Lightcone

The test transmitted TCP packets only to `127.0.0.1` inside a disposable
`unshare -Urn` user/network namespace. No external host was contacted. A local
listener supplied an open-port control; a separate unbound port supplied a
closed-port control. `tcpdump` captured the real loopback packets as classic
Ethernet PCAP, then the existing `network-lightcone-replay` processed that
unaltered capture through the actual structural observer and Rust Lightcone.
The challenge and capture remain outside authored and compiled training worlds.
The world pack remained `local_diagnostic`, `sealed=false`.

The harness wrote its plan before transmission. It sent a raw SYN from source
port 42000 to the local open port, followed on that same tuple by an ACK with
36 application-like bytes, then FIN+ACK, then an intentionally bad-checksum
ACK. The local TCP stack answered the out-of-state follow-ups with resets. A
separate ordinary socket completed a connection, exchanged a request and
response, and closed. This is a bounded continuation test, not a claim to
represent every attacker continuation.

| Captured frame | Observation | Lightcone admission |
| --- | --- | --- |
| 3: raw SYN | `tcp_syn` direct seed | Context admitted; 59 nodes |
| 6: out-of-state ACK with data | `tcp_ack` and `tcp_payload` direct seeds | Context admitted; 56 nodes |
| 8: out-of-state FIN+ACK | `tcp_fin` and `tcp_ack` direct seeds | Context admitted; 59 nodes |
| 10: deliberately incorrect-checksum ACK | zero direct seeds | Empty neighborhood |

Therefore admitting the SYN did not confer any continuing permission, but
the current observer independently admitted the later valid-checksum ACK/data
and FIN packets. It checks each packet's wire structure; it does not verify
TCP sequence numbers against an established connection. The local TCP stack
rejected those out-of-state packets, while the passive Lightcone still emitted
causal context. This is the answer to the requested follow-up test: the
Lightcone **did not exclude** these follow-up packets.

## Capture caveat

The ordinary socket connection actually completed and exchanged data, but
its ten captured packets (frames 11–20) all had TCP checksum fields that
`tcpdump` marked incorrect. The replay observer therefore returned empty
neighborhoods for them. The loopback interface reported generic transmit
checksum offload enabled and fixed on; this is consistent with pre-finalized
checksums in a local capture. The empties cannot be interpreted as successful
probe filtering or as evidence that legitimate TCP failed on the wire.
The intentionally corrupted raw ACK in frame 10 is a separate negative
control with a known invalid checksum. A future trusted capture adapter must
handle checksum-offload metadata without simply accepting arbitrary bad
checksums. [Wireshark's capture guidance](https://wiki.wireshark.org/CaptureSetup/Offloading)
describes this class of pre-transmission capture artifact.

## Integrity and preservation

| Artifact | SHA-256 |
| --- | --- |
| Test harness source | `5c23b20a2f066e3857f4fb5dfb6c26c5f3f34ca3a47fe08f90adba3f80a6566f` |
| Frozen-before-transmission plan | `ead32cf4f20e03a7f38ac749acdfa12305954f8db527b338bce9b5dcc60a8955` |
| Captured PCAP | `438060e9cf35ec0294b63936ae21918e7b5afc1f31be2f55d766d25888151c23` |
| Replay JSONL events | `ba1450b2334c040bc49e5f958afea528e036138f8f455f910fdb5eb60367c70d` |
| Replay summary | `d76563bf7a0cced9a05c84f7edb2aa893c983ca6ad8fba2749fe7928599330ed` |
| Unchanged world pack | `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf` |

The final capture is under
`artifacts/experiments/live-tcp-sequence-accepted-v2-20260923/`; detailed
Lightcone events are under
`artifacts/logs/live-tcp-sequence-accepted-v2-20260923/`. Earlier attempts
that failed to finalize or flush capture are preserved under separate names
and were not used for the conclusion. The verified capture contains 20 frames
with no reported capture drops; replay completed with 7 context admissions
and 13 empty neighborhoods. Those aggregate counts mix raw packets with
pre-offload ordinary packets and must not be treated as an effectiveness rate.
