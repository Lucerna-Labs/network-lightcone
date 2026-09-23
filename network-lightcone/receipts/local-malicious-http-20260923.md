# Real isolated malicious-behavior admission test

This test answered whether malicious behavior can admit context in the current
unsealed Network Lightcone. It used a disposable two-namespace veth lab with
transmit checksum offload disabled on both ends. The service contained only a
fake public file and a fake secret. No external host, real account, credential,
or user data was touched. The Lightcone world and runtime were unchanged; the
attack harness and capture remain evaluation-only, outside training inputs.

The plan was written before sending the requests. A benign GET retrieved the
public file. A direct request for the secret returned 404. An intentionally
vulnerable file endpoint then accepted a traversal request and returned the
fake secret. A subsequent POST transferred that exact fake value to a second
local collector endpoint, which recorded receiving it. Thus this was an
actual unauthorized read and follow-up transfer within the disposable lab,
not merely anomalous TCP flags or harmless request text.

The real Ethernet capture contained 52 frames with zero capture drops. The
actual observer and passive Rust Lightcone admitted a neighborhood for all 52.
The hash-bound evaluator located the important application-data frames:

| Captured frame | Lab event | Direct observation | Admission |
| ---: | --- | --- | --- |
| 8 | Benign public-file request | TCP ACK + payload | Context admitted |
| 18 | Direct secret request, denied by service | TCP ACK + payload | Context admitted |
| 28 | Unauthorized traversal request | TCP ACK + payload | Context admitted |
| 30 | Response carrying the fake secret | TCP ACK + payload | Context admitted |
| 38 | POST transferring fake secret to collector | TCP ACK + payload | Context admitted |

Each of those five packets had the **same direct seed set and the same
56-node admitted topology**, whose node/edge identity hash was
`8506a80341cefb057ba118b570a61701b21b49c49fc2ce2a857860f48d1cd699`.
Only the full frame and receipt hashes differed. This establishes that the
current wire observer reduced all five payloads to generic represented TCP
context; it did not expose the unauthorized path, fake secret, or local
transfer as distinct validated symbols. The Lightcone therefore could not
distinguish this malicious lab behavior from the benign request at its
current observation boundary. It did not prevent or block any packet; it is
passive causal admission, not enforcement.

## Integrity

| Artifact | SHA-256 |
| --- | --- |
| Local lab harness | `9bac3336a97a6bdf27f9d47a64343c4ae7ca572195584a47753abc571e449b1b` |
| Hash-checking evaluator | `ab74187fb579b1b06c75a88a2904c76d5a1195546d5cdaf904efaf30fd71d626` |
| Frozen-before-attack plan | `d3ce363a78622fae5c2e5575a8bfbe83b198dfee103ccaddd9316b9dee75bee4` |
| Actual veth PCAP | `a6e6459442e8b073870de6517f924887fb9fb712827d573e99ff3ced1a87c751` |
| Local service result | `641dd60efa711e2b21e927e8b2e7b12e760ab599e17f55561474f853db002e9e` |
| Lightcone JSONL events | `0faf0426ba2f54fb3e53d5e44b4b2233d64d77c5ef9d586a6115a1dcd0f4aa33` |
| Lightcone summary | `839ced07e6834760c8ed59d4e623e3b9d5e0d082e1d19b2b300d568663c72d0f` |
| Evaluated results | `f98d405598e8576d9d0d0dfd12ef46dfc9b483690402d0378c4ca71eedba609f` |
| Unchanged world pack | `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf` |

Generated PCAP and service evidence are under
`artifacts/experiments/local-malicious-http-20260923/`; the detailed
payload-free Lightcone log is under
`artifacts/logs/local-malicious-http-20260923/`; evaluated frame mappings are
under `artifacts/experiments/local-malicious-http-results-verified-20260923/`.
The disposable interfaces and processes were gone after the run. The active
pack remains `local_diagnostic`, `sealed=false`.

To reproduce with new output directories, run
`unshare -Urn python3 network-replay/experiments/local_malicious_http.py --out <capture-dir>`,
then `cargo run -p network-lightcone-replay --offline -- --input <capture-dir>/capture.pcap --out <replay-dir>`,
then `python3 network-replay/experiments/evaluate_local_malicious_http.py --capture <capture-dir> --replay <replay-dir> --out <results-dir>`.

This is one contained attack chain against an intentionally vulnerable toy
service, not a population estimate or proof about every malicious packet.
The observed limitation belongs to the application/host observation boundary:
any future extension must keep attack examples out of the positive training
world and retain passive Lightcone admission semantics.
