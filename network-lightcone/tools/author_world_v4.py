#!/usr/bin/env python3
"""Author the broad, source-bound network world without attack exemplars."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
AS_OF = "2026-09-23"
SNAPSHOT = "db5f6624ac35ebe040d769511555f41fa2923c14"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "network-lightcone-source-verifier/1.0"},
    )
    return urllib.request.urlopen(request, timeout=30).read()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


RFC_SOURCES = [
    (768, "UDP", "Fields; IP Interface", "7dc8880e1ecef9c3f9da0db4b876a16e96bfa4f0953cc9d977d414f8f680c2f0"),
    (791, "IPv4", "Header format; fragmentation; lifetime", "6cfb387fcecfc1b72f2f69343c5b6951b5d263d708162e2b5c66ab8f394f6265"),
    (792, "ICMPv4", "Echo; errors; redirects", "58714393ded142bacf188d7e8977eef98f4110c4c87ac94595f750df5664c2c6"),
    (826, "ARP", "Packet format; packet reception", "01bc62fe6a37e90f1246ac43e8e145f1322b4ed1474836145c3da93d2bd3c8a6"),
    (1034, "DNS concepts and facilities", "Resolvers; servers; zones; caching", "d6b10a71441df879cc2817d23f2dad120c8a5f87e74eba1e4ed4b743a76a891a"),
    (1035, "DNS implementation and specification", "Messages; names; resource records", "d14ae809fc9b41bbcae26bb38c937c9515808b944f3252b00de9fe0e95f4fdfb"),
    (2131, "DHCP", "Client-server exchanges and leases", "a043b705785b81762505ded4cf71d61392b2b1da2b4ce1e32c13bc984de5f4a5"),
    (2328, "OSPFv2", "Adjacency; LSAs; shortest-path calculation", "981690e297fbba9e8ef655802552b5529cb17f1ffe790ad2d55706cc522ff50c"),
    (3376, "IGMPv3", "Membership reports and source filtering", "0f28032de6034da1e13d85f2a34ff9f2956c0e7bb9ad9dd3be84c7ddcde780ed"),
    (3411, "SNMP management architecture", "Engines; messages; security and access control", "5cae3a3d7ab2013b5ba9e285e3fc3c9001b7ccba8fafda48bd04b04e0e366016"),
    (3704, "Ingress filtering", "Source-address validation", "79aadfe01455bcb96b1663b0bd299c93649f12e623e20105ee0810839a128f89"),
    (4033, "DNSSEC introduction and requirements", "Authenticity and authenticated denial", "b6803149a879dff56cbaffcb8c5a1795d2a2d2facdc3400ebd9937e38724e4cd"),
    (4253, "SSH transport layer", "Key exchange; server authentication; integrity", "b471173305154f6c66facffcf7a4a25fc5c32765cb30542120be6c20a88f1ed3"),
    (4271, "BGP-4", "Sessions; UPDATE messages; route selection inputs", "98b851146abcd56ecbb398dd1a818bcde2dcac6fde3d901c423d988f86eaab76"),
    (4301, "IPsec architecture", "Policy; security associations; packet processing", "a2411e90515f59665e1059b1bb66d8123bd9e384ccfc8b7ccca65db85d5d7736"),
    (4443, "ICMPv6", "Errors; informational messages; checksum", "f20d1de8878e1142000bfeaa3ad1b0540fab7653a395cf7b07e81d2da2f650bf"),
    (4787, "NAT UDP requirements", "Mappings; filtering; timers", "5db82ec5f0d6b9b0fc0a37ce7d5b40592e4e6f41562ba8fbc55f1daa52648405"),
    (4861, "IPv6 Neighbor Discovery", "Neighbor and router discovery; reachability", "1a4309c117d765a7c0edfcb2297fc90c3c09f0fcae255f15e53b20748bcc09fb"),
    (5424, "Syslog protocol", "Structured event messages", "24d91f90a05d2536730ada929c296f45ae9cd72226e22b6775ad8c04cae37a53"),
    (5905, "NTPv4", "Clock selection and synchronization", "8b7abd903c60202e2953ee012fefa6916666c3b0c71825c748cdd262024fb268"),
    (8200, "IPv6", "Header; extension headers; fragmentation", "371ae3f133d562db5d6385e6def4ca9914c4f831be228ea7779fd28799c2f490"),
    (8201, "IPv6 path MTU discovery", "Packet Too Big and path MTU state", "96c2ea7ac1bf5810f6b817d4ac372a35f68231d2bd0e2675740f1268eb9ac752"),
    (8446, "TLS 1.3", "Handshake; certificates; key schedule; records", "47871bc8820a2c3b6ea89f061055577058862cf543686b82d10131239702b3bd"),
    (9000, "QUIC", "Connections; packet numbers; streams; migration", "f88aae47f8b18e102024916e975e919201d8dde689cba79b01079eaedd402e22"),
    (9110, "HTTP semantics", "Requests; responses; methods; authority", "21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a"),
    (9293, "TCP", "Header; state; sequencing; flow control", "6d9ac8be4b0286f8c3d337addf442b2eb6a9b14e1366594ea7fbc273f93dc2d9"),
]

NIST_SOURCES = [
    (
        "nist80041",
        "Guidelines on Firewalls and Firewall Policy",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf",
        "NIST SP 800-41 Rev. 1",
        "Policy, filtering, segmentation, logging and administration",
        "06642409a8f0dcc9de8725f2d76d6feedea2d4d1faa860c2ee18488863dd1f4f",
    ),
    (
        "nist800207",
        "Zero Trust Architecture",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf",
        "NIST SP 800-207",
        "Identity, policy decision, resource and session context",
        "0290d6ece24874287316f4bf430fef770aa4ec08a2227c8f2c1e5b2ff975e03d",
    ),
]


NODE_ROWS = r"""
ipv6|rfc8200|IPv6 packet|An IPv6 packet carries fixed header fields followed by extension headers or an upper-layer payload.|source_grounded_mechanism|mechanism
ipv6_payload_length|rfc8200|IPv6 payload length|The IPv6 payload length covers bytes following the fixed header subject to the standard jumbo-payload exception.|source_grounded_mechanism|invariant
ipv6_next_header|rfc8200|IPv6 next-header chain|Each IPv6 next-header value identifies the following extension header or upper-layer protocol.|source_grounded_mechanism|mechanism
ipv6_hop_limit|rfc8200|IPv6 hop limit|Each forwarding node decrements the IPv6 hop limit and discards a packet when the limit reaches zero.|source_grounded_mechanism|boundary
ipv6_extension|rfc8200|IPv6 extension header|IPv6 extension headers carry optional internet-layer information in a declared chain.|source_grounded_mechanism|mechanism
ipv6_fragment|rfc8200|IPv6 fragment header|An IPv6 source uses a fragment header when source fragmentation is required.|source_grounded_mechanism|mechanism
ipv6_reassembly|rfc8200|IPv6 reassembly|A destination reassembles matching IPv6 fragments before interpreting a complete upper-layer message.|source_grounded_mechanism|mechanism
ipv6_source|rfc8200|IPv6 source field|The IPv6 source field carries the address claimed as the packet source.|source_grounded_mechanism|representation
ipv6_destination|rfc8200|IPv6 destination field|The IPv6 destination field identifies the intended packet destination or next routing destination.|source_grounded_mechanism|representation
ipv6_not_identity|rfc8200|IPv6 identity claim|Claim that an IPv6 source address alone authenticates the sender.|unsupported_inference|unsupported_claim
icmpv6|rfc4443|ICMPv6 message|ICMPv6 reports IPv6 errors and carries informational control messages.|source_grounded_mechanism|mechanism
icmpv6_checksum|rfc4443|ICMPv6 checksum|The ICMPv6 checksum covers the message and an IPv6 pseudo-header.|source_grounded_mechanism|invariant
icmpv6_error|rfc4443|ICMPv6 error|An ICMPv6 error includes enough invoking-packet context for the receiver to associate the report.|source_grounded_mechanism|mechanism
ndp|rfc4861|Neighbor Discovery|IPv6 Neighbor Discovery supports router discovery, prefix discovery, address resolution and reachability information.|source_grounded_mechanism|mechanism
neighbor_solicitation|rfc4861|Neighbor Solicitation|A Neighbor Solicitation requests link-layer or reachability information for a target IPv6 address.|source_grounded_mechanism|mechanism
neighbor_advertisement|rfc4861|Neighbor Advertisement|A Neighbor Advertisement supplies target link-layer or reachability information under Neighbor Discovery rules.|source_grounded_mechanism|mechanism
router_solicitation|rfc4861|Router Solicitation|A Router Solicitation asks local routers to provide advertisements sooner than their periodic schedule.|source_grounded_mechanism|mechanism
router_advertisement|rfc4861|Router Advertisement|A Router Advertisement supplies router, prefix and configuration information for the local link.|source_grounded_mechanism|mechanism
duplicate_address_detection|rfc4861|Duplicate-address detection|Neighbor Solicitation and Advertisement exchanges help determine whether a tentative IPv6 address is already in use.|source_grounded_mechanism|boundary
neighbor_cache|rfc4861|Neighbor cache|A neighbor cache retains reachability and link-layer information with explicit state transitions.|source_grounded_mechanism|state
ndp_option|rfc4861|Neighbor Discovery option|Neighbor Discovery options carry bounded link-layer, prefix, MTU or redirected-header information.|source_grounded_mechanism|representation
ndp_not_identity|rfc4861|Neighbor Discovery identity claim|Claim that an unauthenticated Neighbor Discovery message proves peer identity or authority.|unsupported_inference|unsupported_claim
path_mtu_discovery|rfc8201|IPv6 path MTU discovery|IPv6 path MTU discovery uses Packet Too Big information to maintain a usable packet-size estimate.|source_grounded_mechanism|mechanism
path_mtu_state|rfc8201|Path MTU state|Path MTU information is scoped to a path and may require expiry or revalidation as the path changes.|source_grounded_mechanism|state
dns|rfc1034,rfc1035|Domain Name System|DNS maps names through distributed zones, resolvers, servers and typed resource records.|source_grounded_mechanism|mechanism
dns_query|rfc1035|DNS query|A DNS query names a question and its requested resource-record type and class.|source_grounded_mechanism|mechanism
dns_response|rfc1035|DNS response|A DNS response carries answer, authority and additional sections tied to the query context.|source_grounded_mechanism|mechanism
dns_name|rfc1034,rfc1035|DNS name|A DNS name is a sequence of labels interpreted within the DNS namespace.|source_grounded_mechanism|representation
dns_referral|rfc1034|DNS referral|A referral directs resolution toward servers authoritative for a delegated namespace.|source_grounded_mechanism|mechanism
dns_cache|rfc1034|DNS cache|A resolver may cache resource records for bounded reuse.|source_grounded_mechanism|state
dns_ttl|rfc1035|DNS time to live|A DNS TTL bounds how long a cached resource record may be reused without refresh.|source_grounded_mechanism|boundary
dns_recursive|rfc1034|Recursive resolution|A recursive resolver follows resolution dependencies on behalf of a client.|source_grounded_mechanism|mechanism
dns_authoritative|rfc1034|Authoritative DNS data|An authoritative server answers from zone data for which it has authority.|source_grounded_mechanism|mechanism
dns_not_identity|rfc1034,rfc1035|DNS identity claim|Claim that an unsigned DNS answer alone authenticates the endpoint named by the answer.|unsupported_inference|unsupported_claim
dnssec|rfc4033|DNSSEC|DNSSEC adds origin authentication and integrity protection for DNS data using signed records and a validation chain.|source_grounded_mechanism|mechanism
dnssec_signature|rfc4033|DNSSEC signature|A DNSSEC signature binds covered DNS data to a signing key for a validity interval.|source_grounded_mechanism|invariant
dnssec_chain|rfc4033|DNSSEC chain of trust|A DNSSEC validator follows authenticated delegations from a configured trust anchor.|source_grounded_mechanism|mechanism
dnssec_validation|rfc4033,rfc1035|DNSSEC validation state|DNSSEC validation distinguishes secure, insecure, bogus and indeterminate outcomes for DNS record sets under local policy.|source_grounded_mechanism|state
dnssec_authenticated_denial|rfc4033|DNSSEC authenticated denial|DNSSEC authenticated-denial records can provide signed evidence that a queried name or type does not exist.|source_grounded_mechanism|mechanism
dns_negative_response|rfc1035|DNS negative response|A DNS negative response reports that a requested name or record type was not found in the responding authority context.|source_grounded_mechanism|representation
dhcp|rfc2131|DHCP|DHCP coordinates configuration parameters and address leases between clients and servers.|source_grounded_mechanism|mechanism
dhcp_discover|rfc2131|DHCP Discover|A DHCP client broadcasts a discovery message when seeking available configuration service.|source_grounded_mechanism|mechanism
dhcp_offer|rfc2131|DHCP Offer|A DHCP server may offer configuration and a proposed address lease in response to discovery.|source_grounded_mechanism|mechanism
dhcp_request|rfc2131|DHCP Request|A DHCP request identifies the client's selected offer or requests continuation of an existing lease.|source_grounded_mechanism|mechanism
dhcp_ack|rfc2131|DHCP acknowledgment|A DHCP acknowledgment confirms configuration parameters and lease timing.|source_grounded_mechanism|mechanism
dhcp_lease|rfc2131|DHCP lease|A DHCP lease grants bounded use of an address subject to renewal, rebinding and expiry.|source_grounded_mechanism|state
dhcp_server_identity|rfc2131|DHCP server identity field|The DHCP server-identifier option distinguishes the selected server within the exchange.|source_grounded_mechanism|representation
dhcp_not_identity|rfc2131|DHCP authority claim|Claim that an unauthenticated DHCP offer alone establishes trusted configuration authority.|unsupported_inference|unsupported_claim
tls|rfc8446|TLS 1.3 connection|TLS 1.3 establishes protected records after a negotiated handshake and key schedule.|source_grounded_mechanism|mechanism
tls_client_hello|rfc8446|TLS ClientHello|A TLS ClientHello proposes protocol parameters, key shares and extensions.|source_grounded_mechanism|mechanism
tls_server_hello|rfc8446|TLS ServerHello|A TLS ServerHello selects negotiated parameters and contributes key-establishment material.|source_grounded_mechanism|mechanism
tls_handshake|rfc8446|TLS handshake transcript|TLS handshake messages form a transcript bound into key derivation and Finished verification.|source_grounded_mechanism|invariant
tls_certificate|rfc8446|TLS certificate message|A TLS certificate message conveys the peer certificate chain when certificate authentication is used.|source_grounded_mechanism|representation
tls_chain|rfc8446|Certificate chain validation|Certificate authentication depends on path validation, trust anchors, validity and usage constraints supplied by the host.|source_grounded_mechanism|mechanism
tls_name_validation|rfc8446|TLS service-name validation|A host validates that authenticated certificate identity matches the intended service name under its policy.|source_grounded_mechanism|boundary
tls_key_schedule|rfc8446|TLS key schedule|The TLS 1.3 key schedule derives traffic secrets from negotiated inputs and the handshake transcript.|source_grounded_mechanism|mechanism
tls_record|rfc8446|TLS protected record|A TLS record protects typed content with keys for the current traffic epoch.|source_grounded_mechanism|mechanism
tls_integrity|rfc8446|TLS record integrity|Successful record authentication supplies integrity evidence for the protected record and its context.|source_grounded_mechanism|invariant
tls_confidentiality|rfc8446|TLS record confidentiality|TLS record protection encrypts protected content under negotiated traffic keys.|source_grounded_mechanism|mechanism
tls_replay_context|rfc8446|TLS replay context|Replay properties depend on handshake mode, record sequence and application handling, especially for early data.|source_grounded_mechanism|boundary
tls_not_authorization|rfc8446,nist800207|TLS authorization claim|Claim that a valid TLS channel alone authorizes every requested resource or operation.|unsupported_inference|unsupported_claim
quic|rfc9000|QUIC connection|QUIC carries secure multiplexed transport over UDP with connection-level state.|source_grounded_mechanism|mechanism
quic_connection_id|rfc9000|QUIC connection ID|A QUIC connection ID supports routing a connection independently of one network address tuple.|source_grounded_mechanism|representation
quic_packet_number|rfc9000|QUIC packet number|QUIC packet numbers support ordering, acknowledgment and loss detection within a packet-number space.|source_grounded_mechanism|state
quic_tls|rfc9000,rfc8446|QUIC TLS handshake|QUIC uses TLS handshake messages while carrying QUIC transport parameters in the protected negotiation.|source_grounded_mechanism|mechanism
quic_stream|rfc9000|QUIC stream|A QUIC stream is an ordered byte sequence with independent stream state.|source_grounded_mechanism|mechanism
quic_flow_control|rfc9000|QUIC flow control|QUIC limits data at both connection and stream scopes.|source_grounded_mechanism|boundary
quic_migration|rfc9000|QUIC migration|A QUIC connection may continue across a changed peer address after path validation.|source_grounded_mechanism|mechanism
quic_address_validation|rfc9000|QUIC address validation|QUIC address validation provides evidence that a peer can receive packets at a claimed address.|source_grounded_mechanism|mechanism
quic_retry|rfc9000|QUIC Retry|A QUIC server may use Retry to require address validation before committing substantial connection state.|source_grounded_mechanism|mechanism
quic_not_identity|rfc9000|QUIC identity claim|Claim that a QUIC connection ID or validated address alone authenticates the application peer.|unsupported_inference|unsupported_claim
http|rfc9110|HTTP semantics|HTTP defines request and response semantics independently of a particular transport version.|source_grounded_mechanism|mechanism
http_request|rfc9110|HTTP request|An HTTP request combines a method, target, fields and optional content under protocol semantics.|source_grounded_mechanism|mechanism
http_response|rfc9110|HTTP response|An HTTP response carries a status code, fields and optional content tied to a request context.|source_grounded_mechanism|mechanism
http_authority|rfc9110|HTTP authority|The HTTP authority component identifies the origin authority intended by the request.|source_grounded_mechanism|representation
http_method|rfc9110|HTTP method|An HTTP method states the request semantics expected of the target resource.|source_grounded_mechanism|representation
http_status|rfc9110|HTTP status|An HTTP status code communicates the response class and result semantics.|source_grounded_mechanism|representation
http_connection_context|rfc9110|HTTP connection context|HTTP message meaning depends on the selected origin, version, fields and connection context.|source_grounded_mechanism|boundary
http_not_authorization|rfc9110,nist800207|HTTP authorization claim|Claim that a syntactically valid HTTP request is authorized for the target resource.|unsupported_inference|unsupported_claim
ssh_transport|rfc4253|SSH transport|The SSH transport layer negotiates algorithms, exchanges keys and protects a byte stream.|source_grounded_mechanism|mechanism
ssh_key_exchange|rfc4253|SSH key exchange|SSH key exchange establishes shared keys and binds the exchange hash to the session.|source_grounded_mechanism|mechanism
ssh_host_key|rfc4253|SSH host key|SSH server authentication uses a host key whose trust decision belongs to the client policy.|source_grounded_mechanism|mechanism
ssh_encryption|rfc4253|SSH encryption|SSH applies negotiated encryption to transport packets after key activation.|source_grounded_mechanism|mechanism
ssh_integrity|rfc4253|SSH integrity|SSH applies negotiated integrity protection or an authenticated-encryption mode to transport packets.|source_grounded_mechanism|invariant
ssh_session_id|rfc4253|SSH session identifier|The first key-exchange hash becomes a stable identifier for the SSH session.|source_grounded_mechanism|state
ssh_not_authorization|rfc4253,nist800207|SSH authorization claim|Claim that transport authentication alone grants command or resource authorization.|unsupported_inference|unsupported_claim
ntp|rfc5905|NTP association|NTP exchanges timestamped messages and selects clock sources to discipline local time.|source_grounded_mechanism|mechanism
ntp_timestamp|rfc5905|NTP timestamp|NTP timestamps support offset and delay calculations when interpreted in the exchange context.|source_grounded_mechanism|representation
ntp_stratum|rfc5905|NTP stratum|NTP stratum indicates a server's distance from a reference clock within the synchronization hierarchy.|source_grounded_mechanism|representation
ntp_selection|rfc5905|NTP clock selection|NTP selection and clustering compare candidate associations before choosing synchronization sources.|source_grounded_mechanism|mechanism
ntp_freshness|rfc5905|NTP freshness|Clock state and reachability require continuing observations rather than indefinite reuse of one response.|source_grounded_mechanism|boundary
ntp_not_identity|rfc5905|NTP identity claim|Claim that a timestamp or stratum value alone authenticates the time source.|unsupported_inference|unsupported_claim
snmp|rfc3411|SNMP architecture|SNMP separates message processing, security, access control and application behavior.|source_grounded_mechanism|mechanism
snmp_engine|rfc3411|SNMP engine|An SNMP engine coordinates message processing, security and access-control subsystems.|source_grounded_mechanism|mechanism
snmp_message|rfc3411|SNMP message|An SNMP message carries version-specific management data within a message-processing model.|source_grounded_mechanism|representation
snmp_security_model|rfc3411|SNMP security model|An SNMP security model supplies authentication, privacy and timeliness services according to its model.|source_grounded_mechanism|mechanism
snmp_access_control|rfc3411|SNMP access control|SNMP access control decides whether a security principal may perform a management operation on a managed object.|source_grounded_mechanism|mechanism
snmp_not_authorization|rfc3411|SNMP authorization claim|Claim that receipt of an SNMP message alone authorizes the requested management operation.|unsupported_inference|unsupported_claim
ipsec|rfc4301|IPsec architecture|IPsec applies policy-selected security services to IP traffic using security associations.|source_grounded_mechanism|mechanism
security_association|rfc4301|IPsec security association|A security association binds algorithms, keys, identifiers, lifetimes and direction for protected traffic.|source_grounded_mechanism|state
esp|rfc4301|ESP processing|ESP can provide confidentiality, integrity, origin authentication and anti-replay services as configured.|source_grounded_mechanism|mechanism
ah|rfc4301|AH processing|AH can provide connectionless integrity, origin authentication and anti-replay services as configured.|source_grounded_mechanism|mechanism
anti_replay|rfc4301|IPsec anti-replay|IPsec anti-replay state uses sequence numbers and a receiver window when the service is enabled.|source_grounded_mechanism|state
ipsec_policy|rfc4301|IPsec policy|IPsec policy selects whether traffic is discarded, bypassed or protected and identifies applicable security associations.|source_grounded_mechanism|mechanism
ipsec_not_identity|rfc4301|IPsec authorization claim|Claim that an IPsec-protected packet is automatically authorized for every host resource.|unsupported_inference|unsupported_claim
bgp|rfc4271|BGP session|BGP exchanges reachability information between routing speakers over a stateful session.|source_grounded_mechanism|mechanism
bgp_update|rfc4271|BGP UPDATE|A BGP UPDATE announces or withdraws reachable prefixes with path attributes.|source_grounded_mechanism|mechanism
bgp_path|rfc4271|BGP path attributes|BGP path attributes describe properties used by policy and route selection.|source_grounded_mechanism|representation
bgp_policy|rfc4271|BGP routing policy|A BGP implementation applies local policy to accepted and advertised routes.|source_grounded_mechanism|mechanism
bgp_withdrawal|rfc4271|BGP withdrawal|A BGP withdrawal removes previously advertised reachability from consideration.|source_grounded_mechanism|mechanism
bgp_not_authority|rfc4271|BGP authority claim|Claim that receipt of a BGP announcement alone proves authority over the announced prefix.|unsupported_inference|unsupported_claim
ospf|rfc2328|OSPF routing|OSPF distributes link-state information inside one autonomous system.|source_grounded_mechanism|mechanism
ospf_adjacency|rfc2328|OSPF adjacency|OSPF neighbors form adjacencies before synchronizing link-state databases under protocol rules.|source_grounded_mechanism|state
ospf_lsa|rfc2328|OSPF link-state advertisement|An OSPF LSA describes routing topology or reachability information with sequence and age state.|source_grounded_mechanism|representation
ospf_database|rfc2328|OSPF link-state database|Routers in an OSPF area calculate routes from a synchronized link-state database.|source_grounded_mechanism|state
ospf_spf|rfc2328|OSPF shortest-path calculation|OSPF derives a routing tree from the accepted link-state database.|source_grounded_mechanism|mechanism
ospf_not_identity|rfc2328|OSPF authority claim|Claim that an OSPF packet alone establishes a trusted routing peer outside configured authentication and area context.|unsupported_inference|unsupported_claim
nat|rfc4787|NAT mapping behavior|A NAT maps an internal address and port context to an external transport context under implementation policy.|source_grounded_mechanism|mechanism
nat_mapping|rfc4787|NAT mapping|A NAT mapping records the internal and external transport identifiers used for translated traffic.|source_grounded_mechanism|state
nat_filtering|rfc4787|NAT filtering|NAT filtering controls which inbound datagrams may use an existing mapping.|source_grounded_mechanism|mechanism
nat_timeout|rfc4787|NAT mapping timeout|A NAT removes idle mappings according to bounded timer behavior.|source_grounded_mechanism|boundary
nat_not_identity|rfc4787|NAT identity claim|Claim that a translated address and port uniquely authenticate the internal endpoint.|unsupported_inference|unsupported_claim
multicast|rfc3376|IPv4 multicast reception|IPv4 multicast reception depends on group membership and local interface state.|source_grounded_mechanism|mechanism
igmp_query|rfc3376|IGMP query|An IGMP query asks receivers to report multicast reception state.|source_grounded_mechanism|mechanism
igmp_report|rfc3376|IGMP report|An IGMP report communicates group and optional source-filter state.|source_grounded_mechanism|mechanism
multicast_membership|rfc3376|Multicast membership state|Multicast membership state controls requested group and source reception on an interface.|source_grounded_mechanism|state
multicast_filter_mode|rfc3376|Multicast filter mode|IGMPv3 include and exclude modes determine how a source list constrains multicast reception.|source_grounded_mechanism|state
multicast_source_list|rfc3376|Multicast source list|An IGMPv3 source list names sources included in or excluded from reception under the associated filter mode.|source_grounded_mechanism|representation
multicast_not_identity|rfc3376|Multicast identity claim|Claim that multicast membership proves identity or authorization of every receiver.|unsupported_inference|unsupported_claim
asset_identity|nist800207|Asset identity|A protected resource and requesting subject need stable identities and current attributes for policy evaluation.|source_grounded_mechanism|control
approved_service|nist80041|Approved service|A network policy enumerates permitted services, directions and endpoints with an accountable owner.|source_grounded_mechanism|control
authenticated_peer|nist800207|Authenticated peer context|Peer authentication supplies bounded identity evidence whose strength and freshness remain part of policy evaluation.|source_grounded_mechanism|control
authorized_flow|nist800207,nist80041|Authorized flow context|A host policy may authorize a specific subject, resource, service and session context for bounded communication.|source_grounded_mechanism|control
segmentation|nist80041|Network segmentation|Segmentation constrains communication paths between security zones according to policy.|source_grounded_mechanism|control
stateful_validation|nist80041|Stateful validation|Stateful validation relates a packet to permitted connection state and protocol progression.|source_grounded_mechanism|control
source_validation|rfc3704|Source-address validation|Source-address validation rejects packets whose claimed source is inconsistent with the receiving interface or expected route policy.|source_grounded_mechanism|control
rate_limit|nist80041|Rate limit|A rate policy bounds accepted work for a declared service and time window.|source_grounded_mechanism|control
egress_policy|nist80041|Egress policy|An egress policy constrains outbound destinations, services and source identities.|source_grounded_mechanism|control
telemetry|rfc5424,nist800207|Network telemetry|Structured event records preserve time, origin, event identity and relevant context for later analysis.|source_grounded_mechanism|control
time_sync|rfc5905,nist800207|Trusted time context|Policy and evidence evaluation depend on bounded and monitored clock state.|source_grounded_mechanism|control
config_integrity|nist800207|Configuration integrity|Policy components and enforcement points require authenticated, versioned configuration with controlled changes.|source_grounded_mechanism|control
default_deny|nist80041|Default-deny policy|A default-deny policy permits only traffic matched by an explicit applicable rule.|source_grounded_mechanism|control
unknown_observation|kernel|Unknown observation|A structurally valid observation with no represented mechanism remains outside the admitted causal neighborhood.|implementation_observation|boundary
policy_not_packet_fact|nist800207|Packet-policy equivalence claim|Claim that packet structure alone proves identity, authorization and acceptable session context.|unsupported_inference|unsupported_claim
policy_decision|nist800207|Host policy decision|A host policy decision evaluates identity, resource, service, session and environmental context outside passive Lightcone admission.|source_grounded_mechanism|control
"""


EDGE_ROWS = r"""
ip_df|ip_fragment|does_not_establish|ipv4_df_boundary|regression|rfc791|The do-not-fragment flag constrains fragmentation and does not establish that this datagram is a fragment.
unknown|unknown_observation|describes|unknown_world_boundary|sealed_test|kernel|An unsupported protocol symbol remains an explicit unknown observation with no invented mechanism path.
ipv6|ipv6_payload_length|requires|ipv6_framing|train|rfc8200|IPv6 framing is well-formed only when the declared payload extent agrees with bytes following the fixed header.
ipv6|ipv6_next_header|requires|ipv6_dispatch|train|rfc8200|Upper-layer interpretation follows the next-header chain rather than treating payload bytes as an implicit protocol.
ipv6|ipv6_hop_limit|requires|ipv6_lifetime|train|rfc8200|Forwarding an IPv6 packet requires processing the hop limit as bounded lifetime state.
ipv6_extension|ipv6_next_header|depends_on|ipv6_extensions|validation|rfc8200|Each extension header is located and typed by the preceding next-header value.
ipv6_fragment|ipv6_reassembly|requires|ipv6_fragmentation|sealed_test|rfc8200|A complete upper-layer message cannot be interpreted from IPv6 fragments until matching fragment state is reassembled.
ipv6_source|ipv6_not_identity|does_not_establish|ipv6_identity_boundary|train|rfc8200|The IPv6 source field is an address claim and contains no cryptographic proof of sender identity.
ipv6_destination|ipv6|describes|ipv6_destination_context|train|rfc8200|The destination field supplies the routing destination interpreted by IPv6 processing.
icmpv6|icmpv6_checksum|requires|icmpv6_integrity|train|rfc4443|ICMPv6 processing requires checksum validation over the message and IPv6 pseudo-header.
icmpv6_error|ipv6|depends_on|icmpv6_error_context|train|rfc4443,rfc8200|An ICMPv6 error is interpreted using the quoted invoking IPv6 packet context.
ndp|icmpv6|depends_on|ndp_transport|train|rfc4861,rfc4443|Neighbor Discovery messages are carried as defined ICMPv6 message types.
neighbor_solicitation|neighbor_advertisement|enables|ndp_neighbor_resolution|validation|rfc4861|A valid Neighbor Advertisement can answer a solicitation for target reachability or link-layer information.
neighbor_advertisement|neighbor_cache|describes|ndp_neighbor_cache|validation|rfc4861|Accepted advertisement fields update neighbor-cache information under Neighbor Discovery state rules.
router_solicitation|router_advertisement|enables|ndp_router_discovery|validation|rfc4861|A Router Solicitation requests timely Router Advertisements from routers on the local link.
router_advertisement|ndp_option|describes|ndp_router_options|validation|rfc4861|Router Advertisement options carry bounded prefix, MTU and link-layer configuration information.
neighbor_solicitation|duplicate_address_detection|enables|ndp_duplicate_detection|validation|rfc4861|A solicitation for a tentative address participates in duplicate-address detection under the specified source and target constraints.
ndp_option|ndp_not_identity|does_not_establish|ndp_identity_boundary|validation|rfc4861|Neighbor Discovery option fields do not by themselves authenticate the sender or authorize configuration.
path_mtu_discovery|path_mtu_state|describes|ipv6_path_mtu|cross_composition|rfc8201|Path MTU discovery maintains scoped packet-size state from validated path feedback.
path_mtu_discovery|icmpv6_error|depends_on|ipv6_packet_too_big|cross_composition|rfc8201,rfc4443|IPv6 Path MTU discovery depends on associating Packet Too Big feedback with the relevant path.
dns|dns_query|describes|dns_question|train|rfc1035|The DNS question section supplies the name, type and class requested by a resolver.
dns_query|dns_response|enables|dns_exchange|train|rfc1035|A response is associated with its query through message identity and question context before records are used.
dns_query|dns_name|depends_on|dns_namespace|train|rfc1034,rfc1035|DNS resolution interprets the queried labels within the distributed DNS namespace.
dns_recursive|dns_referral|depends_on|dns_delegation|train|rfc1034|Recursive resolution follows referrals when the current server delegates the queried namespace.
dns_referral|dns_authoritative|describes|dns_authority|train|rfc1034|A referral identifies servers for a delegated zone whose data is authoritative within that zone.
dns_response|dns_cache|enables|dns_caching|validation|rfc1034,rfc1035|A resolver may cache eligible response records only with their provenance and lifetime context.
dns_cache|dns_ttl|depends_on|dns_cache_lifetime|validation|rfc1035|Cache reuse is bounded by each resource record's remaining TTL.
dns_response|dns_not_identity|does_not_establish|dns_identity_boundary|train|rfc1034,rfc1035|An unsigned DNS response maps names and data but supplies no cryptographic endpoint authentication.
dnssec|dnssec_signature|requires|dnssec_signatures|train|rfc4033|DNSSEC origin authentication requires validating signatures over the covered DNS record sets.
dnssec_validation|dnssec_chain|depends_on|dnssec_trust_chain|sealed_test|rfc4033|A secure DNSSEC result depends on a chain from configured trust anchors through authenticated delegations.
dnssec_signature|dnssec_validation|enables|dnssec_validation_state|sealed_test|rfc4033|A valid signature contributes to a validation result only after key, time and delegation checks succeed.
dhcp|dhcp_discover|describes|dhcp_client_start|train|rfc2131|The DHCP client begins configuration discovery with a Discover message when it lacks usable lease state.
dhcp_discover|dhcp_offer|enables|dhcp_discovery|train|rfc2131|A server may answer discovery with a proposed configuration and lease offer.
dhcp_offer|dhcp_request|enables|dhcp_selection|sealed_test|rfc2131|The client identifies its selected offer when requesting the proposed lease.
dhcp_request|dhcp_ack|enables|dhcp_commit|sealed_test|rfc2131|A server acknowledgment confirms the parameters the client may apply.
dhcp_ack|dhcp_lease|describes|dhcp_lease_state|sealed_test|rfc2131|The acknowledgment supplies lease timing and configuration bound to the DHCP exchange.
dhcp_server_identity|dhcp_not_identity|does_not_establish|dhcp_identity_boundary|sealed_test|rfc2131|The server-identifier option distinguishes a server in the exchange but does not cryptographically authenticate its authority.
tls_client_hello|tls_server_hello|enables|tls_negotiation|train|rfc8446|Compatible hello parameters select the TLS version, cipher suite and key-establishment inputs.
tls_server_hello|tls_handshake|describes|tls_transcript|train|rfc8446|The negotiated ServerHello becomes part of the transcript bound into later verification.
tls_handshake|tls_key_schedule|enables|tls_key_derivation|train|rfc8446|TLS traffic secrets are derived from negotiated key material and transcript-bound stages.
tls_certificate|tls_chain|requires|tls_certificate_path|sealed_test|rfc8446|Certificate authentication requires a host-validated chain with acceptable trust, validity and key usage.
tls_chain|tls_name_validation|requires|tls_service_identity|sealed_test|rfc8446|A valid certificate path must also match the service identity intended by the client.
tls_record|tls_integrity|requires|tls_record_integrity|train|rfc8446|A protected record is accepted only after authentication succeeds for its traffic epoch and sequence context.
tls_record|tls_confidentiality|enables|tls_record_confidentiality|train|rfc8446|Record protection encrypts content with negotiated traffic keys for the active epoch.
tls_replay_context|tls_not_authorization|does_not_establish|tls_authorization_boundary|sealed_test|rfc8446,nist800207|Transport replay handling and channel validity do not decide application resource authorization.
tls|tls_not_authorization|does_not_establish|tls_channel_boundary|train|rfc8446,nist800207|A valid protected channel supplies bounded channel evidence while resource authorization remains a host-policy decision.
quic|quic_connection_id|describes|quic_connection_routing|train|rfc9000|Connection IDs identify QUIC connection state independently of a single address tuple.
quic|quic_packet_number|requires|quic_packet_space|cross_composition|rfc9000|QUIC loss recovery and acknowledgments depend on packet numbers within the correct packet-number space.
quic|quic_tls|depends_on|quic_tls_binding|cross_composition|rfc9000,rfc8446|QUIC establishes cryptographic state through TLS handshake messages bound to QUIC transport parameters.
quic_stream|quic_flow_control|depends_on|quic_stream_flow|validation|rfc9000|Stream progress is bounded by both stream-level and connection-level flow-control state.
quic_migration|quic_address_validation|requires|quic_migration_validation|validation|rfc9000|Migration to a new peer address requires path validation before that path is trusted for normal use.
quic_retry|quic_address_validation|enables|quic_retry_validation|cross_composition|rfc9000|Retry allows a server to validate return reachability before retaining substantial connection state.
quic_connection_id|quic_not_identity|does_not_establish|quic_identity_boundary|cross_composition|rfc9000|A connection ID routes state and does not authenticate the application peer.
http|http_request|describes|http_request_semantics|train|rfc9110|HTTP request semantics are expressed by the method, target, fields and optional content together.
http_request|http_method|requires|http_method_semantics|train|rfc9110|Interpreting a request requires applying the semantics of its declared method.
http_request|http_authority|depends_on|http_origin_context|train|rfc9110|Routing and origin selection depend on the request's intended authority and scheme context.
http_response|http_status|requires|http_response_status|train|rfc9110|The status code supplies the standardized result class used to interpret a response.
http_request|http_connection_context|depends_on|http_message_context|train|rfc9110|Message interpretation depends on version, fields, origin and connection context.
http_request|http_not_authorization|does_not_establish|http_authorization_boundary|train|rfc9110,nist800207|HTTP syntax and routing fields do not prove that the requester may perform the requested operation.
ssh_transport|ssh_key_exchange|requires|ssh_key_establishment|train|rfc4253|SSH transport protection begins with negotiated key exchange and exchange-hash binding.
ssh_key_exchange|ssh_host_key|depends_on|ssh_server_authentication|validation|rfc4253|Server authentication depends on verifying the key-exchange signature and applying host-key trust policy.
ssh_transport|ssh_encryption|enables|ssh_confidentiality|validation|rfc4253|Negotiated transport keys enable encryption after the new-key transition.
ssh_transport|ssh_integrity|requires|ssh_integrity|train|rfc4253|Protected SSH packets require the negotiated integrity or authenticated-encryption mechanism.
ssh_key_exchange|ssh_session_id|describes|ssh_session_binding|validation|rfc4253|The initial exchange hash becomes the session identifier used to bind later authentication exchanges.
ssh_host_key|ssh_not_authorization|does_not_establish|ssh_authorization_boundary|validation|rfc4253,nist800207|Host authentication identifies the server context and does not authorize client commands or resources.
ntp|ntp_timestamp|requires|ntp_measurement|train|rfc5905|NTP offset and delay calculations require timestamp fields interpreted as one exchange.
ntp|ntp_stratum|describes|ntp_hierarchy|cross_composition|rfc5905|The stratum field reports the association's distance from its reference source within NTP hierarchy rules.
ntp_selection|ntp_freshness|depends_on|ntp_selection_state|cross_composition|rfc5905|Clock selection depends on current reachability and measurement history rather than one stale response.
ntp_timestamp|ntp_not_identity|does_not_establish|ntp_identity_boundary|cross_composition|rfc5905|A timestamp value contains no cryptographic proof of the time source's identity.
snmp|snmp_engine|depends_on|snmp_engine_context|train|rfc3411|SNMP message processing occurs within an authoritative engine and its configured models.
snmp_message|snmp_security_model|requires|snmp_security_processing|validation|rfc3411|A management message must pass the security processing selected for its model and level.
snmp_message|snmp_access_control|depends_on|snmp_access_decision|validation|rfc3411|Permitting a management operation depends on the authenticated principal, context and managed object.
snmp_message|snmp_not_authorization|does_not_establish|snmp_authorization_boundary|validation|rfc3411|Receiving a syntactically valid management message does not establish access permission.
ipsec|ipsec_policy|depends_on|ipsec_policy_selection|train|rfc4301|IPsec processing starts with policy that selects discard, bypass or protected handling.
ipsec_policy|security_association|requires|ipsec_sa_selection|train|rfc4301|Protected handling requires selecting a security association compatible with policy and direction.
security_association|esp|enables|ipsec_esp|sealed_test|rfc4301|An ESP security association supplies the algorithms, keys and state for configured ESP services.
security_association|ah|enables|ipsec_ah|sealed_test|rfc4301|An AH security association supplies the algorithms, keys and state for configured AH services.
security_association|anti_replay|enables|ipsec_replay_state|sealed_test|rfc4301|When enabled, the association's sequence state and receiver window support anti-replay processing.
esp|ipsec_not_identity|does_not_establish|ipsec_authorization_boundary|sealed_test|rfc4301|Successful ESP processing protects the packet under one association and does not grant every host permission.
bgp|bgp_update|describes|bgp_reachability|train|rfc4271|BGP speakers use UPDATE messages to announce and withdraw reachability.
bgp_update|bgp_path|requires|bgp_path_attributes|train|rfc4271|An announced route carries path attributes interpreted under BGP rules and local policy.
bgp_path|bgp_policy|depends_on|bgp_policy_selection|train|rfc4271|Route preference and export depend on local policy applied to accepted path attributes.
bgp_withdrawal|bgp_update|describes|bgp_withdrawal_state|train|rfc4271|Withdrawn routes are identified in UPDATE processing and removed from the relevant route state.
bgp_update|bgp_not_authority|does_not_establish|bgp_authority_boundary|train|rfc4271|A protocol announcement conveys reachability but does not itself prove organizational authority over a prefix.
ospf|ospf_adjacency|requires|ospf_neighbor_state|train|rfc2328|OSPF database synchronization depends on neighbors reaching the required adjacency states.
ospf_adjacency|ospf_lsa|enables|ospf_database_exchange|cross_composition|rfc2328|Adjacent routers exchange and acknowledge LSAs to synchronize link-state information.
ospf_lsa|ospf_database|describes|ospf_database_state|cross_composition|rfc2328|Accepted LSAs populate the area's link-state database with sequence and age handling.
ospf_database|ospf_spf|enables|ospf_route_calculation|cross_composition|rfc2328|The shortest-path calculation derives routes from the accepted link-state database.
ospf_lsa|ospf_not_identity|does_not_establish|ospf_identity_boundary|cross_composition|rfc2328|An LSA's contents do not establish a trusted neighbor outside configured adjacency and authentication context.
nat|nat_mapping|requires|nat_mapping_state|train|rfc4787|Translation requires mapping internal transport identifiers to the external context retained by the NAT.
nat_mapping|nat_filtering|depends_on|nat_inbound_filtering|train|rfc4787|Inbound use of a mapping depends on the NAT's configured filtering behavior.
nat_mapping|nat_timeout|depends_on|nat_mapping_lifetime|train|rfc4787|Mapping availability is bounded by idle timers and refresh behavior.
nat_mapping|nat_not_identity|does_not_establish|nat_identity_boundary|train|rfc4787|A translated tuple may be shared or reused and does not uniquely authenticate the internal endpoint.
igmp_query|igmp_report|enables|multicast_membership_exchange|validation|rfc3376|Queries solicit receiver reports that describe current multicast reception state.
igmp_report|multicast_membership|enables|multicast_membership_state|regression|rfc3376|A valid report supplies group and source-filter information used to update membership state.
multicast_filter_mode|multicast_source_list|describes|multicast_source_filter|validation|rfc3376|The IGMPv3 filter mode defines whether the accompanying source list is interpreted as included or excluded reception state.
multicast|multicast_membership|depends_on|multicast_delivery_context|train|rfc3376|Requested multicast reception depends on local interface membership and source-filter state.
multicast_membership|multicast_not_identity|does_not_establish|multicast_identity_boundary|validation|rfc3376|Membership state requests delivery and does not prove receiver identity or resource authorization.
authorized_flow|approved_service|requires|firewall_service_policy|train|nist80041|A permitted flow must match an explicitly approved service, direction and endpoint rule.
authorized_flow|stateful_validation|depends_on|firewall_state_context|train|nist80041|For stateful policy, continued permission depends on valid connection and protocol progression.
authorized_flow|segmentation|depends_on|firewall_zone_policy|train|nist80041|A flow must comply with the policy connecting its source and destination security zones.
authorized_flow|egress_policy|depends_on|firewall_egress_policy|train|nist80041|Outbound communication remains constrained by destination, service and source rules.
authorized_flow|rate_limit|depends_on|firewall_rate_policy|train|nist80041|When a service has a rate policy, accepted work remains bounded by that declared window.
authorized_flow|authenticated_peer|depends_on|zero_trust_identity_context|cross_composition|nist800207|A policy decision may require current peer identity evidence appropriate to the protected resource.
authenticated_peer|asset_identity|depends_on|zero_trust_asset_context|cross_composition|nist800207|Peer evidence is interpreted against stable subject and asset identities with current attributes.
policy_decision|authorized_flow|describes|zero_trust_policy_decision|cross_composition|nist800207|The host policy decision records whether the specific subject, resource, service and session context is permitted.
policy_decision|config_integrity|depends_on|zero_trust_policy_integrity|cross_composition|nist800207|Policy decisions depend on authenticated and versioned policy inputs at the enforcement boundary.
telemetry|time_sync|depends_on|telemetry_time_context|validation|rfc5424,rfc5905|Event ordering and validity analysis depend on bounded, monitored clock context.
policy_decision|telemetry|enables|policy_observability|validation|nist800207,rfc5424|Structured records make policy inputs and outcomes observable for later review.
source_validation|default_deny|depends_on|source_validation_default|train|rfc3704,nist80041|A source-validation rule is enforced within the host's explicit default-deny and exception policy.
source_validation|authorized_flow|depends_on|source_validation_policy|sealed_test|rfc3704,nist80041|Where source validation applies, a flow must be consistent with the receiving interface or expected route policy.
default_deny|unknown_observation|describes|unknown_default_deny|sealed_test|nist80041,kernel|A represented default-deny policy gives unrecognized observations no implicit permission.
tls_certificate|tls_not_authorization|does_not_establish|tls_certificate_authorization_boundary|sealed_test|rfc8446,nist800207|A certificate message contributes identity evidence but does not grant every application permission.
dhcp_offer|dhcp_not_identity|does_not_establish|dhcp_offer_authority_boundary|sealed_test|rfc2131|An offered lease is protocol input and does not prove trusted configuration authority by itself.
ipsec_policy|policy_not_packet_fact|does_not_establish|ipsec_policy_boundary|sealed_test|rfc4301,nist800207|IPsec policy and protection context remain inputs to host authorization rather than a universal permission.
http_connection_context|tls|depends_on|http_tls_composition|cross_composition|rfc9110,rfc8446|For HTTPS, HTTP origin semantics depend on the validated TLS channel and intended service identity.
dnssec_validation|dns_response|requires|dnssec_dns_composition|regression|rfc4033,rfc1035|A DNSSEC result requires the DNS response record sets and their authenticated delegation context.
dns_negative_response|dnssec_authenticated_denial|requires|dnssec_negative_composition|cross_composition|rfc4033,rfc1035|A secure negative DNS result requires authenticated-denial evidence covering the requested name or type.
authorized_flow|tls_name_validation|depends_on|policy_tls_composition|cross_composition|nist800207,rfc8446|Where TLS service identity is required, a permitted flow depends on successful name validation as one policy input.
snmp_access_control|policy_decision|depends_on|policy_management_composition|cross_composition|rfc3411,nist800207|A management access decision is evaluated within the host's current subject, resource and operation policy.
quic|path_mtu_state|depends_on|quic_path_mtu_composition|cross_composition|rfc9000,rfc8201|QUIC packet sizing and path use depend on current path MTU state for the selected network path.
frame|policy_not_packet_fact|does_not_establish|packet_policy_boundary|train|kernel,nist800207|An Ethernet frame supplies wire structure while identity and authorization require separate host context.
tcp|policy_not_packet_fact|does_not_establish|transport_policy_boundary|train|rfc9293,nist800207|TCP state supplies transport context while host policy still evaluates subject, resource and service authorization.
tls|policy_not_packet_fact|does_not_establish|channel_policy_boundary|train|rfc8446,nist800207|TLS channel evidence remains one policy input and cannot replace the host's resource decision.
"""


DOMAIN_CONTEXT = {
    "ipv6": (
        "The IPv6 fixed header and declared next-header chain were structurally validated for this packet context.",
        "Unknown extensions, truncated chains and unvalidated fragment sets remain outside the relation.",
    ),
    "icmpv6": (
        "The ICMPv6 type, code, checksum and invoking-packet bounds were validated.",
        "Quoted bytes and address fields do not authenticate a sender or make routing advice authoritative.",
    ),
    "ndp": (
        "The message is an eligible Neighbor Discovery type on the expected IPv6 link context.",
        "Link scope, option validation and host policy still apply; message presence is not identity proof.",
    ),
    "dns": (
        "The DNS message bounds, question context and record encoding were validated.",
        "Cache state, delegation, truncation and local validation policy can limit use of the data.",
    ),
    "dnssec": (
        "The validator has the required DNSSEC records, time context and configured trust anchor.",
        "Unsigned delegations and validation failures remain explicit outcomes rather than inferred trust.",
    ),
    "dhcp": (
        "The DHCP transaction identifiers, message roles and lease state correspond to one client exchange.",
        "Broadcast reachability and identifier fields alone do not authenticate configuration authority.",
    ),
    "tls": (
        "The TLS 1.3 handshake or record is interpreted within one negotiated connection and traffic epoch.",
        "Certificate, name, freshness and application authorization checks retain separate host owners.",
    ),
    "quic": (
        "The QUIC packet belongs to the correct encryption level, number space and connection context.",
        "Connection IDs and address validation do not independently authenticate the application identity.",
    ),
    "http": (
        "The HTTP message is parsed with its version, origin and connection context.",
        "Message syntax, method and authority do not establish resource authorization.",
    ),
    "ssh": (
        "The SSH message belongs to one negotiated transport and key-exchange state.",
        "Host authentication and transport protection do not grant user or command authorization.",
    ),
    "ntp": (
        "The NTP fields are interpreted as one association with current reachability and clock state.",
        "Timestamps and hierarchy fields alone do not authenticate the time source.",
    ),
    "snmp": (
        "The SNMP engine, message model, security level and management context are known.",
        "A parseable management message has no authority until security and access-control processing succeeds.",
    ),
    "ipsec": (
        "The packet is evaluated under the applicable IPsec policy and directional security association.",
        "Successful protection does not grant permissions outside the association and host policy.",
    ),
    "bgp": (
        "The BGP message belongs to an established speaker session and is processed under local routing policy.",
        "Protocol reachability is distinct from external authority over an address resource.",
    ),
    "ospf": (
        "The OSPF message belongs to the configured area, neighbor and link-state database context.",
        "Topology data outside valid adjacency, age, sequence and authentication context remains unusable.",
    ),
    "nat": (
        "The translated packet is interpreted with the applicable mapping, filtering and timer state.",
        "A translated tuple can be shared or reused and is not a stable endpoint identity.",
    ),
    "multicast": (
        "The IGMP message and membership state apply to the named interface, group and source filter.",
        "Membership requests do not establish receiver identity or application authorization.",
    ),
    "firewall": (
        "The host supplied the current policy version and the flow's zones, endpoints, service and state context.",
        "Passive graph admission remains context for the host decision and never releases traffic by itself.",
    ),
    "zero_trust": (
        "The policy engine supplied current subject, asset, resource, service and session attributes.",
        "One authenticated channel or packet field cannot replace the complete policy decision.",
    ),
    "telemetry": (
        "The event record has bounded origin, time, event identity and policy-version context.",
        "Missing, delayed or unauthenticated telemetry remains limited evidence.",
    ),
    "source_validation": (
        "The receiving interface and applicable routing policy are known for the claimed source.",
        "Asymmetric routing and explicitly permitted exceptions require declared policy handling.",
    ),
    "unknown": (
        "The observation has no represented mechanism seed in this world revision.",
        "A later sourced world revision may add a mechanism; absence is scoped to this revision.",
    ),
    "packet": (
        "The packet fields were structurally decoded into represented protocol symbols.",
        "Wire structure does not establish identity, intent, authorization or acceptable session history.",
    ),
    "transport": (
        "The transport header and state were interpreted within the supported protocol context.",
        "Transport validity remains separate from peer identity and host authorization.",
    ),
    "channel": (
        "The protected channel evidence was validated for its negotiated connection context.",
        "Channel validity remains only one input to resource policy.",
    ),
}


def context_for(group: str) -> tuple[str, str]:
    for prefix, value in DOMAIN_CONTEXT.items():
        if group.startswith(prefix):
            return value
    return (
        f"The {group.replace('_', ' ')} mechanism is interpreted within its cited protocol and declared scope.",
        "Unsupported extensions and missing prerequisite context remain outside this relation.",
    )


def base_warrant(edge: dict, nodes: dict[str, dict]) -> str:
    source = nodes[edge["source"]]["title"]
    target = nodes[edge["target"]]["title"]
    group = edge["mechanism_group"].replace("_", " ")
    relation = edge["relation"]
    if relation == "requires":
        return f"For {group}, {source} is valid only when the {target} requirement is satisfied under the cited protocol rules."
    if relation == "depends_on":
        return f"The {source} state depends on {target} to interpret {group} within the declared protocol context."
    if relation == "enables":
        return f"Within {group}, {source} supplies the specific mechanism that permits {target} under its stated conditions."
    if relation == "describes":
        return f"For {group}, the fields or state represented by {source} describe the bounded {target} context."
    return f"The {source} fields lack the cryptographic or host-policy evidence required to establish {target}."


def make_sources(verify_remote: bool) -> list[dict]:
    sources = []
    for number, title, sections, expected in RFC_SOURCES:
        url = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
        if verify_remote:
            actual = sha256(fetch(url))
            require(actual == expected, f"RFC {number} hash changed: {actual}")
        sources.append(
            {
                "id": f"rfc{number}",
                "title": title,
                "author": "IETF / RFC Editor; authors identified in the linked RFC",
                "url": url,
                "version": f"RFC {number}",
                "sections": sections,
                "sha256": expected,
                "rights_lane": "citation_only",
                "use": "Original concise factual summaries only; the RFC text is not redistributed or used as bulk training text.",
                "retrieved": AS_OF,
                "trust_role": "authoritative_protocol_standard",
                "attribution": f"RFC {number}, authors and IETF Trust terms at the source URL",
            }
        )
    for source_id, title, url, version, sections, expected in NIST_SOURCES:
        if verify_remote:
            actual = sha256(fetch(url))
            require(actual == expected, f"{version} hash changed: {actual}")
        sources.append(
            {
                "id": source_id,
                "title": title,
                "author": "National Institute of Standards and Technology",
                "url": url,
                "version": version,
                "sections": sections,
                "sha256": expected,
                "rights_lane": "citation_only",
                "use": "Original concise control summaries only; the source document is cited and not redistributed as training text.",
                "retrieved": AS_OF,
                "trust_role": "authoritative_security_guidance",
                "attribution": f"{version}, NIST",
            }
        )
    adapter = PROJECT / "integration/atom-os/kernel-net-lightcone.rs"
    adapter_hash = sha256(adapter.read_bytes())
    require(
        adapter_hash == "d81b2fecc75cd5fdefaa549c8133ee6cf807b901ea50dba0682ef77a58d4f002",
        "standalone observation adapter differs from the revision-4 source",
    )
    sources.append(
        {
            "id": "kernel",
            "title": "Atom OS network observation boundary",
            "author": "Jesse Alicea / Rekonquest",
            "url": "https://github.com/Rekonquest/atom-os-kernel",
            "version": f"standalone revision 4 derived from Atom OS {SNAPSHOT}",
            "sections": "Copied kernel-net Lightcone observation adapter",
            "sha256": adapter_hash,
            "rights_lane": "user_authorized",
            "use": "Implementation facts and explicit ownership boundaries; not a security proof.",
            "retrieved": AS_OF,
            "trust_role": "implementation_source",
            "attribution": f"Standalone revision-4 adapter derived from Atom OS source snapshot {SNAPSHOT}",
        }
    )
    return sources


def parse_nodes() -> list[dict]:
    nodes = []
    for line in NODE_ROWS.splitlines():
        if not line.strip():
            continue
        node_id, source_ids, title, statement, epistemic, kind = line.split("|")
        nodes.append(
            {
                "id": node_id,
                "title": title,
                "statement": statement,
                "source_ids": source_ids.split(","),
                "epistemic_class": epistemic,
                "scope": "Network mechanism or defensive control context; admission is evidence context, never a packet verdict.",
                "limitations": "Requires the declared protocol, state, identity and host-policy context; unsupported context remains unknown.",
                "lanes": ["causal", "geometry"],
                "aliases": [node_id.replace("_", " "), title.casefold()],
                "record_kind": kind,
                "as_of": AS_OF,
                "version_boundary": "Network world revision 4",
                "coverage_axes": [
                    "mechanism",
                    "causality",
                    "scope",
                    "limitations",
                    "unknown_abstention",
                ],
            }
        )
    return nodes


def parse_edges(start: int, node_by_id: dict[str, dict]) -> list[dict]:
    edges = []
    for offset, line in enumerate(EDGE_ROWS.splitlines()):
        if not line.strip():
            continue
        source, target, relation, group, split, source_ids, evidence = line.split("|", 6)
        conditions, exceptions = context_for(group)
        require(source in node_by_id and target in node_by_id, f"unknown endpoint in {line}")
        edges.append(
            {
                "id": f"e{start + offset:03d}",
                "source": source,
                "target": target,
                "relation": relation,
                "polarity": -1 if relation == "does_not_establish" else 1,
                "mechanism_group": group,
                "split": split,
                "source_ids": source_ids.split(","),
                "conditions": conditions,
                "exceptions": exceptions,
                "scope": "bounded network mechanism or host defensive-control relationship",
                "epistemic_class": "source_grounded_mechanism",
                "evidence": evidence,
                "direction": "forward",
            }
        )
    return edges


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-sources", action="store_true")
    args = parser.parse_args()

    base = json.loads((ROOT / "sources/world-v3.json").read_bytes())
    nodes = deepcopy(base["nodes"])
    for node in nodes:
        node["as_of"] = AS_OF
        node["version_boundary"] = "Network world revision 4"
        node["scope"] = "Network mechanism or defensive control context; admission is evidence context, never a packet verdict."
        node["limitations"] = "Requires the declared protocol, state, identity and host-policy context; unsupported context remains unknown."
        node["coverage_axes"] = [
            "mechanism",
            "causality",
            "scope",
            "limitations",
            "unknown_abstention",
        ]

    additions = parse_nodes()
    existing = {node["id"] for node in nodes}
    require(not (existing & {node["id"] for node in additions}), "v4 node duplicates v3")
    nodes.extend(additions)
    node_by_id = {node["id"]: node for node in nodes}

    base_edges = []
    for edge in deepcopy(base["edges"]):
        if edge["id"] in {"e018", "e054"}:
            continue
        if edge["id"] == "e042":
            edge["relation"] = "does_not_establish"
            edge["polarity"] = -1
        edge["evidence"] = base_warrant(edge, node_by_id)
        edge["conditions"], edge["exceptions"] = context_for(edge["mechanism_group"])
        edge["scope"] = "bounded network mechanism or host defensive-control relationship"
        base_edges.append(edge)
    for index, edge in enumerate(base_edges):
        edge["id"] = f"e{index:03d}"

    edges = base_edges + parse_edges(len(base_edges), node_by_id)
    for index, edge in enumerate(edges):
        edge["id"] = f"e{index:03d}"

    forbidden = re.compile(r"\b(scan|probe|attack|malware|exploit|flood|beacon|exfiltration)\w*\b", re.I)
    training_text = json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True)
    require(not forbidden.search(training_text), "attack or probe exemplar entered the training world")
    require(len(nodes) <= 256, f"node limit exceeded: {len(nodes)}")
    require(len(edges) <= 512, f"edge limit exceeded: {len(edges)}")
    evidence = [" ".join(edge["evidence"].casefold().split()) for edge in edges]
    require(len(evidence) == len(set(evidence)), "edge evidence must be relation-specific and unique")
    require(
        all(
            edge["evidence"]
            != node_by_id[edge["source"]]["statement"]
            + " "
            + node_by_id[edge["target"]]["statement"]
            for edge in edges
        ),
        "edge evidence may not be endpoint-statement concatenation",
    )

    relations = {
        "requires": 0,
        "enables": 1,
        "describes": 2,
        "does_not_establish": 3,
        "depends_on": 4,
    }
    splits = ["train", "validation", "sealed_test", "cross_composition", "regression"]
    manifest = {
        split: sorted({edge["mechanism_group"] for edge in edges if edge["split"] == split})
        for split in splits
    }
    world = {
        "schema": 2,
        "id": "atom-network-causal-v4",
        "version": 4,
        "dimensions": 48,
        "relations": relations,
        "nodes": nodes,
        "edges": edges,
        "sources": make_sources(args.verify_sources),
        "policy": {
            "id": "network-context-v2",
            "max_hops": 3,
            "max_nodes": 64,
            "direction": "both",
            "relation_mask": 31,
            "polarity": "both",
        },
        "geometry_seed_policy": "Only exact structurally validated observation or host-context symbols may seed admission. Full 48D geometry is retained; similarity never invents a node or edge.",
        "split_rule": "Entire mechanism groups and exact typed relations are confined to one split. Attack and probe exemplars are excluded from the authored and compiled world and may appear only in separately labelled evaluation challenges.",
    }
    (ROOT / "sources/world.json").write_bytes(canonical(world) + b"\n")
    (ROOT / "sources/splits.json").write_bytes(canonical(manifest) + b"\n")
    counts = {split: sum(edge["split"] == split for edge in edges) for split in splits}
    coverage = {
        "open_world": True,
        "revision": 4,
        "status": "authored",
        "world_id": world["id"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "split_edge_counts": counts,
        "covered": [
            "Ethernet and ARP context",
            "IPv4 and IPv6 framing, lifetime, extension and fragmentation context",
            "ICMPv4, ICMPv6 and IPv6 Neighbor Discovery context",
            "UDP, TCP, QUIC and NAT transport context",
            "DNS, DNSSEC and DHCP configuration context",
            "TLS, HTTP and SSH channel and application context",
            "NTP and SNMP operational context",
            "IPsec, BGP, OSPF and multicast control context",
            "Firewall, segmentation, source validation, egress, telemetry and policy-decision prerequisites",
            "Explicit identity and authorization non-inferences",
        ],
        "gaps": [
            "Complete application-protocol coverage",
            "Wireless link management",
            "Full routing-protocol family coverage",
            "Environment-specific asset and service inventories",
            "Validated host observation adapters for the remaining application and routing protocols",
            "Independent long-duration production traffic evaluation",
            "Measured effectiveness against a representative external challenge set",
        ],
        "lanes": {
            "causal": "passive exact typed graph",
            "geometry": "48D authoritative geometry plus observer-only spatial x,y,z,w shadow",
            "host_policy": "separate consumer and enforcement owner",
        },
        "attack_exemplars_in_training": False,
        "accelerator_acceptance": False,
        "sealed": False,
    }
    (ROOT / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
    print(json.dumps({"nodes": len(nodes), "edges": len(edges), "splits": counts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
