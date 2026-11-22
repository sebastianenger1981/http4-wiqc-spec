---
title: "HTTP/4: Mapping HTTP Semantics over the WIQC Decentralized Real-Time Torrent Transport Protocol"
abbrev: "HTTP/4 over WIQC"
docname: draft-enger-httpbis-http4-wiqc-00
category: exp
ipr: trust200902
area: Applications and Real-Time
workgroup: HTTP Working Group
submissiontype: IETF
kw:
  - HTTP/4
  - WIQC
  - P2P
  - Real-Time Streaming
  - Decentralized Torrent
  - Merkle Tree
stand_alone: true

author:
  - ins: S. Enger
    name: Sebastian Enger
    org: Einzelunternehmen Sebastian Enger
    abbrev: ESE
    street: Linienstrasse 11
    city: Brandenburg an der Havel
    code: D-14776
    country: Germany
    email: Sebastian.Enger@Gmail.com

normative:
  RFC2119:
  RFC5234:
  RFC7574:
  RFC7838:
  RFC8174:
  RFC9000:
  RFC9110:
  RFC9114:
  RFC9204:
  RFC9218:
  RFC9221:
  RFC9297:
  RFC9421:
  RFC9460:
  RFC9530:
  RFC9846:
  BEP52:
    title: "The BitTorrent Protocol Specification v2"
    author:
      - name: BEP 52 Specification Authors
    date: 2020-09
    target: "https://www.bittorrent.org/beps/bep_0052.html"
    seriesinfo:
      BEP: 52

informative:
  RFC3552:
  I-D.ietf-moq-transport:
  I-D.seemann-quic-nat-traversal:
  LIBP2P-TLS:
    title: "libp2p TLS 1.3 Handshake Specification"
    author:
      - org: Protocol Labs
    date: 2024
    target: "https://github.com/libp2p/specs/blob/master/tls/tls.md"
--- abstract

This document specifies HTTP/4, an application-layer mapping of HTTP
semantics over a decentralized, peer-to-peer real-time streaming
transport protocol named WIQC (Web-Integrated QUIC-derived
Content-swarming). By design, the HTTP/4 protocol allows
decentralized real-time streaming via a torrent protocol called not
QUIC but WIQC. While HTTP/3 delegates stream multiplexing and
congestion control to unicast client-server QUIC connections, HTTP/4
extends these capabilities to multipoint peer swarms. WIQC integrates
encrypted UDP stream multiplexing with fine-grained cryptographic
block verification using SHA-256 Merkle hash trees, live
sliding-window chunk addressing, Unified Merkle Tree signatures for
low-latency live streams, mutual peer authentication without
centralized certificate authorities, and native UDP hole punching.
This specification defines the wire framing, stream mapping, swarm
discovery headers, real-time object prioritization, and security
properties required to operate HTTP/4 natively across decentralized
networks.

--- middle

# Introduction

The architectural evolution of the Hypertext Transfer Protocol has
progressively decoupled high-level application semantics {{RFC9110}}
from underlying transport bindings. While HTTP/1.1 and HTTP/2 rely
primarily on Transmission Control Protocol (TCP) connections, HTTP/3
{{RFC9114}} maps HTTP semantics onto the QUIC transport protocol
{{RFC9000}} to eliminate transport-layer head-of-line blocking and
reduce handshake latency. However, HTTP/3 remains fundamentally bound
to a centralized, unicast client-server topology. Real-time media
delivery and large-scale content distribution over HTTP/3 still require
centralized Content Delivery Network (CDN) relay infrastructures
{{I-D.ietf-moq-transport}}.

This document establishes the foundational mandate for the next
generation of web transport:

The HTTP/4 protocol will allow decentralized real time streaming via
torrent protocol called not QUIC but WIQC.

To fulfill this mandate, this specification defines WIQC
(Web-Integrated QUIC-derived Content-swarming) as the underlying
transport layer for HTTP/4. Rather than treating a resource origin as
a single IP endpoint, HTTP/4 treats content representations and live
media tracks as cryptographically verifiable swarms. Peers
participating in an HTTP/4 exchange simultaneously act as consumers
and relays, exchanging independent streams and unreliable datagrams
{{RFC9221}} across a decentralized mesh.

WIQC synthesizes four core protocol mechanisms into a unified
transport layer:

1. Multiplexed Encrypted Framing: Derived from {{RFC9000}}, providing
   connection migration, 0-RTT/1-RTT setup, and independent per-stream
   flow control.

2. Real-Time Swarm Integrity and Torrent Framing: Incorporating the
   bin-based chunk addressing, Live Discard Window, and Unified Merkle
   Tree live signature mechanisms of the Peer-to-Peer Streaming Peer
   Protocol (PPSPP) {{RFC7574}} alongside the 16 KiB SHA-256 Merkle
   leaf verification of BitTorrent v2 {{BEP52}}.

3. Sub-Second Media Hierarchy: Adapting the Track, Group, Subgroup,
   and Object data model of Media over QUIC Transport
   {{I-D.ietf-moq-transport}} so that each Subgroup maps to an
   independent unidirectional WIQC stream for immediate peer-to-peer
   forwarding and Earliest Deadline First (EDF) scheduling.

4. Decentralized Mutual Authentication and NAT Traversal: Utilizing
   self-signed X.509 certificates carrying the libp2p Public Key
   Extension {{LIBP2P-TLS}} over TLS 1.3 {{RFC9846}} and native
   path-probing frames {{I-D.seemann-quic-nat-traversal}} to establish
   direct peer-to-peer paths across Network Address Translators (NATs).

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

This document uses the variable-length integer encoding and packet
formatting conventions defined in Section 1.3 of {{RFC9000}}.

The following terms are used throughout this specification:

* WIQC Endpoint: A network node implementing the WIQC transport
  protocol capable of simultaneously initiating and accepting swarm
  streams as both an HTTP/4 client (subscriber/leecher) and an HTTP/4
  peer server (publisher/seeder).

* Swarm Identifier (Swarm ID): A cryptographic identifier uniquely
  representing an HTTP/4 resource or live stream. For static
  representations, the Swarm ID is the 32-byte SHA-256 Merkle root
  (pieces root) {{BEP52}}. For live streams, the Swarm ID is the
  public key fingerprint of the origin publisher {{RFC7574}}.

* Leaf Block: The smallest unit of cryptographic verification in WIQC,
  fixed at 16 KiB (16,384 bytes) in accordance with {{BEP52}}.

* Munro Hash: An interior node root of a power-of-two subtree within a
  Unified Merkle Tree {{RFC7574}} that is cryptographically signed by
  the live origin publisher via a SIGNED_INTEGRITY frame to authenticate
  dynamically generated live streaming chunks.

* Subgroup Stream: A unidirectional WIQC stream carrying a sequence of
  media or data Objects that share a delivery priority and decoding
  dependency {{I-D.ietf-moq-transport}}.

# The WIQC Transport Protocol Architecture

## Relationship to QUIC and Peer-to-Peer Swarming

WIQC preserves the UDP packet framing, long and short headers,
connection IDs, and per-stream reliability mechanisms of {{RFC9000}},
but replaces the asymmetric client-server session model with a
symmetric swarm channel model. A single HTTP/4 logical request can be
satisfied concurrently by multiple WIQC connections to distinct peers
participating in the same Swarm ID.

Figure 1 illustrates the architectural layering of HTTP/4 over WIQC
compared to HTTP/2 and HTTP/3:

~~~ ascii-art
+----------------------------------------------------------------+
|                   HTTP Semantics (RFC 9110)                    |
+-------------------+--------------------+-----------------------+
| HTTP/2 (RFC 9113) | HTTP/3 (RFC 9114)  |   HTTP/4 over WIQC    |
+-------------------+--------------------+-----------------------+
|   HPACK Framing   | QPACK + H3 Frames  | QPACK + RFC 9421 Sig. |
+-------------------+--------------------+-----------------------+
| TLS 1.2/1.3 (PKIX)| QUIC Streams(9000) | MOQT Subgroups + EDF  |
+-------------------+--------------------+-----------------------+
| TCP (Single Stream| TLS 1.3 (CA PKIX)  | WIQC Swarm (RFC7574)  |
+-------------------+--------------------+-----------------------+
|    IP / Unicast   |    UDP / Unicast   | Mutual TLS 1.3        |
+-------------------+--------------------+-----------------------+
|                   |                    | UDP + Hole Punching   |
+-------------------+--------------------+-----------------------+
~~~
{: #fig-protocol-stack title="HTTP/4 over WIQC Protocol Stack Comparison"}

## Swarm Handshake and Channel Multiplexing

During connection establishment or stream initialization, WIQC
endpoints exchange swarm capabilities derived from {{RFC7574}} and
{{BEP52}}:

1. Swarm Metadata Negotiation: Endpoints negotiate the Swarm
   Identifier (Option Code 2), Content Integrity Protection Method
   (Option Code 3), Merkle Hash Tree Function (Option Code 4, fixed to
   SHA-256, code 0x02), Chunk Addressing Method (Option Code 6,
   defaulting to 64-bit bins, code 0x03), and Live Discard Window
   (Option Code 7) as defined in {{RFC7574}}.

2. Anti-Amplification Rule: In accordance with {{RFC7574}} and
   {{RFC9000}}, an initiating peer's first flight MUST NOT contain
   heavy payloads (such as DATA or SIGNED_INTEGRITY frames) prior to
   address validation via channel ID echoing or QUIC PATH_RESPONSE
   verification.

## Cryptographic Integrity: Static and Live Torrent Modes

Because HTTP/4 peers receive byte ranges and real-time media frames
from untrusted swarm participants, transport-level TLS 1.3 encryption
{{RFC9846}} only protects the hop-by-hop channel. End-to-end content
integrity MUST be verified at the block or object level before data
is passed to the HTTP/4 application or forwarded to other peers:

* Static Content Mode (BEP 52 Merkle Mode): Content is divided into
  16 KiB leaf blocks hashed with SHA-256 into a binary Merkle tree
  {{BEP52}}. Peers exchange standard peer wire protocol messages
  (IDs 21, 22, and 23 for hash request, hashes, and hash reject) to
  fetch missing uncle hashes required to verify a 16 KiB block
  immediately upon arrival. Corrupt blocks are discarded immediately,
  and the offending peer is isolated.

* Decentralized Real-Time Streaming Mode (Unified Merkle Tree Mode):
  Since the total stream length is unknown ahead of time in live
  streaming, WIQC utilizes Content Integrity Protection Method 3
  (Unified Merkle Tree) from {{RFC7574}}. As the publisher generates
  new groups of real-time chunks, it computes the binary subtree root
  (the munro hash) covering the newly generated bin range, signs the
  munro hash using its private key, and distributes SIGNED_INTEGRITY
  and INTEGRITY frames across the swarm. Receiving peers verify each
  chunk against its munro branch before playback and immediately
  re-seed verified chunks to downstream peers.

# Real-Time Streaming and Swarm Scheduling in HTTP/4

## Media Data Model Mapping

To achieve sub-second real-time latency across a decentralized torrent
swarm, HTTP/4 adopts the hierarchical data model of
{{I-D.ietf-moq-transport}}:

* Track: Identified by a tuple of Track Namespace (bound to the HTTP/4
  :authority and :path pseudo-headers) and Track Name (e.g., video
  bitrate variant, audio channel, or catalog track).

* Group: A temporally bounded collection of objects starting at an
  independent synchronization point (such as an IDR keyframe),
  directly aligned with a WIQC Unified Merkle Tree munro subtree.

* Subgroup: A subset of objects within a Group sharing a common
  priority and dependency chain. Each Subgroup MUST be mapped to
  exactly one unidirectional WIQC stream. If packet loss occurs on a
  lower-priority enhancement layer Subgroup, higher-priority base
  layer Subgroups proceed without head-of-line blocking.

* Object: The smallest addressable media unit (e.g., a single encoded
  video frame or Low Overhead Container (LOC) payload).

## Hybrid Earliest Deadline First (EDF) and Rarest-First Scheduling

Traditional torrent protocols rely purely on Rarest-First piece
selection, which maximizes swarm diversity but ignores playback
deadlines. Conversely, purely sequential fetching causes swarm starvation.
WIQC endpoints implementing HTTP/4 real-time streaming MUST implement a
dual-zone sliding window scheduler within the negotiated Live Discard
Window {{RFC7574}}, extending HTTP priority signaling {{RFC9218}}:

1. Emergency Priority Zone (EDF Zone): For chunks whose playback
   deadline falls within a configurable threshold (e.g., < 150 ms), the
   peer requests missing Subgroups strictly in Earliest Deadline First
   (EDF) order from the lowest-RTT unchoked peers.

2. Swarm Health Zone (Rarest-First Zone): For chunks further ahead in
   the Live Discard Window, the peer uses remaining bandwidth to request
   the rarest chunks announced via HAVE frames, ensuring robust piece
   availability across the swarm.

Figure 2 depicts the dual-zone sliding window scheduler and wire-level
frame multiplexing in WIQC:

~~~ ascii-art
|<---------------- Live Discard Window (RFC 7574) --------------->|
+---------------------------------+-------------------------------+
|  Emergency Zone (< 150 ms)      |     Swarm Health Zone         |
|  Scheduler: Strictly EDF        |     Scheduler: Rarest-First   |
|  Target: Lowest-RTT Peers       |     Target: HAVE Bin Diversity|
+---------------------------------+-------------------------------+
        |                                         |
        v                                         v
+-----------------------------------------------------------------+
| WIQC Subgroup Stream (0x40): [MOQT Object] + [WIQC_INTEGRITY]   |
| WIQC Swarm Control   (0x41): [WIQC_HAVE]   + [SIGNED_INTEGRITY] |
+-----------------------------------------------------------------+
~~~
{: #fig-scheduler-pipeline title="WIQC Dual-Zone Real-Time Swarm Scheduler and Stream Pipeline"}

# Expressing HTTP Semantics over WIQC

## HTTP/4 Stream Mapping

HTTP/4 preserves the stream categories of {{RFC9114}} while introducing
swarm-specific stream types:

| Stream Type ID | Stream Name | Directionality | Purpose in HTTP/4 over WIQC |
| :--- | :--- | :--- | :--- |
| 0x00 | Control Stream | Unidirectional (pair) | Carries SETTINGS, GOAWAY, MAX_PUSH_ID, and swarm capabilities. |
| 0x01 | Push Stream | Unidirectional | Server- or peer-initiated push of promised HTTP/4 representations. |
| 0x02 | QPACK Encoder | Unidirectional | Dynamic header table insertions per {{RFC9204}}. |
| 0x03 | QPACK Decoder | Unidirectional | Header table acknowledgments and stream cancellations per {{RFC9204}}. |
| 0x40 | WIQC Swarm Subgroup | Unidirectional | Carries a single real-time media Subgroup alongside its Merkle INTEGRITY proof. |
| 0x41 | WIQC Swarm Control | Bidirectional | Exchanges HAVE, REQUEST, CANCEL, CHOKE, UNCHOKE, and SIGNED_INTEGRITY frames. |

## HTTP/4 Frame Layout and Extensions

All HTTP/4 frames follow the variable-length integer framing layout of
Section 7.1 of {{RFC9114}}: Type (i), Length (i), and Frame Payload (..).
In addition to DATA (0x00), HEADERS (0x01), CANCEL_PUSH (0x03),
SETTINGS (0x04), PUSH_PROMISE (0x05), GOAWAY (0x07), and MAX_PUSH_ID
(0x0d), HTTP/4 defines the following WIQC swarm frames:

| Frame Type | Frame Name | Permitted Streams | Description |
| :--- | :--- | :--- | :--- |
| 0x4101 | WIQC_HAVE | WIQC Swarm Control | Announces possession of verified 64-bit bin ranges {{RFC7574}}. |
| 0x4102 | WIQC_INTEGRITY | WIQC Swarm Subgroup / Control | Carries uncle hashes or Merkle branch proofs {{RFC7574}} {{BEP52}}. |
| 0x4103 | WIQC_SIGNED_INTEGRITY | WIQC Swarm Subgroup / Control | Carries publisher-signed munro root hashes for live streaming {{RFC7574}}. |
| 0x4104 | WIQC_PEX | Control / WIQC Swarm Control | Peer Exchange (PEX_RESv4, PEX_RESv6, PEX_REQ) for trackerless discovery {{RFC7574}}. |

## HTTP Header Fields for Swarm Integrity and Origin Authentication

When initiating a request or responding over HTTP/4, endpoints combine
standard HTTP integrity and signature headers with WIQC swarm metadata:

1. Representation Digest (Repr-Digest and Content-Digest): In accordance
   with {{RFC9530}}, static HTTP/4 responses MUST include a Repr-Digest
   header encoding the SHA-256 root hash, accompanied by a Swarm-Root
   dictionary field carrying the BEP 52 pieces root.

2. Origin Message Signatures (Signature-Input and Signature): Because
   HTTP/4 responses may be assembled from multiple untrusted peers, the
   origin server signs the response metadata (@status, content-type,
   repr-digest, and wiqc-swarm-id) using {{RFC9421}}. Any peer in the
   swarm can forward the signed header block, and any receiving client
   can cryptographically verify that the metadata originated from the
   authoritative publisher.

3. Alternative Service and Discovery: Transition from unicast HTTP/3
   {{RFC7838}} or DNS resolution via SVCB/HTTPS records {{RFC9460}} to
   HTTP/4 swarms is accomplished by advertising "h4" ALPN endpoints.

4. HTTP Datagrams and Capsule Protocol: Ultra-low-latency unreliable
   media objects MAY be transmitted via QUIC DATAGRAM frames {{RFC9221}}
   associated with an HTTP/4 request stream, or encapsulated via the
   DATAGRAM Capsule (0x00) per {{RFC9297}} when traversing HTTP
   intermediaries.

# Decentralized Peer Authentication and NAT Traversal

## Mutual TLS 1.3 with Self-Signed Peer Identity

In a decentralized torrent swarm, peers typically lack domain names and
cannot obtain certificates from commercial PKIX Certificate Authorities
(CAs). Therefore, WIQC mandates mutual authentication over TLS 1.3
{{RFC9846}} using the libp2p TLS handshake mechanism {{LIBP2P-TLS}}:

* Both dialing and listening WIQC endpoints MUST present a single
  self-signed X.509 certificate during the TLS 1.3 handshake (chains
  longer than one certificate MUST cause connection termination).

* The certificate MUST include the libp2p Public Key Extension
  identified by Object Identifier (OID) 1.3.6.1.4.1.53594.1.1.

* The extension contains an ASN.1-encoded SignedKey structure holding
  the peer's public host key (e.g., Ed25519) and a cryptographic
  signature over the concatenation of the ASCII string
  "libp2p-tls-handshake:" and the DER-encoded SubjectPublicKeyInfo of
  the ephemeral certificate key.

* For browser-based HTTP/4 endpoints operating over WebTransport, where
  the browser enforces CA checks or certificate pinning, endpoints MAY
  authenticate peers by embedding the certificate hash (certhash) in the
  peer advertisement and performing an in-band cryptographic binding
  handshake on the first stream.

## Native WIQC NAT Traversal

To enable direct peer-to-peer streaming between home and mobile nodes
behind NATs without relying on external ICE/STUN/TURN stacks, WIQC
incorporates the native QUIC NAT traversal extension
{{I-D.seemann-quic-nat-traversal}}:

* Well-connected relay or seed peers inform joining peers of their
  external UDP socket address using the OBSERVED_ADDRESS frame.

* Peers advertise candidate addresses over existing swarm connections
  using ADD_ADDRESS (0x3d7e90..0x3d7e91) and REMOVE_ADDRESS (0x3d7e94)
  frames, and coordinate simultaneous UDP hole punching via
  PUNCH_ME_NOW (0x3d7e92..0x3d7e93) or grant-based PUNCH_REQUEST frames
  followed by standard PATH_CHALLENGE and PATH_RESPONSE validation
  {{RFC9000}}.

# Formal Syntax (ABNF)

The following Augmented Backus-Naur Form (ABNF) grammar {{RFC5234}}
defines the syntax of the WIQC-Swarm-Info HTTP header field and the h4
Alternative Service discovery token:

~~~ abnf
WIQC-Swarm-Info = "swarm-id=" byte-sequence ";"
                  "mode=" ( "merkle-v2" / "unified-live" )
                  [ ";window=" 1*DIGIT ]
                  [ ";chunk-addr=" ( "bin32" / "bin64" ) ]

byte-sequence   = ":" *( BASE64CHAR ) ":"
BASE64CHAR      = ALPHA / DIGIT / "+" / "/" / "="

h4-alpn-id      = %x68.34 ; "h4" in ASCII
wiqc-alpn-id    = %x77.69.71.63 ; "wiqc" in ASCII
~~~
{: artwork-name="wiqc-abnf-syntax"}

# Security Considerations

This section analyzes the threat model of HTTP/4 over WIQC in accordance
with {{RFC3552}}.

## Stream Pollution Attacks in Decentralized Swarms

In peer-to-peer live streaming, a malicious peer with high upload
bandwidth can inject corrupted chunks ("pollution attack") to degrade
playback across the swarm. WIQC mitigates this by enforcing mandatory
cryptographic verification before forwarding: every 16 KiB block in
static mode is verified against the SHA-256 Merkle root {{BEP52}}, and
every live chunk in Unified Merkle Tree mode is verified against a
publisher-signed munro hash {{RFC7574}}. Merkle-tree chaining keeps
cryptographic verification bandwidth overhead around 5% (as evaluated
under 128-bit MD5 and 1024-bit RSA reference parameters) while enabling
deterministic identification and immediate banning of polluting peers.

## Reflection and Amplification Attacks

Because WIQC operates over UDP, unverified source IP addresses pose a
reflection amplification risk. Endpoints MUST enforce the
anti-amplification limits of {{RFC9000}} and MUST echo the peer's
randomly chosen Channel ID per Section 12.1 of {{RFC7574}} before
transmitting heavy payloads such as DATA or SIGNED_INTEGRITY messages.

## Compression Side Channels and Replay Risks

When using QPACK {{RFC9204}} in HTTP/4, endpoints MUST NOT compress
sensitive authentication tokens alongside attacker-controlled data within
the same dynamic table context (Section 10.6 of {{RFC9114}}).
Furthermore, 0-RTT swarm requests MUST only be used for idempotent
operations (such as subscribing to public live tracks) to prevent replay
attacks.

# IANA Considerations

## ALPN Protocol ID Registration

This document requests IANA to register the following Application-Layer
Protocol Negotiation (ALPN) IDs in the "TLS Application-Layer Protocol
Negotiation (ALPN) Protocol IDs" registry:

* Protocol: HTTP/4 over WIQC
* Identification Sequence: 0x68 0x34 ("h4")
* Reference: This document
* Protocol: Raw WIQC Swarm Transport
* Identification Sequence: 0x77 0x69 0x71 0x63 ("wiqc")
* Reference: This document

## HTTP Header Field Registration

This document requests registration of the WIQC-Swarm-Info field in
the "Hypertext Transfer Protocol (HTTP) Field Name Registry" per
{{RFC9110}} with status experimental.

--- back

# Acknowledgements
{:unnumbered}

This specification synthesizes foundational work by the IETF HTTP
Working Group, the QUIC Working Group, the Media over QUIC (MOQ)
Working Group, the Peer-to-Peer Streaming Protocol (PPSP) Working
Group, the BitTorrent BEP 52 authors, and the libp2p specification
community.