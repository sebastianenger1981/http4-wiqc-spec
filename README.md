# HTTP/4 over WIQC: Decentralized Real-Time Torrent Streaming Protocol

[![GitHub Commit](https://img.shields.io/badge/Commit-ce61e80-181717.svg?logo=github)](https://github.com/sebastianenger1981/http4-wiqc-spec/commit/2e727b79f7fc215198a42cbaafcfaee4549f19c7)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

> **Foundational Mandate:**
> *"The HTTP/4 protocol will allow decentralized real time streaming via torrent protocol called not QUIC but WIQC."*
> *Description: "WIQC (Web-Integrated QUIC-derived Content-swarming Protocol)"*

## Overview

Draft published at ([`https://datatracker.ietf.org/doc/draft-enger-httpbis-http4-wiqc/`](https://datatracker.ietf.org/doc/draft-enger-httpbis-http4-wiqc/).

This repository ([`sebastianenger1981/http4-wiqc-spec`](https://github.com/sebastianenger1981/http4-wiqc-spec)) hosts the formal architectural specification and IETF Internet-Draft (`draft-enger-httpbis-http4-wiqc-00`) for **HTTP/4**, an application-layer mapping of HTTP Semantics (RFC 9110) over a decentralized, peer-to-peer real-time streaming transport protocol named **WIQC** (*Web-Integrated QUIC-derived Content-swarming*).

While HTTP/3 (RFC 9114) maps HTTP semantics onto unicast client-server QUIC connections (RFC 9000), it remains dependent on centralized origin servers and Content Delivery Network (CDN) relays. **HTTP/4 over WIQC** replaces the unicast transport model with a cryptographically verified peer-to-peer mesh. Participating endpoints simultaneously consume and relay multiplexed media streams and static representations across a decentralized swarm with sub-second latency.

* **Genesis Prior-Art Commit:** [`2e727b79f7fc215198a42cbaafcfaee4549f19c7`](https://github.com/sebastianenger1981/http4-wiqc-spec/commit/2e727b79f7fc215198a42cbaafcfaee4549f19c7)

## Author & Official Web Properties

This specification is authored and maintained by **Sebastian Enger (M.Sc., B.Sc.)**. Official platforms, research portals, and business resources associated with this project:

* **ArtikelSchreiber.com (Main Portal):** [https://www.artikelschreiber.com/](https://www.artikelschreiber.com/)
* **Author Profile & Publications:** [https://www.artikelschreiber.com/author/](https://www.artikelschreiber.com/author/)
* **Business & Architecture Services:** [https://www.artikelschreiber.com/business/](https://www.artikelschreiber.com/business/)
* **UNAIQUE.NET:** [https://www.unaique.net/](https://www.unaique.net/)
* **ArtikelSchreiben.com:** [https://www.artikelschreiben.com/](https://www.artikelschreiben.com/)

## Core Architectural Pillars

1. **Multiplexed UDP Transport without Head-of-Line Blocking:** Retains QUIC v1 (RFC 9000) packet framing, 0-RTT/1-RTT encrypted handshakes, connection migration, and stream-level flow control while extending connection semantics to multipoint peer swarms.
2. **Cryptographic Swarm Integrity (PPSPP + BitTorrent v2):**
   * **Static Mode (BEP 52):** Divides representations into 16 KiB leaf blocks hashed into a binary SHA-256 Merkle tree (`pieces root`). Peers exchange native wire messages (IDs 21 `hash request`, 22 `hashes`, 23 `hash reject`) to verify every 16 KiB block on arrival and isolate polluting peers.
   * **Live Streaming Mode (RFC 7574 Unified Merkle Tree):** Uses 64-bit bin addressing, a sliding `Live Discard Window` (Option Code 7), and `Unified Merkle Tree` integrity (Method 3). The origin publisher signs binary subtree roots (*munro* hashes) via `WIQC_SIGNED_INTEGRITY` frames (`0x4103`), enabling real-time swarm verification at ~5% bandwidth overhead.
3. **Sub-Second Media Hierarchy & Hybrid EDF Scheduling:**
   * Adopts the **Track -> Group -> Subgroup -> Object** hierarchy from Media over QUIC Transport (`draft-ietf-moq-transport`). Each Subgroup maps to one unidirectional WIQC stream (`0x40`) so packet loss on an enhancement layer never blocks base layers.
   * Targets under 150 ms end-to-end latency (under 100 ms glass-to-glass) via the MOQT Streaming Format (MSF / LOC raw frames over WebCodecs) and 0.5 to 1.0 s via CMAF/MSE (CMSF).
   * Pairs **Earliest Deadline First (EDF)** scheduling for urgent playback deadlines (under 150 ms) with **Rarest-First** piece selection across the outer `Live Discard Window`.
4. **Decentralized Mutual Authentication, Origin Signatures & Native NAT Traversal:**
   * **Mutual TLS 1.3 without Central CAs:** Endpoints authenticate peer IDs via self-signed X.509 certificates carrying the `libp2p` Public Key Extension (OID `1.3.6.1.4.1.53594.1.1`), or via `certhash` + Noise handshakes over WebTransport for browser nodes.
   * **Multi-Hop Origin Authenticity:** Combines HTTP Digest Fields (`Repr-Digest`, `Content-Digest`, RFC 9530) with HTTP Message Signatures (`Signature-Input`, `Signature`, RFC 9421) so responses assembled from untrusted peers remain cryptographically bound to the origin publisher.
   * **Direct P2P Hole Punching:** Coordinates direct UDP paths using native NAT traversal frames (`OBSERVED_ADDRESS`, `ADD_ADDRESS`, `PUNCH_ME_NOW` / `PUNCH_REQUEST`, `REMOVE_ADDRESS`) with fallback to the HTTP Capsule Protocol (`DATAGRAM` Capsule `0x00`, RFC 9297) when UDP is blocked.

## Protocol Generation Comparison

| Feature | HTTP/1.1 (RFC 9112) | HTTP/2 (RFC 9113) | HTTP/3 (RFC 9114) | HTTP/4 (WIQC Spec) |
| :--- | :--- | :--- | :--- | :--- |
| **Semantics** | RFC 9110 | RFC 9110 | RFC 9110 | RFC 9110 |
| **Transport** | TCP Unicast | TCP Unicast | QUIC Unicast | WIQC P2P Swarm |
| **Multiplexing** | None | Stream (TCP HoL) | Independent Streams | 1 Subgroup / Stream |
| **Header Format** | Plaintext | HPACK (RFC 7541) | QPACK (RFC 9204) | QPACK + RFC 9421 |
| **Block Integrity** | Optional Digest | Optional Digest | Optional Digest | SHA-256 Merkle + Munro |
| **Peer Auth** | PKIX CAs | PKIX CAs | PKIX CAs (TLS 1.3) | libp2p TLS 1.3 + certhash |
| **Live Streaming** | Chunked / HLS | Server Push / DASH | MOQT via CDN Relays | Native P2P MOQT + EDF |
| **NAT Traversal** | None | None | External ICE / TURN | Native Hole Punching |

HTTP/4 retains backward compatibility with RFC 9110 semantics and QPACK header compression while shifting content verification, peer discovery, and real-time subgroup relay directly into the WIQC transport layer.

## Wire Protocol Codepoints

### Stream Types

| Stream ID | Name | Directionality | Purpose |
| :--- | :--- | :--- | :--- |
| `0x00` | Control Stream | Unidirectional | Carries `SETTINGS`, `GOAWAY`, `MAX_PUSH_ID`, and swarm capabilities |
| `0x01` | Push Stream | Unidirectional | Server- or peer-initiated representation push |
| `0x02` | QPACK Encoder | Unidirectional | Dynamic header table insertions (RFC 9204) |
| `0x03` | QPACK Decoder | Unidirectional | Header acknowledgments and stream cancellations (RFC 9204) |
| `0x40` | WIQC Swarm Subgroup | Unidirectional | Single real-time media Subgroup + Merkle `INTEGRITY` proof |
| `0x41` | WIQC Swarm Control | Bidirectional | `HAVE`, `REQUEST`, `CANCEL`, `CHOKE`, `UNCHOKE`, `SIGNED_INTEGRITY` |

### Swarm Frame Types

| Frame ID | Frame Name | Permitted Streams | Payload Summary |
| :--- | :--- | :--- | :--- |
| `0x4101` | `WIQC_HAVE` | Swarm Control | Verified 64-bit bin ranges (RFC 7574) |
| `0x4102` | `WIQC_INTEGRITY` | Subgroup / Control | Uncle hashes and Merkle branch proofs (RFC 7574 / BEP 52) |
| `0x4103` | `WIQC_SIGNED_INTEGRITY` | Subgroup / Control | Publisher-signed munro subtree roots for live streams |
| `0x4104` | `WIQC_PEX` | Control / Swarm Control | Trackerless Peer Exchange (`PEX_RESv4`, `PEX_RESv6`, `PEX_REQ`) |

### ALPN Identifiers & Formal Header Syntax (ABNF)

* **ALPN Protocol IDs:** `h4` (`0x68 0x34` — HTTP/4 over WIQC) and `wiqc` (`0x77 0x69 0x71 0x63` — Raw WIQC Swarm Transport)
* **HTTP Header Field:** `WIQC-Swarm-Info`

```abnf
WIQC-Swarm-Info = "swarm-id=" byte-sequence ";"
                  "mode=" ( "merkle-v2" / "unified-live" )
                  [ ";window=" 1*DIGIT ]
                  [ ";chunk-addr=" ( "bin32" / "bin64" ) ]

byte-sequence   = ":" *( BASE64CHAR ) ":"
BASE64CHAR      = ALPHA / DIGIT / "+" / "/" / "="

h4-alpn-id      = %x68.34 ; "h4" in ASCII
wiqc-alpn-id    = %x77.69.71.63 ; "wiqc" in ASCII
```

## Permanent Archival & Citation

This specification is preserved as verifiable prior art across multiple independent registries:

1. **GitHub Commit Record:** [`2e727b79f7fc215198a42cbaafcfaee4549f19c7`](https://github.com/sebastianenger1981/http4-wiqc-spec/commit/2e727b79f7fc215198a42cbaafcfaee4549f19c7)

To cite this specification in academic publications, standards contributions, or implementations, use the **Cite this repository** button on GitHub or the following BibTeX entry:

```bibtex
@software{Enger_http4_wiqc_spec, author = {Enger, Sebastian}, title = {http4-wiqc-spec}, year = {2026}, url = {https://github.com/sebastianenger1981/http4-wiqc-spec}, urldate = {2026-11-18}, version = {main} }
```
