# HTTP/4 over WIQC — Python 3.14 / 3.15 Minimal Viable Prototype (MVP)

An object-oriented, zero-dependency Python 3.14 / 3.15 Minimal Viable Prototype implementing the **HTTP/4 over WIQC** specification published in IETF Internet-Draft [`draft-enger-httpbis-http4-wiqc-00`](https://datatracker.ietf.org/doc/draft-enger-httpbis-http4-wiqc/) (*"HTTP/4: Mapping HTTP Semantics over the WIQC Decentralized Real-Time Torrent Transport Protocol"* by Sebastian Enger).

---

## Architecture Overview

```text
+------------------------------------------------------------------------+
|                     HTTP/4 Semantics (RFC 9110)                        |
|        HTTP4WIQCClient (client.py)  <->  HTTP4WIQCServer (server.py)   |
+------------------------------------------------------------------------+
|  QPACK (qpack.py, Streams 0x02/0x03, RFC 9114 §10.6 Side-Channel Guard)|
|  Headers (headers.py): WIQC-Swarm-Info ABNF, RFC 9421 Sig, RFC 9530    |
+------------------------------------------------------------------------+
|  MOQT Media Model + Dual-Zone EDF / Rarest-First Scheduler (media.py)  |
|  Subgroup Streams (0x40) | Swarm Control (0x41) | Server Push (0x01)   |
+------------------------------------------------------------------------+
|  WIQC Swarm Integrity (merkle.py, swarm.py):                           |
|  - Static Mode: BEP 52 16 KiB SHA-256 Merkle + Hash Messages 21/22/23  |
|  - Live Mode:   RFC 7574 CIPM 3 Unified Merkle Tree + Munro Signatures |
|  - Discovery:   Trackerless WIQC_PEX (0x4104), Alt-Svc, HTTPS/SVCB RR  |
+------------------------------------------------------------------------+
|  Decentralized Mutual TLS 1.3 (tls_libp2p.py, crypto.py):              |
|  - Pure-Python RFC 8032 Ed25519, RFC 7748 X25519, RFC 8439 ChaCha20    |
|  - Single Self-Signed X.509 v3 Cert + libp2p OID 1.3.6.1.4.1.53594.1.1 |
|  - ALPNs: "h4" (0x68 0x34) & "wiqc" (0x77 0x69 0x71 0x63) + 0-RTT      |
+------------------------------------------------------------------------+
|  WIQC Encrypted UDP Transport (transport.py) + NAT Traversal (nat.py)  |
|  - Long/Short Headers, DCID Connection Migration, 3x Anti-Amplification|
|  - Per-Stream Flow Control (Zero HoL), RFC 9221 Datagrams & Capsules   |
|  - OBSERVED_ADDRESS, ADD/REMOVE_ADDRESS, PUNCH_ME_NOW, PATH_CHALLENGE  |
+------------------------------------------------------------------------+
```

---

## Complete Feature-to-Module Mapping

| Specification Section | Proposed Feature | Implementation |
| :--- | :--- | :--- |
| §2 & §5.2 | RFC 9000 VarInt encoding/decoding + `Type / Length / Payload` framing | `http4_wiqc/varint.py`, `http4_wiqc/frames.py` |
| §3.1 | Multiplexed encrypted UDP transport (Long/Short headers, DCID migration, zero HoL, flow control, 0-RTT/1-RTT) | `http4_wiqc/transport.py`, `http4_wiqc/crypto.py` |
| §3.2 | RFC 7574 Swarm Capabilities Negotiation (Options `2, 3, 4 [SHA-256 0x02], 6 [bin32/64], 7 [Live Discard Window]`) | `http4_wiqc/swarm.py` |
| §3.2 & §8.2 | Anti-Amplification: 3x unvalidated byte cap, Channel ID echoing, first-flight heavy payload rejection | `http4_wiqc/transport.py` |
| §3.3 | Static Content Mode: BEP 52 16 KiB SHA-256 Merkle tree + Hash Wire Messages `21/22/23` | `http4_wiqc/merkle.py`, `http4_wiqc/swarm.py` |
| §3.3 | Live Streaming Mode: RFC 7574 CIPM 3 Unified Merkle Tree + Publisher Munro Hash Signatures | `http4_wiqc/merkle.py`, `http4_wiqc/swarm.py` |
| §4.1 | MOQT Hierarchy (`Track`, `Group`, `Subgroup`, `Object`) with 1:1 Subgroup -> Unidirectional `0x40` stream | `http4_wiqc/media.py`, `http4_wiqc/server.py` |
| §4.2 | Hybrid Dual-Zone Sliding Window Scheduler (Emergency EDF `<150 ms` lowest-RTT + Swarm Health Rarest-First) | `http4_wiqc/media.py` |
| §5.1 | All 6 HTTP/4 Stream Types (`0x00` Control, `0x01` Push, `0x02` QPACK Enc, `0x03` QPACK Dec, `0x40` Subgroup, `0x41` Swarm Control) | `http4_wiqc/frames.py`, `server.py`, `client.py` |
| §5.2 | Normative Frames (`DATA`, `HEADERS`, `CANCEL_PUSH`, `SETTINGS`, `PUSH_PROMISE`, `GOAWAY`, `MAX_PUSH_ID`, `WIQC_HAVE 0x4101`, `WIQC_INTEGRITY 0x4102`, `WIQC_SIGNED_INTEGRITY 0x4103`, `WIQC_PEX 0x4104`) | `http4_wiqc/frames.py` |
| §5.3.1–5.3.3 | `Repr-Digest`, `Content-Digest`, `Swarm-Root` (RFC 9530), Origin Signatures (`Signature-Input` / `Signature`, RFC 9421), `Alt-Svc` (RFC 7838), `SVCB`/`HTTPS` (RFC 9460) | `http4_wiqc/headers.py` |
| §5.3.4 | Unreliable QUIC `DATAGRAM` frames (RFC 9221) & `DATAGRAM Capsule (0x00)` (RFC 9297) | `http4_wiqc/transport.py`, `http4_wiqc/frames.py` |
| §6.1 & §9.1 | Mutual TLS 1.3 with single self-signed X.509 v3 cert + OID `1.3.6.1.4.1.53594.1.1`, WebTransport `certhash`, ALPN `"h4"` / `"wiqc"` | `http4_wiqc/tls_libp2p.py` |
| §6.2 | Native WIQC NAT Traversal (`OBSERVED_ADDRESS`, `ADD_ADDRESS 0x3d7e90/91`, `PUNCH_ME_NOW 0x3d7e92/93`, `REMOVE_ADDRESS 0x3d7e94`, `PUNCH_REQUEST`, `PATH_CHALLENGE/RESPONSE`) | `http4_wiqc/nat.py`, `http4_wiqc/transport.py` |
| §7 | Strict RFC 5234 ABNF Parser/Formatter for `WIQC-Swarm-Info` | `http4_wiqc/headers.py` |
| §8.1 | Deterministic Stream-Pollution Detection & Peer Banning (`PeerReputationManager`) | `http4_wiqc/media.py`, `http4_wiqc/client.py` |
| §8.3 | QPACK Sensitive-Header Side-Channel Guard (`NEVER_INDEX`) + 0-RTT Idempotency Guard (`425 Too Early`) | `http4_wiqc/qpack.py`, `server.py`, `client.py` |

---

## Core Protocol Workflows

### 1. Handshake & Anti-Amplification Workflow
```text
Client (WIQCEndpoint)                                Server (WIQCEndpoint)
  |--- INITIAL (1200B padded, ClientHello, ALPN=h4) --->| (3x anti-amp cap checked)
  |<-- INITIAL (ServerHello, ChannelID=C) --------------|
  |<-- HANDSHAKE (Enc: Cert[len=1, OID], CV, Fin, Tkt)--|
  | [Verify single self-signed X.509 + libp2p OID]      |
  |--- HANDSHAKE (ChannelID=C echo, Enc: Cert, CV, Fin)>| [ChannelID echo validates addr!]
  |                                                     | [Verify single client X.509 + OID]
  |<-- 1-RTT Short Header (ACK + OBSERVED_ADDRESS) -----|
  |<=== Encrypted ChaCha20-Poly1305 HTTP/4 Streams ====>|
```

### 2. Multi-Peer Static Swarm & Pollution Defense Workflow
```text
Client -> Origin: GET /assets/video-sample.bin (HTTP/4 Request Stream)
Origin -> Client: 200 OK + RFC 9421 Signature + Repr-Digest + Swarm-Root + WIQC-Swarm-Info
Origin -> Client: PUSH_PROMISE (0x05) + Push Stream (0x01) [/assets/manifest.json]
Client -> Origin: WIQC_PEX (PEX_REQ) -> discovers Honest Seeder trackerlessly
Client -> [Origin, Honest, Rogue]: WIQC_HANDSHAKE_CAPS (0x41) -> UNCHOKE + WIQC_HAVE
Client -> Rogue : WIQC_REQUEST(bin) -> Rogue sends corrupted 16 KiB block on Stream 0x40
Client          : SHA-256 Merkle proof FAILS -> DISCARD block + BAN Rogue Peer immediately!
Client -> Honest: WIQC_REQUEST(bin) -> Honest sends valid block + WIQC_INTEGRITY -> VERIFIED!
```

### 3. Live Real-Time Streaming & Relay Re-Seeding Workflow
```text
Origin Publisher:
  MOQT Group g -> UnifiedMerklePublisher.commit_group() -> Ed25519 Signed Munro Hash
  Stream 0x41: WIQC_SIGNED_INTEGRITY (0x4103) + WIQC_HAVE (0x4101)
  Stream 0x40 #1 (Base Layer u=0)        : [MOQT IDR + Base Frames] + [WIQC_INTEGRITY]
  Stream 0x40 #2 (Enhancement Layer u=4) : [MOQT Enhancement Frames] + [WIQC_INTEGRITY]
        (Loss on #2 NEVER blocks delivery of #1 -> Zero Head-of-Line Blocking!)
Relay Peer:
  Verifies Ed25519 munro + Merkle proof -> delivers locally AND immediately re-seeds on 0x40!
```

---

## Quick Start (Python 3.14 or Python 3.15 — Zero External Dependencies)

### 1. Run the Self-Contained Full 10-Workflow Demo
```powershell
py -3.15 example.client.py --self-contained
# Or with Python 3.14:
py -3.14 example.client.py --self-contained
```

### 2. Run Separate Server and Client Processes
Terminal 1 (Server):
```powershell
py -3.15 example.server.py --host 127.0.0.1 --port 4433 --deterministic-key
```
Terminal 2 (Client):
```powershell
py -3.15 example.client.py --host 127.0.0.1 --port 4433
```

### 3. Run the Full Automated Test Suite (Unit + Live UDP E2E + Fault Injection)
```powershell
py -3.15 -m unittest discover -s tests -t . -v
py -3.14 -m unittest discover -s tests -t . -v
```
