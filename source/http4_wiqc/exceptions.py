"""
HTTP/4 over WIQC Protocol Exception Hierarchy.

Defines structured, fault-tolerant exception classes corresponding to the error
conditions specified in `draft-enger-httpbis-http4-wiqc-00`, RFC 9000 (QUIC),
RFC 9114 (HTTP/3), RFC 7574 (PPSPP), BEP 52, RFC 9421, and libp2p-tls.

Using typed exceptions lets both the HTTP/4 server and client distinguish between:
- Recoverable per-packet / per-chunk faults (e.g., corrupted UDP datagram or single
  bad chunk from a malicious peer, where the peer is isolated and the swarm continues),
- Fatal connection-level security violations (e.g., X.509 certificate chain > 1,
  invalid libp2p OID 1.3.6.1.4.1.53594.1.1 signature, anti-amplification violation),
- Application-level HTTP/4 semantic errors (e.g., non-idempotent 0-RTT rejection).
"""

from __future__ import annotations


class HTTP4WIQCError(Exception):
    """Base exception for all HTTP/4 over WIQC protocol errors."""

    error_code: int = 0x0100

    def __init__(self, message: str, error_code: int | None = None) -> None:
        super().__init__(message)
        if error_code is not None:
            self.error_code = error_code


class WireFormatError(HTTP4WIQCError):
    """Raised when a VarInt, packet header, frame, or capsule is malformed or truncated."""

    error_code = 0x0101


class CryptoError(HTTP4WIQCError):
    """Raised on cryptographic verification, AEAD decryption, or key-exchange failure."""

    error_code = 0x0102


class TLSAuthenticationError(CryptoError):
    """
    Raised when Mutual TLS 1.3 peer authentication fails, including:
    - Certificate chain length != 1 (normative MUST terminate per Section 6.1),
    - Missing or invalid libp2p Public Key Extension (OID 1.3.6.1.4.1.53594.1.1),
    - Invalid SignedKey signature or certificate self-signature,
    - Unsupported ALPN (neither 'h4' nor 'wiqc').
    """

    error_code = 0x0103


class AntiAmplificationError(HTTP4WIQCError):
    """
    Raised when an endpoint violates RFC 9000 / RFC 7574 anti-amplification rules:
    - Heavy payloads (DATA / WIQC_SIGNED_INTEGRITY) in an unvalidated first flight,
    - Exceeding the 3x amplification budget prior to address validation.
    """

    error_code = 0x0104


class IntegrityVerificationError(HTTP4WIQCError):
    """
    Raised when cryptographic content verification fails:
    - Static BEP 52 16 KiB leaf block SHA-256 Merkle proof mismatch,
    - Live Unified Merkle Tree munro hash or publisher Ed25519 signature failure,
    - RFC 9530 Repr-Digest / Swarm-Root mismatch,
    - RFC 9421 Origin Message Signature verification failure.

    Triggers deterministic isolation/banning of the offending peer to defeat
    stream pollution attacks (Section 8.1 of draft-enger-httpbis-http4-wiqc-00).
    """

    error_code = 0x0105


class PeerBannedError(HTTP4WIQCError):
    """Raised when a connection or chunk originates from an isolated/banned peer."""

    error_code = 0x0106


class SwarmNegotiationError(HTTP4WIQCError):
    """
    Raised when RFC 7574 swarm capability negotiation fails, e.g.,
    unsupported Merkle hash function (must be SHA-256 code 0x02) or
    mismatched Swarm ID.
    """

    error_code = 0x0107


class HeaderSyntaxError(HTTP4WIQCError):
    """Raised when WIQC-Swarm-Info ABNF, Alt-Svc, SVCB, or RFC 9421 headers are invalid."""

    error_code = 0x0108


class QPACKError(HTTP4WIQCError):
    """Raised on QPACK decoding errors or sensitive-header compression policy violations."""

    error_code = 0x0109


class ReplayProtectionError(HTTP4WIQCError):
    """
    Raised when a non-idempotent HTTP/4 request is attempted over 0-RTT
    (forbidden by Section 8.3 of draft-enger-httpbis-http4-wiqc-00).
    """

    error_code = 0x010A


class FlowControlError(HTTP4WIQCError):
    """Raised when a peer violates per-stream or connection flow-control windows."""

    error_code = 0x010B


class NATTraversalError(HTTP4WIQCError):
    """Raised when native WIQC NAT traversal / hole punching fails or times out."""

    error_code = 0x010C


class ConnectionClosedError(HTTP4WIQCError):
    """Raised when operating on a closed or GOAWAY-drained WIQC connection."""

    error_code = 0x010D
