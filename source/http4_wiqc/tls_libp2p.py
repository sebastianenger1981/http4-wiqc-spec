"""
Decentralized Mutual TLS 1.3 with Self-Signed Peer Identity (libp2p-tls)
and WebTransport Certhash Fallback.

Implements Section 6.1 ("Mutual TLS 1.3 with Self-Signed Peer Identity") and
Section 9.1 ("ALPN Protocol ID Registration") of `draft-enger-httpbis-http4-wiqc-00`:

1. **ALPN Protocol IDs**:
   - `b"h4"` (`0x68 0x34`) — HTTP/4 over WIQC
   - `b"wiqc"` (`0x77 0x69 0x71 0x63`) — Raw WIQC Swarm Transport

2. **Self-Signed X.509 v3 Certificate with libp2p Public Key Extension**:
   - Both dialing and listening WIQC endpoints MUST present a **single** self-signed
     X.509 v3 certificate (chains longer than 1 certificate MUST cause immediate
     connection termination).
   - The certificate MUST carry extension OID `1.3.6.1.4.1.53594.1.1`.
   - Inside that extension sits an ASN.1 `SignedKey` SEQUENCE containing:
     `publicKey` (host Ed25519 public key) and `signature` (host Ed25519 signature
     over `b"libp2p-tls-handshake:" + DER(SubjectPublicKeyInfo of ephemeral cert key)`).
   - No centralized Certificate Authorities (PKIX CAs) are required.

3. **Mutual TLS 1.3 Handshake State Machine**:
   - Ephemeral X25519 key exchange -> HKDF-SHA256 transcript-bound handshake & 1-RTT
     application traffic secrets (`c2s_key`, `c2s_iv`, `s2c_key`, `s2c_iv`).
   - Mutual authentication: BOTH server and client present their single self-signed
     X.509 cert, sign the handshake transcript (`CertificateVerify`), and prove key
     possession (`Finished` HMAC).
   - Supports **0-RTT session resumption tickets** (for idempotent requests only!).

4. **WebTransport Certhash Fallback**:
   - Supports browser/WebTransport endpoints where the peer advertises
     `certhash = SHA-256(cert_der)` and executes an in-band cryptographic binding
     handshake on the first stream.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass

from .crypto import (
    ChaCha20Poly1305,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    PeerIdentity,
    X25519KeyPair,
    hkdf_expand_label,
    hkdf_extract,
)
from .exceptions import CryptoError, TLSAuthenticationError
from .varint import ByteReader, ByteWriter

# Normative ALPN Identifiers (Section 7 & Section 9.1)
ALPN_H4 = b"h4"  # 0x68 0x34
ALPN_WIQC = b"wiqc"  # 0x77 0x69 0x71 0x63
SUPPORTED_ALPNS = (ALPN_H4, ALPN_WIQC)

# Normative libp2p-tls constants (Section 6.1)
LIBP2P_TLS_OID = "1.3.6.1.4.1.53594.1.1"
LIBP2P_HANDSHAKE_PREFIX = b"libp2p-tls-handshake:"

# Standard ASN.1 OIDs used in X.509 v3 certificates
OID_ED25519 = "1.3.101.112"
OID_COMMON_NAME = "2.5.4.3"


# =============================================================================
# Minimal, Strict ASN.1 DER Encoder & Decoder (Zero Dependencies)
# =============================================================================


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def der_tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(value)) + value


def der_sequence(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_tlv(0x31, b"".join(items))


def der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("Only non-negative DER integers supported")
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return der_tlv(0x02, raw)


def der_bit_string(data: bytes) -> bytes:
    # Leading 0x00 indicates zero unused bits.
    return der_tlv(0x03, b"\x00" + data)


def der_octet_string(data: bytes) -> bytes:
    return der_tlv(0x04, data)


def der_utf8_string(text: str) -> bytes:
    return der_tlv(0x0C, text.encode("utf-8"))


def der_generalized_time(timestamp: int) -> bytes:
    tm = time.gmtime(timestamp)
    formatted = (
        f"{tm.tm_year:04d}{tm.tm_mon:02d}{tm.tm_mday:02d}"
        f"{tm.tm_hour:02d}{tm.tm_min:02d}{tm.tm_sec:02d}Z"
    )
    return der_tlv(0x18, formatted.encode("ascii"))


def der_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid_str}")
    out = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc == 0:
            out.append(0)
            continue
        chunks: list[int] = []
        v = arc
        while v > 0:
            chunks.append(v & 0x7F)
            v >>= 7
        chunks.reverse()
        for i, c in enumerate(chunks):
            out.append(c | (0x80 if i < len(chunks) - 1 else 0))
    return der_tlv(0x06, bytes(out))


def der_explicit(tag_num: int, inner: bytes) -> bytes:
    return der_tlv(0xA0 | tag_num, inner)


def parse_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int, bytes]:
    """
    Parse one ASN.1 DER TLV starting at `offset`.
    Returns (tag, value_bytes, next_offset, raw_tlv_bytes).
    """
    if offset >= len(data):
        raise TLSAuthenticationError("Truncated DER element")
    tag = data[offset]
    if offset + 1 >= len(data):
        raise TLSAuthenticationError("Truncated DER length")
    len_byte = data[offset + 1]
    pos = offset + 2
    if len_byte < 0x80:
        length = len_byte
    else:
        num_octets = len_byte & 0x7F
        if num_octets == 0 or pos + num_octets > len(data):
            raise TLSAuthenticationError("Invalid DER length encoding")
        length = int.from_bytes(data[pos : pos + num_octets], "big")
        pos += num_octets
    if pos + length > len(data):
        raise TLSAuthenticationError("DER value exceeds buffer bounds")
    value = data[pos : pos + length]
    raw = data[offset : pos + length]
    return tag, value, pos + length, raw


def decode_der_oid(oid_bytes: bytes) -> str:
    if not oid_bytes:
        raise TLSAuthenticationError("Empty DER OID")
    first = oid_bytes[0]
    arcs = [first // 40, first % 40]
    acc = 0
    for b in oid_bytes[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(acc)
            acc = 0
    return ".".join(str(a) for a in arcs)


def decode_der_generalized_time(raw: bytes) -> int:
    text = raw.decode("ascii")
    if len(text) != 15 or not text.endswith("Z"):
        raise TLSAuthenticationError(f"Unsupported GeneralizedTime format: {text}")
    tm = time.strptime(text, "%Y%m%d%H%M%SZ")
    import calendar

    return int(calendar.timegm(tm))


# =============================================================================
# Self-Signed X.509 v3 Certificate with libp2p Public Key Extension
# =============================================================================


@dataclass(frozen=True)
class Libp2pCertificateBundle:
    """A peer's generated self-signed X.509 v3 DER certificate and ephemeral key."""

    cert_der: bytes
    ephemeral_private_key: Ed25519PrivateKey
    host_public_key: Ed25519PublicKey
    not_before: int
    not_after: int

    @property
    def certhash(self) -> bytes:
        """SHA-256 fingerprint of the DER certificate (used for WebTransport certhash mode)."""
        return hashlib.sha256(self.cert_der).digest()


@dataclass(frozen=True)
class VerifiedPeerCertificate:
    """Result of strict libp2p-tls X.509 verification."""

    host_public_key: Ed25519PublicKey
    ephemeral_public_key: Ed25519PublicKey
    peer_id: bytes
    certhash: bytes
    not_before: int
    not_after: int


def build_ed25519_spki(public_key_bytes: bytes) -> bytes:
    """Construct DER-encoded SubjectPublicKeyInfo for an Ed25519 public key (RFC 8410)."""
    alg_id = der_sequence(der_oid(OID_ED25519))
    return der_sequence(alg_id, der_bit_string(public_key_bytes))


def generate_libp2p_self_signed_cert(
    host_identity: PeerIdentity,
    validity_seconds: int = 86400,
    now: int | None = None,
) -> Libp2pCertificateBundle:
    """
    Generate a self-signed X.509 v3 certificate carrying the libp2p Public Key
    Extension (OID 1.3.6.1.4.1.53594.1.1) per Section 6.1 of the draft.

    Workflow:
    1. Generate a fresh ephemeral Ed25519 certificate keypair.
    2. Encode its DER SubjectPublicKeyInfo (`spki_der`).
    3. Sign `b"libp2p-tls-handshake:" + spki_der` using the peer's long-term
       host Ed25519 private key.
    4. Pack ASN.1 `SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }`
       into X.509 v3 Extension OID `1.3.6.1.4.1.53594.1.1`.
    5. Self-sign `TBSCertificate` with the ephemeral certificate private key.
    """
    now_ts = int(time.time()) if now is None else int(now)
    not_before = now_ts - 60  # small clock-skew grace
    not_after = now_ts + validity_seconds

    ephemeral_key = Ed25519PrivateKey()
    spki_der = build_ed25519_spki(ephemeral_key.public_bytes)

    # SignedKey signature binds the ephemeral TLS key to the long-term host identity.
    signed_key_sig = host_identity.private_key.sign(LIBP2P_HANDSHAKE_PREFIX + spki_der)
    signed_key_asn1 = der_sequence(
        der_octet_string(host_identity.public_bytes),
        der_octet_string(signed_key_sig),
    )

    # X.509 v3 Extension: SEQUENCE { extnID OID, critical BOOLEAN(TRUE), extnValue OCTET STRING }
    libp2p_ext = der_sequence(
        der_oid(LIBP2P_TLS_OID),
        der_tlv(0x01, b"\xff"),  # critical = TRUE
        der_octet_string(signed_key_asn1),
    )
    extensions_wrapper = der_explicit(3, der_sequence(libp2p_ext))

    serial = int.from_bytes(secrets.token_bytes(16), "big") | 1
    sig_alg = der_sequence(der_oid(OID_ED25519))
    name = der_sequence(
        der_set(der_sequence(der_oid(OID_COMMON_NAME), der_utf8_string(host_identity.label)))
    )
    validity = der_sequence(
        der_generalized_time(not_before),
        der_generalized_time(not_after),
    )

    tbs_cert = der_sequence(
        der_explicit(0, der_integer(2)),  # X.509 version v3 (=2)
        der_integer(serial),
        sig_alg,
        name,  # issuer
        validity,
        name,  # subject (self-signed)
        spki_der,
        extensions_wrapper,
    )

    cert_sig = ephemeral_key.sign(tbs_cert)
    cert_der = der_sequence(tbs_cert, sig_alg, der_bit_string(cert_sig))

    return Libp2pCertificateBundle(
        cert_der=cert_der,
        ephemeral_private_key=ephemeral_key,
        host_public_key=host_identity.public_key,
        not_before=not_before,
        not_after=not_after,
    )


def verify_libp2p_certificate_chain(
    cert_chain: list[bytes] | tuple[bytes, ...],
    now: int | None = None,
) -> VerifiedPeerCertificate:
    """
    Strictly verify a peer's X.509 certificate chain per Section 6.1:

    - MUST contain strictly ONE self-signed certificate (len != 1 -> terminate!).
    - Certificate MUST be valid at `now`.
    - Certificate self-signature MUST verify against its embedded Ed25519 SPKI.
    - MUST contain libp2p Public Key Extension OID `1.3.6.1.4.1.53594.1.1`.
    - SignedKey signature MUST verify `b"libp2p-tls-handshake:" + SPKI_DER` under
      the embedded host public key.
    """
    if len(cert_chain) != 1:
        raise TLSAuthenticationError(
            f"WIQC libp2p-tls requires exactly 1 self-signed certificate, got chain length {len(cert_chain)}"
        )

    cert_der = cert_chain[0]
    tag, cert_body, next_off, _ = parse_der_tlv(cert_der, 0)
    if tag != 0x30 or next_off != len(cert_der):
        raise TLSAuthenticationError("Outer X.509 certificate must be a single DER SEQUENCE")

    # Parse Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    tbs_tag, tbs_body, pos, tbs_raw = parse_der_tlv(cert_body, 0)
    if tbs_tag != 0x30:
        raise TLSAuthenticationError("TBSCertificate must be a DER SEQUENCE")
    _, sig_alg_body, pos, _ = parse_der_tlv(cert_body, pos)
    sig_tag, sig_bits, pos, _ = parse_der_tlv(cert_body, pos)
    if sig_tag != 0x03 or not sig_bits or sig_bits[0] != 0:
        raise TLSAuthenticationError("Invalid certificate signature BIT STRING")
    cert_signature = sig_bits[1:]

    # Verify outer signature algorithm is Ed25519
    alg_oid_tag, alg_oid_val, _, _ = parse_der_tlv(sig_alg_body, 0)
    if alg_oid_tag != 0x06 or decode_der_oid(alg_oid_val) != OID_ED25519:
        raise TLSAuthenticationError("Unsupported certificate signature algorithm (expected Ed25519)")

    # Walk TBSCertificate fields
    tpos = 0
    ver_tag, ver_inner, tpos, _ = parse_der_tlv(tbs_body, tpos)
    if ver_tag != 0xA0:
        raise TLSAuthenticationError("X.509 v3 explicit version [0] missing")
    _, ver_bytes, _, _ = parse_der_tlv(ver_inner, 0)
    if int.from_bytes(ver_bytes, "big") != 2:
        raise TLSAuthenticationError("Certificate must be X.509 v3")

    _, _, tpos, _ = parse_der_tlv(tbs_body, tpos)  # serialNumber
    _, _, tpos, _ = parse_der_tlv(tbs_body, tpos)  # signature
    _, _, tpos, _ = parse_der_tlv(tbs_body, tpos)  # issuer

    # Validity ::= SEQUENCE { notBefore, notAfter }
    val_tag, val_body, tpos, _ = parse_der_tlv(tbs_body, tpos)
    if val_tag != 0x30:
        raise TLSAuthenticationError("Invalid Validity SEQUENCE")
    nb_tag, nb_raw, vpos, _ = parse_der_tlv(val_body, 0)
    na_tag, na_raw, _, _ = parse_der_tlv(val_body, vpos)
    if nb_tag != 0x18 or na_tag != 0x18:
        raise TLSAuthenticationError("Expected GeneralizedTime in certificate validity")
    not_before = decode_der_generalized_time(nb_raw)
    not_after = decode_der_generalized_time(na_raw)

    now_ts = int(time.time()) if now is None else int(now)
    if not (not_before <= now_ts <= not_after):
        raise TLSAuthenticationError(
            f"Certificate expired or not yet valid (now={now_ts}, range=[{not_before}, {not_after}])"
        )

    _, _, tpos, _ = parse_der_tlv(tbs_body, tpos)  # subject

    # SubjectPublicKeyInfo (keep raw DER bytes for SignedKey verification!)
    spki_tag, spki_body, tpos, spki_raw = parse_der_tlv(tbs_body, tpos)
    if spki_tag != 0x30:
        raise TLSAuthenticationError("Invalid SubjectPublicKeyInfo")
    _, spki_alg, spos, _ = parse_der_tlv(spki_body, 0)
    spki_alg_tag, spki_alg_oid, _, _ = parse_der_tlv(spki_alg, 0)
    if spki_alg_tag != 0x06 or decode_der_oid(spki_alg_oid) != OID_ED25519:
        raise TLSAuthenticationError("SPKI algorithm must be Ed25519")
    pk_tag, pk_bits, _, _ = parse_der_tlv(spki_body, spos)
    if pk_tag != 0x03 or not pk_bits or pk_bits[0] != 0:
        raise TLSAuthenticationError("Invalid SPKI public key BIT STRING")
    try:
        ephemeral_pub = Ed25519PublicKey(pk_bits[1:])
    except CryptoError as exc:
        raise TLSAuthenticationError(f"Invalid ephemeral Ed25519 key in cert: {exc}") from exc

    # Verify self-signature on TBSCertificate
    if not ephemeral_pub.verify(cert_signature, tbs_raw):
        raise TLSAuthenticationError("X.509 self-signature verification failed")

    # Locate X.509 v3 extensions [3] EXPLICIT
    libp2p_ext_value: bytes | None = None
    while tpos < len(tbs_body):
        etag, ebody, tpos, _ = parse_der_tlv(tbs_body, tpos)
        if etag == 0xA3:
            seq_tag, ext_seq, _, _ = parse_der_tlv(ebody, 0)
            if seq_tag != 0x30:
                raise TLSAuthenticationError("Malformed X.509 Extensions SEQUENCE")
            epos = 0
            while epos < len(ext_seq):
                xtag, xbody, epos, _ = parse_der_tlv(ext_seq, epos)
                if xtag != 0x30:
                    raise TLSAuthenticationError("Malformed X.509 Extension entry")
                oid_t, oid_v, xpos, _ = parse_der_tlv(xbody, 0)
                if oid_t != 0x06:
                    continue
                oid_str = decode_der_oid(oid_v)
                nxt_t, nxt_v, xpos, _ = parse_der_tlv(xbody, xpos)
                if nxt_t == 0x01:  # optional critical BOOLEAN
                    nxt_t, nxt_v, xpos, _ = parse_der_tlv(xbody, xpos)
                if oid_str == LIBP2P_TLS_OID:
                    if nxt_t != 0x04:
                        raise TLSAuthenticationError("libp2p extension value must be OCTET STRING")
                    libp2p_ext_value = nxt_v

    if libp2p_ext_value is None:
        raise TLSAuthenticationError(
            f"Missing mandatory libp2p Public Key Extension (OID {LIBP2P_TLS_OID})"
        )

    # Parse SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
    sk_tag, sk_body, _, _ = parse_der_tlv(libp2p_ext_value, 0)
    if sk_tag != 0x30:
        raise TLSAuthenticationError("SignedKey must be a DER SEQUENCE")
    hpk_tag, host_pub_bytes, sk_pos, _ = parse_der_tlv(sk_body, 0)
    hsig_tag, host_sig_bytes, _, _ = parse_der_tlv(sk_body, sk_pos)
    if hpk_tag != 0x04 or hsig_tag != 0x04:
        raise TLSAuthenticationError("SignedKey fields must be OCTET STRINGs")

    try:
        host_pub = Ed25519PublicKey(host_pub_bytes)
    except CryptoError as exc:
        raise TLSAuthenticationError(f"Invalid host public key in SignedKey: {exc}") from exc

    if not host_pub.verify(host_sig_bytes, LIBP2P_HANDSHAKE_PREFIX + spki_raw):
        raise TLSAuthenticationError(
            "libp2p SignedKey signature verification failed over 'libp2p-tls-handshake:' + SPKI"
        )

    return VerifiedPeerCertificate(
        host_public_key=host_pub,
        ephemeral_public_key=ephemeral_pub,
        peer_id=host_pub.fingerprint(),
        certhash=hashlib.sha256(cert_der).digest(),
        not_before=not_before,
        not_after=not_after,
    )


# =============================================================================
# WebTransport Certhash In-Band Cryptographic Binding (Section 6.1)
# =============================================================================


@dataclass(frozen=True)
class WebTransportCerthashBinding:
    """
    In-band peer identity binding for browser-based HTTP/4 endpoints over
    WebTransport (Section 6.1 of draft-enger-httpbis-http4-wiqc-00).
    """

    certhash: bytes
    host_public_key: bytes
    nonce: bytes
    signature: bytes

    BINDING_DOMAIN = b"wiqc-webtransport-certhash-binding:"

    @classmethod
    def create(
        cls, identity: PeerIdentity, cert_der: bytes, nonce: bytes | None = None
    ) -> WebTransportCerthashBinding:
        certhash = hashlib.sha256(cert_der).digest()
        n = secrets.token_bytes(16) if nonce is None else nonce
        sig = identity.private_key.sign(cls.BINDING_DOMAIN + certhash + n)
        return cls(
            certhash=certhash,
            host_public_key=identity.public_bytes,
            nonce=n,
            signature=sig,
        )

    def encode(self) -> bytes:
        w = ByteWriter()
        w.write_varbytes(self.certhash)
        w.write_varbytes(self.host_public_key)
        w.write_varbytes(self.nonce)
        w.write_varbytes(self.signature)
        return w.to_bytes()

    @classmethod
    def decode(cls, data: bytes) -> WebTransportCerthashBinding:
        r = ByteReader(data)
        return cls(
            certhash=r.read_varbytes(64),
            host_public_key=r.read_varbytes(64),
            nonce=r.read_varbytes(64),
            signature=r.read_varbytes(128),
        )

    def verify(self, expected_certhash: bytes) -> bytes:
        """
        Verify certhash pin match and host signature. Returns verified 32-byte Peer ID.
        """
        if not hmac.compare_digest(self.certhash, expected_certhash):
            raise TLSAuthenticationError("WebTransport certhash mismatch")
        try:
            pub = Ed25519PublicKey(self.host_public_key)
        except CryptoError as exc:
            raise TLSAuthenticationError(f"Invalid host key in certhash binding: {exc}") from exc
        if not pub.verify(self.signature, self.BINDING_DOMAIN + self.certhash + self.nonce):
            raise TLSAuthenticationError("WebTransport certhash binding signature invalid")
        return pub.fingerprint()


# =============================================================================
# Mutual TLS 1.3-Derived Handshake + 0-RTT Session Tickets
# =============================================================================

TLS_MSG_CLIENT_HELLO = 1
TLS_MSG_SERVER_HELLO = 2
TLS_MSG_SERVER_AUTH = 3  # Encrypted Server Cert + CertificateVerify + Finished (+ optional ticket)
TLS_MSG_CLIENT_AUTH = 4  # Encrypted Client Cert + CertificateVerify + Finished


@dataclass(frozen=True)
class TrafficKeys:
    """Directional 1-RTT or 0-RTT ChaCha20-Poly1305 packet protection keys."""

    send_cipher: ChaCha20Poly1305
    send_iv: bytes
    recv_cipher: ChaCha20Poly1305
    recv_iv: bytes


@dataclass(frozen=True)
class ZeroRTTTicket:
    """
    Session resumption ticket enabling 0-RTT early data for idempotent HTTP/4
    operations (e.g., subscribing to public live tracks).
    """

    ticket_id: bytes
    psk: bytes  # 32-byte resumption master secret
    alpn: bytes
    server_peer_id: bytes
    issued_at: float
    ttl_seconds: float = 3600.0

    def derive_early_keys(self, is_client: bool) -> TrafficKeys:
        c2s_key = hkdf_expand_label(self.psk, b"wiqc 0rtt key", self.ticket_id, 32)
        c2s_iv = hkdf_expand_label(self.psk, b"wiqc 0rtt iv", self.ticket_id, 12)
        cipher = ChaCha20Poly1305(c2s_key)
        # 0-RTT is client -> server unidirectional early data.
        return TrafficKeys(
            send_cipher=cipher,
            send_iv=c2s_iv,
            recv_cipher=cipher,
            recv_iv=c2s_iv,
        )

    def is_expired(self, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        return t > (self.issued_at + self.ttl_seconds)


class MutualTLSHandshake:
    """
    Mutual TLS 1.3-derived handshake engine with libp2p self-signed certificates.

    Workflow (1-RTT Mutual Authentication):
        Client                                           Server
        ------                                           ------
        ClientHello (X25519 pub, ALPNs, opt 0-RTT id) ->
                                                      <- ServerHello (X25519 pub, ALPN)
                                                      <- ServerAuth [enc]: Cert(len=1, OID) +
                                                         CertVerify + Finished + Ticket
        [Client verifies Server Cert & Finished]
        ClientAuth [enc]: Cert(len=1, OID) +          ->
        CertVerify + Finished
                                                         [Server verifies Client Cert & Finished]
        <====== 1-RTT Bidirectional Encrypted WIQC Traffic ======>
    """

    def __init__(
        self,
        identity: PeerIdentity,
        is_server: bool,
        alpns: tuple[bytes, ...] = SUPPORTED_ALPNS,
        cert_bundle: Libp2pCertificateBundle | None = None,
        ticket_store: dict[bytes, ZeroRTTTicket] | None = None,
    ) -> None:
        self.identity = identity
        self.is_server = is_server
        self.alpns = alpns
        self.cert_bundle = cert_bundle or generate_libp2p_self_signed_cert(identity)
        self.ticket_store = ticket_store if ticket_store is not None else {}

        self._ecdh = X25519KeyPair()
        self._transcript = bytearray()
        self._handshake_secret: bytes | None = None
        self._hs_c2s_cipher: ChaCha20Poly1305 | None = None
        self._hs_s2c_cipher: ChaCha20Poly1305 | None = None
        self._hs_c2s_iv: bytes = b""
        self._hs_s2c_iv: bytes = b""
        self._client_fin_key: bytes = b""
        self._server_fin_key: bytes = b""

        self.negotiated_alpn: bytes | None = None
        self.peer_cert: VerifiedPeerCertificate | None = None
        self.app_keys: TrafficKeys | None = None
        self.received_ticket: ZeroRTTTicket | None = None
        self.used_0rtt_ticket: ZeroRTTTicket | None = None
        self.completed: bool = False

    def _transcript_hash(self) -> bytes:
        return hashlib.sha256(self._transcript).digest()

    def _derive_handshake_secrets(self, shared_secret: bytes) -> None:
        early = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        derived = hkdf_expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
        hs_secret = hkdf_extract(derived, shared_secret)
        self._handshake_secret = hs_secret

        th = self._transcript_hash()
        c_hs = hkdf_expand_label(hs_secret, b"c hs traffic", th, 32)
        s_hs = hkdf_expand_label(hs_secret, b"s hs traffic", th, 32)

        self._hs_c2s_cipher = ChaCha20Poly1305(hkdf_expand_label(c_hs, b"key", b"", 32))
        self._hs_c2s_iv = hkdf_expand_label(c_hs, b"iv", b"", 12)
        self._hs_s2c_cipher = ChaCha20Poly1305(hkdf_expand_label(s_hs, b"key", b"", 32))
        self._hs_s2c_iv = hkdf_expand_label(s_hs, b"iv", b"", 12)
        self._client_fin_key = hkdf_expand_label(c_hs, b"finished", b"", 32)
        self._server_fin_key = hkdf_expand_label(s_hs, b"finished", b"", 32)

    def _derive_application_keys(self) -> TrafficKeys:
        assert self._handshake_secret is not None
        derived = hkdf_expand_label(
            self._handshake_secret, b"derived", hashlib.sha256(b"").digest(), 32
        )
        master = hkdf_extract(derived, b"\x00" * 32)
        th = self._transcript_hash()
        c_app = hkdf_expand_label(master, b"c ap traffic", th, 32)
        s_app = hkdf_expand_label(master, b"s ap traffic", th, 32)

        c2s_cipher = ChaCha20Poly1305(hkdf_expand_label(c_app, b"key", b"", 32))
        c2s_iv = hkdf_expand_label(c_app, b"iv", b"", 12)
        s2c_cipher = ChaCha20Poly1305(hkdf_expand_label(s_app, b"key", b"", 32))
        s2c_iv = hkdf_expand_label(s_app, b"iv", b"", 12)

        if self.is_server:
            return TrafficKeys(
                send_cipher=s2c_cipher,
                send_iv=s2c_iv,
                recv_cipher=c2s_cipher,
                recv_iv=c2s_iv,
            )
        return TrafficKeys(
            send_cipher=c2s_cipher,
            send_iv=c2s_iv,
            recv_cipher=s2c_cipher,
            recv_iv=s2c_iv,
        )

    # ---- Client Step 1 ----
    def create_client_hello(self, zero_rtt_ticket: ZeroRTTTicket | None = None) -> bytes:
        if self.is_server:
            raise TLSAuthenticationError("Server cannot create ClientHello")
        w = ByteWriter()
        w.write_u8(TLS_MSG_CLIENT_HELLO)
        w.write_u16(0x0304)  # TLS 1.3
        w.write_bytes(secrets.token_bytes(32))  # client_random
        w.write_bytes(self._ecdh.public_bytes)  # 32-byte X25519 share
        w.write_u8(len(self.alpns))
        for alpn in self.alpns:
            w.write_varbytes(alpn)
        if zero_rtt_ticket is not None and not zero_rtt_ticket.is_expired():
            self.used_0rtt_ticket = zero_rtt_ticket
            w.write_varbytes(zero_rtt_ticket.ticket_id)
        else:
            w.write_varbytes(b"")
        msg = w.to_bytes()
        self._transcript.extend(msg)
        return msg

    # ---- Server Step 1 ----
    def process_client_hello(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Process ClientHello and produce (ServerHello, EncryptedServerAuth).
        """
        if not self.is_server:
            raise TLSAuthenticationError("Client cannot process ClientHello")
        r = ByteReader(data)
        if r.read_u8() != TLS_MSG_CLIENT_HELLO:
            raise TLSAuthenticationError("Expected ClientHello")
        version = r.read_u16()
        if version != 0x0304:
            raise TLSAuthenticationError(f"WIQC mandates TLS 1.3 (0x0304), got 0x{version:04x}")
        _client_random = r.read_bytes(32)
        client_x25519_pub = r.read_bytes(32)
        alpn_count = r.read_u8()
        client_alpns = [r.read_varbytes(32) for _ in range(alpn_count)]
        ticket_id = r.read_varbytes(64)

        selected: bytes | None = None
        for offered in client_alpns:
            if offered in self.alpns:
                selected = offered
                break
        if selected is None:
            raise TLSAuthenticationError(
                f"ALPN negotiation failed: client offered {client_alpns!r}, server supports {self.alpns!r}"
            )
        self.negotiated_alpn = selected

        if ticket_id and ticket_id in self.ticket_store:
            tkt = self.ticket_store[ticket_id]
            if not tkt.is_expired():
                self.used_0rtt_ticket = tkt

        self._transcript.extend(data)

        # Build ServerHello
        sh = ByteWriter()
        sh.write_u8(TLS_MSG_SERVER_HELLO)
        sh.write_u16(0x0304)
        sh.write_bytes(secrets.token_bytes(32))
        sh.write_bytes(self._ecdh.public_bytes)
        sh.write_varbytes(selected)
        server_hello = sh.to_bytes()
        self._transcript.extend(server_hello)

        # Derive handshake encryption keys
        shared = self._ecdh.shared_secret(client_x25519_pub)
        self._derive_handshake_secrets(shared)

        # Issue fresh 0-RTT ticket for future idempotent connections
        new_ticket = ZeroRTTTicket(
            ticket_id=secrets.token_bytes(16),
            psk=secrets.token_bytes(32),
            alpn=selected,
            server_peer_id=self.identity.peer_id,
            issued_at=time.time(),
        )
        self.ticket_store[new_ticket.ticket_id] = new_ticket

        # Build ServerAuth plaintext: cert_chain(len=1) + CertVerify + Finished + Ticket
        cert_verify_input = b"WIQC-TLS13-SERVER-CV:" + self._transcript_hash()
        cert_verify_sig = self.cert_bundle.ephemeral_private_key.sign(cert_verify_input)

        body = ByteWriter()
        body.write_u8(1)  # single self-signed cert
        body.write_varbytes(self.cert_bundle.cert_der)
        body.write_varbytes(cert_verify_sig)
        body.write_varbytes(new_ticket.ticket_id)
        body.write_varbytes(new_ticket.psk)
        auth_payload_without_fin = body.to_bytes()
        self._transcript.extend(auth_payload_without_fin)

        finished_mac = hmac.digest(self._server_fin_key, self._transcript_hash(), "sha256")
        self._transcript.extend(finished_mac)

        assert self._hs_s2c_cipher is not None
        enc_server_auth = self._hs_s2c_cipher.encrypt(
            self._hs_s2c_iv,
            auth_payload_without_fin + finished_mac,
            aad=b"WIQC-SERVER-AUTH",
        )
        outer = ByteWriter()
        outer.write_u8(TLS_MSG_SERVER_AUTH)
        outer.write_varbytes(enc_server_auth)
        return server_hello, outer.to_bytes()

    # ---- Client Step 2 ----
    def process_server_flight(
        self,
        server_hello: bytes,
        server_auth: bytes,
        override_client_cert_chain: list[bytes] | None = None,
    ) -> bytes:
        """
        Verify ServerHello & encrypted ServerAuth (including strict libp2p X.509
        chain check), then produce EncryptedClientAuth for Mutual TLS 1.3.

        `override_client_cert_chain` exists solely for negative security testing
        (e.g., verifying that the server rejects cert chains longer than 1).
        """
        if self.is_server:
            raise TLSAuthenticationError("Server cannot process server flight")

        r = ByteReader(server_hello)
        if r.read_u8() != TLS_MSG_SERVER_HELLO:
            raise TLSAuthenticationError("Expected ServerHello")
        if r.read_u16() != 0x0304:
            raise TLSAuthenticationError("Server did not negotiate TLS 1.3")
        _server_random = r.read_bytes(32)
        server_x25519_pub = r.read_bytes(32)
        selected_alpn = r.read_varbytes(32)
        if selected_alpn not in self.alpns:
            raise TLSAuthenticationError(f"Server selected unoffered ALPN: {selected_alpn!r}")
        self.negotiated_alpn = selected_alpn

        self._transcript.extend(server_hello)
        shared = self._ecdh.shared_secret(server_x25519_pub)
        self._derive_handshake_secrets(shared)

        # Decrypt ServerAuth
        ar = ByteReader(server_auth)
        if ar.read_u8() != TLS_MSG_SERVER_AUTH:
            raise TLSAuthenticationError("Expected ServerAuth")
        enc_blob = ar.read_varbytes()
        assert self._hs_s2c_cipher is not None
        try:
            plaintext = self._hs_s2c_cipher.decrypt(
                self._hs_s2c_iv, enc_blob, aad=b"WIQC-SERVER-AUTH"
            )
        except CryptoError as exc:
            raise TLSAuthenticationError(f"Failed to decrypt ServerAuth: {exc}") from exc

        if len(plaintext) < 32:
            raise TLSAuthenticationError("Truncated ServerAuth")
        auth_body = plaintext[:-32]
        server_fin = plaintext[-32:]

        pr = ByteReader(auth_body)
        cert_count = pr.read_u8()
        cert_chain = [pr.read_varbytes(16384) for _ in range(cert_count)]
        cert_verify_sig = pr.read_varbytes(128)
        ticket_id = pr.read_varbytes(64)
        ticket_psk = pr.read_varbytes(64)

        # Strict libp2p X.509 verification (chain length == 1, OID 1.3.6.1.4.1.53594.1.1)
        verified_server = verify_libp2p_certificate_chain(cert_chain)

        # Verify Server CertificateVerify against current transcript hash
        cv_input = b"WIQC-TLS13-SERVER-CV:" + self._transcript_hash()
        if not verified_server.ephemeral_public_key.verify(cert_verify_sig, cv_input):
            raise TLSAuthenticationError("Server CertificateVerify signature invalid")

        # Verify Server Finished MAC
        self._transcript.extend(auth_body)
        expected_fin = hmac.digest(self._server_fin_key, self._transcript_hash(), "sha256")
        if not hmac.compare_digest(server_fin, expected_fin):
            raise TLSAuthenticationError("Server Finished MAC mismatch")
        self._transcript.extend(server_fin)

        self.peer_cert = verified_server
        if ticket_id and ticket_psk:
            self.received_ticket = ZeroRTTTicket(
                ticket_id=ticket_id,
                psk=ticket_psk,
                alpn=selected_alpn,
                server_peer_id=verified_server.peer_id,
                issued_at=time.time(),
            )

        # Build Mutual-Auth ClientAuth: Client Cert + CertificateVerify + Finished
        client_cv_input = b"WIQC-TLS13-CLIENT-CV:" + self._transcript_hash()
        client_cv_sig = self.cert_bundle.ephemeral_private_key.sign(client_cv_input)

        chain_to_send = (
            override_client_cert_chain
            if override_client_cert_chain is not None
            else [self.cert_bundle.cert_der]
        )
        cb = ByteWriter()
        cb.write_u8(len(chain_to_send))
        for cert in chain_to_send:
            cb.write_varbytes(cert)
        cb.write_varbytes(client_cv_sig)
        client_auth_body = cb.to_bytes()
        self._transcript.extend(client_auth_body)

        client_fin = hmac.digest(self._client_fin_key, self._transcript_hash(), "sha256")
        self._transcript.extend(client_fin)

        assert self._hs_c2s_cipher is not None
        enc_client_auth = self._hs_c2s_cipher.encrypt(
            self._hs_c2s_iv,
            client_auth_body + client_fin,
            aad=b"WIQC-CLIENT-AUTH",
        )
        outer = ByteWriter()
        outer.write_u8(TLS_MSG_CLIENT_AUTH)
        outer.write_varbytes(enc_client_auth)

        # Derive 1-RTT application traffic keys!
        self.app_keys = self._derive_application_keys()
        self.completed = True
        return outer.to_bytes()

    # ---- Server Step 2 ----
    def process_client_auth(self, client_auth: bytes) -> VerifiedPeerCertificate:
        """
        Decrypt & strictly verify ClientAuth (Mutual TLS 1.3).
        Derives 1-RTT application keys upon success.
        """
        if not self.is_server:
            raise TLSAuthenticationError("Client cannot process ClientAuth")
        r = ByteReader(client_auth)
        if r.read_u8() != TLS_MSG_CLIENT_AUTH:
            raise TLSAuthenticationError("Expected ClientAuth")
        enc_blob = r.read_varbytes()

        assert self._hs_c2s_cipher is not None
        try:
            plaintext = self._hs_c2s_cipher.decrypt(
                self._hs_c2s_iv, enc_blob, aad=b"WIQC-CLIENT-AUTH"
            )
        except CryptoError as exc:
            raise TLSAuthenticationError(f"Failed to decrypt ClientAuth: {exc}") from exc

        if len(plaintext) < 32:
            raise TLSAuthenticationError("Truncated ClientAuth")
        auth_body = plaintext[:-32]
        client_fin = plaintext[-32:]

        pr = ByteReader(auth_body)
        cert_count = pr.read_u8()
        cert_chain = [pr.read_varbytes(16384) for _ in range(cert_count)]
        cert_verify_sig = pr.read_varbytes(128)

        # Strict libp2p X.509 check (rejects chains != 1, missing OID, bad signature)
        verified_client = verify_libp2p_certificate_chain(cert_chain)

        # Verify Client CertificateVerify
        cv_input = b"WIQC-TLS13-CLIENT-CV:" + self._transcript_hash()
        if not verified_client.ephemeral_public_key.verify(cert_verify_sig, cv_input):
            raise TLSAuthenticationError("Client CertificateVerify signature invalid")

        # Verify Client Finished MAC
        self._transcript.extend(auth_body)
        expected_fin = hmac.digest(self._client_fin_key, self._transcript_hash(), "sha256")
        if not hmac.compare_digest(client_fin, expected_fin):
            raise TLSAuthenticationError("Client Finished MAC mismatch")
        self._transcript.extend(client_fin)

        self.peer_cert = verified_client
        self.app_keys = self._derive_application_keys()
        self.completed = True
        return verified_client
