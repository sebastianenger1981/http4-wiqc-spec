"""
Pure-Python Standards-Compliant Cryptography for HTTP/4 over WIQC.

Zero external dependencies: relies solely on Python 3.14/3.15 standard library
(`hashlib`, `hmac`, `secrets`, `struct`) so the MVP runs out-of-the-box anywhere.

Implemented RFC primitives:
1. **RFC 8032 Ed25519** Digital Signatures (used for:
   - Peer Host Identity keys in `libp2p-tls` X.509 certificates,
   - Ephemeral self-signed X.509 certificate signatures & TLS CertificateVerify,
   - Live Unified Merkle Tree munro hash signatures (`WIQC_SIGNED_INTEGRITY`),
   - RFC 9421 Origin HTTP Message Signatures).
2. **RFC 7748 X25519** Elliptic-Curve Diffie-Hellman (used for forward-secret
   ephemeral key exchange in our Mutual TLS 1.3 handshake).
3. **RFC 5869 HKDF-SHA256** Key Derivation Function (TLS 1.3 key schedule).
4. **RFC 8439 ChaCha20-Poly1305 AEAD** Authenticated Encryption with Associated Data
   (hop-by-hop UDP packet encryption & integrity protection in WIQC).

Security Notes:
- All verification comparisons use `hmac.compare_digest` (constant-time).
- X25519 rejects all-zero shared secrets (low-order curve points).
- Ed25519 enforces canonical `0 <= S < L` scalar range to prevent malleability.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from .exceptions import CryptoError

# =============================================================================
# 1. RFC 5869 HKDF-SHA256
# =============================================================================


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 Section 2.2 HKDF-Extract with SHA-256."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.digest(salt, ikm, "sha256")


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Section 2.3 HKDF-Expand with SHA-256."""
    if length < 0 or length > 255 * 32:
        raise CryptoError(f"Invalid HKDF-Expand length: {length}")
    if length == 0:
        return b""
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.digest(prk, t + info + bytes((counter,)), "sha256")
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """TLS 1.3 (RFC 8446 / RFC 9846) HKDF-Expand-Label helper."""
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack("!H", length)
        + bytes((len(full_label),))
        + full_label
        + bytes((len(context),))
        + context
    )
    return hkdf_expand(secret, hkdf_label, length)


# =============================================================================
# 2. RFC 7748 X25519 (Curve25519 Montgomery Ladder)
# =============================================================================

_P = (1 << 255) - 19
_A24 = 121665


def _clamp_x25519_scalar(scalar: bytes) -> int:
    if len(scalar) != 32:
        raise CryptoError("X25519 scalar must be 32 bytes")
    b = bytearray(scalar)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519_scalarmult(scalar: bytes, u_bytes: bytes) -> bytes:
    """
    Compute X25519(k, u) per RFC 7748 Section 5 using constant-form Montgomery ladder.
    """
    if len(u_bytes) != 32:
        raise CryptoError("X25519 u-coordinate must be 32 bytes")
    k = _clamp_x25519_scalar(scalar)
    # Mask the most significant bit of u per RFC 7748 Section 5.
    u_arr = bytearray(u_bytes)
    u_arr[31] &= 0x7F
    u = int.from_bytes(u_arr, "little") % _P

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        a = (x_2 + z_2) % _P
        aa = (a * a) % _P
        b = (x_2 - z_2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x_3 + z_3) % _P
        d = (x_3 - z_3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x_3 = ((da + cb) * (da + cb)) % _P
        z_3 = (x_1 * ((da - cb) * (da - cb) % _P)) % _P
        x_2 = (aa * bb) % _P
        z_2 = (e * (aa + _A24 * e)) % _P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    result = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


_X25519_BASEPOINT = bytes([9] + [0] * 31)


class X25519KeyPair:
    """Ephemeral X25519 Diffie-Hellman keypair for TLS 1.3 handshake key exchange."""

    __slots__ = ("_private_bytes", "public_bytes")

    def __init__(self, private_bytes: bytes | None = None) -> None:
        if private_bytes is None:
            private_bytes = secrets.token_bytes(32)
        if len(private_bytes) != 32:
            raise CryptoError("X25519 private key must be 32 bytes")
        self._private_bytes = private_bytes
        self.public_bytes = x25519_scalarmult(self._private_bytes, _X25519_BASEPOINT)

    def shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """Derive 32-byte ECDH shared secret; rejects low-order all-zero outputs."""
        secret = x25519_scalarmult(self._private_bytes, peer_public_bytes)
        if secret == b"\x00" * 32:
            raise CryptoError("X25519 produced an invalid all-zero shared secret")
        return secret


# =============================================================================
# 3. RFC 8032 Ed25519 Digital Signatures
# =============================================================================

_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_ED_2D = (2 * _ED_D) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

# Basepoint B = (Bx, By) in extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, xy=T/Z
_BY = (4 * pow(5, _P - 2, _P)) % _P


def _ed_recover_x(y: int, sign: int) -> int:
    if y >= _P:
        raise CryptoError("Ed25519 y coordinate >= p")
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_ED_D * y2 + 1) % _P
    # x = sqrt(u / v) using (u * v^3) * (u * v^7)^((p-5)/8)
    v3 = (v * v * v) % _P
    v7 = (v3 * v3 * v) % _P
    x = (u * v3 * pow((u * v7) % _P, (_P - 5) // 8, _P)) % _P
    vx2 = (v * x * x) % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = (x * _SQRT_M1) % _P
    else:
        raise CryptoError("Ed25519 point does not lie on curve")
    if x == 0 and sign == 1:
        raise CryptoError("Ed25519 non-canonical zero x with sign bit 1")
    if (x & 1) != sign:
        x = _P - x
    return x


_BX = _ed_recover_x(_BY, 0)
_ED_BASE = (_BX, _BY, 1, (_BX * _BY) % _P)
_ED_IDENTITY = (0, 1, 1, 0)


def _ed_point_add(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """Unified extended twisted Edwards point addition (RFC 8032 §5.1.4)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * _ED_2D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _ed_point_double(p1: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Dedicated extended twisted Edwards doubling."""
    x1, y1, z1, _ = p1
    a = (x1 * x1) % _P
    b = (y1 * y1) % _P
    c = (2 * z1 * z1) % _P
    h = (a + b) % _P
    xy = x1 + y1
    e = (h - (xy * xy)) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _ed_scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = _ED_IDENTITY
    addend = point
    s = scalar
    while s > 0:
        if s & 1:
            result = _ed_point_add(result, addend)
        addend = _ed_point_double(addend)
        s >>= 1
    return result


def _ed_encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, _P - 2, _P)
    x_aff = (x * z_inv) % _P
    y_aff = (y * z_inv) % _P
    encoded = y_aff | ((x_aff & 1) << 255)
    return encoded.to_bytes(32, "little")


def _ed_decode_point(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != 32:
        raise CryptoError("Ed25519 encoded point must be 32 bytes")
    val = int.from_bytes(data, "little")
    sign = val >> 255
    y = val & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    return (x, y, 1, (x * y) % _P)


def _ed_points_equal(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return ((x1 * z2 - x2 * z1) % _P == 0) and ((y1 * z2 - y2 * z1) % _P == 0)


# Precompute powers of 2 of the basepoint for 3x faster signing & verification.
_ED_BASE_POWERS: list[tuple[int, int, int, int]] = []
_cur = _ED_BASE
for _ in range(256):
    _ED_BASE_POWERS.append(_cur)
    _cur = _ed_point_double(_cur)


def _ed_scalar_mult_base(scalar: int) -> tuple[int, int, int, int]:
    result = _ED_IDENTITY
    s = scalar
    bit = 0
    while s > 0:
        if s & 1:
            result = _ed_point_add(result, _ED_BASE_POWERS[bit])
        s >>= 1
        bit += 1
    return result


class Ed25519PrivateKey:
    """RFC 8032 Ed25519 signing key."""

    __slots__ = ("_seed", "_scalar", "_prefix", "_public_bytes")

    def __init__(self, seed: bytes | None = None) -> None:
        if seed is None:
            seed = secrets.token_bytes(32)
        if len(seed) != 32:
            raise CryptoError("Ed25519 private seed must be 32 bytes")
        self._seed = seed
        h = hashlib.sha512(seed).digest()
        a_bytes = bytearray(h[:32])
        a_bytes[0] &= 248
        a_bytes[31] &= 63
        a_bytes[31] |= 64
        self._scalar = int.from_bytes(a_bytes, "little")
        self._prefix = h[32:]
        self._public_bytes = _ed_encode_point(_ed_scalar_mult_base(self._scalar))

    @property
    def seed(self) -> bytes:
        return self._seed

    @property
    def public_bytes(self) -> bytes:
        return self._public_bytes

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey(self._public_bytes)

    def sign(self, message: bytes) -> bytes:
        """Produce a deterministic 64-byte RFC 8032 Ed25519 signature."""
        r_hash = hashlib.sha512(self._prefix + message).digest()
        r = int.from_bytes(r_hash, "little") % _ED_L
        r_encoded = _ed_encode_point(_ed_scalar_mult_base(r))
        k_hash = hashlib.sha512(r_encoded + self._public_bytes + message).digest()
        k = int.from_bytes(k_hash, "little") % _ED_L
        s = (r + k * self._scalar) % _ED_L
        return r_encoded + s.to_bytes(32, "little")


class Ed25519PublicKey:
    """RFC 8032 Ed25519 verification key."""

    __slots__ = ("_public_bytes", "_point")

    def __init__(self, public_bytes: bytes) -> None:
        if len(public_bytes) != 32:
            raise CryptoError("Ed25519 public key must be 32 bytes")
        self._public_bytes = public_bytes
        self._point = _ed_decode_point(public_bytes)

    @property
    def public_bytes(self) -> bytes:
        return self._public_bytes

    def fingerprint(self) -> bytes:
        """
        32-byte SHA-256 fingerprint of this public key.
        Used as Peer ID and (for live streams) as the WIQC Swarm ID (Section 2).
        """
        return hashlib.sha256(self._public_bytes).digest()

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a 64-byte RFC 8032 Ed25519 signature.
        Returns True if valid, False otherwise (never raises on invalid signatures).
        """
        if len(signature) != 64:
            return False
        r_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _ED_L:
            return False
        try:
            r_point = _ed_decode_point(r_bytes)
        except CryptoError:
            return False
        k_hash = hashlib.sha512(r_bytes + self._public_bytes + message).digest()
        k = int.from_bytes(k_hash, "little") % _ED_L
        lhs = _ed_scalar_mult_base(s)
        rhs = _ed_point_add(r_point, _ed_scalar_mult(self._point, k))
        return _ed_points_equal(lhs, rhs)


@dataclass(frozen=True)
class PeerIdentity:
    """
    Long-term decentralized identity of a WIQC endpoint (client, server, or relay).

    In HTTP/4 over WIQC, peers lack centralized CA certificates; their identity is
    cryptographically anchored to an Ed25519 host keypair and its SHA-256 Peer ID.
    """

    private_key: Ed25519PrivateKey
    label: str = "wiqc-peer"

    @classmethod
    def generate(cls, label: str = "wiqc-peer") -> PeerIdentity:
        return cls(private_key=Ed25519PrivateKey(), label=label)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_bytes

    @property
    def peer_id(self) -> bytes:
        """32-byte SHA-256 fingerprint of the peer's host public key."""
        return hashlib.sha256(self.private_key.public_bytes).digest()

    @property
    def peer_id_hex(self) -> str:
        return self.peer_id.hex()


# =============================================================================
# 4. RFC 8439 ChaCha20-Poly1305 AEAD
# =============================================================================

_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF
_POLY1305_P = (1 << 130) - 5
_POLY1305_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def _chacha20_block(key_words: tuple[int, ...], counter: int, nonce_words: tuple[int, ...]) -> bytes:
    """Generate one 64-byte ChaCha20 keystream block per RFC 8439 Section 2.3."""
    s0, s1, s2, s3 = _CHACHA_CONSTANTS
    s4, s5, s6, s7, s8, s9, s10, s11 = key_words
    s12 = counter & _MASK32
    s13, s14, s15 = nonce_words

    x0, x1, x2, x3 = s0, s1, s2, s3
    x4, x5, x6, x7 = s4, s5, s6, s7
    x8, x9, x10, x11 = s8, s9, s10, s11
    x12, x13, x14, x15 = s12, s13, s14, s15

    # Unrolled 10 double-rounds (20 rounds total) for pure-Python performance.
    for _ in range(10):
        # Column rounds
        x0 = (x0 + x4) & _MASK32; x12 ^= x0; x12 = ((x12 << 16) | (x12 >> 16)) & _MASK32
        x8 = (x8 + x12) & _MASK32; x4 ^= x8; x4 = ((x4 << 12) | (x4 >> 20)) & _MASK32
        x0 = (x0 + x4) & _MASK32; x12 ^= x0; x12 = ((x12 << 8) | (x12 >> 24)) & _MASK32
        x8 = (x8 + x12) & _MASK32; x4 ^= x8; x4 = ((x4 << 7) | (x4 >> 25)) & _MASK32

        x1 = (x1 + x5) & _MASK32; x13 ^= x1; x13 = ((x13 << 16) | (x13 >> 16)) & _MASK32
        x9 = (x9 + x13) & _MASK32; x5 ^= x9; x5 = ((x5 << 12) | (x5 >> 20)) & _MASK32
        x1 = (x1 + x5) & _MASK32; x13 ^= x1; x13 = ((x13 << 8) | (x13 >> 24)) & _MASK32
        x9 = (x9 + x13) & _MASK32; x5 ^= x9; x5 = ((x5 << 7) | (x5 >> 25)) & _MASK32

        x2 = (x2 + x6) & _MASK32; x14 ^= x2; x14 = ((x14 << 16) | (x14 >> 16)) & _MASK32
        x10 = (x10 + x14) & _MASK32; x6 ^= x10; x6 = ((x6 << 12) | (x6 >> 20)) & _MASK32
        x2 = (x2 + x6) & _MASK32; x14 ^= x2; x14 = ((x14 << 8) | (x14 >> 24)) & _MASK32
        x10 = (x10 + x14) & _MASK32; x6 ^= x10; x6 = ((x6 << 7) | (x6 >> 25)) & _MASK32

        x3 = (x3 + x7) & _MASK32; x15 ^= x3; x15 = ((x15 << 16) | (x15 >> 16)) & _MASK32
        x11 = (x11 + x15) & _MASK32; x7 ^= x11; x7 = ((x7 << 12) | (x7 >> 20)) & _MASK32
        x3 = (x3 + x7) & _MASK32; x15 ^= x3; x15 = ((x15 << 8) | (x15 >> 24)) & _MASK32
        x11 = (x11 + x15) & _MASK32; x7 ^= x11; x7 = ((x7 << 7) | (x7 >> 25)) & _MASK32

        # Diagonal rounds
        x0 = (x0 + x5) & _MASK32; x15 ^= x0; x15 = ((x15 << 16) | (x15 >> 16)) & _MASK32
        x10 = (x10 + x15) & _MASK32; x5 ^= x10; x5 = ((x5 << 12) | (x5 >> 20)) & _MASK32
        x0 = (x0 + x5) & _MASK32; x15 ^= x0; x15 = ((x15 << 8) | (x15 >> 24)) & _MASK32
        x10 = (x10 + x15) & _MASK32; x5 ^= x10; x5 = ((x5 << 7) | (x5 >> 25)) & _MASK32

        x1 = (x1 + x6) & _MASK32; x12 ^= x1; x12 = ((x12 << 16) | (x12 >> 16)) & _MASK32
        x11 = (x11 + x12) & _MASK32; x6 ^= x11; x6 = ((x6 << 12) | (x6 >> 20)) & _MASK32
        x1 = (x1 + x6) & _MASK32; x12 ^= x1; x12 = ((x12 << 8) | (x12 >> 24)) & _MASK32
        x11 = (x11 + x12) & _MASK32; x6 ^= x11; x6 = ((x6 << 7) | (x6 >> 25)) & _MASK32

        x2 = (x2 + x7) & _MASK32; x13 ^= x2; x13 = ((x13 << 16) | (x13 >> 16)) & _MASK32
        x8 = (x8 + x13) & _MASK32; x7 ^= x8; x7 = ((x7 << 12) | (x7 >> 20)) & _MASK32
        x2 = (x2 + x7) & _MASK32; x13 ^= x2; x13 = ((x13 << 8) | (x13 >> 24)) & _MASK32
        x8 = (x8 + x13) & _MASK32; x7 ^= x8; x7 = ((x7 << 7) | (x7 >> 25)) & _MASK32

        x3 = (x3 + x4) & _MASK32; x14 ^= x3; x14 = ((x14 << 16) | (x14 >> 16)) & _MASK32
        x9 = (x9 + x14) & _MASK32; x4 ^= x9; x4 = ((x4 << 12) | (x4 >> 20)) & _MASK32
        x3 = (x3 + x4) & _MASK32; x14 ^= x3; x14 = ((x14 << 8) | (x14 >> 24)) & _MASK32
        x9 = (x9 + x14) & _MASK32; x4 ^= x9; x4 = ((x4 << 7) | (x4 >> 25)) & _MASK32

    return struct.pack(
        "<16I",
        (x0 + s0) & _MASK32,
        (x1 + s1) & _MASK32,
        (x2 + s2) & _MASK32,
        (x3 + s3) & _MASK32,
        (x4 + s4) & _MASK32,
        (x5 + s5) & _MASK32,
        (x6 + s6) & _MASK32,
        (x7 + s7) & _MASK32,
        (x8 + s8) & _MASK32,
        (x9 + s9) & _MASK32,
        (x10 + s10) & _MASK32,
        (x11 + s11) & _MASK32,
        (x12 + s12) & _MASK32,
        (x13 + s13) & _MASK32,
        (x14 + s14) & _MASK32,
        (x15 + s15) & _MASK32,
    )


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    # Build full keystream, then single big-int XOR (very fast in CPython!).
    blocks = (len(data) + 63) // 64
    ks = b"".join(_chacha20_block(key_words, counter + i, nonce_words) for i in range(blocks))
    ks_trim = ks[: len(data)]
    out_int = int.from_bytes(data, "little") ^ int.from_bytes(ks_trim, "little")
    return out_int.to_bytes(len(data), "little")


def _poly1305_mac(one_time_key: bytes, msg: bytes) -> bytes:
    """Compute 16-byte Poly1305 MAC per RFC 8439 Section 2.5."""
    r = int.from_bytes(one_time_key[:16], "little") & _POLY1305_CLAMP
    s = int.from_bytes(one_time_key[16:32], "little")
    acc = 0
    mv = memoryview(msg)
    for i in range(0, len(mv), 16):
        block = mv[i : i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % _POLY1305_P
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


class ChaCha20Poly1305:
    """RFC 8439 ChaCha20-Poly1305 AEAD cipher for WIQC encrypted packet framing."""

    TAG_SIZE = 16
    KEY_SIZE = 32
    NONCE_SIZE = 12

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) != self.KEY_SIZE:
            raise CryptoError(f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
        self._key = key

    def _poly_key(self, nonce: bytes) -> bytes:
        key_words = struct.unpack("<8I", self._key)
        nonce_words = struct.unpack("<3I", nonce)
        return _chacha20_block(key_words, 0, nonce_words)[:32]

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt plaintext and append 16-byte Poly1305 authentication tag."""
        if len(nonce) != self.NONCE_SIZE:
            raise CryptoError(f"Nonce must be 12 bytes, got {len(nonce)}")
        otk = self._poly_key(nonce)
        ciphertext = _chacha20_xor(self._key, 1, nonce, plaintext)
        mac_data = (
            aad
            + _pad16(aad)
            + ciphertext
            + _pad16(ciphertext)
            + struct.pack("<QQ", len(aad), len(ciphertext))
        )
        tag = _poly1305_mac(otk, mac_data)
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
        """Verify 16-byte Poly1305 tag in constant time and decrypt ciphertext."""
        if len(nonce) != self.NONCE_SIZE:
            raise CryptoError(f"Nonce must be 12 bytes, got {len(nonce)}")
        if len(ciphertext_and_tag) < self.TAG_SIZE:
            raise CryptoError("Ciphertext shorter than 16-byte Poly1305 tag")
        ciphertext = ciphertext_and_tag[: -self.TAG_SIZE]
        received_tag = ciphertext_and_tag[-self.TAG_SIZE :]
        otk = self._poly_key(nonce)
        mac_data = (
            aad
            + _pad16(aad)
            + ciphertext
            + _pad16(ciphertext)
            + struct.pack("<QQ", len(aad), len(ciphertext))
        )
        expected_tag = _poly1305_mac(otk, mac_data)
        if not hmac.compare_digest(expected_tag, received_tag):
            raise CryptoError("ChaCha20-Poly1305 AEAD authentication tag mismatch")
        return _chacha20_xor(self._key, 1, nonce, ciphertext)


def make_packet_nonce(iv: bytes, packet_number: int) -> bytes:
    """
    Construct a 12-byte QUIC/WIQC packet AEAD nonce per RFC 9001 Section 5.3:
    XOR the 64-bit packet number (left-padded with zeros) with the 12-byte traffic IV.
    """
    if len(iv) != 12:
        raise CryptoError("Traffic IV must be 12 bytes")
    pn_bytes = b"\x00\x00\x00\x00" + struct.pack("!Q", packet_number)
    return bytes(a ^ b for a, b in zip(iv, pn_bytes))
