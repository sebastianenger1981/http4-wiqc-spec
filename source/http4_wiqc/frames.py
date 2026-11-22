"""
HTTP/4 over WIQC Stream Types, Wire Frames, NAT Traversal Frames, and Capsules.

Implements Section 5.1, Section 5.2, Section 5.3.4, and Section 6.2 of
`draft-enger-httpbis-http4-wiqc-00`:

1. **HTTP/4 Stream Type IDs (Section 5.1)**:
   - `0x00`: Control Stream (Unidirectional pair)
   - `0x01`: Push Stream (Unidirectional)
   - `0x02`: QPACK Encoder Stream (Unidirectional)
   - `0x03`: QPACK Decoder Stream (Unidirectional)
   - `0x40`: WIQC Swarm Subgroup Stream (Unidirectional)
   - `0x41`: WIQC Swarm Control Stream (Bidirectional)

2. **HTTP/4 Standard & WIQC Swarm Frames (Section 5.2)** — RFC 9114 §7.1 layout
   `Type (VarInt) | Length (VarInt) | Payload (Length bytes)`:
   - `0x00`: `DATA`
   - `0x01`: `HEADERS`
   - `0x03`: `CANCEL_PUSH`
   - `0x04`: `SETTINGS`
   - `0x05`: `PUSH_PROMISE`
   - `0x07`: `GOAWAY`
   - `0x0d`: `MAX_PUSH_ID`
   - `0x4101`: `WIQC_HAVE` (64-bit or 32-bit bin ranges)
   - `0x4102`: `WIQC_INTEGRITY` (uncle hashes / Merkle branch proofs)
   - `0x4103`: `WIQC_SIGNED_INTEGRITY` (publisher-signed munro root hashes)
   - `0x4104`: `WIQC_PEX` (Peer Exchange: PEX_REQ, PEX_RESv4, PEX_RESv6)
   - Swarm Control companion wire frames on Stream `0x41`:
     `0x4105` `WIQC_REQUEST`, `0x4106` `WIQC_CANCEL`, `0x4107` `WIQC_CHOKE`,
     `0x4108` `WIQC_UNCHOKE`, `0x4109` `WIQC_HANDSHAKE_CAPS` (RFC 7574 options),
     `0x4115` `WIQC_BEP52_HASH_MSG` (wraps BEP 52 IDs 21/22/23),
     `0x4120` `WIQC_SUBGROUP_OBJECT` (MOQT Object payload on Stream `0x40`).

3. **Native WIQC NAT Traversal Frames (Section 6.2, I-D.seemann-quic-nat-traversal)**:
   - `0x1a`: `PATH_CHALLENGE` (RFC 9000)
   - `0x1b`: `PATH_RESPONSE` (RFC 9000)
   - `0x3d7e90`: `ADD_ADDRESS_IPV4`
   - `0x3d7e91`: `ADD_ADDRESS_IPV6`
   - `0x3d7e92`: `PUNCH_ME_NOW_IPV4`
   - `0x3d7e93`: `PUNCH_ME_NOW_IPV6`
   - `0x3d7e94`: `REMOVE_ADDRESS`
   - `0x3d7e95`: `PUNCH_REQUEST` (grant-based hole-punch request)
   - `0x9f81a6`: `OBSERVED_ADDRESS_IPV4` / `0x9f81a7`: `OBSERVED_ADDRESS_IPV6`

4. **HTTP Capsule Protocol (RFC 9297, Section 5.3.4)**:
   - `0x00`: `DATAGRAM` Capsule for traversing HTTP intermediaries.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from enum import IntEnum

from .exceptions import WireFormatError
from .merkle import SHA256_LEN, SignedMunro, UncleProofEntry
from .varint import ByteReader, ByteWriter, decode_varint, encode_varint


# =============================================================================
# Stream Types (Section 5.1)
# =============================================================================


class StreamType(IntEnum):
    """HTTP/4 over WIQC Stream Type Identifiers (Section 5.1)."""

    CONTROL = 0x00
    PUSH = 0x01
    QPACK_ENCODER = 0x02
    QPACK_DECODER = 0x03
    WIQC_SWARM_SUBGROUP = 0x40
    WIQC_SWARM_CONTROL = 0x41


# =============================================================================
# Frame Types (Section 5.2 & Section 6.2)
# =============================================================================


class FrameType(IntEnum):
    """HTTP/4 Standard Frames and WIQC Extension Frame Types."""

    # Standard HTTP/3+4 Frames (RFC 9114)
    DATA = 0x00
    HEADERS = 0x01
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0D

    # Normative WIQC Swarm Frames (Section 5.2 Table)
    WIQC_HAVE = 0x4101
    WIQC_INTEGRITY = 0x4102
    WIQC_SIGNED_INTEGRITY = 0x4103
    WIQC_PEX = 0x4104

    # Swarm Control & Subgroup Companion Frames (Stream 0x41 & 0x40)
    WIQC_REQUEST = 0x4105
    WIQC_CANCEL = 0x4106
    WIQC_CHOKE = 0x4107
    WIQC_UNCHOKE = 0x4108
    WIQC_HANDSHAKE_CAPS = 0x4109
    WIQC_BEP52_HASH_MSG = 0x4115
    WIQC_SUBGROUP_OBJECT = 0x4120


class SettingsID(IntEnum):
    """HTTP/4 SETTINGS identifiers (RFC 9114 + RFC 9204 + RFC 9297 + WIQC)."""

    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE = 0x06
    QPACK_BLOCKED_STREAMS = 0x07
    H3_DATAGRAM = 0x33
    WIQC_MAX_SWARM_PEERS = 0x4100
    WIQC_LIVE_DISCARD_WINDOW = 0x4101
    WIQC_CHUNK_ADDRESSING = 0x4102


class PEXSubType(IntEnum):
    """RFC 7574 Peer Exchange sub-types inside `WIQC_PEX` (0x4104)."""

    PEX_REQ = 0x01
    PEX_RESv4 = 0x02
    PEX_RESv6 = 0x03


class NATFrameType(IntEnum):
    """Native WIQC NAT Traversal & Path Validation Transport Frame Types."""

    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    ADD_ADDRESS_V4 = 0x3D7E90
    ADD_ADDRESS_V6 = 0x3D7E91
    PUNCH_ME_NOW_V4 = 0x3D7E92
    PUNCH_ME_NOW_V6 = 0x3D7E93
    REMOVE_ADDRESS = 0x3D7E94
    PUNCH_REQUEST = 0x3D7E95
    OBSERVED_ADDRESS_V4 = 0x9F81A6
    OBSERVED_ADDRESS_V6 = 0x9F81A7


# =============================================================================
# Generic HTTP/4 Frame Envelope: Type (i), Length (i), Payload (..)
# =============================================================================


@dataclass(frozen=True)
class RawFrame:
    """Generic RFC 9114 Section 7.1 HTTP/4 frame envelope."""

    frame_type: int
    payload: bytes

    def encode(self) -> bytes:
        return (
            encode_varint(self.frame_type)
            + encode_varint(len(self.payload))
            + self.payload
        )

    @classmethod
    def decode_from_reader(cls, reader: ByteReader) -> RawFrame:
        ft = reader.read_varint()
        length = reader.read_varint()
        payload = reader.read_bytes(length)
        return cls(frame_type=ft, payload=payload)

    @classmethod
    def decode_all(cls, data: bytes) -> list[RawFrame]:
        reader = ByteReader(data)
        frames: list[RawFrame] = []
        while not reader.eof():
            frames.append(cls.decode_from_reader(reader))
        return frames


# =============================================================================
# Typed HTTP/4 Standard Frames
# =============================================================================


@dataclass(frozen=True)
class DataFrame:
    data: bytes

    def to_raw(self) -> RawFrame:
        return RawFrame(FrameType.DATA, self.data)

    @classmethod
    def from_payload(cls, payload: bytes) -> DataFrame:
        return cls(data=payload)


@dataclass(frozen=True)
class HeadersFrame:
    encoded_field_section: bytes

    def to_raw(self) -> RawFrame:
        return RawFrame(FrameType.HEADERS, self.encoded_field_section)

    @classmethod
    def from_payload(cls, payload: bytes) -> HeadersFrame:
        return cls(encoded_field_section=payload)


@dataclass(frozen=True)
class SettingsFrame:
    settings: dict[int, int] = field(default_factory=dict)

    def to_raw(self) -> RawFrame:
        w = ByteWriter()
        for k, v in self.settings.items():
            w.write_varint(k)
            w.write_varint(v)
        return RawFrame(FrameType.SETTINGS, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> SettingsFrame:
        r = ByteReader(payload)
        parsed: dict[int, int] = {}
        while not r.eof():
            k = r.read_varint()
            v = r.read_varint()
            if k in parsed:
                raise WireFormatError(f"Duplicate SETTINGS identifier: 0x{k:x}")
            parsed[k] = v
        return cls(settings=parsed)


@dataclass(frozen=True)
class PushPromiseFrame:
    push_id: int
    encoded_field_section: bytes

    def to_raw(self) -> RawFrame:
        w = ByteWriter()
        w.write_varint(self.push_id)
        w.write_bytes(self.encoded_field_section)
        return RawFrame(FrameType.PUSH_PROMISE, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> PushPromiseFrame:
        r = ByteReader(payload)
        push_id = r.read_varint()
        return cls(push_id=push_id, encoded_field_section=r.read_rest())


@dataclass(frozen=True)
class CancelPushFrame:
    push_id: int

    def to_raw(self) -> RawFrame:
        return RawFrame(FrameType.CANCEL_PUSH, encode_varint(self.push_id))

    @classmethod
    def from_payload(cls, payload: bytes) -> CancelPushFrame:
        r = ByteReader(payload)
        return cls(push_id=r.read_varint())


@dataclass(frozen=True)
class GoAwayFrame:
    last_stream_or_push_id: int

    def to_raw(self) -> RawFrame:
        return RawFrame(FrameType.GOAWAY, encode_varint(self.last_stream_or_push_id))

    @classmethod
    def from_payload(cls, payload: bytes) -> GoAwayFrame:
        r = ByteReader(payload)
        return cls(last_stream_or_push_id=r.read_varint())


@dataclass(frozen=True)
class MaxPushIdFrame:
    max_push_id: int

    def to_raw(self) -> RawFrame:
        return RawFrame(FrameType.MAX_PUSH_ID, encode_varint(self.max_push_id))

    @classmethod
    def from_payload(cls, payload: bytes) -> MaxPushIdFrame:
        r = ByteReader(payload)
        return cls(max_push_id=r.read_varint())


# =============================================================================
# Typed Normative WIQC Swarm Frames (0x4101 .. 0x4104 + Control Frames)
# =============================================================================


@dataclass(frozen=True)
class WIQCHaveFrame:
    """
    `WIQC_HAVE` (0x4101): Announces possession of verified 64-bit (or 32-bit)
    bin ranges per RFC 7574. Permitted on WIQC Swarm Control Stream (0x41).
    """

    swarm_id: bytes
    bins: tuple[int, ...]
    use_bin64: bool = True

    def to_raw(self) -> RawFrame:
        if len(self.swarm_id) != SHA256_LEN:
            raise WireFormatError("WIQC_HAVE requires 32-byte swarm_id")
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_u8(0x03 if self.use_bin64 else 0x02)
        w.write_varint(len(self.bins))
        for b in self.bins:
            if self.use_bin64:
                w.write_u64(b)
            else:
                w.write_u32(b)
        return RawFrame(FrameType.WIQC_HAVE, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCHaveFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        addr_mode = r.read_u8()
        if addr_mode not in (0x02, 0x03):
            raise WireFormatError(f"Unsupported chunk addressing mode in WIQC_HAVE: {addr_mode}")
        use_bin64 = addr_mode == 0x03
        count = r.read_varint()
        bins = tuple(r.read_u64() if use_bin64 else r.read_u32() for _ in range(count))
        return cls(swarm_id=swarm_id, bins=bins, use_bin64=use_bin64)


@dataclass(frozen=True)
class WIQCIntegrityFrame:
    """
    `WIQC_INTEGRITY` (0x4102): Carries uncle hashes or Merkle branch proofs
    (RFC 7574 & BEP 52). Permitted on WIQC Swarm Subgroup (0x40) & Control (0x41).
    """

    swarm_id: bytes
    target_bin: int
    uncles: tuple[UncleProofEntry, ...]

    def to_raw(self) -> RawFrame:
        if len(self.swarm_id) != SHA256_LEN:
            raise WireFormatError("WIQC_INTEGRITY requires 32-byte swarm_id")
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_u64(self.target_bin)
        w.write_varint(len(self.uncles))
        for u in self.uncles:
            w.write_u64(u.bin_id)
            w.write_bytes(u.digest)
        return RawFrame(FrameType.WIQC_INTEGRITY, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCIntegrityFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        target_bin = r.read_u64()
        count = r.read_varint()
        uncles = tuple(
            UncleProofEntry(bin_id=r.read_u64(), digest=r.read_bytes(SHA256_LEN))
            for _ in range(count)
        )
        return cls(swarm_id=swarm_id, target_bin=target_bin, uncles=uncles)


@dataclass(frozen=True)
class WIQCSignedIntegrityFrame:
    """
    `WIQC_SIGNED_INTEGRITY` (0x4103): Carries publisher-signed munro root hashes
    for decentralized real-time streaming (RFC 7574 CIPM 3).
    """

    swarm_id: bytes
    signed_munro: SignedMunro

    def to_raw(self) -> RawFrame:
        if len(self.swarm_id) != SHA256_LEN:
            raise WireFormatError("WIQC_SIGNED_INTEGRITY requires 32-byte swarm_id")
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_u64(self.signed_munro.munro_bin)
        w.write_bytes(self.signed_munro.munro_hash)
        w.write_u64(self.signed_munro.timestamp_us)
        w.write_u64(self.signed_munro.group_id)
        w.write_varbytes(self.signed_munro.signature)
        return RawFrame(FrameType.WIQC_SIGNED_INTEGRITY, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCSignedIntegrityFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        munro_bin = r.read_u64()
        munro_hash = r.read_bytes(SHA256_LEN)
        timestamp_us = r.read_u64()
        group_id = r.read_u64()
        signature = r.read_varbytes(128)
        return cls(
            swarm_id=swarm_id,
            signed_munro=SignedMunro(
                munro_bin=munro_bin,
                munro_hash=munro_hash,
                timestamp_us=timestamp_us,
                group_id=group_id,
                signature=signature,
            ),
        )


@dataclass(frozen=True)
class PeerEndpoint:
    """Network endpoint exchanged via `WIQC_PEX` (0x4104)."""

    host: str
    port: int
    peer_id: bytes = b""


@dataclass(frozen=True)
class WIQCPexFrame:
    """
    `WIQC_PEX` (0x4104): Peer Exchange (`PEX_REQ`, `PEX_RESv4`, `PEX_RESv6`)
    for trackerless decentralized peer discovery (RFC 7574).
    """

    subtype: PEXSubType
    swarm_id: bytes
    peers: tuple[PeerEndpoint, ...] = ()

    def to_raw(self) -> RawFrame:
        if len(self.swarm_id) != SHA256_LEN:
            raise WireFormatError("WIQC_PEX requires 32-byte swarm_id")
        w = ByteWriter()
        w.write_u8(int(self.subtype))
        w.write_bytes(self.swarm_id)
        if self.subtype in (PEXSubType.PEX_RESv4, PEXSubType.PEX_RESv6):
            w.write_varint(len(self.peers))
            for peer in self.peers:
                ip = ipaddress.ip_address(peer.host)
                if self.subtype == PEXSubType.PEX_RESv4:
                    if ip.version != 4:
                        raise WireFormatError(f"Expected IPv4 for PEX_RESv4, got {peer.host}")
                    w.write_bytes(ip.packed)
                else:
                    if ip.version != 6:
                        raise WireFormatError(f"Expected IPv6 for PEX_RESv6, got {peer.host}")
                    w.write_bytes(ip.packed)
                w.write_u16(peer.port)
                w.write_varbytes(peer.peer_id)
        return RawFrame(FrameType.WIQC_PEX, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCPexFrame:
        r = ByteReader(payload)
        subtype = PEXSubType(r.read_u8())
        swarm_id = r.read_bytes(SHA256_LEN)
        peers: list[PeerEndpoint] = []
        if subtype in (PEXSubType.PEX_RESv4, PEXSubType.PEX_RESv6):
            count = r.read_varint()
            ip_len = 4 if subtype == PEXSubType.PEX_RESv4 else 16
            for _ in range(count):
                packed = r.read_bytes(ip_len)
                host = str(ipaddress.ip_address(packed))
                port = r.read_u16()
                pid = r.read_varbytes(64)
                peers.append(PeerEndpoint(host=host, port=port, peer_id=pid))
        return cls(subtype=subtype, swarm_id=swarm_id, peers=tuple(peers))


@dataclass(frozen=True)
class WIQCRequestFrame:
    """Swarm Control `REQUEST` frame (0x4105): request specific bins/chunks with priority."""

    swarm_id: bytes
    bins: tuple[int, ...]
    priority_urgency: int = 3  # RFC 9218 urgency 0..7 (0 = highest)
    deadline_ms: int = 0  # 0 = static/no hard playback deadline

    def to_raw(self) -> RawFrame:
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_u8(self.priority_urgency & 0x07)
        w.write_varint(self.deadline_ms)
        w.write_varint(len(self.bins))
        for b in self.bins:
            w.write_u64(b)
        return RawFrame(FrameType.WIQC_REQUEST, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCRequestFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        urgency = r.read_u8()
        deadline_ms = r.read_varint()
        count = r.read_varint()
        bins = tuple(r.read_u64() for _ in range(count))
        return cls(swarm_id=swarm_id, bins=bins, priority_urgency=urgency, deadline_ms=deadline_ms)


@dataclass(frozen=True)
class WIQCCancelFrame:
    """Swarm Control `CANCEL` frame (0x4106): cancel pending bin requests."""

    swarm_id: bytes
    bins: tuple[int, ...]

    def to_raw(self) -> RawFrame:
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_varint(len(self.bins))
        for b in self.bins:
            w.write_u64(b)
        return RawFrame(FrameType.WIQC_CANCEL, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCCancelFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        count = r.read_varint()
        return cls(swarm_id=swarm_id, bins=tuple(r.read_u64() for _ in range(count)))


@dataclass(frozen=True)
class WIQCChokeFrame:
    """Swarm Control `CHOKE` (0x4107) or `UNCHOKE` (0x4108) frame."""

    swarm_id: bytes
    choked: bool

    def to_raw(self) -> RawFrame:
        ft = FrameType.WIQC_CHOKE if self.choked else FrameType.WIQC_UNCHOKE
        return RawFrame(ft, self.swarm_id)

    @classmethod
    def from_raw(cls, raw: RawFrame) -> WIQCChokeFrame:
        if len(raw.payload) != SHA256_LEN:
            raise WireFormatError("CHOKE/UNCHOKE payload must be 32-byte swarm_id")
        return cls(swarm_id=raw.payload, choked=(raw.frame_type == FrameType.WIQC_CHOKE))


@dataclass(frozen=True)
class WIQCSubgroupObjectFrame:
    """
    MOQT Object carried on a unidirectional WIQC Swarm Subgroup Stream (0x40).
    Paired with `WIQC_INTEGRITY` (0x4102) and optional `WIQC_SIGNED_INTEGRITY` (0x4103).
    """

    swarm_id: bytes
    track_name: str
    group_id: int
    subgroup_id: int
    object_id: int
    chunk_index: int
    priority_urgency: int
    is_keyframe: bool
    deadline_ms: int
    payload: bytes

    def to_raw(self) -> RawFrame:
        w = ByteWriter()
        w.write_bytes(self.swarm_id)
        w.write_varbytes(self.track_name.encode("utf-8"))
        w.write_varint(self.group_id)
        w.write_varint(self.subgroup_id)
        w.write_varint(self.object_id)
        w.write_varint(self.chunk_index)
        flags = (self.priority_urgency & 0x07) | (0x80 if self.is_keyframe else 0x00)
        w.write_u8(flags)
        w.write_varint(self.deadline_ms)
        w.write_varbytes(self.payload)
        return RawFrame(FrameType.WIQC_SUBGROUP_OBJECT, w.to_bytes())

    @classmethod
    def from_payload(cls, payload: bytes) -> WIQCSubgroupObjectFrame:
        r = ByteReader(payload)
        swarm_id = r.read_bytes(SHA256_LEN)
        track_name = r.read_varbytes(256).decode("utf-8")
        group_id = r.read_varint()
        subgroup_id = r.read_varint()
        object_id = r.read_varint()
        chunk_index = r.read_varint()
        flags = r.read_u8()
        urgency = flags & 0x07
        is_keyframe = bool(flags & 0x80)
        deadline_ms = r.read_varint()
        obj_payload = r.read_varbytes()
        return cls(
            swarm_id=swarm_id,
            track_name=track_name,
            group_id=group_id,
            subgroup_id=subgroup_id,
            object_id=object_id,
            chunk_index=chunk_index,
            priority_urgency=urgency,
            is_keyframe=is_keyframe,
            deadline_ms=deadline_ms,
            payload=obj_payload,
        )


# =============================================================================
# Native WIQC NAT Traversal Frames (Section 6.2)
# =============================================================================


@dataclass(frozen=True)
class ObservedAddressFrame:
    """`OBSERVED_ADDRESS`: Relay/seed tells joining peer its external UDP address."""

    host: str
    port: int
    sequence: int = 0

    def encode(self) -> bytes:
        ip = ipaddress.ip_address(self.host)
        ft = NATFrameType.OBSERVED_ADDRESS_V4 if ip.version == 4 else NATFrameType.OBSERVED_ADDRESS_V6
        w = ByteWriter()
        w.write_varint(int(ft))
        w.write_varint(self.sequence)
        w.write_bytes(ip.packed)
        w.write_u16(self.port)
        return w.to_bytes()

    @classmethod
    def decode(cls, frame_type: int, reader: ByteReader) -> ObservedAddressFrame:
        seq = reader.read_varint()
        ip_len = 4 if frame_type == NATFrameType.OBSERVED_ADDRESS_V4 else 16
        host = str(ipaddress.ip_address(reader.read_bytes(ip_len)))
        port = reader.read_u16()
        return cls(host=host, port=port, sequence=seq)


@dataclass(frozen=True)
class AddAddressFrame:
    """`ADD_ADDRESS` (0x3d7e90 IPv4 / 0x3d7e91 IPv6): Advertise candidate UDP address."""

    sequence: int
    host: str
    port: int

    def encode(self) -> bytes:
        ip = ipaddress.ip_address(self.host)
        ft = NATFrameType.ADD_ADDRESS_V4 if ip.version == 4 else NATFrameType.ADD_ADDRESS_V6
        w = ByteWriter()
        w.write_varint(int(ft))
        w.write_varint(self.sequence)
        w.write_bytes(ip.packed)
        w.write_u16(self.port)
        return w.to_bytes()

    @classmethod
    def decode(cls, frame_type: int, reader: ByteReader) -> AddAddressFrame:
        seq = reader.read_varint()
        ip_len = 4 if frame_type == NATFrameType.ADD_ADDRESS_V4 else 16
        host = str(ipaddress.ip_address(reader.read_bytes(ip_len)))
        port = reader.read_u16()
        return cls(sequence=seq, host=host, port=port)


@dataclass(frozen=True)
class RemoveAddressFrame:
    """`REMOVE_ADDRESS` (0x3d7e94): Withdraw previously advertised candidate address."""

    sequence: int

    def encode(self) -> bytes:
        w = ByteWriter()
        w.write_varint(int(NATFrameType.REMOVE_ADDRESS))
        w.write_varint(self.sequence)
        return w.to_bytes()

    @classmethod
    def decode(cls, reader: ByteReader) -> RemoveAddressFrame:
        return cls(sequence=reader.read_varint())


@dataclass(frozen=True)
class PunchMeNowFrame:
    """
    `PUNCH_ME_NOW` (0x3d7e92 IPv4 / 0x3d7e93 IPv6): Coordinate simultaneous UDP
    hole punching toward the specified peer address on a synchronized round.
    """

    round_num: int
    paired_with_seq: int
    host: str
    port: int

    def encode(self) -> bytes:
        ip = ipaddress.ip_address(self.host)
        ft = NATFrameType.PUNCH_ME_NOW_V4 if ip.version == 4 else NATFrameType.PUNCH_ME_NOW_V6
        w = ByteWriter()
        w.write_varint(int(ft))
        w.write_varint(self.round_num)
        w.write_varint(self.paired_with_seq)
        w.write_bytes(ip.packed)
        w.write_u16(self.port)
        return w.to_bytes()

    @classmethod
    def decode(cls, frame_type: int, reader: ByteReader) -> PunchMeNowFrame:
        round_num = reader.read_varint()
        paired = reader.read_varint()
        ip_len = 4 if frame_type == NATFrameType.PUNCH_ME_NOW_V4 else 16
        host = str(ipaddress.ip_address(reader.read_bytes(ip_len)))
        port = reader.read_u16()
        return cls(round_num=round_num, paired_with_seq=paired, host=host, port=port)


@dataclass(frozen=True)
class PunchRequestFrame:
    """Grant-based `PUNCH_REQUEST` frame for relay-coordinated UDP hole punching."""

    target_peer_id: bytes
    grant_token: bytes
    candidate_host: str
    candidate_port: int

    def encode(self) -> bytes:
        ip = ipaddress.ip_address(self.candidate_host)
        w = ByteWriter()
        w.write_varint(int(NATFrameType.PUNCH_REQUEST))
        w.write_varbytes(self.target_peer_id)
        w.write_varbytes(self.grant_token)
        w.write_u8(4 if ip.version == 4 else 6)
        w.write_bytes(ip.packed)
        w.write_u16(self.candidate_port)
        return w.to_bytes()

    @classmethod
    def decode(cls, reader: ByteReader) -> PunchRequestFrame:
        target_peer_id = reader.read_varbytes(64)
        grant_token = reader.read_varbytes(64)
        ip_ver = reader.read_u8()
        ip_len = 4 if ip_ver == 4 else 16
        host = str(ipaddress.ip_address(reader.read_bytes(ip_len)))
        port = reader.read_u16()
        return cls(
            target_peer_id=target_peer_id,
            grant_token=grant_token,
            candidate_host=host,
            candidate_port=port,
        )


@dataclass(frozen=True)
class PathChallengeFrame:
    """RFC 9000 `PATH_CHALLENGE` (0x1a) carrying 8-byte unpredictable token."""

    data: bytes

    def encode(self) -> bytes:
        if len(self.data) != 8:
            raise WireFormatError("PATH_CHALLENGE must be exactly 8 bytes")
        return encode_varint(int(NATFrameType.PATH_CHALLENGE)) + self.data

    @classmethod
    def decode(cls, reader: ByteReader) -> PathChallengeFrame:
        return cls(data=reader.read_bytes(8))


@dataclass(frozen=True)
class PathResponseFrame:
    """RFC 9000 `PATH_RESPONSE` (0x1b) echoing the 8-byte challenge token."""

    data: bytes

    def encode(self) -> bytes:
        if len(self.data) != 8:
            raise WireFormatError("PATH_RESPONSE must be exactly 8 bytes")
        return encode_varint(int(NATFrameType.PATH_RESPONSE)) + self.data

    @classmethod
    def decode(cls, reader: ByteReader) -> PathResponseFrame:
        return cls(data=reader.read_bytes(8))


# =============================================================================
# RFC 9297 HTTP Capsule Protocol (DATAGRAM Capsule = 0x00)
# =============================================================================

CAPSULE_TYPE_DATAGRAM = 0x00


@dataclass(frozen=True)
class DatagramCapsule:
    """
    RFC 9297 Section 3.5 `DATAGRAM` Capsule (`Type = 0x00`, `Length`, `HTTP Datagram Payload`).
    Allows unreliable ultra-low-latency media objects to traverse HTTP intermediaries
    when raw QUIC DATAGRAM frames (RFC 9221) cannot pass end-to-end.
    """

    quarter_stream_id: int
    payload: bytes

    def encode(self) -> bytes:
        inner = encode_varint(self.quarter_stream_id) + self.payload
        return encode_varint(CAPSULE_TYPE_DATAGRAM) + encode_varint(len(inner)) + inner

    @classmethod
    def decode(cls, data: bytes) -> DatagramCapsule:
        r = ByteReader(data)
        ctype = r.read_varint()
        if ctype != CAPSULE_TYPE_DATAGRAM:
            raise WireFormatError(f"Expected DATAGRAM Capsule (0x00), got 0x{ctype:x}")
        length = r.read_varint()
        body = r.read_bytes(length)
        br = ByteReader(body)
        qsid = br.read_varint()
        return cls(quarter_stream_id=qsid, payload=br.read_rest())


class StreamFrameBuffer:
    """
    Incremental HTTP/4 frame assembler for a single WIQC stream.

    Because WIQC segments streams into ~1024-byte UDP packets, a 16 KiB
    `WIQC_SUBGROUP_OBJECT` or `DATA` frame arrives across many packets.
    `StreamFrameBuffer` handles:
    - Optional leading unidirectional/swarm Stream Type VarInt header,
    - Arbitrary packet split boundaries,
    - Yielding complete `RawFrame(frame_type, payload)` objects as soon as ready.
    """

    def __init__(self, expect_stream_type_header: bool = False) -> None:
        self.expect_stream_type_header = expect_stream_type_header
        self.stream_type: int | None = None
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[RawFrame]:
        if data:
            self._buf.extend(data)
        frames: list[RawFrame] = []

        if self.expect_stream_type_header and self.stream_type is None:
            if not self._buf:
                return frames
            try:
                stype, consumed = decode_varint(self._buf, 0)
            except WireFormatError:
                return frames
            self.stream_type = stype
            del self._buf[:consumed]

        while self._buf:
            try:
                ft, pos1 = decode_varint(self._buf, 0)
                length, pos2 = decode_varint(self._buf, pos1)
            except WireFormatError:
                # Incomplete VarInt header; wait for next UDP packet
                break
            total_needed = pos2 + length
            if len(self._buf) < total_needed:
                # Incomplete frame payload; wait for remaining UDP packets
                break
            payload = bytes(self._buf[pos2:total_needed])
            del self._buf[:total_needed]
            frames.append(RawFrame(frame_type=ft, payload=payload))
        return frames


def is_valid_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False
