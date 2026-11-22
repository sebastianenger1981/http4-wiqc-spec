"""
QUIC Variable-Length Integer (VarInt) Codec and Fault-Tolerant Binary Buffer.

Implements Section 16 of RFC 9000 ("Variable-Length Integer Encoding"), which
`draft-enger-httpbis-http4-wiqc-00` normatively adopts in Section 2 ("Conventions
and Definitions") and Section 5.2 ("HTTP/4 Frame Layout and Extensions").

Encoding Layout (Big-Endian / Network Byte Order):
    2-bit MSB Prefix | Length | Usable Bits | Range
    -----------------+--------+-------------+---------------------------
    0b00             | 1 byte | 6 bits      | 0 .. 63
    0b01             | 2 bytes| 14 bits     | 0 .. 16,383
    0b10             | 4 bytes| 30 bits     | 0 .. 1,073,741,823
    0b11             | 8 bytes| 62 bits     | 0 .. 4,611,686,018,427,387,903

Every read method strictly checks remaining bounds before slicing to prevent
partial-buffer bugs or malicious length-field crashes.
"""

from __future__ import annotations

import struct

from .exceptions import WireFormatError

MAX_VARINT_1B = (1 << 6) - 1  # 63
MAX_VARINT_2B = (1 << 14) - 1  # 16,383
MAX_VARINT_4B = (1 << 30) - 1  # 1,073,741,823
MAX_VARINT_8B = (1 << 62) - 1  # 4,611,686,018,427,387,903


def encode_varint(value: int) -> bytes:
    """
    Encode a non-negative integer using minimal RFC 9000 variable-length format.

    Args:
        value: Integer in [0, 2**62 - 1].

    Returns:
        1, 2, 4, or 8 bytes in big-endian order with 2-bit length prefix.

    Raises:
        WireFormatError: If value is negative or exceeds 2**62 - 1.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise WireFormatError(f"VarInt requires int, got {type(value).__name__}")
    if value < 0 or value > MAX_VARINT_8B:
        raise WireFormatError(f"VarInt value out of RFC 9000 bounds: {value}")
    if value <= MAX_VARINT_1B:
        return bytes((value,))
    if value <= MAX_VARINT_2B:
        return struct.pack("!H", 0x4000 | value)
    if value <= MAX_VARINT_4B:
        return struct.pack("!I", 0x80000000 | value)
    return struct.pack("!Q", 0xC000000000000000 | value)


def decode_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int]:
    """
    Decode an RFC 9000 variable-length integer starting at `offset`.

    Args:
        data: Input bytes or memoryview.
        offset: Starting byte index.

    Returns:
        Tuple of (decoded_integer, next_offset).

    Raises:
        WireFormatError: If data is truncated or offset is out of range.
    """
    total = len(data)
    if offset < 0 or offset >= total:
        raise WireFormatError(f"Truncated VarInt at offset {offset} (len={total})")

    first = data[offset]
    prefix = first >> 6
    length = 1 << prefix  # 1, 2, 4, or 8 bytes

    if offset + length > total:
        raise WireFormatError(
            f"Truncated {length}-byte VarInt at offset {offset} (remaining={total - offset})"
        )

    if length == 1:
        return first & 0x3F, offset + 1
    if length == 2:
        raw = struct.unpack_from("!H", data, offset)[0]
        return raw & 0x3FFF, offset + 2
    if length == 4:
        raw = struct.unpack_from("!I", data, offset)[0]
        return raw & 0x3FFFFFFF, offset + 4
    raw = struct.unpack_from("!Q", data, offset)[0]
    return raw & 0x3FFFFFFFFFFFFFFF, offset + 8


class ByteReader:
    """
    Bounds-checked cursor for parsing wire frames and packets safely.

    All read methods validate remaining length and raise `WireFormatError`
    rather than returning silently truncated byte slices.
    """

    __slots__ = ("_buf", "_pos", "_end")

    def __init__(self, data: bytes | bytearray | memoryview, offset: int = 0) -> None:
        self._buf = memoryview(data)
        self._pos = offset
        self._end = len(self._buf)

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    def eof(self) -> bool:
        return self._pos >= self._end

    def read_bytes(self, count: int) -> bytes:
        if count < 0 or self._pos + count > self._end:
            raise WireFormatError(
                f"Cannot read {count} bytes at offset {self._pos} (remaining={self.remaining})"
            )
        out = bytes(self._buf[self._pos : self._pos + count])
        self._pos += count
        return out

    def read_rest(self) -> bytes:
        out = bytes(self._buf[self._pos : self._end])
        self._pos = self._end
        return out

    def read_u8(self) -> int:
        if self._pos + 1 > self._end:
            raise WireFormatError("Truncated u8")
        val = self._buf[self._pos]
        self._pos += 1
        return val

    def read_u16(self) -> int:
        if self._pos + 2 > self._end:
            raise WireFormatError("Truncated u16")
        val = struct.unpack_from("!H", self._buf, self._pos)[0]
        self._pos += 2
        return val

    def read_u32(self) -> int:
        if self._pos + 4 > self._end:
            raise WireFormatError("Truncated u32")
        val = struct.unpack_from("!I", self._buf, self._pos)[0]
        self._pos += 4
        return val

    def read_u64(self) -> int:
        if self._pos + 8 > self._end:
            raise WireFormatError("Truncated u64")
        val = struct.unpack_from("!Q", self._buf, self._pos)[0]
        self._pos += 8
        return val

    def read_varint(self) -> int:
        val, self._pos = decode_varint(self._buf, self._pos)
        return val

    def read_varbytes(self, max_len: int | None = None) -> bytes:
        """Read a VarInt length-prefixed byte sequence."""
        length = self.read_varint()
        if max_len is not None and length > max_len:
            raise WireFormatError(f"VarBytes length {length} exceeds maximum {max_len}")
        return self.read_bytes(length)


class ByteWriter:
    """Efficient growable byte builder for constructing wire frames and packets."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def write_bytes(self, data: bytes | bytearray | memoryview) -> None:
        self._buf.extend(data)

    def write_u8(self, value: int) -> None:
        if not 0 <= value <= 0xFF:
            raise WireFormatError(f"u8 out of range: {value}")
        self._buf.append(value)

    def write_u16(self, value: int) -> None:
        if not 0 <= value <= 0xFFFF:
            raise WireFormatError(f"u16 out of range: {value}")
        self._buf.extend(struct.pack("!H", value))

    def write_u32(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFF:
            raise WireFormatError(f"u32 out of range: {value}")
        self._buf.extend(struct.pack("!I", value))

    def write_u64(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise WireFormatError(f"u64 out of range: {value}")
        self._buf.extend(struct.pack("!Q", value))

    def write_varint(self, value: int) -> None:
        self._buf.extend(encode_varint(value))

    def write_varbytes(self, data: bytes | bytearray | memoryview) -> None:
        self.write_varint(len(data))
        self._buf.extend(data)

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)
