"""
QPACK Header Compression (RFC 9204) with Side-Channel Protection (RFC 9114 §10.6).

Implements Section 5.1 (Streams 0x02 QPACK Encoder & 0x03 QPACK Decoder) and
Section 8.3 ("Compression Side Channels and Replay Risks") of
`draft-enger-httpbis-http4-wiqc-00`:

1. **Static Table**: Core HTTP/4 pseudo-headers and common WIQC headers (`:method`,
   `:scheme`, `:authority`, `:path`, `:status`, `content-type`, `repr-digest`,
   `wiqc-swarm-info`, `swarm-root`, `alt-svc`, `priority`, etc.).
2. **Dynamic Table + Unidirectional QPACK Streams (0x02 & 0x03)**:
   - `QPACKEncoder` inserts eligible recurring headers into the dynamic table and
     emits `INSERT_WITH_LITERAL_NAME` instructions for Stream `0x02`.
   - `QPACKDecoder` ingests Stream `0x02` instructions, decodes encoded field sections
     from `HEADERS` frames, and emits `SECTION_ACK` / `STREAM_CANCEL` instructions
     on Stream `0x03`.
3. **Mandatory Compression Side-Channel Guard (Section 8.3)**:
   - Sensitive authentication headers (`authorization`, `proxy-authorization`,
     `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, or explicitly marked
     sensitive names) MUST NEVER be inserted into the shared dynamic table!
   - They are always encoded as `LITERAL_NEVER_INDEXED` (flag `N=1`) to defeat
     BREACH/CRIME-class oracle attacks when combined with attacker-controlled headers.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .exceptions import QPACKError
from .varint import ByteReader, ByteWriter

# Headers forbidden from dynamic-table indexing per Section 8.3 / RFC 9114 §10.6
SENSITIVE_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-session-token",
    }
)

# Subset of RFC 9204 Appendix A Static Table extended with common HTTP/4 pairs
QPACK_STATIC_TABLE: tuple[tuple[str, str], ...] = (
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept-encoding", "gzip, deflate, br"),
    ("content-type", "application/octet-stream"),
    ("content-type", "application/json"),
    ("content-type", "text/plain;charset=utf-8"),
    ("content-type", "video/mp4"),
    ("alt-svc", ""),
    ("priority", "u=3"),
    ("repr-digest", ""),
    ("content-digest", ""),
    ("swarm-root", ""),
    ("wiqc-swarm-info", ""),
    ("wiqc-swarm-id", ""),
    ("signature-input", ""),
    ("signature", ""),
)

# Field Line Representation opcodes inside an encoded field section
_OP_INDEXED_STATIC = 0x01
_OP_INDEXED_DYNAMIC = 0x02
_OP_LITERAL = 0x03
_OP_LITERAL_NEVER_INDEXED = 0x04

# QPACK Encoder Stream (0x02) instructions
_ENC_INSERT_LITERAL = 0x40
_ENC_SET_CAPACITY = 0x20

# QPACK Decoder Stream (0x03) instructions
_DEC_SECTION_ACK = 0x80
_DEC_STREAM_CANCEL = 0x40
_DEC_INSERT_COUNT_INC = 0x00


@dataclass(frozen=True)
class DynamicTableEntry:
    abs_index: int
    name: str
    value: str

    @property
    def entry_size(self) -> int:
        # RFC 9204 Section 3.2.1: len(name) + len(value) + 32 bytes overhead
        return len(self.name.encode("utf-8")) + len(self.value.encode("utf-8")) + 32


class QPACKDynamicTable:
    """FIFO dynamic header table with strict capacity enforcement (RFC 9204 §3.2)."""

    def __init__(self, max_capacity: int = 4096) -> None:
        self.max_capacity = max_capacity
        self.current_size = 0
        self.insert_count = 0
        self._entries: deque[DynamicTableEntry] = deque()
        self._by_index: dict[int, DynamicTableEntry] = {}
        self._by_pair: dict[tuple[str, str], int] = {}

    def set_capacity(self, new_capacity: int) -> None:
        if new_capacity < 0:
            raise QPACKError("Negative QPACK capacity")
        self.max_capacity = new_capacity
        self._evict_to_fit(0)

    def _evict_to_fit(self, incoming_size: int) -> bool:
        if incoming_size > self.max_capacity:
            return False
        while self._entries and (self.current_size + incoming_size > self.max_capacity):
            old = self._entries.popleft()
            self.current_size -= old.entry_size
            self._by_index.pop(old.abs_index, None)
            if self._by_pair.get((old.name, old.value)) == old.abs_index:
                self._by_pair.pop((old.name, old.value), None)
        return True

    def insert(self, name: str, value: str) -> int | None:
        """
        Insert `(name, value)` into the dynamic table if it fits and is NOT sensitive.
        Returns the new absolute index, or None if rejected/too large.
        """
        name_l = name.lower()
        if name_l in SENSITIVE_HEADER_NAMES:
            raise QPACKError(
                f"Compression side-channel violation: sensitive header {name_l!r} "
                "MUST NOT be inserted into QPACK dynamic table (RFC 9114 §10.6)"
            )
        entry = DynamicTableEntry(abs_index=self.insert_count, name=name_l, value=value)
        if not self._evict_to_fit(entry.entry_size):
            return None
        self._entries.append(entry)
        self._by_index[entry.abs_index] = entry
        self._by_pair[(name_l, value)] = entry.abs_index
        self.current_size += entry.entry_size
        self.insert_count += 1
        return entry.abs_index

    def lookup_pair(self, name: str, value: str) -> int | None:
        return self._by_pair.get((name.lower(), value))

    def get(self, abs_index: int) -> DynamicTableEntry:
        entry = self._by_index.get(abs_index)
        if entry is None:
            raise QPACKError(f"QPACK dynamic table index {abs_index} not found (evicted or future)")
        return entry

    def __len__(self) -> int:
        return len(self._entries)


class QPACKEncoder:
    """
    HTTP/4 QPACK Encoder generating:
    - Encoded field sections for `HEADERS` frames,
    - Dynamic table insertions for QPACK Encoder Stream (`0x02`).
    """

    def __init__(self, max_table_capacity: int = 4096) -> None:
        self.table = QPACKDynamicTable(max_capacity=max_table_capacity)
        self._static_exact: dict[tuple[str, str], int] = {
            pair: idx for idx, pair in enumerate(QPACK_STATIC_TABLE)
        }
        self.acknowledged_streams: list[int] = []
        self.cancelled_streams: list[int] = []
        self.known_received_count: int = 0

    def encode(
        self,
        headers: list[tuple[str, str]] | dict[str, str],
        extra_sensitive: set[str] | None = None,
        allow_dynamic: bool = True,
    ) -> tuple[bytes, bytes]:
        """
        Encode HTTP/4 header fields into `(encoded_field_section, encoder_stream_instructions)`.

        Returns both:
        1. `encoded_field_section`: payload for the stream's `HEADERS` frame.
        2. `encoder_stream_instructions`: bytes to write onto Stream `0x02` (QPACK Encoder).
        """
        items = list(headers.items()) if isinstance(headers, dict) else list(headers)
        sensitive_set = SENSITIVE_HEADER_NAMES | {s.lower() for s in (extra_sensitive or set())}

        enc_inst = ByteWriter()
        body = ByteWriter()
        required_insert_count = 0

        for raw_name, value in items:
            name = raw_name.lower()
            is_sensitive = name in sensitive_set

            # Side-channel defense: sensitive headers NEVER enter dynamic table or shared compression
            if is_sensitive:
                body.write_u8(_OP_LITERAL_NEVER_INDEXED)
                body.write_varbytes(name.encode("utf-8"))
                body.write_varbytes(value.encode("utf-8"))
                continue

            # 1. Exact Static Table match
            static_idx = self._static_exact.get((name, value))
            if static_idx is not None:
                body.write_u8(_OP_INDEXED_STATIC)
                body.write_varint(static_idx)
                continue

            # 2. Exact Dynamic Table match
            if allow_dynamic and self.table.max_capacity > 0:
                dyn_idx = self.table.lookup_pair(name, value)
                if dyn_idx is not None:
                    body.write_u8(_OP_INDEXED_DYNAMIC)
                    body.write_varint(dyn_idx)
                    required_insert_count = max(required_insert_count, dyn_idx + 1)
                    continue

                # Insert eligible non-sensitive, reasonably sized headers into dynamic table
                if len(name) + len(value) <= 256:
                    new_idx = self.table.insert(name, value)
                    if new_idx is not None:
                        enc_inst.write_u8(_ENC_INSERT_LITERAL)
                        enc_inst.write_varbytes(name.encode("utf-8"))
                        enc_inst.write_varbytes(value.encode("utf-8"))
                        body.write_u8(_OP_INDEXED_DYNAMIC)
                        body.write_varint(new_idx)
                        required_insert_count = max(required_insert_count, new_idx + 1)
                        continue

            # 3. Literal representation (non-sensitive)
            body.write_u8(_OP_LITERAL)
            body.write_varbytes(name.encode("utf-8"))
            body.write_varbytes(value.encode("utf-8"))

        # Prepend Field Section Prefix: Required Insert Count + Base
        out = ByteWriter()
        out.write_varint(required_insert_count)
        out.write_varint(self.table.insert_count)
        out.write_bytes(body.to_bytes())
        return out.to_bytes(), enc_inst.to_bytes()

    def process_decoder_stream(self, data: bytes) -> None:
        """Process acknowledgments and cancellations arriving on QPACK Decoder Stream (0x03)."""
        r = ByteReader(data)
        while not r.eof():
            op = r.read_u8()
            if op == _DEC_SECTION_ACK:
                sid = r.read_varint()
                self.acknowledged_streams.append(sid)
            elif op == _DEC_STREAM_CANCEL:
                sid = r.read_varint()
                self.cancelled_streams.append(sid)
            elif op == _DEC_INSERT_COUNT_INC:
                inc = r.read_varint()
                self.known_received_count += inc
            else:
                raise QPACKError(f"Unknown QPACK decoder stream instruction: 0x{op:02x}")


class QPACKDecoder:
    """
    HTTP/4 QPACK Decoder ingesting Stream `0x02` instructions and emitting Stream `0x03`
    section acknowledgments / stream cancellations.
    """

    def __init__(self, max_table_capacity: int = 4096) -> None:
        self.table = QPACKDynamicTable(max_capacity=max_table_capacity)

    def process_encoder_stream(self, data: bytes) -> bytes:
        """
        Apply dynamic table insertions from Stream `0x02`.
        Returns an Insert Count Increment instruction for Stream `0x03`.
        """
        r = ByteReader(data)
        inserted = 0
        while not r.eof():
            op = r.read_u8()
            if op == _ENC_INSERT_LITERAL:
                name = r.read_varbytes(1024).decode("utf-8")
                value = r.read_varbytes(8192).decode("utf-8")
                self.table.insert(name, value)
                inserted += 1
            elif op == _ENC_SET_CAPACITY:
                cap = r.read_varint()
                self.table.set_capacity(cap)
            else:
                raise QPACKError(f"Unknown QPACK encoder stream instruction: 0x{op:02x}")
        if inserted > 0:
            w = ByteWriter()
            w.write_u8(_DEC_INSERT_COUNT_INC)
            w.write_varint(inserted)
            return w.to_bytes()
        return b""

    def decode(
        self,
        encoded_field_section: bytes,
        stream_id: int = 0,
    ) -> tuple[list[tuple[str, str]], bytes]:
        """
        Decode an encoded field section from a `HEADERS` frame.

        Returns `(headers_list, decoder_stream_ack_bytes)` where `decoder_stream_ack_bytes`
        contains a `SECTION_ACK` instruction for Stream `0x03` whenever dynamic references
        were resolved.
        """
        r = ByteReader(encoded_field_section)
        required_insert_count = r.read_varint()
        _base = r.read_varint()

        if required_insert_count > self.table.insert_count:
            raise QPACKError(
                f"Blocked QPACK section on stream {stream_id}: requires insert_count "
                f"{required_insert_count}, have {self.table.insert_count}"
            )

        headers: list[tuple[str, str]] = []
        used_dynamic = False

        while not r.eof():
            op = r.read_u8()
            if op == _OP_INDEXED_STATIC:
                idx = r.read_varint()
                if idx >= len(QPACK_STATIC_TABLE):
                    raise QPACKError(f"Static table index out of range: {idx}")
                headers.append(QPACK_STATIC_TABLE[idx])
            elif op == _OP_INDEXED_DYNAMIC:
                abs_idx = r.read_varint()
                entry = self.table.get(abs_idx)
                headers.append((entry.name, entry.value))
                used_dynamic = True
            elif op in (_OP_LITERAL, _OP_LITERAL_NEVER_INDEXED):
                name = r.read_varbytes(1024).decode("utf-8")
                value = r.read_varbytes(16384).decode("utf-8")
                headers.append((name, value))
            else:
                raise QPACKError(f"Unknown QPACK field line opcode: 0x{op:02x}")

        ack = b""
        if used_dynamic or required_insert_count > 0:
            w = ByteWriter()
            w.write_u8(_DEC_SECTION_ACK)
            w.write_varint(stream_id)
            ack = w.to_bytes()
        return headers, ack

    @staticmethod
    def encode_stream_cancel(stream_id: int) -> bytes:
        w = ByteWriter()
        w.write_u8(_DEC_STREAM_CANCEL)
        w.write_varint(stream_id)
        return w.to_bytes()
