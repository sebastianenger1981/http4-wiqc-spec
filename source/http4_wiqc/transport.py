"""
WIQC Encrypted UDP Transport Layer (RFC 9000-Derived, Multiplexed, Fault-Tolerant).

Implements Section 3.1, Section 3.2, Section 5.3.4, Section 6.1, Section 6.2,
and Section 8.2 of `draft-enger-httpbis-http4-wiqc-00`:

1. **UDP Long & Short Packet Framing**:
   - Long Header (`INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`) carrying WIQC version
     (`0x57495104`), DCID, SCID, RFC 7574 Channel ID, packet number, and payload.
   - Short Header (`1-RTT`) carrying 8-byte DCID, 4-byte Channel ID, packet number,
     and ChaCha20-Poly1305 AEAD encrypted inner frames (header authenticated as AAD!).

2. **Connection Migration & Path Validation**:
   - Connections route by 8-byte `DCID`, NOT source IP/port!
   - When an authenticated Short Header packet arrives from a new UDP `(host, port)`,
     the endpoint seamlessly updates the peer's path and triggers RFC 9000
     `PATH_CHALLENGE` / `PATH_RESPONSE` validation.

3. **Anti-Amplification Protection (Section 3.2 & Section 8.2)**:
   - Rejects heavy payloads (`DATA`, `WIQC_SIGNED_INTEGRITY`, or oversized first-flight
     stream frames) before peer address validation via Channel ID echoing or
     `PATH_RESPONSE`.
   - Enforces the RFC 9000 3x amplification budget (`bytes_sent <= 3 * bytes_received`)
     for unvalidated peer addresses.

4. **Independent Per-Stream Reliability & Flow Control (Zero Head-of-Line Blocking)**:
   - Each stream maintains its own offset-reassembly buffer, send/recv flow control
     windows (`MAX_STREAM_DATA`, `MAX_DATA`), and independent delivery callbacks.
   - Selective packet ACKs + adaptive RTO retransmission ensure packet loss on one
     Subgroup stream NEVER stalls delivery on another Subgroup stream!

5. **Unreliable QUIC DATAGRAM Frames (RFC 9221)** & **0-RTT Early Data**:
   - Unreliable datagrams bypass retransmission for sub-100ms real-time objects.
   - 0-RTT packets encrypt early idempotent requests using resumption tickets.

6. **Fault Injection & Resilience**:
   - Malformed, truncated, or unauthenticated UDP datagrams are safely dropped and
     logged without impacting healthy connections.
   - Optional `FaultInjectionProfile` enables deterministic testing of packet loss,
     per-stream drops (HoL test), NAT filtering, and latency!
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum

from .crypto import ChaCha20Poly1305, PeerIdentity, make_packet_nonce
from .exceptions import (
    AntiAmplificationError,
    ConnectionClosedError,
    CryptoError,
    FlowControlError,
    PeerBannedError,
    TLSAuthenticationError,
    WireFormatError,
)
from .frames import (
    AddAddressFrame,
    NATFrameType,
    ObservedAddressFrame,
    PathChallengeFrame,
    PathResponseFrame,
    PunchMeNowFrame,
    PunchRequestFrame,
    RemoveAddressFrame,
)
from .media import PeerReputationManager
from .nat import NATTraversalCoordinator, SimulatedRestrictedNAT
from .tls_libp2p import (
    SUPPORTED_ALPNS,
    Libp2pCertificateBundle,
    MutualTLSHandshake,
    TrafficKeys,
    ZeroRTTTicket,
    generate_libp2p_self_signed_cert,
)
from .varint import ByteReader, ByteWriter, encode_varint

logger = logging.getLogger("http4_wiqc.transport")

WIQC_VERSION = 0x57495104  # "WIQ\x04"
CID_LEN = 8
MAX_STREAM_CHUNK = 1024  # Fits safely within 1200-byte QUIC UDP MTU
DEFAULT_INITIAL_STREAM_WINDOW = 2 * 1024 * 1024  # 2 MiB per stream
DEFAULT_INITIAL_CONN_WINDOW = 8 * 1024 * 1024  # 8 MiB per connection


class PacketType(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    SHORT_1RTT = 4


class TransportFrameType(IntEnum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    CRYPTO = 0x06
    STREAM = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    CONNECTION_CLOSE = 0x1C
    DATAGRAM = 0x30  # RFC 9221 unreliable QUIC DATAGRAM


MIN_INITIAL_DATAGRAM_BYTES = 1200  # RFC 9000 §14.1 anti-amplification padding floor


@dataclass
class FaultInjectionProfile:
    """
    Configurable network fault injector for testing WIQC fault tolerance,
    retransmission, zero Head-of-Line blocking, and NAT hole punching.
    """

    drop_rate: float = 0.0
    extra_latency_ms: float = 0.0
    corrupt_rate: float = 0.0
    # Drop the first N packets carrying a specific stream_id (proves zero HoL!)
    drop_stream_counts: dict[int, int] = field(default_factory=dict)
    # Optional simulated cone NAT filter
    nat_filter: SimulatedRestrictedNAT | None = None
    _rng: random.Random = field(default_factory=lambda: random.Random(42))
    dropped_total: int = 0

    def should_drop_outbound(self, dest_addr: tuple[str, int], stream_ids: list[int]) -> bool:
        if self.nat_filter is not None:
            self.nat_filter.allow_outbound(dest_addr)
        for sid in stream_ids:
            rem = self.drop_stream_counts.get(sid, 0)
            if rem > 0:
                self.drop_stream_counts[sid] = rem - 1
                self.dropped_total += 1
                return True
        if self.drop_rate > 0.0 and self._rng.random() < self.drop_rate:
            self.dropped_total += 1
            return True
        return False

    def allow_inbound(self, src_addr: tuple[str, int]) -> bool:
        if self.nat_filter is not None:
            return self.nat_filter.filter_inbound(src_addr)
        return True


# =============================================================================
# Per-Stream State (Independent Reassembly & Flow Control)
# =============================================================================


class WIQCStream:
    """
    Independent multiplexed WIQC stream with offset-based reassembly and flow
    control. Delivery on one stream NEVER waits for missing packets on another.
    """

    def __init__(
        self,
        stream_id: int,
        initial_send_window: int = DEFAULT_INITIAL_STREAM_WINDOW,
        initial_recv_window: int = DEFAULT_INITIAL_STREAM_WINDOW,
    ) -> None:
        self.stream_id = stream_id
        self.send_offset: int = 0
        self.send_fin: bool = False
        self.max_send_offset: int = initial_send_window

        self.recv_next_offset: int = 0
        self.recv_fin_offset: int | None = None
        self.max_recv_offset: int = initial_recv_window
        self._ooo_chunks: dict[int, bytes] = {}  # out-of-order offset -> bytes
        self._ready_buf = bytearray()
        self.data_event = asyncio.Event()
        self.fin_received: bool = False

    def ingest_chunk(self, offset: int, data: bytes, fin: bool) -> bytes:
        """
        Insert a received `STREAM` frame chunk into the per-stream reassembly buffer.
        Returns newly contiguous bytes ready for upper-layer HTTP/4 framing.
        """
        end_offset = offset + len(data)
        if end_offset > self.max_recv_offset:
            raise FlowControlError(
                f"Stream {self.stream_id} exceeded recv flow-control window "
                f"({end_offset} > {self.max_recv_offset})"
            )
        if fin:
            self.recv_fin_offset = end_offset

        if end_offset > self.recv_next_offset:
            if offset <= self.recv_next_offset:
                trim = self.recv_next_offset - offset
                new_bytes = data[trim:]
                self._ready_buf.extend(new_bytes)
                self.recv_next_offset += len(new_bytes)
            else:
                # Out-of-order segment: hold until preceding gap fills
                existing = self._ooo_chunks.get(offset)
                if existing is None or len(data) > len(existing):
                    self._ooo_chunks[offset] = data

            # Drain any now-contiguous out-of-order chunks
            while self.recv_next_offset in self._ooo_chunks:
                seg = self._ooo_chunks.pop(self.recv_next_offset)
                self._ready_buf.extend(seg)
                self.recv_next_offset += len(seg)
            # Also handle overlapping OOO keys
            for off in sorted(list(self._ooo_chunks.keys())):
                if off > self.recv_next_offset:
                    break
                seg = self._ooo_chunks.pop(off)
                if off + len(seg) > self.recv_next_offset:
                    trim = self.recv_next_offset - off
                    self._ready_buf.extend(seg[trim:])
                    self.recv_next_offset = off + len(seg)

        if self.recv_fin_offset is not None and self.recv_next_offset >= self.recv_fin_offset:
            self.fin_received = True

        produced = bytes(self._ready_buf)
        self._ready_buf.clear()
        if produced or self.fin_received:
            self.data_event.set()
        return produced


@dataclass
class InFlightPacket:
    packet_number: int
    raw_bytes: bytes
    sent_at: float
    retransmits: int = 0
    is_reliable: bool = True
    stream_ids: list[int] = field(default_factory=list)


# =============================================================================
# WIQC Packet Encoding & Decoding
# =============================================================================


def encode_long_packet(
    pkt_type: PacketType,
    dcid: bytes,
    scid: bytes,
    channel_id: int,
    packet_number: int,
    payload: bytes,
    extra: bytes = b"",
    cipher: ChaCha20Poly1305 | None = None,
    iv: bytes | None = None,
) -> bytes:
    w = ByteWriter()
    first_byte = 0x80 | ((int(pkt_type) & 0x03) << 4)
    w.write_u8(first_byte)
    w.write_u32(WIQC_VERSION)
    w.write_u8(len(dcid))
    w.write_bytes(dcid)
    w.write_u8(len(scid))
    w.write_bytes(scid)
    w.write_u32(channel_id)
    w.write_u32(packet_number)
    w.write_varbytes(extra)
    header = w.to_bytes()
    if cipher is not None and iv is not None:
        nonce = make_packet_nonce(iv, packet_number)
        encrypted = cipher.encrypt(nonce, payload, aad=header)
        return header + encrypted
    return header + payload


def encode_short_packet(
    dcid: bytes,
    channel_id: int,
    packet_number: int,
    payload: bytes,
    cipher: ChaCha20Poly1305,
    iv: bytes,
) -> bytes:
    if len(dcid) != CID_LEN:
        raise WireFormatError(f"Short header DCID must be {CID_LEN} bytes")
    header = struct.pack("!B", 0x40) + dcid + struct.pack("!II", channel_id, packet_number)
    nonce = make_packet_nonce(iv, packet_number)
    encrypted = cipher.encrypt(nonce, payload, aad=header)
    return header + encrypted


@dataclass(frozen=True)
class ParsedPacketHeader:
    is_long: bool
    pkt_type: PacketType
    dcid: bytes
    scid: bytes
    channel_id: int
    packet_number: int
    extra: bytes
    header_bytes: bytes
    payload_bytes: bytes


def parse_packet_header(datagram: bytes) -> ParsedPacketHeader:
    if len(datagram) < 17:
        raise WireFormatError(f"UDP datagram too short ({len(datagram)} bytes)")
    first = datagram[0]
    if first & 0x80:
        # Long Header
        r = ByteReader(datagram)
        fb = r.read_u8()
        pkt_type = PacketType((fb >> 4) & 0x03)
        version = r.read_u32()
        if version != WIQC_VERSION:
            raise WireFormatError(f"Unsupported WIQC version 0x{version:08x}")
        dcid_len = r.read_u8()
        dcid = r.read_bytes(dcid_len)
        scid_len = r.read_u8()
        scid = r.read_bytes(scid_len)
        channel_id = r.read_u32()
        pkt_num = r.read_u32()
        extra = r.read_varbytes(128)
        hdr_len = r.pos
        payload = r.read_rest()
        return ParsedPacketHeader(
            is_long=True,
            pkt_type=pkt_type,
            dcid=dcid,
            scid=scid,
            channel_id=channel_id,
            packet_number=pkt_num,
            extra=extra,
            header_bytes=datagram[:hdr_len],
            payload_bytes=payload,
        )
    else:
        # Short Header (1-RTT)
        if not (first & 0x40):
            raise WireFormatError("Short header missing QUIC fixed bit 0x40")
        dcid = datagram[1 : 1 + CID_LEN]
        channel_id, pkt_num = struct.unpack_from("!II", datagram, 1 + CID_LEN)
        hdr_len = 1 + CID_LEN + 8
        return ParsedPacketHeader(
            is_long=False,
            pkt_type=PacketType.SHORT_1RTT,
            dcid=dcid,
            scid=b"",
            channel_id=channel_id,
            packet_number=pkt_num,
            extra=b"",
            header_bytes=datagram[:hdr_len],
            payload_bytes=datagram[hdr_len:],
        )


# =============================================================================
# WIQC Connection State Machine (Client & Server Symmetric Swarm Channel)
# =============================================================================


class WIQCConnection:
    """
    A single encrypted, multiplexed WIQC connection between two peers over UDP.

    Provides:
    - Mutual TLS 1.3 handshake (`libp2p-tls` single self-signed cert + OID check),
    - RFC 7574 §12.1 Channel ID anti-amplification & 3x byte cap prior to validation,
    - Independent multiplexed streams (`0x00..0x03`, `0x40`, `0x41`, request streams),
    - Unreliable RFC 9221 DATAGRAMs,
    - Seamless Connection Migration & NAT Traversal frame handling,
    - Adaptive RTO retransmission & fault-tolerant packet parsing.
    """

    def __init__(
        self,
        endpoint: WIQCEndpoint,
        local_cid: bytes,
        remote_cid: bytes,
        remote_addr: tuple[str, int],
        is_server: bool,
        alpns: tuple[bytes, ...] = SUPPORTED_ALPNS,
    ) -> None:
        self.endpoint = endpoint
        self.local_cid = local_cid
        self.remote_cid = remote_cid
        self.remote_addr = remote_addr
        self.is_server = is_server

        # RFC 7574 §12.1 randomly chosen Channel ID for address-validation echoing
        self.local_channel_id: int = int.from_bytes(secrets.token_bytes(4), "big") | 1
        self.remote_channel_id: int = 0
        self.address_validated: bool = not is_server  # Client knows server addr; server must validate client
        self.unvalidated_bytes_received: int = 0
        self.unvalidated_bytes_sent: int = 0

        self.tls = MutualTLSHandshake(
            identity=endpoint.identity,
            is_server=is_server,
            alpns=alpns,
            cert_bundle=endpoint.cert_bundle,
            ticket_store=endpoint.ticket_store,
        )
        self.keys: TrafficKeys | None = None
        self.zero_rtt_keys: TrafficKeys | None = None
        self.handshake_event = asyncio.Event()
        self.handshake_error: Exception | None = None
        self.closed: bool = False
        self.close_reason: str = ""

        # Packet numbers, ACK tracking, RTT (EWMA), retransmission
        self._next_pkt_num: int = 1
        self._in_flight: dict[int, InFlightPacket] = {}
        self._received_pkt_nums: set[int] = set()
        self._pending_acks: list[int] = []
        self.smoothed_rtt_ms: float = 20.0

        # Multiplexed streams & flow control
        self.streams: dict[int, WIQCStream] = {}
        self._next_bidi_stream_id: int = 1 if is_server else 0
        self._next_uni_stream_id: int = 3 if is_server else 2
        self.conn_bytes_sent: int = 0
        self.conn_bytes_received: int = 0
        self.max_conn_send: int = DEFAULT_INITIAL_CONN_WINDOW
        self.max_conn_recv: int = DEFAULT_INITIAL_CONN_WINDOW

        # NAT traversal & migration metrics
        self.nat = NATTraversalCoordinator()
        self.migration_count: int = 0
        self.received_datagrams: list[tuple[int, bytes]] = []
        self.anti_amplification_blocks: int = 0

        # Callbacks populated by HTTP/4 server/client layer
        self.on_stream_data: Callable[[WIQCConnection, int, bytes, bool], Awaitable[None] | None] | None = None
        self.on_datagram: Callable[[WIQCConnection, int, bytes], Awaitable[None] | None] | None = None
        self.on_nat_frame: Callable[[WIQCConnection, object], Awaitable[None] | None] | None = None
        self.on_zero_rtt_stream: Callable[[WIQCConnection, int, bytes, bool], Awaitable[None] | None] | None = None

        self._retransmit_task: asyncio.Task[None] | None = None

    @property
    def peer_id(self) -> bytes | None:
        return self.tls.peer_cert.peer_id if self.tls.peer_cert else None

    @property
    def negotiated_alpn(self) -> bytes | None:
        return self.tls.negotiated_alpn

    def start_background_tasks(self) -> None:
        if self._retransmit_task is None or self._retransmit_task.done():
            self._retransmit_task = asyncio.create_task(self._retransmit_loop())

    def alloc_bidi_stream_id(self) -> int:
        sid = self._next_bidi_stream_id
        self._next_bidi_stream_id += 4
        self._get_or_create_stream(sid)
        return sid

    def alloc_uni_stream_id(self) -> int:
        sid = self._next_uni_stream_id
        self._next_uni_stream_id += 4
        self._get_or_create_stream(sid)
        return sid

    def _get_or_create_stream(self, stream_id: int) -> WIQCStream:
        st = self.streams.get(stream_id)
        if st is None:
            st = WIQCStream(stream_id=stream_id)
            self.streams[stream_id] = st
        return st

    def _alloc_pkt_num(self) -> int:
        pn = self._next_pkt_num
        self._next_pkt_num += 1
        return pn

    def _check_anti_amplification_send(self, payload_len: int) -> None:
        """
        RFC 9000 §8.1 / RFC 7574 §12.1: Before validating a client's UDP source
        address, server MUST NOT send more than 3x the bytes received from it.
        """
        if self.is_server and not self.address_validated:
            limit = 3 * self.unvalidated_bytes_received
            if self.unvalidated_bytes_sent + payload_len > limit:
                self.anti_amplification_blocks += 1
                raise AntiAmplificationError(
                    f"Anti-amplification 3x budget exceeded prior to address validation "
                    f"(sent={self.unvalidated_bytes_sent + payload_len} > limit={limit})"
                )
            self.unvalidated_bytes_sent += payload_len

    def _send_raw_datagram(
        self,
        datagram: bytes,
        pkt_num: int | None = None,
        reliable: bool = False,
        stream_ids: list[int] | None = None,
        dest_addr: tuple[str, int] | None = None,
    ) -> None:
        target = dest_addr or self.remote_addr
        self._check_anti_amplification_send(len(datagram))
        if reliable and pkt_num is not None:
            self._in_flight[pkt_num] = InFlightPacket(
                packet_number=pkt_num,
                raw_bytes=datagram,
                sent_at=time.monotonic(),
                is_reliable=True,
                stream_ids=list(stream_ids or ()),
            )
        self.endpoint._transmit_udp(datagram, target, stream_ids=stream_ids or [])

    # -------------------------------------------------------------------------
    # Handshake Initiation & Processing (1-RTT + 0-RTT)
    # -------------------------------------------------------------------------

    async def start_client_handshake(
        self,
        zero_rtt_ticket: ZeroRTTTicket | None = None,
        early_data_stream: tuple[int, bytes, bool] | None = None,
        timeout: float = 5.0,
        override_client_cert_chain: list[bytes] | None = None,
    ) -> None:
        """
        Execute client-side Mutual TLS 1.3 handshake over WIQC UDP packets.
        Optionally sends an idempotent 0-RTT early request packet immediately
        after ClientHello when holding a valid `ZeroRTTTicket`.
        """
        self._override_cert_chain = override_client_cert_chain
        ch = self.tls.create_client_hello(zero_rtt_ticket=zero_rtt_ticket)

        # Build INITIAL packet carrying CRYPTO(ClientHello), padded to 1200 bytes
        # per RFC 9000 §14.1 so the server's 3x anti-amplification budget covers ServerAuth.
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.CRYPTO))
        w.write_varbytes(ch)
        payload = w.to_bytes()
        # Header size for INITIAL is ~32 bytes; pad payload to reach >= 1200 bytes total.
        if len(payload) < MIN_INITIAL_DATAGRAM_BYTES:
            payload += b"\x00" * (MIN_INITIAL_DATAGRAM_BYTES - len(payload))
        pn = self._alloc_pkt_num()
        pkt = encode_long_packet(
            pkt_type=PacketType.INITIAL,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=0,  # First flight has channel_id=0 until server assigns one
            packet_number=pn,
            payload=payload,
        )
        self.start_background_tasks()
        self._send_raw_datagram(pkt, pkt_num=pn, reliable=True)

        # Optional 0-RTT early data flight (MUST only be used for idempotent requests!)
        if zero_rtt_ticket is not None and early_data_stream is not None:
            sid, data, fin = early_data_stream
            ekeys = zero_rtt_ticket.derive_early_keys(is_client=True)
            self.zero_rtt_keys = ekeys
            sw = ByteWriter()
            sw.write_varint(int(TransportFrameType.STREAM))
            sw.write_varint(sid)
            sw.write_varint(0)
            sw.write_u8(1 if fin else 0)
            sw.write_varbytes(data)
            epn = self._alloc_pkt_num()
            epkt = encode_long_packet(
                pkt_type=PacketType.ZERO_RTT,
                dcid=self.remote_cid,
                scid=self.local_cid,
                channel_id=0,
                packet_number=epn,
                payload=sw.to_bytes(),
                extra=zero_rtt_ticket.ticket_id,
                cipher=ekeys.send_cipher,
                iv=ekeys.send_iv,
            )
            self._send_raw_datagram(epkt, pkt_num=epn, reliable=False, stream_ids=[sid])

        try:
            await asyncio.wait_for(self.handshake_event.wait(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            await self.close(reason="handshake timeout")
            raise TLSAuthenticationError("WIQC Mutual TLS 1.3 handshake timed out") from exc
        if self.handshake_error is not None:
            raise self.handshake_error

    async def send_unvalidated_heavy_first_flight_test(self, heavy_payload: bytes) -> None:
        """
        Helper strictly for security testing: sends a forbidden heavy payload
        inside an unvalidated INITIAL packet to verify server anti-amplification rejection.
        """
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.STREAM))
        w.write_varint(0)
        w.write_varint(0)
        w.write_u8(1)
        w.write_varbytes(heavy_payload)
        pn = self._alloc_pkt_num()
        pkt = encode_long_packet(
            pkt_type=PacketType.INITIAL,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=0,
            packet_number=pn,
            payload=w.to_bytes(),
        )
        self._send_raw_datagram(pkt, pkt_num=pn, reliable=False)

    # -------------------------------------------------------------------------
    # High-Level Encrypted 1-RTT Sending APIs
    # -------------------------------------------------------------------------

    def _send_1rtt_frames(
        self,
        frame_bytes: bytes,
        reliable: bool = True,
        stream_ids: list[int] | None = None,
        dest_addr: tuple[str, int] | None = None,
    ) -> int:
        if self.closed:
            raise ConnectionClosedError(f"Connection closed: {self.close_reason}")
        if self.keys is None:
            raise TLSAuthenticationError("Cannot send 1-RTT traffic before handshake completes")
        # Piggyback pending ACKs cleanly
        full_payload = frame_bytes
        if self._pending_acks:
            ack_frame = self._encode_ack_frame(self._pending_acks[-32:])
            self._pending_acks.clear()
            full_payload = ack_frame + frame_bytes

        pn = self._alloc_pkt_num()
        pkt = encode_short_packet(
            dcid=self.remote_cid,
            channel_id=self.remote_channel_id or self.local_channel_id,
            packet_number=pn,
            payload=full_payload,
            cipher=self.keys.send_cipher,
            iv=self.keys.send_iv,
        )
        self._send_raw_datagram(
            pkt, pkt_num=pn, reliable=reliable, stream_ids=stream_ids, dest_addr=dest_addr
        )
        return pn

    def send_stream_data(self, stream_id: int, data: bytes, fin: bool = False) -> None:
        """
        Segment and transmit bytes reliably on an independent WIQC stream.
        Enforces per-stream & connection flow-control windows.
        """
        st = self._get_or_create_stream(stream_id)
        if st.send_offset + len(data) > st.max_send_offset:
            raise FlowControlError(f"Stream {stream_id} send flow-control window exhausted")
        if self.conn_bytes_sent + len(data) > self.max_conn_send:
            raise FlowControlError("Connection send flow-control window exhausted")

        if not data:
            if fin and not st.send_fin:
                w = ByteWriter()
                w.write_varint(int(TransportFrameType.STREAM))
                w.write_varint(stream_id)
                w.write_varint(st.send_offset)
                w.write_u8(1)
                w.write_varbytes(b"")
                st.send_fin = True
                self._send_1rtt_frames(w.to_bytes(), reliable=True, stream_ids=[stream_id])
            return

        pos = 0
        total = len(data)
        while pos < total:
            chunk = data[pos : pos + MAX_STREAM_CHUNK]
            is_last = (pos + len(chunk)) >= total
            chunk_fin = fin and is_last
            w = ByteWriter()
            w.write_varint(int(TransportFrameType.STREAM))
            w.write_varint(stream_id)
            w.write_varint(st.send_offset)
            w.write_u8(1 if chunk_fin else 0)
            w.write_varbytes(chunk)
            st.send_offset += len(chunk)
            self.conn_bytes_sent += len(chunk)
            if chunk_fin:
                st.send_fin = True
            self._send_1rtt_frames(w.to_bytes(), reliable=True, stream_ids=[stream_id])
            pos += len(chunk)

    def send_datagram(self, quarter_stream_id: int, payload: bytes) -> None:
        """
        Send an unreliable ultra-low-latency QUIC DATAGRAM frame (RFC 9221,
        Section 5.3.4) associated with an HTTP/4 request stream.
        """
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.DATAGRAM))
        w.write_varint(quarter_stream_id)
        w.write_varbytes(payload)
        self._send_1rtt_frames(w.to_bytes(), reliable=False)

    def send_nat_frame(self, encoded_frame: bytes, dest_addr: tuple[str, int] | None = None) -> None:
        """Transmit a Native WIQC NAT Traversal or PATH_CHALLENGE/RESPONSE frame."""
        self._send_1rtt_frames(encoded_frame, reliable=False, dest_addr=dest_addr)

    def send_ping(self) -> int:
        return self._send_1rtt_frames(encode_varint(int(TransportFrameType.PING)), reliable=True)

    async def validate_direct_path(
        self, target_addr: tuple[str, int], round_num: int = 0, timeout: float = 2.0
    ) -> float:
        """
        Transmit `PATH_CHALLENGE` directly to `target_addr` and await `PATH_RESPONSE`.
        Returns measured direct path RTT in milliseconds.
        """
        frame, pending = self.nat.start_path_challenge(target_addr, round_num=round_num)
        # Send up to 3 probes spaced 80ms apart to tolerate simultaneous hole-punch timing skew
        async def _probe_sender() -> None:
            for _ in range(4):
                if pending.validated or self.closed:
                    return
                self.send_nat_frame(frame.encode(), dest_addr=target_addr)
                await asyncio.sleep(0.08)

        sender = asyncio.create_task(_probe_sender())
        try:
            await asyncio.wait_for(pending.event.wait(), timeout=timeout)
        finally:
            sender.cancel()
            try:
                await sender
            except asyncio.CancelledError:
                pass
        assert pending.validated_rtt_ms is not None
        return pending.validated_rtt_ms

    async def migrate_to_new_local_endpoint(self, new_endpoint: WIQCEndpoint) -> float:
        """
        Demonstrate RFC 9000 / WIQC Connection Migration: move this active connection
        onto a new UDP socket/port (`new_endpoint`) while preserving the DCID and
        validating the migrated path with `PATH_CHALLENGE`/`PATH_RESPONSE`.
        """
        self.endpoint.unregister_connection(self.local_cid)
        self.endpoint = new_endpoint
        self.endpoint.register_connection(self)
        rtt_ms = await self.validate_direct_path(self.remote_addr)
        return rtt_ms

    # -------------------------------------------------------------------------
    # Inbound Packet Handling (Fault-Tolerant)
    # -------------------------------------------------------------------------

    def _encode_ack_frame(self, pkt_nums: list[int]) -> bytes:
        unique = sorted(set(pkt_nums))
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.ACK))
        w.write_varint(unique[-1])
        w.write_varint(0)  # ack delay us
        w.write_varint(len(unique))
        for p in unique:
            w.write_varint(p)
        return w.to_bytes()

    def _send_ack_only(self, pkt_nums: list[int]) -> None:
        if self.keys is None or self.closed:
            return
        ack = self._encode_ack_frame(pkt_nums)
        pn = self._alloc_pkt_num()
        pkt = encode_short_packet(
            dcid=self.remote_cid,
            channel_id=self.remote_channel_id or self.local_channel_id,
            packet_number=pn,
            payload=ack,
            cipher=self.keys.send_cipher,
            iv=self.keys.send_iv,
        )
        self._send_raw_datagram(pkt, pkt_num=pn, reliable=False)

    async def handle_datagram(self, parsed: ParsedPacketHeader, src_addr: tuple[str, int]) -> None:
        if self.closed:
            return
        if self.is_server and not self.address_validated:
            self.unvalidated_bytes_received += len(parsed.header_bytes) + len(parsed.payload_bytes)

        if parsed.is_long:
            await self._handle_long_packet(parsed, src_addr)
        else:
            await self._handle_short_packet(parsed, src_addr)

    async def _handle_long_packet(
        self, parsed: ParsedPacketHeader, src_addr: tuple[str, int]
    ) -> None:
        if parsed.pkt_type == PacketType.INITIAL:
            r = ByteReader(parsed.payload_bytes)
            frames: list[tuple[int, bytes]] = []
            while not r.eof():
                ft = r.read_varint()
                if ft == TransportFrameType.PADDING:
                    continue
                elif ft == TransportFrameType.CRYPTO:
                    frames.append((ft, r.read_varbytes()))
                elif ft == TransportFrameType.STREAM:
                    # Normative Anti-Amplification Rule (Section 3.2 & Section 8.2):
                    # First flight MUST NOT contain heavy payloads prior to address validation!
                    if self.is_server and not self.address_validated:
                        self.anti_amplification_blocks += 1
                        await self.close(
                            error_code=AntiAmplificationError.error_code,
                            reason="Heavy STREAM/DATA payload forbidden in unvalidated first flight",
                        )
                        return
                elif ft == TransportFrameType.CONNECTION_CLOSE:
                    code = r.read_varint()
                    reason = r.read_varbytes(512).decode("utf-8", errors="replace")
                    self._fail_handshake(
                        AntiAmplificationError(reason, code)
                        if code == AntiAmplificationError.error_code
                        else TLSAuthenticationError(f"Peer closed during handshake (0x{code:x}): {reason}")
                    )
                    return
                else:
                    raise WireFormatError(f"Unexpected frame type 0x{ft:x} in INITIAL packet")

            for _, crypto_blob in frames:
                if self.is_server:
                    await self._server_on_client_hello(crypto_blob, parsed.scid, src_addr)
                else:
                    await self._client_on_server_hello(crypto_blob, parsed.scid, parsed.channel_id)

        elif parsed.pkt_type == PacketType.HANDSHAKE:
            r = ByteReader(parsed.payload_bytes)
            while not r.eof():
                ft = r.read_varint()
                if ft == TransportFrameType.PADDING:
                    continue
                elif ft == TransportFrameType.CRYPTO:
                    blob = r.read_varbytes()
                    if self.is_server:
                        # Address validation via RFC 7574 Channel ID echo!
                        if parsed.channel_id != self.local_channel_id:
                            self.anti_amplification_blocks += 1
                            await self.close(
                                error_code=AntiAmplificationError.error_code,
                                reason="Invalid Channel ID echo during address validation",
                            )
                            return
                        self.address_validated = True
                        await self._server_on_client_auth(blob, parsed.packet_number)
                    else:
                        await self._client_on_server_auth(blob, parsed.channel_id)
                elif ft == TransportFrameType.CONNECTION_CLOSE:
                    code = r.read_varint()
                    reason = r.read_varbytes(512).decode("utf-8", errors="replace")
                    self._fail_handshake(
                        TLSAuthenticationError(f"Handshake rejected by peer (0x{code:x}): {reason}")
                    )
                    return

        elif parsed.pkt_type == PacketType.ZERO_RTT:
            if not self.is_server:
                return
            ticket_id = parsed.extra
            ticket = self.endpoint.ticket_store.get(ticket_id)
            if ticket is None or ticket.is_expired():
                logger.warning("Dropping 0-RTT packet with unknown/expired ticket")
                return
            ekeys = ticket.derive_early_keys(is_client=False)
            nonce = make_packet_nonce(ekeys.recv_iv, parsed.packet_number)
            try:
                plaintext = ekeys.recv_cipher.decrypt(
                    nonce, parsed.payload_bytes, aad=parsed.header_bytes
                )
            except CryptoError:
                logger.warning("Dropping 0-RTT packet with invalid AEAD tag")
                return
            await self._dispatch_inner_frames(plaintext, src_addr, is_zero_rtt=True)

    _server_hello_sent: bool = False
    _cached_server_flight: tuple[bytes, bytes] | None = None
    _buffered_server_hello: bytes | None = None
    _buffered_server_auth: bytes | None = None
    _override_cert_chain: list[bytes] | None = None
    _client_auth_sent: bool = False

    async def _server_on_client_hello(
        self, client_hello: bytes, client_scid: bytes, src_addr: tuple[str, int]
    ) -> None:
        if self.tls.completed:
            return
        if self._server_hello_sent and self._cached_server_flight is not None:
            # Retransmit cached server flight if client retransmitted ClientHello due to UDP loss
            pkt1, pkt2 = self._cached_server_flight
            try:
                self._send_raw_datagram(pkt1)
                self._send_raw_datagram(pkt2)
            except AntiAmplificationError:
                pass
            return

        self.remote_cid = client_scid
        self.remote_addr = src_addr
        try:
            server_hello, server_auth = self.tls.process_client_hello(client_hello)
        except Exception as exc:
            await self._send_long_close(
                PacketType.INITIAL, TLSAuthenticationError.error_code, str(exc)
            )
            self._fail_handshake(exc)
            return

        self._server_hello_sent = True
        self.start_background_tasks()

        sh_w = ByteWriter()
        sh_w.write_varint(int(TransportFrameType.CRYPTO))
        sh_w.write_varbytes(server_hello)
        pn1 = self._alloc_pkt_num()
        pkt1 = encode_long_packet(
            pkt_type=PacketType.INITIAL,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=self.local_channel_id,  # Client MUST echo this Channel ID!
            packet_number=pn1,
            payload=sh_w.to_bytes(),
        )

        sa_w = ByteWriter()
        sa_w.write_varint(int(TransportFrameType.CRYPTO))
        sa_w.write_varbytes(server_auth)
        pn2 = self._alloc_pkt_num()
        pkt2 = encode_long_packet(
            pkt_type=PacketType.HANDSHAKE,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=self.local_channel_id,
            packet_number=pn2,
            payload=sa_w.to_bytes(),
        )
        self._cached_server_flight = (pkt1, pkt2)
        try:
            # Strictly enforce the RFC 9000 3x anti-amplification budget!
            self._send_raw_datagram(pkt1)
            self._send_raw_datagram(pkt2)
        except AntiAmplificationError as exc:
            logger.warning("Blocked amplification to unvalidated %s: %s", src_addr, exc)
            return

    async def _client_on_server_hello(
        self, server_hello: bytes, server_scid: bytes, server_channel_id: int
    ) -> None:
        if self.tls.completed or self._client_auth_sent:
            return
        self.remote_cid = server_scid
        self.remote_channel_id = server_channel_id
        self._buffered_server_hello = server_hello
        await self._maybe_complete_client_handshake()

    async def _client_on_server_auth(self, server_auth: bytes, server_channel_id: int) -> None:
        if self.tls.completed or self._client_auth_sent:
            return
        if server_channel_id:
            self.remote_channel_id = server_channel_id
        self._buffered_server_auth = server_auth
        await self._maybe_complete_client_handshake()

    async def _maybe_complete_client_handshake(self) -> None:
        if (
            self._client_auth_sent
            or self._buffered_server_hello is None
            or self._buffered_server_auth is None
        ):
            return
        # Stop retransmitting ClientHello now that we have both ServerHello & ServerAuth
        self._in_flight.clear()
        try:
            client_auth = self.tls.process_server_flight(
                self._buffered_server_hello,
                self._buffered_server_auth,
                override_client_cert_chain=self._override_cert_chain,
            )
        except Exception as exc:
            await self._send_long_close(
                PacketType.HANDSHAKE, TLSAuthenticationError.error_code, str(exc)
            )
            self._fail_handshake(exc)
            return

        # Check ban list on server peer_id
        if self.tls.peer_cert and self.endpoint.reputation.is_banned(
            self.tls.peer_cert.peer_id, self.remote_addr
        ):
            exc = PeerBannedError("Remote peer is banned")
            self._fail_handshake(exc)
            return

        self.keys = self.tls.app_keys
        self._client_auth_sent = True
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.CRYPTO))
        w.write_varbytes(client_auth)
        pn = self._alloc_pkt_num()
        pkt = encode_long_packet(
            pkt_type=PacketType.HANDSHAKE,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=self.remote_channel_id,  # Echo Server's Channel ID!
            packet_number=pn,
            payload=w.to_bytes(),
        )
        # Reliable send: retransmits until server confirms Mutual TLS with 1-RTT ACK + OBSERVED_ADDRESS!
        self._send_raw_datagram(pkt, pkt_num=pn, reliable=True)

    async def _server_on_client_auth(self, client_auth: bytes, client_auth_pn: int) -> None:
        if self.tls.completed:
            # Re-ACK if ClientAuth was retransmitted
            self._send_ack_only([client_auth_pn])
            return
        try:
            verified = self.tls.process_client_auth(client_auth)
        except Exception as exc:
            await self._send_long_close(
                PacketType.HANDSHAKE, TLSAuthenticationError.error_code, str(exc)
            )
            self._fail_handshake(exc)
            return

        if self.endpoint.reputation.is_banned(verified.peer_id, self.remote_addr):
            await self._send_long_close(
                PacketType.HANDSHAKE, PeerBannedError.error_code, "Peer is banned"
            )
            self._fail_handshake(PeerBannedError("Banned peer attempted connection"))
            return

        self.keys = self.tls.app_keys
        self.handshake_event.set()
        # Confirm Mutual TLS acceptance with 1-RTT ACK(client_auth_pn) + OBSERVED_ADDRESS!
        obs = self.nat.build_observed_address(self.remote_addr, seq=1)
        confirm_payload = self._encode_ack_frame([client_auth_pn]) + obs.encode()
        self._send_1rtt_frames(confirm_payload, reliable=True)
        # Notify server application that a mutually authenticated peer has connected
        if self.endpoint.on_connection_established is not None:
            res = self.endpoint.on_connection_established(self)
            if asyncio.iscoroutine(res):
                await res

    async def _send_long_close(self, pkt_type: PacketType, error_code: int, reason: str) -> None:
        w = ByteWriter()
        w.write_varint(int(TransportFrameType.CONNECTION_CLOSE))
        w.write_varint(error_code)
        w.write_varbytes(reason.encode("utf-8")[:256])
        pn = self._alloc_pkt_num()
        pkt = encode_long_packet(
            pkt_type=pkt_type,
            dcid=self.remote_cid,
            scid=self.local_cid,
            channel_id=self.local_channel_id,
            packet_number=pn,
            payload=w.to_bytes(),
        )
        self.endpoint._transmit_udp(pkt, self.remote_addr)

    def _fail_handshake(self, exc: Exception) -> None:
        self.handshake_error = exc
        self.closed = True
        self.handshake_event.set()

    async def _handle_short_packet(
        self, parsed: ParsedPacketHeader, src_addr: tuple[str, int]
    ) -> None:
        if self.keys is None:
            logger.debug("Ignoring 1-RTT packet before handshake keys ready")
            return
        nonce = make_packet_nonce(self.keys.recv_iv, parsed.packet_number)
        try:
            plaintext = self.keys.recv_cipher.decrypt(
                nonce, parsed.payload_bytes, aad=parsed.header_bytes
            )
        except CryptoError:
            logger.warning("Dropped 1-RTT packet with invalid AEAD tag from %s", src_addr)
            return

        # Authenticated packet from a NEW UDP source -> Seamless Connection Migration!
        if src_addr != self.remote_addr:
            logger.info(
                "WIQC Connection Migration detected for DCID=%s: %s -> %s",
                self.local_cid.hex()[:8],
                self.remote_addr,
                src_addr,
            )
            self.remote_addr = src_addr
            self.migration_count += 1
            # Validate the new migrated path with PATH_CHALLENGE
            challenge, _ = self.nat.start_path_challenge(src_addr)
            self.send_nat_frame(challenge.encode(), dest_addr=src_addr)

        # Deduplicate retransmitted packets, still ACK them!
        is_duplicate = parsed.packet_number in self._received_pkt_nums
        self._received_pkt_nums.add(parsed.packet_number)
        if len(self._received_pkt_nums) > 4096:
            # Prune oldest packet numbers to bound memory
            cutoff = max(self._received_pkt_nums) - 2048
            self._received_pkt_nums = {p for p in self._received_pkt_nums if p > cutoff}

        need_ack = await self._dispatch_inner_frames(
            plaintext, src_addr, is_zero_rtt=False, skip_data=is_duplicate
        )
        # First authenticated 1-RTT packet from server confirms Mutual TLS acceptance
        # and ensures ACK + OBSERVED_ADDRESS are processed before connect() returns!
        if not self.is_server and not self.handshake_event.is_set():
            self.handshake_event.set()
        if need_ack:
            self._send_ack_only([parsed.packet_number])

    async def _dispatch_inner_frames(
        self,
        payload: bytes,
        src_addr: tuple[str, int],
        is_zero_rtt: bool = False,
        skip_data: bool = False,
    ) -> bool:
        r = ByteReader(payload)
        need_ack = False
        while not r.eof():
            ft = r.read_varint()

            if ft == TransportFrameType.PING:
                need_ack = True

            elif ft == TransportFrameType.ACK:
                _largest = r.read_varint()
                _delay = r.read_varint()
                count = r.read_varint()
                now = time.monotonic()
                for _ in range(count):
                    acked_pn = r.read_varint()
                    inflight = self._in_flight.pop(acked_pn, None)
                    if inflight is not None and inflight.retransmits == 0:
                        rtt_ms = max(0.2, (now - inflight.sent_at) * 1000.0)
                        self.smoothed_rtt_ms = 0.875 * self.smoothed_rtt_ms + 0.125 * rtt_ms

            elif ft == TransportFrameType.STREAM:
                stream_id = r.read_varint()
                offset = r.read_varint()
                fin = bool(r.read_u8())
                chunk = r.read_varbytes()
                need_ack = True
                if skip_data:
                    continue
                if is_zero_rtt:
                    cb = self.on_zero_rtt_stream or self.endpoint.on_zero_rtt_stream
                    if cb is not None:
                        res = cb(self, stream_id, chunk, fin)
                        if asyncio.iscoroutine(res):
                            await res
                    continue

                self.conn_bytes_received += len(chunk)
                st = self._get_or_create_stream(stream_id)
                ready = st.ingest_chunk(offset, chunk, fin)
                # Replenish flow-control window if >50% consumed
                if st.recv_next_offset + (DEFAULT_INITIAL_STREAM_WINDOW // 2) > st.max_recv_offset:
                    st.max_recv_offset += DEFAULT_INITIAL_STREAM_WINDOW
                    mw = ByteWriter()
                    mw.write_varint(int(TransportFrameType.MAX_STREAM_DATA))
                    mw.write_varint(stream_id)
                    mw.write_varint(st.max_recv_offset)
                    self._send_1rtt_frames(mw.to_bytes(), reliable=False)

                if (ready or st.fin_received) and self.on_stream_data is not None:
                    res = self.on_stream_data(self, stream_id, ready, st.fin_received)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft == TransportFrameType.MAX_DATA:
                new_max = r.read_varint()
                if new_max > self.max_conn_send:
                    self.max_conn_send = new_max

            elif ft == TransportFrameType.MAX_STREAM_DATA:
                sid = r.read_varint()
                new_max = r.read_varint()
                st = self._get_or_create_stream(sid)
                if new_max > st.max_send_offset:
                    st.max_send_offset = new_max

            elif ft == TransportFrameType.DATAGRAM:
                qsid = r.read_varint()
                dgram_payload = r.read_varbytes()
                if not skip_data:
                    self.received_datagrams.append((qsid, dgram_payload))
                    if self.on_datagram is not None:
                        res = self.on_datagram(self, qsid, dgram_payload)
                        if asyncio.iscoroutine(res):
                            await res

            elif ft == TransportFrameType.PATH_CHALLENGE:
                pc = PathChallengeFrame.decode(r)
                resp = self.nat.handle_path_challenge(pc)
                self.send_nat_frame(resp.encode(), dest_addr=src_addr)

            elif ft == TransportFrameType.PATH_RESPONSE:
                pr = PathResponseFrame.decode(r)
                pending = self.nat.handle_path_response(pr, src_addr)
                if pending is not None and pending.validated_rtt_ms is not None:
                    self.address_validated = True
                    self.smoothed_rtt_ms = (
                        0.875 * self.smoothed_rtt_ms + 0.125 * pending.validated_rtt_ms
                    )
                if self.on_nat_frame is not None:
                    res = self.on_nat_frame(self, pr)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft in (NATFrameType.OBSERVED_ADDRESS_V4, NATFrameType.OBSERVED_ADDRESS_V6):
                obs = ObservedAddressFrame.decode(ft, r)
                need_ack = True
                if not skip_data:
                    self.nat.handle_observed_address(obs)
                    if self.on_nat_frame is not None:
                        res = self.on_nat_frame(self, obs)
                        if asyncio.iscoroutine(res):
                            await res

            elif ft in (NATFrameType.ADD_ADDRESS_V4, NATFrameType.ADD_ADDRESS_V6):
                add_f = AddAddressFrame.decode(ft, r)
                if self.peer_id:
                    self.nat.handle_remote_add_address(self.peer_id, add_f)
                if self.on_nat_frame is not None:
                    res = self.on_nat_frame(self, add_f)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft == NATFrameType.REMOVE_ADDRESS:
                rem_f = RemoveAddressFrame.decode(r)
                if self.peer_id:
                    self.nat.handle_remote_remove_address(self.peer_id, rem_f)
                if self.on_nat_frame is not None:
                    res = self.on_nat_frame(self, rem_f)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft in (NATFrameType.PUNCH_ME_NOW_V4, NATFrameType.PUNCH_ME_NOW_V6):
                pmn = PunchMeNowFrame.decode(ft, r)
                if self.on_nat_frame is not None:
                    res = self.on_nat_frame(self, pmn)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft == NATFrameType.PUNCH_REQUEST:
                prq = PunchRequestFrame.decode(r)
                if self.on_nat_frame is not None:
                    res = self.on_nat_frame(self, prq)
                    if asyncio.iscoroutine(res):
                        await res

            elif ft == TransportFrameType.CONNECTION_CLOSE:
                code = r.read_varint()
                reason = r.read_varbytes(512).decode("utf-8", errors="replace")
                self.closed = True
                self.close_reason = f"peer close 0x{code:x}: {reason}"
                if not self.handshake_event.is_set():
                    self._fail_handshake(ConnectionClosedError(self.close_reason, code))
                return False

            else:
                raise WireFormatError(f"Unknown WIQC transport frame type: 0x{ft:x}")

        return need_ack

    async def _retransmit_loop(self) -> None:
        """Adaptive RTO retransmission loop guaranteeing fault-tolerant UDP delivery."""
        try:
            while not self.closed:
                await asyncio.sleep(0.025)
                if not self._in_flight:
                    continue
                now = time.monotonic()
                rto = max(0.06, min(1.0, (self.smoothed_rtt_ms / 1000.0) * 3.0))
                for pn, pkt in list(self._in_flight.items()):
                    if not pkt.is_reliable:
                        self._in_flight.pop(pn, None)
                        continue
                    if (now - pkt.sent_at) >= rto * (1.5 ** min(pkt.retransmits, 4)):
                        if pkt.retransmits >= 8:
                            self._in_flight.pop(pn, None)
                            continue
                        pkt.retransmits += 1
                        pkt.sent_at = now
                        self.endpoint._transmit_udp(
                            pkt.raw_bytes, self.remote_addr, stream_ids=pkt.stream_ids
                        )
        except asyncio.CancelledError:
            return

    async def close(self, error_code: int = 0, reason: str = "normal close") -> None:
        if self.closed:
            return
        self.closed = True
        self.close_reason = reason
        try:
            if self.keys is not None:
                w = ByteWriter()
                w.write_varint(int(TransportFrameType.CONNECTION_CLOSE))
                w.write_varint(error_code)
                w.write_varbytes(reason.encode("utf-8")[:256])
                pn = self._alloc_pkt_num()
                pkt = encode_short_packet(
                    dcid=self.remote_cid,
                    channel_id=self.remote_channel_id or self.local_channel_id,
                    packet_number=pn,
                    payload=w.to_bytes(),
                    cipher=self.keys.send_cipher,
                    iv=self.keys.send_iv,
                )
                self.endpoint._transmit_udp(pkt, self.remote_addr)
            else:
                await self._send_long_close(PacketType.INITIAL, error_code, reason)
        except Exception:
            pass
        if self._retransmit_task is not None:
            self._retransmit_task.cancel()
            try:
                await self._retransmit_task
            except asyncio.CancelledError:
                pass
        self.endpoint.unregister_connection(self.local_cid)


# =============================================================================
# WIQC UDP Endpoint (Multiplexes Many Peer Connections on One UDP Socket)
# =============================================================================


class _WIQCUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, endpoint: WIQCEndpoint) -> None:
        self._endpoint = endpoint

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._endpoint._on_udp_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        # Windows UDP ICMP Port Unreachable errors (WinError 10054) can fire when a
        # peer crashes mid-swarm; fault-tolerantly ignore so healthy peers continue!
        logger.debug("UDP socket transient error (ignored for fault tolerance): %s", exc)


class WIQCEndpoint:
    """
    Symmetric WIQC UDP Endpoint capable of simultaneously accepting incoming
    swarm connections (peer server/seeder) and initiating outbound connections
    (client/leecher) on a single bound UDP socket.
    """

    def __init__(
        self,
        identity: PeerIdentity,
        host: str = "127.0.0.1",
        port: int = 0,
        alpns: tuple[bytes, ...] = SUPPORTED_ALPNS,
        reputation: PeerReputationManager | None = None,
        fault_profile: FaultInjectionProfile | None = None,
    ) -> None:
        self.identity = identity
        self.bind_host = host
        self.bind_port = port
        self.alpns = alpns
        self.cert_bundle: Libp2pCertificateBundle = generate_libp2p_self_signed_cert(identity)
        self.reputation = reputation or PeerReputationManager()
        self.fault_profile = fault_profile
        self.ticket_store: dict[bytes, ZeroRTTTicket] = {}

        self._transport: asyncio.DatagramTransport | None = None
        self._connections: dict[bytes, WIQCConnection] = {}  # local_cid -> conn
        self._initial_by_client_cid: dict[bytes, WIQCConnection] = {}  # remote_cid -> conn
        self.malformed_datagrams_dropped: int = 0
        self.on_connection_established: Callable[[WIQCConnection], Awaitable[None] | None] | None = None
        self.on_zero_rtt_stream: Callable[[WIQCConnection, int, bytes, bool], Awaitable[None] | None] | None = None
        self.on_raw_nat_punch_packet: Callable[[bytes, tuple[str, int]], Awaitable[None] | None] | None = None

    @property
    def local_address(self) -> tuple[str, int]:
        if self._transport is None:
            return (self.bind_host, self.bind_port)
        sockname = self._transport.get_extra_info("sockname")
        return (sockname[0], sockname[1])

    async def start(self) -> tuple[str, int]:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _WIQCUDPProtocol(self),
            local_addr=(self.bind_host, self.bind_port),
        )
        self._transport = transport
        return self.local_address

    async def stop(self) -> None:
        for conn in list(self._connections.values()):
            await conn.close(reason="endpoint shutdown")
        self._connections.clear()
        self._initial_by_client_cid.clear()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            await asyncio.sleep(0.015)

    def register_connection(self, conn: WIQCConnection) -> None:
        self._connections[conn.local_cid] = conn

    def unregister_connection(self, local_cid: bytes) -> None:
        conn = self._connections.pop(local_cid, None)
        if conn is not None:
            self._initial_by_client_cid.pop(conn.remote_cid, None)

    def _transmit_udp(
        self,
        datagram: bytes,
        dest_addr: tuple[str, int],
        stream_ids: list[int] | None = None,
    ) -> None:
        if self._transport is None or self._transport.is_closing():
            return
        if self.fault_profile is not None:
            if self.fault_profile.should_drop_outbound(dest_addr, stream_ids or []):
                return
            if self.fault_profile.corrupt_rate > 0.0 and self.fault_profile._rng.random() < self.fault_profile.corrupt_rate:
                mut = bytearray(datagram)
                mut[-1] ^= 0xFF
                datagram = bytes(mut)
            if self.fault_profile.extra_latency_ms > 0.0:
                delay = self.fault_profile.extra_latency_ms / 1000.0
                asyncio.get_running_loop().call_later(
                    delay, self._safe_sendto, datagram, dest_addr
                )
                return
        self._safe_sendto(datagram, dest_addr)

    def _safe_sendto(self, datagram: bytes, dest_addr: tuple[str, int]) -> None:
        if self._transport is not None and not self._transport.is_closing():
            try:
                self._transport.sendto(datagram, dest_addr)
            except OSError as exc:
                logger.debug("UDP sendto error to %s: %s", dest_addr, exc)

    def send_unencrypted_nat_probe(self, payload: bytes, dest_addr: tuple[str, int]) -> None:
        """
        Send a lightweight UDP NAT hole-punch probe (`b"WIQC-PUNCH" + ...`) directly
        to a peer's external UDP socket before a shared 1-RTT connection exists.
        """
        self._transmit_udp(b"WIQC-PUNCH:" + payload, dest_addr)

    async def connect(
        self,
        remote_addr: tuple[str, int],
        zero_rtt_ticket: ZeroRTTTicket | None = None,
        early_data_stream: tuple[int, bytes, bool] | None = None,
        timeout: float = 5.0,
        override_client_cert_chain: list[bytes] | None = None,
        on_conn_created: Callable[[WIQCConnection], None] | None = None,
    ) -> WIQCConnection:
        if self._transport is None:
            await self.start()
        local_cid = secrets.token_bytes(CID_LEN)
        initial_dcid = secrets.token_bytes(CID_LEN)
        conn = WIQCConnection(
            endpoint=self,
            local_cid=local_cid,
            remote_cid=initial_dcid,
            remote_addr=remote_addr,
            is_server=False,
            alpns=self.alpns,
        )
        self.register_connection(conn)
        if on_conn_created is not None:
            on_conn_created(conn)
        await conn.start_client_handshake(
            zero_rtt_ticket=zero_rtt_ticket,
            early_data_stream=early_data_stream,
            timeout=timeout,
            override_client_cert_chain=override_client_cert_chain,
        )
        return conn

    async def _on_udp_datagram(self, data: bytes, src_addr: tuple[str, int]) -> None:
        if self.fault_profile is not None and not self.fault_profile.allow_inbound(src_addr):
            return
        if self.reputation.is_banned(address=src_addr):
            return

        # Direct NAT traversal probe packet (simultaneous hole punch before 1-RTT)
        if data.startswith(b"WIQC-PUNCH:"):
            if self.on_raw_nat_punch_packet is not None:
                res = self.on_raw_nat_punch_packet(data[len(b"WIQC-PUNCH:") :], src_addr)
                if asyncio.iscoroutine(res):
                    await res
            return

        try:
            parsed = parse_packet_header(data)
        except WireFormatError:
            self.malformed_datagrams_dropped += 1
            return

        conn = self._connections.get(parsed.dcid)
        if conn is None and parsed.is_long:
            # New incoming client INITIAL or ZERO_RTT packet!
            if parsed.pkt_type in (PacketType.INITIAL, PacketType.ZERO_RTT):
                conn = self._initial_by_client_cid.get(parsed.scid)
                if conn is None:
                    local_cid = secrets.token_bytes(CID_LEN)
                    conn = WIQCConnection(
                        endpoint=self,
                        local_cid=local_cid,
                        remote_cid=parsed.scid,
                        remote_addr=src_addr,
                        is_server=True,
                        alpns=self.alpns,
                    )
                    self.register_connection(conn)
                    self._initial_by_client_cid[parsed.scid] = conn

        if conn is None:
            self.malformed_datagrams_dropped += 1
            return

        try:
            await conn.handle_datagram(parsed, src_addr)
        except Exception as exc:
            logger.debug("Fault-tolerant packet drop on connection %s: %s", conn.local_cid.hex()[:8], exc)
            self.malformed_datagrams_dropped += 1
