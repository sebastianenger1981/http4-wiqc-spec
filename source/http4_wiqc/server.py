"""
HTTP/4 over WIQC Server (Authoritative Origin Publisher, Static Seeder,
Live Streamer, Relay Peer, and NAT Traversal Coordinator).

Implements the complete server/peer-server architecture of
`draft-enger-httpbis-http4-wiqc-00`:
- Symmetric WIQC UDP Endpoint with Mutual TLS 1.3 (`libp2p-tls`, single cert +
  OID `1.3.6.1.4.1.53594.1.1`) and ALPN negotiation (`h4`, `wiqc`).
- All 6 HTTP/4 Stream Types (`0x00` Control, `0x01` Push, `0x02` QPACK Encoder,
  `0x03` QPACK Decoder, `0x40` WIQC Subgroup, `0x41` WIQC Swarm Control) +
  Bidirectional HTTP/4 Request Streams.
- RFC 9421 Origin Message Signatures (`Signature-Input` & `Signature`),
  RFC 9530 `Repr-Digest` & `Swarm-Root`, Section 7 ABNF `WIQC-Swarm-Info`,
  RFC 7838 `Alt-Svc`, RFC 9460 `HTTPS`/`SVCB` record export.
- Static Content Mode (BEP 52 16 KiB SHA-256 Merkle proofs + Hash Messages 21/22/23).
- Real-Time Live Streaming Mode (MOQT Track/Group/Subgroup/Object + RFC 7574 CIPM 3
  Unified Merkle Tree munro signing + per-Subgroup unidirectional `0x40` streams).
- Trackerless Peer Exchange (`WIQC_PEX`), Server Push (`PUSH_PROMISE` + `0x01`),
  HTTP Datagrams (RFC 9221) & DATAGRAM Capsules (RFC 9297).
- 0-RTT Replay Protection (accepts idempotent GET/HEAD/OPTIONS, rejects POST/PUT/DELETE
  with `425 Too Early`).
- Native WIQC NAT Traversal Relay (`OBSERVED_ADDRESS`, `ADD_ADDRESS`, `REMOVE_ADDRESS`,
  `PUNCH_REQUEST` -> synchronized `PUNCH_ME_NOW` hole-punch coordination).
- Optional fault/pollution injection flags strictly for verifying client resilience!
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field

from .crypto import PeerIdentity
from .exceptions import QPACKError, SwarmNegotiationError, WireFormatError
from .frames import (
    AddAddressFrame,
    CancelPushFrame,
    DataFrame,
    DatagramCapsule,
    FrameType,
    GoAwayFrame,
    HeadersFrame,
    MaxPushIdFrame,
    PeerEndpoint,
    PEXSubType,
    PunchRequestFrame,
    PushPromiseFrame,
    RawFrame,
    RemoveAddressFrame,
    SettingsFrame,
    SettingsID,
    StreamFrameBuffer,
    StreamType,
    WIQCCancelFrame,
    WIQCChokeFrame,
    WIQCHaveFrame,
    WIQCIntegrityFrame,
    WIQCPexFrame,
    WIQCRequestFrame,
    WIQCSignedIntegrityFrame,
    WIQCSubgroupObjectFrame,
)
from .headers import (
    AltSvcEntry,
    HTTPSServiceRecord,
    WIQCSwarmInfo,
    format_alt_svc,
    format_repr_digest,
    format_swarm_root,
    sign_http4_headers,
)
from .media import MediaGroup, MediaObject, PeerReputationManager, TrackIdentifier
from .merkle import (
    BEP52_MSG_HASH_REQUEST,
    BEP52HashRequest,
    BinTreeMath,
    SignedMunro,
    UncleProofEntry,
)
from .qpack import QPACKDecoder, QPACKEncoder
from .swarm import (
    ChunkAddressingMethod,
    IntegrityProtectionMethod,
    LiveSwarmChannel,
    PEXRegistry,
    StaticSwarmResource,
    SwarmCapabilities,
    VerifiedLiveChunk,
)
from .tls_libp2p import SUPPORTED_ALPNS
from .transport import FaultInjectionProfile, WIQCConnection, WIQCEndpoint
from .varint import decode_varint, encode_varint

logger = logging.getLogger("http4_wiqc.server")

IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class _ServerPeerSession:
    """Per-connection HTTP/4 + QPACK + WIQC Swarm session state on the server."""

    conn: WIQCConnection
    qpack_encoder: QPACKEncoder = field(default_factory=QPACKEncoder)
    qpack_decoder: QPACKDecoder = field(default_factory=QPACKDecoder)
    control_stream_id: int | None = None
    qpack_enc_stream_id: int | None = None
    qpack_dec_stream_id: int | None = None
    remote_swarm_ctrl_stream_id: int | None = None
    max_push_id: int = 16
    next_push_id: int = 0
    cancelled_pushes: set[int] = field(default_factory=set)
    negotiated_swarms: dict[bytes, SwarmCapabilities] = field(default_factory=dict)
    subscribed_live_swarms: set[bytes] = field(default_factory=set)

    # Incremental buffers per incoming stream_id
    stream_buffers: dict[int, StreamFrameBuffer] = field(default_factory=dict)
    uni_stream_types: dict[int, int] = field(default_factory=dict)
    uni_raw_bufs: dict[int, bytearray] = field(default_factory=dict)
    bidi_is_swarm_ctrl: dict[int, bool] = field(default_factory=dict)
    request_headers: dict[int, dict[str, str]] = field(default_factory=dict)
    request_bodies: dict[int, bytearray] = field(default_factory=dict)
    request_fin_seen: set[int] = field(default_factory=set)
    blocked_qpack_headers: list[tuple[int, bytes]] = field(default_factory=list)
    ready_event: asyncio.Event = field(default_factory=asyncio.Event)


class HTTP4WIQCServer:
    """
    Object-oriented HTTP/4 over WIQC Server supporting:
    - Origin static publishing (BEP 52 16 KiB Merkle swarms + RFC 9421 signed metadata),
    - Origin live streaming (MOQT Groups/Subgroups + Unified Merkle Tree munro signing),
    - Relay/Peer re-seeding (serves verified blocks/chunks acquired from upstream),
    - Trackerless PEX discovery,
    - Server Push, RFC 9221 Datagrams, RFC 9297 Capsules, 0-RTT idempotency guard,
    - Native WIQC NAT Traversal Relay (`OBSERVED_ADDRESS` + `PUNCH_ME_NOW`).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        authority: str = "origin.http4.local",
        identity: PeerIdentity | None = None,
        alpns: tuple[bytes, ...] = SUPPORTED_ALPNS,
        fault_profile: FaultInjectionProfile | None = None,
        pollute_static_chunks: set[int] | None = None,
        pollute_live_chunks: set[int] | None = None,
    ) -> None:
        self.identity = identity or PeerIdentity.generate(label=f"server-{authority}")
        self.authority = authority
        self.reputation = PeerReputationManager()
        self.endpoint = WIQCEndpoint(
            identity=self.identity,
            host=host,
            port=port,
            alpns=alpns,
            reputation=self.reputation,
            fault_profile=fault_profile,
        )
        self.endpoint.on_connection_established = self._on_connection_established
        self.endpoint.on_zero_rtt_stream = self._on_zero_rtt_stream

        # Resource registries
        self.static_by_path: dict[str, StaticSwarmResource] = {}
        self.static_by_swarm_id: dict[bytes, StaticSwarmResource] = {}
        self.push_companions: dict[str, tuple[str, bytes, str]] = {}  # req_path -> (push_path, body, ctype)
        self.live_by_path: dict[str, LiveSwarmChannel] = {}
        self.live_by_swarm_id: dict[bytes, LiveSwarmChannel] = {}

        # PEX trackerless peer table
        self.pex = PEXRegistry()

        # Active sessions keyed by local_cid and peer_id
        self.sessions: dict[bytes, _ServerPeerSession] = {}
        self.sessions_by_peer_id: dict[bytes, _ServerPeerSession] = {}

        # Telemetry & audit counters (great for demos & automated assertions)
        self.zero_rtt_accepted: int = 0
        self.zero_rtt_rejected: int = 0
        self.capsules_received: list[DatagramCapsule] = []
        self.datagrams_received: list[tuple[int, bytes]] = []
        self.nat_punches_coordinated: int = 0
        self.bep52_hash_requests_served: int = 0

        # Optional test-only pollution hooks to simulate a malicious/polluting peer
        self.pollute_static_chunks: set[int] = set(pollute_static_chunks or ())
        self.pollute_live_chunks: set[int] = set(pollute_live_chunks or ())

    @property
    def address(self) -> tuple[str, int]:
        return self.endpoint.local_address

    @property
    def peer_id(self) -> bytes:
        return self.identity.peer_id

    async def start(self) -> tuple[str, int]:
        addr = await self.endpoint.start()
        # Register self in PEX for all published swarms
        for sid in list(self.static_by_swarm_id) + list(self.live_by_swarm_id):
            self.pex.register_peer(sid, PeerEndpoint(host=addr[0], port=addr[1], peer_id=self.peer_id))
        logger.info("HTTP/4 WIQC Server %s listening on UDP %s:%d", self.authority, addr[0], addr[1])
        return addr

    async def stop(self) -> None:
        # Send graceful HTTP/4 GOAWAY (0x07) on every active Control Stream (0x00)
        for sess in list(self.sessions.values()):
            if not sess.conn.closed and sess.control_stream_id is not None:
                try:
                    goaway = GoAwayFrame(last_stream_or_push_id=0).to_raw().encode()
                    sess.conn.send_stream_data(sess.control_stream_id, goaway, fin=True)
                except Exception:
                    pass
        await asyncio.sleep(0.02)
        await self.endpoint.stop()
        self.sessions.clear()
        self.sessions_by_peer_id.clear()

    # =========================================================================
    # Resource Publishing & Discovery Helpers
    # =========================================================================

    def publish_static_resource(
        self,
        path: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        push_companion: tuple[str, bytes, str] | None = None,
    ) -> StaticSwarmResource:
        """
        Publish a static HTTP/4 resource backed by a BEP 52 16 KiB SHA-256 Merkle tree.
        Optionally attaches a companion resource pushed via HTTP/4 `PUSH_PROMISE` + Stream `0x01`.
        """
        res = StaticSwarmResource.from_bytes(path=path, data=data, content_type=content_type)
        self.static_by_path[path] = res
        self.static_by_swarm_id[res.swarm_id] = res
        if push_companion is not None:
            self.push_companions[path] = push_companion
        if self.address[1] > 0:
            self.pex.register_peer(
                res.swarm_id,
                PeerEndpoint(host=self.address[0], port=self.address[1], peer_id=self.peer_id),
            )
        return res

    def register_relay_static_resource(self, resource: StaticSwarmResource) -> None:
        """Register an existing (or partially seeded) static resource for peer re-seeding."""
        self.static_by_path[resource.path] = resource
        self.static_by_swarm_id[resource.swarm_id] = resource
        if self.address[1] > 0:
            self.pex.register_peer(
                resource.swarm_id,
                PeerEndpoint(host=self.address[0], port=self.address[1], peer_id=self.peer_id),
            )

    def create_live_channel(
        self,
        path: str,
        track_name: str,
        munro_layer: int = 2,
        live_discard_window: int = 64,
    ) -> LiveSwarmChannel:
        """Create an authoritative origin live track using RFC 7574 CIPM 3 Unified Merkle Tree."""
        track = TrackIdentifier(authority=self.authority, path=path, track_name=track_name)
        channel = LiveSwarmChannel(
            track=track,
            publisher_public_key=self.identity.public_key,
            publisher_private_key=self.identity.private_key,
            munro_layer=munro_layer,
            live_discard_window=live_discard_window,
        )
        self.live_by_path[path] = channel
        self.live_by_swarm_id[channel.swarm_id] = channel
        if self.address[1] > 0:
            self.pex.register_peer(
                channel.swarm_id,
                PeerEndpoint(host=self.address[0], port=self.address[1], peer_id=self.peer_id),
            )
        return channel

    def register_relay_live_channel(self, channel: LiveSwarmChannel) -> None:
        """Register a relay/downstream live channel for verified peer-to-peer re-seeding."""
        self.live_by_path[channel.track.path] = channel
        self.live_by_swarm_id[channel.swarm_id] = channel
        if self.address[1] > 0:
            self.pex.register_peer(
                channel.swarm_id,
                PeerEndpoint(host=self.address[0], port=self.address[1], peer_id=self.peer_id),
            )

    def build_https_svcb_record(self) -> HTTPSServiceRecord:
        """Generate RFC 9460 DNS `HTTPS`/`SVCB` record advertising `h4` and `wiqc` ALPNs."""
        host, port = self.address
        v4 = (host,) if ":" not in host else ()
        v6 = (host,) if ":" in host else ()
        return HTTPSServiceRecord(
            priority=1,
            target_name=f"{self.authority}.",
            alpn=("h4", "wiqc"),
            port=port,
            ipv4hint=v4,
            ipv6hint=v6,
        )

    async def publish_and_broadcast_live_group(
        self, path: str, group: MediaGroup
    ) -> tuple[SignedMunro, list[VerifiedLiveChunk]]:
        """
        Origin publisher commits a MOQT Group into the Unified Merkle Tree, signs
        its munro hash, and fans out EVERY Subgroup onto its own dedicated
        unidirectional WIQC Subgroup Stream (`0x40`) to all subscribed peers!
        """
        channel = self.live_by_path[path]
        signed_munro, verified_chunks = channel.publish_group(group)

        # Group chunks by subgroup_id so EACH Subgroup gets its own unidirectional 0x40 stream!
        by_subgroup: dict[int, list[VerifiedLiveChunk]] = {}
        for vc in verified_chunks:
            by_subgroup.setdefault(vc.obj.subgroup_id, []).append(vc)

        for sess in list(self.sessions.values()):
            if sess.conn.closed or channel.swarm_id not in sess.subscribed_live_swarms:
                continue
            # 1. Send WIQC_SIGNED_INTEGRITY + WIQC_HAVE on Swarm Control (0x41) if open
            if sess.remote_swarm_ctrl_stream_id is not None:
                si = WIQCSignedIntegrityFrame(
                    swarm_id=channel.swarm_id, signed_munro=signed_munro
                ).to_raw().encode()
                hv = channel.build_have_frame(use_bin64=True).to_raw().encode()
                sess.conn.send_stream_data(sess.remote_swarm_ctrl_stream_id, si + hv, fin=False)

            # 2. Open one dedicated unidirectional WIQC Subgroup Stream (0x40) PER Subgroup!
            for sg_id in sorted(by_subgroup.keys()):
                sg_chunks = by_subgroup[sg_id]
                uni_sid = sess.conn.alloc_uni_stream_id()
                sg_obj = group.subgroups.get(sg_id)
                if sg_obj is not None:
                    sg_obj.wiqc_stream_id = uni_sid
                self._send_subgroup_stream(
                    conn=sess.conn,
                    uni_stream_id=uni_sid,
                    swarm_id=channel.swarm_id,
                    track_name=channel.track.track_name,
                    chunks=sg_chunks,
                    signed_munro=signed_munro,
                    is_live=True,
                )

        return signed_munro, verified_chunks

    def reseed_verified_live_chunk(
        self, path: str, verified_chunk: VerifiedLiveChunk
    ) -> None:
        """
        Relay peer immediately re-seeds a cryptographically verified live chunk to
        all downstream subscribers via a unidirectional WIQC Subgroup stream (0x40)
        and announces updated `WIQC_HAVE` bins on Swarm Control (0x41).
        """
        channel = self.live_by_path[path]
        for sess in list(self.sessions.values()):
            if sess.conn.closed or channel.swarm_id not in sess.subscribed_live_swarms:
                continue
            if sess.remote_swarm_ctrl_stream_id is not None:
                hv = channel.build_have_frame(use_bin64=True).to_raw().encode()
                sess.conn.send_stream_data(sess.remote_swarm_ctrl_stream_id, hv, fin=False)
            uni_sid = sess.conn.alloc_uni_stream_id()
            self._send_subgroup_stream(
                conn=sess.conn,
                uni_stream_id=uni_sid,
                swarm_id=channel.swarm_id,
                track_name=channel.track.track_name,
                chunks=[verified_chunk],
                signed_munro=verified_chunk.signed_munro,
                is_live=True,
            )

    def _send_subgroup_stream(
        self,
        conn: WIQCConnection,
        uni_stream_id: int,
        swarm_id: bytes,
        track_name: str,
        chunks: list[VerifiedLiveChunk],
        signed_munro: SignedMunro | None,
        is_live: bool,
    ) -> None:
        """Write Stream Type 0x40 + [WIQC_SIGNED_INTEGRITY] + [WIQC_SUBGROUP_OBJECT + WIQC_INTEGRITY]."""
        buf = bytearray(encode_varint(int(StreamType.WIQC_SWARM_SUBGROUP)))
        if signed_munro is not None:
            buf.extend(
                WIQCSignedIntegrityFrame(swarm_id=swarm_id, signed_munro=signed_munro)
                .to_raw()
                .encode()
            )
        for vc in chunks:
            payload = vc.obj.payload
            if is_live and vc.obj.chunk_index in self.pollute_live_chunks:
                # Simulated stream-pollution attack for negative security testing!
                mut = bytearray(payload)
                mut[0] ^= 0xFF
                payload = bytes(mut)
            obj_frame = WIQCSubgroupObjectFrame(
                swarm_id=swarm_id,
                track_name=track_name,
                group_id=vc.obj.group_id,
                subgroup_id=vc.obj.subgroup_id,
                object_id=vc.obj.object_id,
                chunk_index=vc.obj.chunk_index,
                priority_urgency=vc.obj.priority_urgency,
                is_keyframe=vc.obj.is_keyframe,
                deadline_ms=vc.obj.playback_deadline_ms,
                payload=payload,
            ).to_raw().encode()
            int_frame = WIQCIntegrityFrame(
                swarm_id=swarm_id,
                target_bin=vc.obj.bin_id,
                uncles=tuple(vc.uncle_proof),
            ).to_raw().encode()
            buf.extend(obj_frame)
            buf.extend(int_frame)
        conn.send_stream_data(uni_stream_id, bytes(buf), fin=True)

    # =========================================================================
    # Connection & Stream Callbacks
    # =========================================================================

    async def _on_connection_established(self, conn: WIQCConnection) -> None:
        sess = self.sessions.get(conn.local_cid)
        if sess is None:
            sess = _ServerPeerSession(conn=conn)
            self.sessions[conn.local_cid] = sess
        if conn.peer_id is not None:
            self.sessions_by_peer_id[conn.peer_id] = sess

        conn.on_stream_data = self._on_stream_data
        conn.on_datagram = self._on_datagram
        conn.on_nat_frame = self._on_nat_frame

        # Initialize HTTP/4 server unidirectional control & QPACK streams (Section 5.1)
        ctrl_sid = conn.alloc_uni_stream_id()
        qenc_sid = conn.alloc_uni_stream_id()
        qdec_sid = conn.alloc_uni_stream_id()
        sess.control_stream_id = ctrl_sid
        sess.qpack_enc_stream_id = qenc_sid
        sess.qpack_dec_stream_id = qdec_sid

        settings = SettingsFrame(
            settings={
                int(SettingsID.QPACK_MAX_TABLE_CAPACITY): 4096,
                int(SettingsID.QPACK_BLOCKED_STREAMS): 16,
                int(SettingsID.H3_DATAGRAM): 1,
                int(SettingsID.WIQC_MAX_SWARM_PEERS): 128,
                int(SettingsID.WIQC_LIVE_DISCARD_WINDOW): 64,
                int(SettingsID.WIQC_CHUNK_ADDRESSING): int(ChunkAddressingMethod.BIN64),
            }
        ).to_raw().encode()
        conn.send_stream_data(
            ctrl_sid, encode_varint(int(StreamType.CONTROL)) + settings, fin=False
        )
        conn.send_stream_data(qenc_sid, encode_varint(int(StreamType.QPACK_ENCODER)), fin=False)
        conn.send_stream_data(qdec_sid, encode_varint(int(StreamType.QPACK_DECODER)), fin=False)
        sess.ready_event.set()

    async def _on_zero_rtt_stream(
        self, conn: WIQCConnection, stream_id: int, data: bytes, fin: bool
    ) -> None:
        """
        Handle 0-RTT early HTTP/4 request frames while strictly enforcing Section 8.3:
        0-RTT MUST ONLY be accepted for idempotent operations (GET, HEAD, OPTIONS)!
        Non-idempotent requests (POST, PUT, DELETE, PATCH) are rejected with `425 Too Early`.
        """
        sess = self.sessions.get(conn.local_cid)
        if sess is None:
            sess = _ServerPeerSession(conn=conn)
            self.sessions[conn.local_cid] = sess
        frames = RawFrame.decode_all(data)
        for frame in frames:
            if frame.frame_type == FrameType.HEADERS:
                hdrs_list, _ = sess.qpack_decoder.decode(frame.payload, stream_id=stream_id)
                hdrs = dict(hdrs_list)
                method = hdrs.get(":method", "").upper()
                path = hdrs.get(":path", "/")
                if method not in IDEMPOTENT_METHODS:
                    self.zero_rtt_rejected += 1
                    logger.warning(
                        "Rejected non-idempotent 0-RTT request %s %s (Section 8.3 replay defense)",
                        method,
                        path,
                    )
                    # Wait briefly until 1-RTT keys are ready to send 425 Too Early response
                    asyncio.create_task(
                        self._send_deferred_status(
                            conn,
                            sess,
                            stream_id,
                            "425",
                            b"Too Early: non-idempotent 0-RTT forbidden by HTTP/4 Section 8.3",
                        )
                    )
                    return
                self.zero_rtt_accepted += 1
                asyncio.create_task(self._dispatch_deferred_0rtt_get(conn, sess, stream_id, hdrs))

    async def _send_deferred_status(
        self,
        conn: WIQCConnection,
        sess: _ServerPeerSession,
        stream_id: int,
        status: str,
        body: bytes,
    ) -> None:
        try:
            await asyncio.wait_for(sess.ready_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            return
        if conn.closed:
            return
        hdrs = {
            ":status": status,
            "content-type": "text/plain;charset=utf-8",
            "x-wiqc-0rtt-replay-guard": "rejected",
        }
        await self._send_http_response(sess, stream_id, hdrs, body)

    async def _dispatch_deferred_0rtt_get(
        self,
        conn: WIQCConnection,
        sess: _ServerPeerSession,
        stream_id: int,
        req_headers: dict[str, str],
    ) -> None:
        try:
            await asyncio.wait_for(sess.ready_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            return
        if conn.closed:
            return
        await self._handle_http_request(sess, stream_id, req_headers, b"", via_0rtt=True)

    async def _on_stream_data(
        self, conn: WIQCConnection, stream_id: int, data: bytes, fin: bool
    ) -> None:
        sess = self.sessions.get(conn.local_cid)
        if sess is None:
            return

        is_uni = (stream_id & 0x02) != 0
        if is_uni:
            await self._handle_uni_stream(sess, stream_id, data, fin)
        else:
            await self._handle_bidi_stream(sess, stream_id, data, fin)

    async def _handle_uni_stream(
        self, sess: _ServerPeerSession, stream_id: int, data: bytes, fin: bool
    ) -> None:
        if stream_id not in sess.uni_stream_types:
            raw = sess.uni_raw_bufs.setdefault(stream_id, bytearray())
            raw.extend(data)
            try:
                stype, consumed = decode_varint(raw, 0)
            except WireFormatError:
                return
            sess.uni_stream_types[stream_id] = stype
            rem = bytes(raw[consumed:])
            del sess.uni_raw_bufs[stream_id]
        else:
            stype = sess.uni_stream_types[stream_id]
            rem = data

        if stype == StreamType.QPACK_ENCODER:
            if rem:
                ack_bytes = sess.qpack_decoder.process_encoder_stream(rem)
                if ack_bytes and sess.qpack_dec_stream_id is not None:
                    sess.conn.send_stream_data(sess.qpack_dec_stream_id, ack_bytes, fin=False)
                await self._replay_blocked_qpack(sess)
        elif stype == StreamType.QPACK_DECODER:
            if rem:
                sess.qpack_encoder.process_decoder_stream(rem)
        elif stype == StreamType.CONTROL:
            buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
            for frame in buf.feed(rem):
                await self._handle_control_frame(sess, frame)
        elif stype == StreamType.WIQC_SWARM_SUBGROUP:
            # Peer pushing/uploading a Subgroup stream to this server/relay
            buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
            buf.feed(rem)

    async def _handle_control_frame(self, sess: _ServerPeerSession, frame: RawFrame) -> None:
        if frame.frame_type == FrameType.SETTINGS:
            _settings = SettingsFrame.from_payload(frame.payload)
        elif frame.frame_type == FrameType.MAX_PUSH_ID:
            sess.max_push_id = MaxPushIdFrame.from_payload(frame.payload).max_push_id
        elif frame.frame_type == FrameType.CANCEL_PUSH:
            pid = CancelPushFrame.from_payload(frame.payload).push_id
            sess.cancelled_pushes.add(pid)
        elif frame.frame_type == FrameType.WIQC_PEX:
            await self._handle_pex_frame(sess, frame, reply_stream_id=sess.control_stream_id)
        elif frame.frame_type == FrameType.GOAWAY:
            logger.info("Client sent GOAWAY on connection %s", sess.conn.local_cid.hex()[:8])

    async def _handle_bidi_stream(
        self, sess: _ServerPeerSession, stream_id: int, data: bytes, fin: bool
    ) -> None:
        # Distinguish bidirectional WIQC Swarm Control (0x41) from HTTP/4 Request Streams
        if stream_id not in sess.bidi_is_swarm_ctrl:
            raw = sess.uni_raw_bufs.setdefault(stream_id, bytearray())
            raw.extend(data)
            if not raw:
                return
            try:
                first_varint, consumed = decode_varint(raw, 0)
            except WireFormatError:
                return
            if first_varint == int(StreamType.WIQC_SWARM_CONTROL):
                sess.bidi_is_swarm_ctrl[stream_id] = True
                sess.remote_swarm_ctrl_stream_id = stream_id
                rem = bytes(raw[consumed:])
            else:
                sess.bidi_is_swarm_ctrl[stream_id] = False
                rem = bytes(raw)
            del sess.uni_raw_bufs[stream_id]
        else:
            rem = data

        buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
        frames = buf.feed(rem)

        if sess.bidi_is_swarm_ctrl[stream_id]:
            for frame in frames:
                await self._handle_swarm_control_frame(sess, stream_id, frame)
        else:
            for frame in frames:
                if frame.frame_type == FrameType.HEADERS:
                    try:
                        hdrs_list, dec_ack = sess.qpack_decoder.decode(
                            frame.payload, stream_id=stream_id
                        )
                    except QPACKError:
                        # Blocked stream (RFC 9204): wait for QPACK Encoder stream 0x02 to catch up
                        sess.blocked_qpack_headers.append((stream_id, frame.payload))
                        continue
                    if dec_ack and sess.qpack_dec_stream_id is not None:
                        sess.conn.send_stream_data(sess.qpack_dec_stream_id, dec_ack, fin=False)
                    sess.request_headers[stream_id] = dict(hdrs_list)
                elif frame.frame_type == FrameType.DATA:
                    sess.request_bodies.setdefault(stream_id, bytearray()).extend(frame.payload)
            if fin:
                sess.request_fin_seen.add(stream_id)
            if stream_id in sess.request_fin_seen and stream_id in sess.request_headers:
                sess.request_fin_seen.discard(stream_id)
                hdrs = sess.request_headers.pop(stream_id)
                body = bytes(sess.request_bodies.pop(stream_id, bytearray()))
                await self._handle_http_request(sess, stream_id, hdrs, body, via_0rtt=False)

    async def _replay_blocked_qpack(self, sess: _ServerPeerSession) -> None:
        if not sess.blocked_qpack_headers:
            return
        remaining: list[tuple[int, bytes]] = []
        for sid, payload in sess.blocked_qpack_headers:
            try:
                hdrs_list, dec_ack = sess.qpack_decoder.decode(payload, stream_id=sid)
            except QPACKError:
                remaining.append((sid, payload))
                continue
            if dec_ack and sess.qpack_dec_stream_id is not None:
                sess.conn.send_stream_data(sess.qpack_dec_stream_id, dec_ack, fin=False)
            sess.request_headers[sid] = dict(hdrs_list)
            if sid in sess.request_fin_seen:
                sess.request_fin_seen.discard(sid)
                hdrs = sess.request_headers.pop(sid)
                body = bytes(sess.request_bodies.pop(sid, bytearray()))
                await self._handle_http_request(sess, sid, hdrs, body, via_0rtt=False)
        sess.blocked_qpack_headers = remaining

    # =========================================================================
    # HTTP/4 Request Handling (Signed Metadata, Server Push, Capsules)
    # =========================================================================

    async def _send_http_response(
        self,
        sess: _ServerPeerSession,
        stream_id: int,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> None:
        encoded_hdrs, enc_inst = sess.qpack_encoder.encode(headers)
        if enc_inst and sess.qpack_enc_stream_id is not None:
            sess.conn.send_stream_data(sess.qpack_enc_stream_id, enc_inst, fin=False)
        out = HeadersFrame(encoded_hdrs).to_raw().encode()
        if body:
            out += DataFrame(body).to_raw().encode()
        sess.conn.send_stream_data(stream_id, out, fin=True)

    async def _handle_http_request(
        self,
        sess: _ServerPeerSession,
        stream_id: int,
        headers: dict[str, str],
        body: bytes,
        via_0rtt: bool = False,
    ) -> None:
        method = headers.get(":method", "GET").upper()
        path = headers.get(":path", "/")
        alt_svc_val = format_alt_svc([AltSvcEntry("h4", f":{self.address[1]}", max_age=86400)])

        # 1. RFC 9297 HTTP Capsule Protocol endpoint (`DATAGRAM Capsule 0x00`)
        if headers.get("capsule-protocol") == "?1" or path == "/capsule":
            if body:
                cap = DatagramCapsule.decode(body)
                self.capsules_received.append(cap)
                reply_cap = DatagramCapsule(
                    quarter_stream_id=cap.quarter_stream_id,
                    payload=b"ACK-CAPSULE:" + cap.payload,
                )
                resp_hdrs = {
                    ":status": "200",
                    "capsule-protocol": "?1",
                    "content-type": "application/octet-stream",
                    "alt-svc": alt_svc_val,
                }
                await self._send_http_response(sess, stream_id, resp_hdrs, reply_cap.encode())
                return

        # 2. Static Content Resource (BEP 52 Merkle Mode)
        static_res = self.static_by_path.get(path)
        if static_res is not None:
            full_bytes = static_res.reassemble() if static_res.is_complete else b""
            repr_digest = (
                format_repr_digest(full_bytes)
                if full_bytes
                else format_repr_digest(static_res.pieces_root, already_hashed=True)
            )
            swarm_info = WIQCSwarmInfo(
                swarm_id=static_res.swarm_id,
                mode="merkle-v2",
                chunk_addr="bin64",
            )
            resp_hdrs = {
                ":status": "200",
                "content-type": static_res.content_type,
                "content-length": str(static_res.total_size),
                "repr-digest": repr_digest,
                "content-digest": repr_digest,
                "swarm-root": format_swarm_root(static_res.pieces_root),
                "wiqc-swarm-id": static_res.swarm_id.hex(),
                "wiqc-swarm-info": swarm_info.format(),
                "wiqc-block-count": str(static_res.block_count),
                "alt-svc": alt_svc_val,
                "x-wiqc-0rtt": "accepted" if via_0rtt else "1rtt",
            }
            # Sign response metadata with RFC 9421 Origin Message Signatures!
            signed_hdrs = sign_http4_headers(
                resp_hdrs,
                origin_private_key=self.identity.private_key,
                key_id=self.peer_id.hex()[:16],
            )

            # Optional HTTP/4 Server Push (PUSH_PROMISE 0x05 + Push Stream 0x01)
            push_companion = self.push_companions.get(path)
            if push_companion is not None and sess.next_push_id <= sess.max_push_id:
                push_path, push_body, push_ctype = push_companion
                push_id = sess.next_push_id
                sess.next_push_id += 1
                if push_id not in sess.cancelled_pushes:
                    promise_hdrs = {
                        ":method": "GET",
                        ":scheme": "https",
                        ":authority": self.authority,
                        ":path": push_path,
                    }
                    enc_prom, enc_inst = sess.qpack_encoder.encode(promise_hdrs)
                    if enc_inst and sess.qpack_enc_stream_id is not None:
                        sess.conn.send_stream_data(sess.qpack_enc_stream_id, enc_inst, fin=False)
                    pp_frame = PushPromiseFrame(push_id, enc_prom).to_raw().encode()
                    sess.conn.send_stream_data(stream_id, pp_frame, fin=False)
                    # Open Unidirectional Push Stream (0x01)
                    push_sid = sess.conn.alloc_uni_stream_id()
                    p_resp_hdrs = {
                        ":status": "200",
                        "content-type": push_ctype,
                        "repr-digest": format_repr_digest(push_body),
                    }
                    enc_ph, enc_inst2 = sess.qpack_encoder.encode(p_resp_hdrs)
                    if enc_inst2 and sess.qpack_enc_stream_id is not None:
                        sess.conn.send_stream_data(sess.qpack_enc_stream_id, enc_inst2, fin=False)
                    push_wire = (
                        encode_varint(int(StreamType.PUSH))
                        + encode_varint(push_id)
                        + HeadersFrame(enc_ph).to_raw().encode()
                        + DataFrame(push_body).to_raw().encode()
                    )
                    sess.conn.send_stream_data(push_sid, push_wire, fin=True)

            inline_body = full_bytes if headers.get("x-wiqc-inline") == "1" else b""
            await self._send_http_response(sess, stream_id, signed_hdrs, inline_body)
            return

        # 3. Live Real-Time Streaming Channel (Unified Merkle Tree Mode)
        live_ch = self.live_by_path.get(path)
        if live_ch is not None:
            sess.subscribed_live_swarms.add(live_ch.swarm_id)
            swarm_info = WIQCSwarmInfo(
                swarm_id=live_ch.swarm_id,
                mode="unified-live",
                window=live_ch.live_discard_window,
                chunk_addr="bin64",
            )
            pub_b64 = base64.b64encode(live_ch.publisher_public_key.public_bytes).decode("ascii")
            resp_hdrs = {
                ":status": "200",
                "content-type": "application/wiqc-live-track",
                "repr-digest": format_repr_digest(live_ch.swarm_id, already_hashed=True),
                "wiqc-swarm-id": live_ch.swarm_id.hex(),
                "wiqc-swarm-info": swarm_info.format(),
                "wiqc-publisher-key": f":{pub_b64}:",
                "wiqc-track-name": live_ch.track.track_name,
                "wiqc-munro-layer": str(live_ch.munro_layer),
                "alt-svc": alt_svc_val,
                "x-wiqc-0rtt": "accepted" if via_0rtt else "1rtt",
            }
            signed_hdrs = sign_http4_headers(
                resp_hdrs,
                origin_private_key=self.identity.private_key,
                key_id=self.peer_id.hex()[:16],
            )
            await self._send_http_response(sess, stream_id, signed_hdrs, b"")
            return

        # 4. Echo endpoint for testing non-idempotent POST/PUT over 1-RTT vs 0-RTT
        if method in ("POST", "PUT") and path == "/echo":
            resp_hdrs = {
                ":status": "200",
                "content-type": "application/octet-stream",
                "repr-digest": format_repr_digest(body),
                "x-wiqc-0rtt": "1rtt",
            }
            await self._send_http_response(sess, stream_id, resp_hdrs, body)
            return

        # 5. Not Found
        await self._send_http_response(
            sess,
            stream_id,
            {":status": "404", "content-type": "text/plain;charset=utf-8"},
            f"HTTP/4 resource not found: {path}".encode("utf-8"),
        )

    # =========================================================================
    # WIQC Swarm Control Stream (0x41) Handler
    # =========================================================================

    async def _handle_swarm_control_frame(
        self, sess: _ServerPeerSession, stream_id: int, frame: RawFrame
    ) -> None:
        if frame.frame_type == FrameType.WIQC_HANDSHAKE_CAPS:
            remote_caps = SwarmCapabilities.decode_payload(frame.payload)
            sid = remote_caps.swarm_id
            if sid in self.static_by_swarm_id:
                res = self.static_by_swarm_id[sid]
                local_caps = SwarmCapabilities(
                    swarm_id=sid,
                    integrity_method=IntegrityProtectionMethod.MERKLE_HASH_TREE_STATIC,
                    chunk_addressing=ChunkAddressingMethod.BIN64,
                    live_discard_window=0,
                )
                negotiated = SwarmCapabilities.negotiate(local_caps, remote_caps)
                sess.negotiated_swarms[sid] = negotiated
                reply = (
                    negotiated.encode_frame().encode()
                    + WIQCChokeFrame(swarm_id=sid, choked=False).to_raw().encode()
                    + res.build_have_frame(
                        use_bin64=(negotiated.chunk_addressing == ChunkAddressingMethod.BIN64)
                    ).to_raw().encode()
                )
                sess.conn.send_stream_data(stream_id, reply, fin=False)
            elif sid in self.live_by_swarm_id:
                ch = self.live_by_swarm_id[sid]
                local_caps = SwarmCapabilities(
                    swarm_id=sid,
                    integrity_method=IntegrityProtectionMethod.UNIFIED_MERKLE_TREE_LIVE,
                    chunk_addressing=ChunkAddressingMethod.BIN64,
                    live_discard_window=ch.live_discard_window,
                )
                negotiated = SwarmCapabilities.negotiate(local_caps, remote_caps)
                sess.negotiated_swarms[sid] = negotiated
                sess.subscribed_live_swarms.add(sid)
                reply = (
                    negotiated.encode_frame().encode()
                    + WIQCChokeFrame(swarm_id=sid, choked=False).to_raw().encode()
                    + ch.build_have_frame(
                        use_bin64=(negotiated.chunk_addressing == ChunkAddressingMethod.BIN64)
                    ).to_raw().encode()
                )
                sess.conn.send_stream_data(stream_id, reply, fin=False)
            else:
                raise SwarmNegotiationError(f"Unknown Swarm ID: {sid.hex()[:12]}")

        elif frame.frame_type == FrameType.WIQC_REQUEST:
            req = WIQCRequestFrame.from_payload(frame.payload)
            await self._serve_swarm_request(sess, req)

        elif frame.frame_type == FrameType.WIQC_BEP52_HASH_MSG:
            # Handle BEP 52 Hash Request (ID 21) -> Hash Response (ID 22) or Hash Reject (ID 23)
            if frame.payload and frame.payload[0] == BEP52_MSG_HASH_REQUEST:
                hreq = BEP52HashRequest.decode(frame.payload)
                res = self.static_by_swarm_id.get(hreq.pieces_root)
                if res is not None and res.merkle_tree is not None:
                    hresp = res.merkle_tree.handle_bep52_hash_request(hreq)
                    self.bep52_hash_requests_served += 1
                    wire = RawFrame(FrameType.WIQC_BEP52_HASH_MSG, hresp.encode()).encode()
                    sess.conn.send_stream_data(stream_id, wire, fin=False)

        elif frame.frame_type == FrameType.WIQC_PEX:
            await self._handle_pex_frame(sess, frame, reply_stream_id=stream_id)

        elif frame.frame_type in (
            FrameType.WIQC_HAVE,
            FrameType.WIQC_CANCEL,
            FrameType.WIQC_CHOKE,
            FrameType.WIQC_UNCHOKE,
        ):
            # Recorded gracefully for symmetric swarm peering
            pass

    async def _serve_swarm_request(
        self, sess: _ServerPeerSession, req: WIQCRequestFrame
    ) -> None:
        sid = req.swarm_id
        # 1. Static BEP 52 Mode
        static_res = self.static_by_swarm_id.get(sid)
        if static_res is not None:
            for b in req.bins:
                lo, hi = BinTreeMath.leaf_range(b)
                for chunk_idx in range(lo, min(hi + 1, static_res.block_count)):
                    block = static_res.verified_blocks.get(chunk_idx)
                    proof = static_res.verified_proofs.get(chunk_idx)
                    if block is None or proof is None:
                        continue
                    if chunk_idx in self.pollute_static_chunks:
                        # Simulated pollution attack: flip 1 byte of the 16 KiB block!
                        mut = bytearray(block)
                        mut[0] ^= 0xAA
                        block = bytes(mut)
                    uni_sid = sess.conn.alloc_uni_stream_id()
                    obj_frame = WIQCSubgroupObjectFrame(
                        swarm_id=sid,
                        track_name=static_res.path,
                        group_id=0,
                        subgroup_id=chunk_idx,
                        object_id=chunk_idx,
                        chunk_index=chunk_idx,
                        priority_urgency=req.priority_urgency,
                        is_keyframe=(chunk_idx == 0),
                        deadline_ms=req.deadline_ms,
                        payload=block,
                    ).to_raw().encode()
                    int_frame = WIQCIntegrityFrame(
                        swarm_id=sid,
                        target_bin=BinTreeMath.leaf_bin(chunk_idx),
                        uncles=tuple(proof),
                    ).to_raw().encode()
                    wire = (
                        encode_varint(int(StreamType.WIQC_SWARM_SUBGROUP))
                        + obj_frame
                        + int_frame
                    )
                    sess.conn.send_stream_data(uni_sid, wire, fin=True)
            return

        # 2. Live Unified Merkle Tree Mode
        live_ch = self.live_by_swarm_id.get(sid)
        if live_ch is not None:
            for b in req.bins:
                lo, hi = BinTreeMath.leaf_range(b)
                for chunk_idx in range(lo, hi + 1):
                    vc = live_ch.verified_chunks.get(chunk_idx)
                    if vc is None:
                        continue
                    uni_sid = sess.conn.alloc_uni_stream_id()
                    self._send_subgroup_stream(
                        conn=sess.conn,
                        uni_stream_id=uni_sid,
                        swarm_id=sid,
                        track_name=live_ch.track.track_name,
                        chunks=[vc],
                        signed_munro=vc.signed_munro,
                        is_live=True,
                    )

    async def _handle_pex_frame(
        self, sess: _ServerPeerSession, frame: RawFrame, reply_stream_id: int | None
    ) -> None:
        pex_msg = WIQCPexFrame.from_payload(frame.payload)
        if pex_msg.subtype == PEXSubType.PEX_REQ and reply_stream_id is not None:
            v4_resp = self.pex.build_pex_response(
                pex_msg.swarm_id, ip_version=4, exclude_address=sess.conn.remote_addr
            )
            sess.conn.send_stream_data(reply_stream_id, v4_resp.to_raw().encode(), fin=False)
            v6_peers = self.pex.get_peers(
                pex_msg.swarm_id, ip_version=6, exclude_address=sess.conn.remote_addr
            )
            if v6_peers:
                v6_resp = self.pex.build_pex_response(
                    pex_msg.swarm_id, ip_version=6, exclude_address=sess.conn.remote_addr
                )
                sess.conn.send_stream_data(reply_stream_id, v6_resp.to_raw().encode(), fin=False)
        elif pex_msg.subtype in (PEXSubType.PEX_RESv4, PEXSubType.PEX_RESv6):
            for peer in pex_msg.peers:
                self.pex.register_peer(pex_msg.swarm_id, peer)

    # =========================================================================
    # Datagrams (RFC 9221) & Native NAT Traversal Relay Coordination (Section 6.2)
    # =========================================================================

    async def _on_datagram(
        self, conn: WIQCConnection, quarter_stream_id: int, payload: bytes
    ) -> None:
        self.datagrams_received.append((quarter_stream_id, payload))
        # Echo unreliable media datagram back with low-latency server tag
        conn.send_datagram(quarter_stream_id, b"ECHO-DGRAM:" + payload)

    async def _on_nat_frame(self, conn: WIQCConnection, frame: object) -> None:
        if isinstance(frame, AddAddressFrame):
            logger.debug("Relay recorded ADD_ADDRESS from %s: %s:%d", conn.remote_addr, frame.host, frame.port)
        elif isinstance(frame, RemoveAddressFrame):
            logger.debug("Relay recorded REMOVE_ADDRESS seq=%d", frame.sequence)
        elif isinstance(frame, PunchRequestFrame):
            # Relay coordinates simultaneous UDP hole punching between requester and target peer!
            target_sess = self.sessions_by_peer_id.get(frame.target_peer_id)
            if target_sess is None or target_sess.conn.closed:
                logger.warning("PUNCH_REQUEST target peer %s not connected to relay", frame.target_peer_id.hex()[:8])
                return
            requester_addr = conn.remote_addr
            target_addr = target_sess.conn.remote_addr
            pmn_for_requester, pmn_for_target = conn.nat.coordinate_simultaneous_punch(
                peer_a_addr=requester_addr,
                peer_b_addr=target_addr,
            )
            # Send synchronized PUNCH_ME_NOW frames simultaneously to BOTH peers!
            conn.send_nat_frame(pmn_for_requester.encode())
            target_sess.conn.send_nat_frame(pmn_for_target.encode())
            self.nat_punches_coordinated += 1
            logger.info(
                "Relay coordinated simultaneous WIQC UDP hole punch (round=%d): %s <-> %s",
                pmn_for_requester.round_num,
                requester_addr,
                target_addr,
            )
