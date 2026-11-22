"""
HTTP/4 over WIQC Client (Multi-Peer Swarm Subscriber, Static Leecher, Live Stream
Receiver, Relay Re-Seeder, and Native NAT Hole-Punching Peer).

Implements the complete client / peer-leecher architecture of
`draft-enger-httpbis-http4-wiqc-00`:
- Concurrent WIQC connections to multiple swarm peers via Mutual TLS 1.3 (`libp2p-tls`).
- Full HTTP/4 Request/Response workflow over QPACK Streams (`0x02`/`0x03`) with
  RFC 9114 §10.6 sensitive-header compression side-channel protection.
- Automatic RFC 9421 Origin Message Signature verification (`@status`, `content-type`,
  `repr-digest`, `wiqc-swarm-id`), RFC 9530 `Repr-Digest` & `Swarm-Root`, and
  Section 7 ABNF `WIQC-Swarm-Info` parsing.
- 0-RTT Idempotent Request support with Replay Protection Guard (Section 8.3).
- Server Push reception (`PUSH_PROMISE` `0x05` + Push Stream `0x01`).
- Unreliable HTTP Datagrams (RFC 9221) & DATAGRAM Capsules (RFC 9297).
- Multi-Peer Static Swarm Download (BEP 52 16 KiB Merkle verification + BEP 52 Hash
  Messages 21/22/23 + `WIQC_PEX` trackerless discovery + deterministic isolation &
  banning of polluting peers + automatic failover across healthy peers!).
- Real-Time Decentralized Live Streaming (MOQT Subgroups over independent `0x40`
  unidirectional streams + RFC 7574 CIPM 3 Unified Merkle Tree munro verification +
  Dual-Zone EDF/Rarest-First scheduler + live re-seeding to downstream peers!).
- Native WIQC NAT Traversal (`OBSERVED_ADDRESS`, `ADD_ADDRESS`, `PUNCH_REQUEST`,
  `PUNCH_ME_NOW` simultaneous UDP hole punching + `PATH_CHALLENGE`/`PATH_RESPONSE`).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .crypto import Ed25519PublicKey, PeerIdentity
from .exceptions import (
    IntegrityVerificationError,
    PeerBannedError,
    QPACKError,
    ReplayProtectionError,
    WireFormatError,
)
from .frames import (
    DataFrame,
    DatagramCapsule,
    FrameType,
    GoAwayFrame,
    HeadersFrame,
    MaxPushIdFrame,
    PeerEndpoint,
    PEXSubType,
    PunchMeNowFrame,
    PushPromiseFrame,
    RawFrame,
    SettingsFrame,
    SettingsID,
    StreamFrameBuffer,
    StreamType,
    WIQCChokeFrame,
    WIQCHaveFrame,
    WIQCIntegrityFrame,
    WIQCPexFrame,
    WIQCRequestFrame,
    WIQCSignedIntegrityFrame,
    WIQCSubgroupObjectFrame,
)
from .headers import (
    WIQCSwarmInfo,
    parse_repr_digest,
    parse_swarm_root,
    verify_http4_headers,
)
from .media import (
    ChunkRequirement,
    DualZoneSwarmScheduler,
    MediaObject,
    PeerReputationManager,
    SwarmPeerState,
    TrackIdentifier,
)
from .merkle import (
    BEP52_MSG_HASHES,
    BEP52Hashes,
    BEP52HashReject,
    BEP52HashRequest,
    BinTreeMath,
    SignedMunro,
    StaticMerkleTree,
    UncleProofEntry,
)
from .qpack import QPACKDecoder, QPACKEncoder
from .swarm import (
    ChunkAddressingMethod,
    IntegrityProtectionMethod,
    LiveSwarmChannel,
    StaticSwarmResource,
    SwarmCapabilities,
    VerifiedLiveChunk,
)
from .tls_libp2p import SUPPORTED_ALPNS, ZeroRTTTicket
from .transport import FaultInjectionProfile, WIQCConnection, WIQCEndpoint
from .varint import decode_varint, encode_varint

logger = logging.getLogger("http4_wiqc.client")

IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class HTTP4Response:
    """Decoded HTTP/4 response including verified origin signatures and pushed resources."""

    status: int
    headers: dict[str, str]
    body: bytes
    origin_signature_verified: bool = False
    pushed_resources: dict[int, tuple[dict[str, str], bytes]] = field(default_factory=dict)


@dataclass
class _ClientPeerSession:
    """Per-peer HTTP/4 + QPACK + WIQC Swarm session state on the client."""

    conn: WIQCConnection
    qpack_encoder: QPACKEncoder = field(default_factory=QPACKEncoder)
    qpack_decoder: QPACKDecoder = field(default_factory=QPACKDecoder)
    control_stream_id: int | None = None
    qpack_enc_stream_id: int | None = None
    qpack_dec_stream_id: int | None = None
    swarm_ctrl_stream_id: int | None = None

    # Request tracking: stream_id -> Future[HTTP4Response]
    pending_requests: dict[int, asyncio.Future[HTTP4Response]] = field(default_factory=dict)
    resp_headers: dict[int, dict[str, str]] = field(default_factory=dict)
    resp_bodies: dict[int, bytearray] = field(default_factory=dict)
    resp_fin_seen: set[int] = field(default_factory=set)
    completed_responses: dict[int, HTTP4Response] = field(default_factory=dict)
    blocked_qpack_headers: list[tuple[int, bytes, bool]] = field(default_factory=list)  # (sid, payload, is_push)

    # Server Push tracking (Stream 0x01)
    promised_pushes: dict[int, dict[str, str]] = field(default_factory=dict)
    received_pushes: dict[int, tuple[dict[str, str], bytes]] = field(default_factory=dict)
    push_stream_ids: dict[int, int] = field(default_factory=dict)  # stream_id -> push_id
    push_headers: dict[int, dict[str, str]] = field(default_factory=dict)
    push_bodies: dict[int, bytearray] = field(default_factory=dict)

    # Swarm state
    negotiated_swarms: dict[bytes, SwarmCapabilities] = field(default_factory=dict)
    caps_events: dict[bytes, asyncio.Event] = field(default_factory=dict)
    have_chunks: dict[bytes, set[int]] = field(default_factory=dict)
    choked_swarms: set[bytes] = field(default_factory=set)
    pex_peers: dict[bytes, list[PeerEndpoint]] = field(default_factory=dict)
    pex_events: dict[bytes, asyncio.Event] = field(default_factory=dict)
    bep52_hash_futures: list[asyncio.Future[BEP52Hashes | BEP52HashReject]] = field(
        default_factory=list
    )

    # Incremental framing buffers
    stream_buffers: dict[int, StreamFrameBuffer] = field(default_factory=dict)
    uni_stream_types: dict[int, int] = field(default_factory=dict)
    uni_raw_bufs: dict[int, bytearray] = field(default_factory=dict)
    subgroup_pending_objects: dict[int, list[WIQCSubgroupObjectFrame]] = field(default_factory=dict)
    subgroup_pending_munros: dict[int, SignedMunro] = field(default_factory=dict)
    goaway_received: bool = False


class HTTP4WIQCClient:
    """
    Object-oriented HTTP/4 over WIQC Client & Decentralized Swarm Peer.

    Can simultaneously connect to multiple origin servers, seeders, and relays,
    verify every static block (BEP 52) and live chunk (Unified Merkle Tree),
    ban malicious/polluting peers deterministically, perform trackerless PEX,
    and establish direct P2P paths through NATs via `PUNCH_ME_NOW`.
    """

    def __init__(
        self,
        label: str = "http4-wiqc-client",
        identity: PeerIdentity | None = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        alpns: tuple[bytes, ...] = SUPPORTED_ALPNS,
        fault_profile: FaultInjectionProfile | None = None,
    ) -> None:
        self.identity = identity or PeerIdentity.generate(label=label)
        self.reputation = PeerReputationManager()
        self.endpoint = WIQCEndpoint(
            identity=self.identity,
            host=bind_host,
            port=bind_port,
            alpns=alpns,
            reputation=self.reputation,
            fault_profile=fault_profile,
        )
        self.endpoint.on_raw_nat_punch_packet = self._on_raw_nat_punch_packet

        self.sessions: dict[bytes, _ClientPeerSession] = {}  # local_cid -> session
        self.tickets: dict[tuple[str, int], ZeroRTTTicket] = {}

        # Active static & live swarm handlers
        self._static_swarms: dict[bytes, StaticSwarmResource] = {}
        self._static_chunk_events: dict[bytes, asyncio.Event] = {}
        self._live_swarms: dict[bytes, LiveSwarmChannel] = {}
        self._live_callbacks: dict[bytes, list[Callable[[VerifiedLiveChunk, int], None]]] = {}

        # Audit metrics
        self.pollution_attacks_blocked: int = 0
        self.datagrams_received: list[tuple[int, bytes]] = []
        self.direct_nat_punches_succeeded: dict[tuple[str, int], float] = {}
        self._punch_events: dict[tuple[str, int], asyncio.Event] = {}
        self._punch_tokens_sent: dict[bytes, tuple[tuple[str, int], float]] = {}

    @property
    def address(self) -> tuple[str, int]:
        return self.endpoint.local_address

    @property
    def peer_id(self) -> bytes:
        return self.identity.peer_id

    async def start(self) -> tuple[str, int]:
        return await self.endpoint.start()

    async def close(self) -> None:
        for sess in list(self.sessions.values()):
            if not sess.conn.closed and sess.control_stream_id is not None:
                try:
                    sess.conn.send_stream_data(
                        sess.control_stream_id,
                        GoAwayFrame(0).to_raw().encode(),
                        fin=True,
                    )
                except Exception:
                    pass
        await self.endpoint.stop()
        self.sessions.clear()

    # =========================================================================
    # Connection Establishment (1-RTT Mutual TLS & 0-RTT Resumption)
    # =========================================================================

    async def connect(
        self,
        server_addr: tuple[str, int],
        timeout: float = 5.0,
        override_client_cert_chain: list[bytes] | None = None,
    ) -> _ClientPeerSession:
        """Establish a mutually authenticated WIQC connection and initialize HTTP/4 streams."""
        if self.reputation.is_banned(address=server_addr):
            raise PeerBannedError(f"Refusing connection to banned peer at {server_addr}")

        holder: list[_ClientPeerSession] = []

        def _pre_bind(c: WIQCConnection) -> None:
            s = self._create_session_binding(c)
            holder.append(s)

        conn = await self.endpoint.connect(
            server_addr,
            timeout=timeout,
            override_client_cert_chain=override_client_cert_chain,
            on_conn_created=_pre_bind,
        )
        sess = holder[0]
        self._init_client_http4_streams(sess)
        if conn.tls.received_ticket is not None:
            self.tickets[server_addr] = conn.tls.received_ticket
        return sess

    def _create_session_binding(self, conn: WIQCConnection) -> _ClientPeerSession:
        sess = _ClientPeerSession(conn=conn)
        self.sessions[conn.local_cid] = sess
        conn.on_stream_data = self._on_stream_data
        conn.on_datagram = self._on_datagram
        conn.on_nat_frame = self._on_nat_frame
        return sess

    def _init_client_http4_streams(self, sess: _ClientPeerSession) -> None:
        conn = sess.conn
        # Open Client HTTP/4 Control (0x00), QPACK Encoder (0x02), QPACK Decoder (0x03)
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
                int(SettingsID.WIQC_LIVE_DISCARD_WINDOW): 64,
                int(SettingsID.WIQC_CHUNK_ADDRESSING): int(ChunkAddressingMethod.BIN64),
            }
        ).to_raw().encode()
        max_push = MaxPushIdFrame(max_push_id=16).to_raw().encode()
        conn.send_stream_data(
            ctrl_sid,
            encode_varint(int(StreamType.CONTROL)) + settings + max_push,
            fin=False,
        )
        conn.send_stream_data(qenc_sid, encode_varint(int(StreamType.QPACK_ENCODER)), fin=False)
        conn.send_stream_data(qdec_sid, encode_varint(int(StreamType.QPACK_DECODER)), fin=False)

    def _ensure_swarm_control_stream(self, sess: _ClientPeerSession) -> int:
        if sess.swarm_ctrl_stream_id is None:
            sid = sess.conn.alloc_bidi_stream_id()
            sess.swarm_ctrl_stream_id = sid
            # Prefix bidirectional stream with StreamType 0x41 (WIQC Swarm Control)
            sess.conn.send_stream_data(
                sid, encode_varint(int(StreamType.WIQC_SWARM_CONTROL)), fin=False
            )
        return sess.swarm_ctrl_stream_id

    # =========================================================================
    # HTTP/4 Request API (1-RTT, 0-RTT Idempotent, RFC 9421, Capsules, Datagrams)
    # =========================================================================

    async def request(
        self,
        sess: _ClientPeerSession,
        method: str,
        path: str,
        authority: str = "origin.http4.local",
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        verify_origin_key: Ed25519PublicKey | None = None,
        timeout: float = 5.0,
    ) -> HTTP4Response:
        """Send an HTTP/4 request over a bidirectional stream and await the response."""
        req_headers = {
            ":method": method.upper(),
            ":scheme": "https",
            ":authority": authority,
            ":path": path,
        }
        if headers:
            req_headers.update(headers)

        stream_id = sess.conn.alloc_bidi_stream_id()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[HTTP4Response] = loop.create_future()
        sess.pending_requests[stream_id] = fut

        encoded_hdrs, enc_inst = sess.qpack_encoder.encode(req_headers)
        if enc_inst and sess.qpack_enc_stream_id is not None:
            sess.conn.send_stream_data(sess.qpack_enc_stream_id, enc_inst, fin=False)

        wire = HeadersFrame(encoded_hdrs).to_raw().encode()
        if body:
            wire += DataFrame(body).to_raw().encode()
        sess.conn.send_stream_data(stream_id, wire, fin=True)

        resp = await asyncio.wait_for(fut, timeout=timeout)
        # Allow tiny tick for any companion Server Push stream (0x01) to finish arriving
        if sess.promised_pushes and not sess.received_pushes:
            await asyncio.sleep(0.05)
        resp.pushed_resources = dict(sess.received_pushes)

        if verify_origin_key is not None and resp.status == 200:
            verify_http4_headers(resp.headers, verify_origin_key)
            resp.origin_signature_verified = True
        return resp

    async def request_0rtt(
        self,
        server_addr: tuple[str, int],
        method: str,
        path: str,
        authority: str = "origin.http4.local",
        headers: dict[str, str] | None = None,
        bypass_client_guard: bool = False,
        timeout: float = 5.0,
    ) -> tuple[_ClientPeerSession, HTTP4Response]:
        """
        Open a 0-RTT resumed WIQC connection carrying an early HTTP/4 request.

        Enforces Section 8.3 ("Compression Side Channels and Replay Risks"):
        - Only idempotent operations (`GET`, `HEAD`, `OPTIONS`) are permitted in 0-RTT!
        - Raises `ReplayProtectionError` on non-idempotent methods unless
          `bypass_client_guard=True` is passed (for testing server-side `425 Too Early`).
        """
        method_u = method.upper()
        if not bypass_client_guard and method_u not in IDEMPOTENT_METHODS:
            raise ReplayProtectionError(
                f"HTTP/4 Section 8.3 forbids non-idempotent {method_u} over 0-RTT"
            )
        ticket = self.tickets.get(server_addr)
        if ticket is None or ticket.is_expired():
            raise ReplayProtectionError(f"No valid 0-RTT resumption ticket cached for {server_addr}")

        req_headers = {
            ":method": method_u,
            ":scheme": "https",
            ":authority": authority,
            ":path": path,
        }
        if headers:
            req_headers.update(headers)

        # Static-only QPACK encoding for 0-RTT (zero dynamic table dependency!)
        enc = QPACKEncoder(max_table_capacity=0)
        encoded_hdrs, _ = enc.encode(req_headers, allow_dynamic=False)
        early_stream_id = 0
        early_wire = HeadersFrame(encoded_hdrs).to_raw().encode()

        holder: list[_ClientPeerSession] = []

        def _pre_bind(c: WIQCConnection) -> None:
            holder.append(self._create_session_binding(c))

        conn = await self.endpoint.connect(
            server_addr,
            zero_rtt_ticket=ticket,
            early_data_stream=(early_stream_id, early_wire, True),
            timeout=timeout,
            on_conn_created=_pre_bind,
        )
        sess = holder[0]
        self._init_client_http4_streams(sess)
        # Advance bidi allocator past stream 0 already used by 0-RTT
        if conn._next_bidi_stream_id == 0:
            conn._next_bidi_stream_id = 4

        if early_stream_id in sess.completed_responses:
            return sess, sess.completed_responses.pop(early_stream_id)

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[HTTP4Response] = loop.create_future()
        sess.pending_requests[early_stream_id] = fut
        resp = await asyncio.wait_for(fut, timeout=timeout)
        return sess, resp

    async def send_capsule_datagram(
        self,
        sess: _ClientPeerSession,
        quarter_stream_id: int,
        payload: bytes,
        timeout: float = 5.0,
    ) -> DatagramCapsule:
        """Send an RFC 9297 `DATAGRAM Capsule (0x00)` over an HTTP/4 request stream."""
        cap = DatagramCapsule(quarter_stream_id=quarter_stream_id, payload=payload)
        resp = await self.request(
            sess,
            method="POST",
            path="/capsule",
            headers={"capsule-protocol": "?1"},
            body=cap.encode(),
            timeout=timeout,
        )
        return DatagramCapsule.decode(resp.body)

    def send_unreliable_datagram(
        self, sess: _ClientPeerSession, quarter_stream_id: int, payload: bytes
    ) -> None:
        """Send an unreliable RFC 9221 QUIC DATAGRAM associated with an HTTP/4 stream."""
        sess.conn.send_datagram(quarter_stream_id, payload)

    # =========================================================================
    # Swarm Negotiation, PEX & BEP 52 Hash Verification
    # =========================================================================

    async def negotiate_swarm(
        self,
        sess: _ClientPeerSession,
        caps: SwarmCapabilities,
        timeout: float = 3.0,
    ) -> SwarmCapabilities:
        """Negotiate RFC 7574 swarm capabilities (Options 2, 3, 4, 6, 7) on Stream 0x41."""
        sid = self._ensure_swarm_control_stream(sess)
        ev = asyncio.Event()
        sess.caps_events[caps.swarm_id] = ev
        sess.conn.send_stream_data(sid, caps.encode_frame().encode(), fin=False)
        await asyncio.wait_for(ev.wait(), timeout=timeout)
        return sess.negotiated_swarms[caps.swarm_id]

    async def query_pex(
        self,
        sess: _ClientPeerSession,
        swarm_id: bytes,
        timeout: float = 3.0,
    ) -> list[PeerEndpoint]:
        """Discover additional swarm peers trackerlessly via `WIQC_PEX` (`PEX_REQ`)."""
        sid = self._ensure_swarm_control_stream(sess)
        ev = asyncio.Event()
        sess.pex_events[swarm_id] = ev
        req = WIQCPexFrame(subtype=PEXSubType.PEX_REQ, swarm_id=swarm_id).to_raw().encode()
        sess.conn.send_stream_data(sid, req, fin=False)
        await asyncio.wait_for(ev.wait(), timeout=timeout)
        return list(sess.pex_peers.get(swarm_id, ()))

    async def query_bep52_hashes(
        self,
        sess: _ClientPeerSession,
        pieces_root: bytes,
        base_layer: int,
        index: int,
        length: int,
        proof_layers: int,
        timeout: float = 3.0,
    ) -> BEP52Hashes | BEP52HashReject:
        """Exchange BEP 52 Hash Wire Messages (`21` HASH_REQUEST -> `22` HASHES / `23` HASH_REJECT)."""
        sid = self._ensure_swarm_control_stream(sess)
        req = BEP52HashRequest(
            pieces_root=pieces_root,
            base_layer=base_layer,
            index=index,
            length=length,
            proof_layers=proof_layers,
        )
        fut: asyncio.Future[BEP52Hashes | BEP52HashReject] = asyncio.get_running_loop().create_future()
        sess.bep52_hash_futures.append(fut)
        wire = RawFrame(FrameType.WIQC_BEP52_HASH_MSG, req.encode()).encode()
        sess.conn.send_stream_data(sid, wire, fin=False)
        return await asyncio.wait_for(fut, timeout=timeout)

    # =========================================================================
    # Multi-Peer Static BEP 52 Swarm Download (Fault-Tolerant & Anti-Pollution)
    # =========================================================================

    async def download_static_swarm(
        self,
        primary_session: _ClientPeerSession,
        path: str,
        origin_public_key: Ed25519PublicKey,
        extra_sessions: list[_ClientPeerSession] | None = None,
        discover_via_pex: bool = True,
        timeout: float = 10.0,
    ) -> tuple[bytes, HTTP4Response, StaticSwarmResource]:
        """
        Complete HTTP/4 Static Swarm Download Workflow:
        1. Fetch signed HTTP/4 metadata via `GET path` and verify RFC 9421 Origin
           Signatures, RFC 9530 `Repr-Digest`, `Swarm-Root`, and `WIQC-Swarm-Info` ABNF.
        2. Optionally query `WIQC_PEX` to discover additional trackerless peers and
           connect to them dynamically.
        3. Negotiate RFC 7574 `SwarmCapabilities` (`merkle-v2`, SHA-256 `0x02`, `bin64`)
           with all connected peers.
        4. Drive `DualZoneSwarmScheduler` across all unbanned peers to fetch 16 KiB
           blocks over independent `0x40` Subgroup streams.
        5. Verify EVERY 16 KiB block immediately against `pieces_root`; if a peer
           injects a corrupted block, discard it, deterministically BAN that peer,
           and seamlessly re-fetch the block from an honest peer!
        6. Reassemble complete bytes and confirm SHA-256 matches `Repr-Digest`.
        """
        # Step 1: Signed HTTP/4 discovery
        resp = await self.request(
            primary_session,
            method="GET",
            path=path,
            verify_origin_key=origin_public_key,
            timeout=timeout,
        )
        if resp.status != 200:
            raise IntegrityVerificationError(f"Expected 200 for {path}, got {resp.status}")

        swarm_info = WIQCSwarmInfo.parse(resp.headers["wiqc-swarm-info"])
        if swarm_info.mode != "merkle-v2":
            raise IntegrityVerificationError(f"Expected merkle-v2 mode, got {swarm_info.mode}")
        pieces_root = parse_swarm_root(resp.headers["swarm-root"])
        expected_repr_digest = parse_repr_digest(resp.headers["repr-digest"])
        if pieces_root != swarm_info.swarm_id:
            raise IntegrityVerificationError("Swarm-Root does not match WIQC-Swarm-Info swarm-id")

        total_size = int(resp.headers["content-length"])
        resource = StaticSwarmResource(
            path=path,
            content_type=resp.headers.get("content-type", "application/octet-stream"),
            pieces_root=pieces_root,
            total_size=total_size,
        )
        self._static_swarms[pieces_root] = resource
        chunk_event = asyncio.Event()
        self._static_chunk_events[pieces_root] = chunk_event

        # Step 2: Assemble peer session pool (+ optional PEX discovery!)
        peer_sessions: list[_ClientPeerSession] = [primary_session]
        if extra_sessions:
            for s in extra_sessions:
                if s not in peer_sessions:
                    peer_sessions.append(s)

        if discover_via_pex:
            try:
                discovered = await self.query_pex(primary_session, pieces_root, timeout=1.0)
                known_addrs = {s.conn.remote_addr for s in peer_sessions}
                for ep in discovered:
                    addr = (ep.host, ep.port)
                    if addr in known_addrs or addr == self.address:
                        continue
                    if self.reputation.is_banned(peer_id=ep.peer_id or None, address=addr):
                        continue
                    try:
                        new_sess = await self.connect(addr, timeout=1.5)
                        peer_sessions.append(new_sess)
                        known_addrs.add(addr)
                    except Exception as exc:
                        logger.debug("Optional PEX peer %s unreachable: %s", addr, exc)
            except Exception:
                pass

        # Step 3: Negotiate SwarmCapabilities with every peer
        caps = SwarmCapabilities(
            swarm_id=pieces_root,
            integrity_method=IntegrityProtectionMethod.MERKLE_HASH_TREE_STATIC,
            chunk_addressing=ChunkAddressingMethod.BIN64,
            live_discard_window=0,
        )
        scheduler = DualZoneSwarmScheduler(
            live_discard_window_chunks=max(64, resource.block_count),
            emergency_threshold_ms=150,
            max_inflight_per_peer=4,
            reputation=self.reputation,
        )
        sessions_by_pid: dict[bytes, _ClientPeerSession] = {}

        for ps in list(peer_sessions):
            if ps.conn.closed or ps.conn.peer_id is None:
                continue
            try:
                await self.negotiate_swarm(ps, caps, timeout=2.0)
                # Give tiny moment for initial WIQC_HAVE to arrive alongside caps
                await asyncio.sleep(0.02)
            except Exception as exc:
                logger.warning("Swarm negotiation with %s failed: %s", ps.conn.remote_addr, exc)
                continue
            pid = ps.conn.peer_id
            sessions_by_pid[pid] = ps
            pstate = SwarmPeerState(
                peer_id=pid,
                address=ps.conn.remote_addr,
                smoothed_rtt_ms=ps.conn.smoothed_rtt_ms,
                choked=(pieces_root in ps.choked_swarms),
                available_chunks=set(ps.have_chunks.get(pieces_root, range(resource.block_count))),
            )
            scheduler.register_peer(pstate)

        for idx in range(resource.block_count):
            scheduler.register_wanted_chunk(
                ChunkRequirement(
                    chunk_index=idx,
                    group_id=0,
                    subgroup_id=idx,
                    deadline_ms=int(time.monotonic() * 1000) + 60_000,
                    priority_urgency=3,
                )
            )

        # Step 4: Fault-tolerant multi-peer scheduling loop with ban & timeout failover!
        deadline = time.monotonic() + timeout
        inflight_sent_at: dict[int, tuple[bytes, float]] = {}

        while not resource.is_complete:
            if time.monotonic() > deadline:
                raise IntegrityVerificationError(
                    f"Timed out downloading static swarm {path}: "
                    f"{len(resource.verified_blocks)}/{resource.block_count} verified"
                )

            # Sync newly verified blocks & peer states into scheduler
            for idx in list(resource.verified_blocks.keys()):
                scheduler.mark_chunk_verified(idx)
                inflight_sent_at.pop(idx, None)

            now_mono = time.monotonic()
            for pid, pstate in scheduler.peers.items():
                ps = sessions_by_pid[pid]
                pstate.smoothed_rtt_ms = ps.conn.smoothed_rtt_ms
                pstate.choked = pieces_root in ps.choked_swarms
                if ps.conn.closed or self.reputation.is_banned(pid, ps.conn.remote_addr):
                    pstate.banned = True
                    pstate.in_flight_chunks.clear()
                elif pieces_root in ps.have_chunks:
                    pstate.available_chunks.update(ps.have_chunks[pieces_root])

            # Expire timed-out in-flight requests so another peer can pick them up!
            for idx, (pid, sent_t) in list(inflight_sent_at.items()):
                if (now_mono - sent_t) > 0.6 or scheduler.peers[pid].banned:
                    scheduler.peers[pid].in_flight_chunks.discard(idx)
                    inflight_sent_at.pop(idx, None)

            decisions = scheduler.schedule_next_batch(
                now_ms=int(now_mono * 1000), max_requests=8
            )
            for dec in decisions:
                ps = sessions_by_pid[dec.peer_id]
                if ps.conn.closed:
                    continue
                ctrl_sid = self._ensure_swarm_control_stream(ps)
                req_frame = WIQCRequestFrame(
                    swarm_id=pieces_root,
                    bins=(dec.bin_id,),
                    priority_urgency=dec.priority_urgency,
                    deadline_ms=0,
                ).to_raw().encode()
                ps.conn.send_stream_data(ctrl_sid, req_frame, fin=False)
                inflight_sent_at[dec.chunk_index] = (dec.peer_id, now_mono)

            if resource.is_complete:
                break
            chunk_event.clear()
            try:
                await asyncio.wait_for(chunk_event.wait(), timeout=0.15)
            except asyncio.TimeoutError:
                pass

        # Step 5: Reassemble and verify end-to-end RFC 9530 Repr-Digest!
        payload = resource.reassemble()
        if hashlib.sha256(payload).digest() != expected_repr_digest:
            raise IntegrityVerificationError("Final reassembled payload failed RFC 9530 Repr-Digest check")
        return payload, resp, resource

    # =========================================================================
    # Live Real-Time Streaming Subscription (Unified Merkle Tree Mode)
    # =========================================================================

    async def subscribe_live_swarm(
        self,
        sess: _ClientPeerSession,
        path: str,
        origin_public_key: Ed25519PublicKey,
        on_verified_chunk: Callable[[VerifiedLiveChunk, int], None] | None = None,
        timeout: float = 5.0,
    ) -> tuple[LiveSwarmChannel, HTTP4Response]:
        """
        Subscribe to a decentralized HTTP/4 real-time live stream:
        1. Issue signed HTTP/4 `GET path` and verify RFC 9421 origin signatures &
           `WIQC-Swarm-Info` (`mode=unified-live`).
        2. Extract publisher public key (confirming SHA-256 fingerprint == `swarm-id`).
        3. Negotiate RFC 7574 CIPM 3 (`UNIFIED_MERKLE_TREE_LIVE`) capabilities on `0x41`.
        4. All subsequent MOQT Subgroup streams (`0x40`) are verified against the
           publisher's Ed25519 signed munro hashes BEFORE delivery to `on_verified_chunk`!
        """
        resp = await self.request(
            sess,
            method="GET",
            path=path,
            verify_origin_key=origin_public_key,
            timeout=timeout,
        )
        if resp.status != 200:
            raise IntegrityVerificationError(f"Live subscribe failed: status {resp.status}")

        swarm_info = WIQCSwarmInfo.parse(resp.headers["wiqc-swarm-info"])
        if swarm_info.mode != "unified-live":
            raise IntegrityVerificationError(f"Expected unified-live mode, got {swarm_info.mode}")
        pub_raw = resp.headers["wiqc-publisher-key"].strip(":")
        pub_key = Ed25519PublicKey(base64.b64decode(pub_raw))
        if pub_key.fingerprint() != swarm_info.swarm_id:
            raise IntegrityVerificationError("Publisher key fingerprint does not match Live Swarm ID")

        track = TrackIdentifier(
            authority=resp.headers.get(":authority", "origin.http4.local"),
            path=path,
            track_name=resp.headers.get("wiqc-track-name", "live"),
        )
        munro_layer = int(resp.headers.get("wiqc-munro-layer", "2"))
        window = swarm_info.window or 64

        channel = self._live_swarms.get(swarm_info.swarm_id)
        if channel is None:
            channel = LiveSwarmChannel(
                track=track,
                publisher_public_key=pub_key,
                munro_layer=munro_layer,
                live_discard_window=window,
            )
            self._live_swarms[swarm_info.swarm_id] = channel

        if on_verified_chunk is not None:
            self._live_callbacks.setdefault(swarm_info.swarm_id, []).append(on_verified_chunk)

        caps = SwarmCapabilities(
            swarm_id=swarm_info.swarm_id,
            integrity_method=IntegrityProtectionMethod.UNIFIED_MERKLE_TREE_LIVE,
            chunk_addressing=ChunkAddressingMethod.BIN64,
            live_discard_window=window,
        )
        await self.negotiate_swarm(sess, caps, timeout=timeout)
        return channel, resp

    # =========================================================================
    # Native WIQC NAT Traversal & Simultaneous UDP Hole Punching (Section 6.2)
    # =========================================================================

    async def initiate_nat_hole_punch(
        self,
        relay_session: _ClientPeerSession,
        target_peer_id: bytes,
        timeout: float = 3.0,
    ) -> tuple[tuple[str, int], float]:
        """
        Coordinate direct P2P UDP hole punching to `target_peer_id` via `relay_session`:
        1. Advertise our observed external UDP address via `ADD_ADDRESS` (`0x3d7e90`).
        2. Send `PUNCH_REQUEST` to the relay targeting `target_peer_id`.
        3. Relay sends synchronized `PUNCH_ME_NOW` (`0x3d7e92`) to BOTH peers.
        4. Both peers fire simultaneous UDP hole-punch `PATH_CHALLENGE` probes directly
           at each other, opening cone-NAT pinholes and confirming via `PATH_RESPONSE`!
        """
        my_addr = relay_session.conn.nat.observed_external_address or self.address
        add_frame = relay_session.conn.nat.add_local_candidate(my_addr[0], my_addr[1])
        relay_session.conn.send_nat_frame(add_frame.encode())

        req = relay_session.conn.nat.create_punch_request(
            target_peer_id=target_peer_id, candidate_addr=my_addr
        )
        relay_session.conn.send_nat_frame(req.encode())

        # Wait until `_on_nat_frame(PunchMeNowFrame)` completes direct UDP validation!
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.direct_nat_punches_succeeded:
                addr, rtt = next(iter(self.direct_nat_punches_succeeded.items()))
                return addr, rtt
            await asyncio.sleep(0.02)
        raise TimeoutError("Direct WIQC NAT hole punch timed out")

    async def _execute_simultaneous_punch(self, frame: PunchMeNowFrame) -> None:
        target = (frame.host, frame.port)
        token = hashlib.sha256(f"{frame.round_num}:{self.peer_id.hex()}".encode()).digest()[:8]
        self._punch_tokens_sent[token] = (target, time.monotonic())
        ev = self._punch_events.setdefault(target, asyncio.Event())

        # Send multiple simultaneous UDP punch probes (opens outbound cone-NAT pinhole!)
        for _ in range(6):
            if ev.is_set():
                return
            self.endpoint.send_unencrypted_nat_probe(b"CHAL:" + token, target)
            await asyncio.sleep(0.04)

    async def _on_raw_nat_punch_packet(
        self, payload: bytes, src_addr: tuple[str, int]
    ) -> None:
        if payload.startswith(b"CHAL:") and len(payload) == 13:
            token = payload[5:]
            # Echo token back via direct UDP PATH_RESPONSE!
            self.endpoint.send_unencrypted_nat_probe(b"RESP:" + token, src_addr)
        elif payload.startswith(b"RESP:") and len(payload) == 13:
            token = payload[5:]
            entry = self._punch_tokens_sent.pop(token, None)
            if entry is not None:
                target, started = entry
                rtt_ms = (time.monotonic() - started) * 1000.0
                self.direct_nat_punches_succeeded[src_addr] = rtt_ms
                ev = self._punch_events.setdefault(target, asyncio.Event())
                ev.set()

    # =========================================================================
    # Inbound Stream, Datagram & NAT Handlers
    # =========================================================================

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
        self, sess: _ClientPeerSession, stream_id: int, data: bytes, fin: bool
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
                ack = sess.qpack_decoder.process_encoder_stream(rem)
                if ack and sess.qpack_dec_stream_id is not None:
                    sess.conn.send_stream_data(sess.qpack_dec_stream_id, ack, fin=False)
                self._replay_blocked_qpack(sess)
        elif stype == StreamType.QPACK_DECODER:
            if rem:
                sess.qpack_encoder.process_decoder_stream(rem)
        elif stype == StreamType.CONTROL:
            buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
            for frame in buf.feed(rem):
                if frame.frame_type == FrameType.GOAWAY:
                    sess.goaway_received = True
                elif frame.frame_type == FrameType.WIQC_PEX:
                    self._ingest_pex_frame(sess, frame)
        elif stype == StreamType.PUSH:
            # Push stream starts with push_id VarInt followed by HEADERS + DATA frames
            if stream_id not in sess.push_stream_ids:
                pbuf = sess.uni_raw_bufs.setdefault(stream_id, bytearray())
                pbuf.extend(rem)
                try:
                    push_id, consumed = decode_varint(pbuf, 0)
                except WireFormatError:
                    return
                sess.push_stream_ids[stream_id] = push_id
                rem = bytes(pbuf[consumed:])
                del sess.uni_raw_bufs[stream_id]
            push_id = sess.push_stream_ids[stream_id]
            fbuf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
            for frame in fbuf.feed(rem):
                if frame.frame_type == FrameType.HEADERS:
                    try:
                        hdrs_list, _ = sess.qpack_decoder.decode(frame.payload, stream_id=stream_id)
                    except QPACKError:
                        sess.blocked_qpack_headers.append((stream_id, frame.payload, True))
                        continue
                    sess.push_headers[push_id] = dict(hdrs_list)
                elif frame.frame_type == FrameType.DATA:
                    sess.push_bodies.setdefault(push_id, bytearray()).extend(frame.payload)
            if fin:
                sess.resp_fin_seen.add(stream_id)
            if stream_id in sess.resp_fin_seen and push_id in sess.push_headers:
                sess.received_pushes[push_id] = (
                    sess.push_headers[push_id],
                    bytes(sess.push_bodies.get(push_id, b"")),
                )
        elif stype == StreamType.WIQC_SWARM_SUBGROUP:
            buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
            for frame in buf.feed(rem):
                await self._handle_subgroup_frame(sess, stream_id, frame)

    async def _handle_bidi_stream(
        self, sess: _ClientPeerSession, stream_id: int, data: bytes, fin: bool
    ) -> None:
        buf = sess.stream_buffers.setdefault(stream_id, StreamFrameBuffer())
        frames = buf.feed(data)

        if stream_id == sess.swarm_ctrl_stream_id:
            for frame in frames:
                await self._handle_swarm_ctrl_frame(sess, frame)
            return

        for frame in frames:
            if frame.frame_type == FrameType.HEADERS:
                try:
                    hdrs_list, dec_ack = sess.qpack_decoder.decode(
                        frame.payload, stream_id=stream_id
                    )
                except QPACKError:
                    sess.blocked_qpack_headers.append((stream_id, frame.payload, False))
                    continue
                if dec_ack and sess.qpack_dec_stream_id is not None:
                    sess.conn.send_stream_data(sess.qpack_dec_stream_id, dec_ack, fin=False)
                sess.resp_headers[stream_id] = dict(hdrs_list)
            elif frame.frame_type == FrameType.DATA:
                sess.resp_bodies.setdefault(stream_id, bytearray()).extend(frame.payload)
            elif frame.frame_type == FrameType.PUSH_PROMISE:
                pp = PushPromiseFrame.from_payload(frame.payload)
                try:
                    ph_list, _ = sess.qpack_decoder.decode(
                        pp.encoded_field_section, stream_id=stream_id
                    )
                    sess.promised_pushes[pp.push_id] = dict(ph_list)
                except QPACKError:
                    sess.promised_pushes[pp.push_id] = {":promised": "pending"}

        if fin:
            sess.resp_fin_seen.add(stream_id)
        self._maybe_finalize_response(sess, stream_id)

    def _maybe_finalize_response(self, sess: _ClientPeerSession, stream_id: int) -> None:
        if stream_id in sess.resp_fin_seen and stream_id in sess.resp_headers:
            sess.resp_fin_seen.discard(stream_id)
            hdrs = sess.resp_headers.pop(stream_id)
            body = bytes(sess.resp_bodies.pop(stream_id, bytearray()))
            resp = HTTP4Response(
                status=int(hdrs.get(":status", "0")),
                headers=hdrs,
                body=body,
            )
            fut = sess.pending_requests.pop(stream_id, None)
            if fut is not None and not fut.done():
                fut.set_result(resp)
            else:
                sess.completed_responses[stream_id] = resp

    def _replay_blocked_qpack(self, sess: _ClientPeerSession) -> None:
        if not sess.blocked_qpack_headers:
            return
        remaining: list[tuple[int, bytes, bool]] = []
        for sid, payload, is_push in sess.blocked_qpack_headers:
            try:
                hdrs_list, dec_ack = sess.qpack_decoder.decode(payload, stream_id=sid)
            except QPACKError:
                remaining.append((sid, payload, is_push))
                continue
            if dec_ack and sess.qpack_dec_stream_id is not None:
                sess.conn.send_stream_data(sess.qpack_dec_stream_id, dec_ack, fin=False)
            if is_push:
                push_id = sess.push_stream_ids[sid]
                sess.push_headers[push_id] = dict(hdrs_list)
                if sid in sess.resp_fin_seen:
                    sess.received_pushes[push_id] = (
                        sess.push_headers[push_id],
                        bytes(sess.push_bodies.get(push_id, b"")),
                    )
            else:
                sess.resp_headers[sid] = dict(hdrs_list)
                self._maybe_finalize_response(sess, sid)
        sess.blocked_qpack_headers = remaining

    async def _handle_swarm_ctrl_frame(
        self, sess: _ClientPeerSession, frame: RawFrame
    ) -> None:
        if frame.frame_type == FrameType.WIQC_HANDSHAKE_CAPS:
            caps = SwarmCapabilities.decode_payload(frame.payload)
            sess.negotiated_swarms[caps.swarm_id] = caps
            ev = sess.caps_events.get(caps.swarm_id)
            if ev is not None:
                ev.set()
        elif frame.frame_type == FrameType.WIQC_HAVE:
            hv = WIQCHaveFrame.from_payload(frame.payload)
            chunks = BinTreeMath.expand_bins_to_chunks(hv.bins)
            sess.have_chunks.setdefault(hv.swarm_id, set()).update(chunks)
        elif frame.frame_type in (FrameType.WIQC_CHOKE, FrameType.WIQC_UNCHOKE):
            cf = WIQCChokeFrame.from_raw(frame)
            if cf.choked:
                sess.choked_swarms.add(cf.swarm_id)
            else:
                sess.choked_swarms.discard(cf.swarm_id)
        elif frame.frame_type == FrameType.WIQC_SIGNED_INTEGRITY:
            si = WIQCSignedIntegrityFrame.from_payload(frame.payload)
            live_ch = self._live_swarms.get(si.swarm_id)
            if live_ch is not None:
                if not live_ch.verifier.accept_signed_munro(si.signed_munro):
                    await self._ban_polluting_peer(
                        sess, f"Forged WIQC_SIGNED_INTEGRITY munro for group {si.signed_munro.group_id}"
                    )
        elif frame.frame_type == FrameType.WIQC_PEX:
            self._ingest_pex_frame(sess, frame)
        elif frame.frame_type == FrameType.WIQC_BEP52_HASH_MSG:
            if sess.bep52_hash_futures:
                fut = sess.bep52_hash_futures.pop(0)
                if not fut.done():
                    msg_id = frame.payload[0] if frame.payload else -1
                    if msg_id == BEP52_MSG_HASHES:
                        fut.set_result(BEP52Hashes.decode(frame.payload))
                    else:
                        fut.set_result(BEP52HashReject.decode(frame.payload))

    def _ingest_pex_frame(self, sess: _ClientPeerSession, frame: RawFrame) -> None:
        pex = WIQCPexFrame.from_payload(frame.payload)
        if pex.subtype in (PEXSubType.PEX_RESv4, PEXSubType.PEX_RESv6):
            sess.pex_peers.setdefault(pex.swarm_id, []).extend(pex.peers)
            ev = sess.pex_events.get(pex.swarm_id)
            if ev is not None:
                ev.set()

    async def _handle_subgroup_frame(
        self, sess: _ClientPeerSession, stream_id: int, frame: RawFrame
    ) -> None:
        """
        Verify every arriving `WIQC_SUBGROUP_OBJECT` + `WIQC_INTEGRITY` pair on
        unidirectional Stream `0x40` BEFORE delivering to app or re-seeding!
        """
        if frame.frame_type == FrameType.WIQC_SIGNED_INTEGRITY:
            si = WIQCSignedIntegrityFrame.from_payload(frame.payload)
            sess.subgroup_pending_munros[stream_id] = si.signed_munro
            live_ch = self._live_swarms.get(si.swarm_id)
            if live_ch is not None:
                if not live_ch.verifier.accept_signed_munro(si.signed_munro):
                    await self._ban_polluting_peer(sess, "Invalid munro signature on subgroup stream")
            return

        if frame.frame_type == FrameType.WIQC_SUBGROUP_OBJECT:
            obj_f = WIQCSubgroupObjectFrame.from_payload(frame.payload)
            sess.subgroup_pending_objects.setdefault(stream_id, []).append(obj_f)
            return

        if frame.frame_type == FrameType.WIQC_INTEGRITY:
            int_f = WIQCIntegrityFrame.from_payload(frame.payload)
            pending_list = sess.subgroup_pending_objects.get(stream_id, [])
            if not pending_list:
                return
            obj_f = pending_list.pop(0)
            sid = obj_f.swarm_id

            # Case A: Static BEP 52 Resource Verification
            static_res = self._static_swarms.get(sid)
            if static_res is not None:
                try:
                    static_res.verify_and_store_block(
                        chunk_index=obj_f.chunk_index,
                        block_data=obj_f.payload,
                        uncle_proof=int_f.uncles,
                    )
                except IntegrityVerificationError as exc:
                    await self._ban_polluting_peer(sess, str(exc))
                    ev = self._static_chunk_events.get(sid)
                    if ev is not None:
                        ev.set()
                    return
                ev = self._static_chunk_events.get(sid)
                if ev is not None:
                    ev.set()
                return

            # Case B: Live Unified Merkle Tree Verification
            live_ch = self._live_swarms.get(sid)
            if live_ch is not None:
                m_obj = MediaObject(
                    group_id=obj_f.group_id,
                    subgroup_id=obj_f.subgroup_id,
                    object_id=obj_f.object_id,
                    chunk_index=obj_f.chunk_index,
                    payload=obj_f.payload,
                    playback_deadline_ms=obj_f.deadline_ms,
                    is_keyframe=obj_f.is_keyframe,
                    priority_urgency=obj_f.priority_urgency,
                )
                signed_munro = sess.subgroup_pending_munros.get(stream_id)
                try:
                    verified = live_ch.verify_and_accept_chunk(
                        obj=m_obj,
                        uncle_proof=int_f.uncles,
                        signed_munro=signed_munro,
                    )
                except IntegrityVerificationError as exc:
                    await self._ban_polluting_peer(sess, str(exc))
                    return
                for cb in self._live_callbacks.get(sid, ()):
                    cb(verified, stream_id)

    async def _ban_polluting_peer(self, sess: _ClientPeerSession, reason: str) -> None:
        """
        Deterministic stream-pollution defense (Section 3.3 & Section 8.1):
        Discard corrupt data, ban the offending peer's identity & address,
        and terminate its WIQC connection immediately.
        """
        self.pollution_attacks_blocked += 1
        pid = sess.conn.peer_id or b"unknown"
        self.reputation.ban_peer(pid, reason=reason, address=sess.conn.remote_addr)
        logger.warning(
            "POLLUTION ATTACK DETECTED! Banned peer %s (%s): %s",
            pid.hex()[:12],
            sess.conn.remote_addr,
            reason,
        )
        await sess.conn.close(
            error_code=IntegrityVerificationError.error_code,
            reason=f"Banned for pollution: {reason}",
        )

    async def _on_datagram(
        self, conn: WIQCConnection, quarter_stream_id: int, payload: bytes
    ) -> None:
        self.datagrams_received.append((quarter_stream_id, payload))

    async def _on_nat_frame(self, conn: WIQCConnection, frame: object) -> None:
        if isinstance(frame, PunchMeNowFrame):
            asyncio.create_task(self._execute_simultaneous_punch(frame))
