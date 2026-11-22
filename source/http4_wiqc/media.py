"""
HTTP/4 Real-Time Media Data Model (MOQT) and Hybrid Dual-Zone Swarm Scheduler.

Implements Section 4.1 ("Media Data Model Mapping") and Section 4.2 ("Hybrid
Earliest Deadline First (EDF) and Rarest-First Scheduling") of
`draft-enger-httpbis-http4-wiqc-00`:

1. **MOQT Hierarchical Data Model**:
   - `Track`: Identified by `(track_namespace=(authority, path), track_name)`
     (e.g., `("live.example.h4", "/concert/stage1")`, `"video-1080p"`).
   - `Group`: Temporally bounded collection of objects starting at an independent
     synchronization point (IDR keyframe), aligned 1:1 with a WIQC Unified Merkle
     Tree munro subtree!
   - `Subgroup`: Subset of objects within a Group sharing a common priority and
     dependency layer (e.g., Base Layer vs Enhancement Layer). Each Subgroup maps
     to **exactly one unidirectional WIQC stream (`0x40`)**, eliminating
     head-of-line blocking between layers.
   - `MediaObject`: Smallest addressable media unit (e.g., single encoded frame /
     Low Overhead Container payload) with chunk index and playback deadline.

2. **Hybrid Dual-Zone Sliding Window Scheduler (RFC 7574 + RFC 9218)**:
   Operates inside the negotiated **Live Discard Window**:
   - **Emergency Priority Zone** (`time_to_deadline < emergency_threshold_ms`, default
     `150 ms`): Strictly **Earliest Deadline First (EDF)**, tie-broken by RFC 9218
     urgency (base layer first), routed to the **lowest-RTT unchoked peers** that
     have announced the chunk via `WIQC_HAVE`.
   - **Swarm Health Zone** (`time_to_deadline >= emergency_threshold_ms`): Strictly
     **Rarest-First** piece selection computed from `WIQC_HAVE` bin availability across
     swarm peers, maximizing piece diversity and swarm resilience.
   - Chunks falling behind the Live Discard Window are dropped automatically so
     real-time playback stays sub-second.

3. **Peer Reputation, RTT Tracking & Deterministic Pollution Banning**:
   - Tracks EWMA smoothed RTT per peer, choke/unchoke status, advertised bins,
     and immediately bans peers caught injecting corrupted chunks (Section 8.1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum

from .merkle import BinTreeMath


# =============================================================================
# 1. MOQT Hierarchical Data Model (Section 4.1)
# =============================================================================


@dataclass(frozen=True)
class TrackIdentifier:
    """MOQT Track identifier bound to HTTP/4 `:authority` and `:path` pseudo-headers."""

    authority: str
    path: str
    track_name: str

    @property
    def namespace(self) -> tuple[str, str]:
        return (self.authority, self.path)

    def canonical_name(self) -> str:
        return f"https://{self.authority}{self.path}#{self.track_name}"


@dataclass(frozen=True)
class MediaObject:
    """Smallest addressable MOQT media unit (LOC frame / audio packet)."""

    group_id: int
    subgroup_id: int
    object_id: int
    chunk_index: int
    payload: bytes
    playback_deadline_ms: int
    is_keyframe: bool = False
    priority_urgency: int = 3  # RFC 9218 urgency: 0=highest (base IDR), 7=lowest

    @property
    def bin_id(self) -> int:
        return BinTreeMath.leaf_bin(self.chunk_index)


@dataclass
class Subgroup:
    """
    A sequence of MediaObjects within a Group sharing a common priority & dependency
    chain. Mapped 1:1 to a single unidirectional WIQC Swarm Subgroup stream (0x40).
    """

    group_id: int
    subgroup_id: int
    priority_urgency: int  # 0 = Base Layer, 3+ = Enhancement Layer
    dependency_layer: str = "base"
    objects: list[MediaObject] = field(default_factory=list)
    wiqc_stream_id: int | None = None

    def add_object(self, obj: MediaObject) -> None:
        if obj.group_id != self.group_id or obj.subgroup_id != self.subgroup_id:
            raise ValueError("MediaObject group/subgroup mismatch")
        self.objects.append(obj)


@dataclass
class MediaGroup:
    """
    Temporally bounded collection of Subgroups starting at an IDR keyframe,
    aligned directly with a WIQC Unified Merkle Tree munro subtree.
    """

    group_id: int
    track: TrackIdentifier
    created_at_ms: int
    subgroups: dict[int, Subgroup] = field(default_factory=dict)
    munro_bin: int | None = None

    def get_or_create_subgroup(
        self,
        subgroup_id: int,
        priority_urgency: int = 3,
        dependency_layer: str = "base",
    ) -> Subgroup:
        sg = self.subgroups.get(subgroup_id)
        if sg is None:
            sg = Subgroup(
                group_id=self.group_id,
                subgroup_id=subgroup_id,
                priority_urgency=priority_urgency,
                dependency_layer=dependency_layer,
            )
            self.subgroups[subgroup_id] = sg
        return sg

    def all_objects_ordered(self) -> list[MediaObject]:
        """Return objects ordered by chunk_index for Unified Merkle Tree commitment."""
        objs: list[MediaObject] = []
        for sg in self.subgroups.values():
            objs.extend(sg.objects)
        objs.sort(key=lambda o: o.chunk_index)
        return objs


# =============================================================================
# 2. Peer Telemetry, Reputation & Pollution Banning (Section 8.1)
# =============================================================================


@dataclass
class SwarmPeerState:
    """Live scheduler state for one remote peer in a WIQC swarm."""

    peer_id: bytes
    address: tuple[str, int]
    smoothed_rtt_ms: float = 50.0
    choked: bool = False
    banned: bool = False
    ban_reason: str = ""
    available_chunks: set[int] = field(default_factory=set)
    in_flight_chunks: set[int] = field(default_factory=set)
    verified_chunks_delivered: int = 0
    invalid_chunks_sent: int = 0
    last_seen: float = field(default_factory=time.monotonic)

    def update_rtt(self, sample_rtt_ms: float) -> None:
        """RFC 9002-style EWMA smoothed RTT update (alpha = 1/8)."""
        if sample_rtt_ms < 0:
            return
        self.smoothed_rtt_ms = 0.875 * self.smoothed_rtt_ms + 0.125 * sample_rtt_ms
        self.last_seen = time.monotonic()

    def record_have_bins(self, bins: list[int] | tuple[int, ...]) -> None:
        """Expand announced RFC 7574 bins from `WIQC_HAVE` into chunk availability."""
        self.available_chunks.update(BinTreeMath.expand_bins_to_chunks(bins))
        self.last_seen = time.monotonic()


class PeerReputationManager:
    """
    Deterministic peer isolation and banning registry (Section 3.3 & Section 8.1).

    In HTTP/4 over WIQC, cryptographic verification is deterministic: a peer that
    delivers a single cryptographically invalid 16 KiB block or forged live chunk
    is immediately isolated so it cannot pollute the swarm.
    """

    def __init__(self) -> None:
        self._banned_peer_ids: dict[bytes, str] = {}
        self._banned_addresses: dict[tuple[str, int], str] = {}

    def ban_peer(
        self,
        peer_id: bytes,
        reason: str,
        address: tuple[str, int] | None = None,
    ) -> None:
        self._banned_peer_ids[peer_id] = reason
        if address is not None:
            self._banned_addresses[address] = reason

    def is_banned(
        self,
        peer_id: bytes | None = None,
        address: tuple[str, int] | None = None,
    ) -> bool:
        if peer_id is not None and peer_id in self._banned_peer_ids:
            return True
        if address is not None and address in self._banned_addresses:
            return True
        return False

    def ban_reason(self, peer_id: bytes) -> str | None:
        return self._banned_peer_ids.get(peer_id)

    @property
    def banned_peers(self) -> dict[bytes, str]:
        return dict(self._banned_peer_ids)


# =============================================================================
# 3. Dual-Zone Sliding Window Scheduler (EDF < 150ms + Rarest-First)
# =============================================================================


class SchedulingZone(StrEnum):
    EMERGENCY_EDF = "emergency-edf"
    SWARM_HEALTH_RAREST_FIRST = "swarm-health-rarest-first"


@dataclass(frozen=True)
class ChunkRequirement:
    """A missing media chunk tracked inside the Live Discard Window."""

    chunk_index: int
    group_id: int
    subgroup_id: int
    deadline_ms: int
    priority_urgency: int = 3  # RFC 9218 urgency (0 = highest)


@dataclass(frozen=True)
class ScheduledRequest:
    """Scheduling decision produced by `DualZoneSwarmScheduler`."""

    peer_id: bytes
    chunk_index: int
    bin_id: int
    zone: SchedulingZone
    priority_urgency: int
    deadline_ms: int
    peer_rtt_ms: float
    rarity_count: int


class DualZoneSwarmScheduler:
    """
    Implements Figure 2 & Section 4.2 of `draft-enger-httpbis-http4-wiqc-00`:

        |<---------------- Live Discard Window (RFC 7574) --------------->|
        +---------------------------------+-------------------------------+
        |  Emergency Zone (< 150 ms)      |     Swarm Health Zone         |
        |  Scheduler: Strictly EDF        |     Scheduler: Rarest-First   |
        |  Target: Lowest-RTT Peers       |     Target: HAVE Bin Diversity|
        +---------------------------------+-------------------------------+

    Workflow on each scheduling tick:
    1. Evict chunks whose index or deadline has fallen outside the Live Discard Window.
    2. Partition missing, non-in-flight chunks into:
       - `emergency`: `(deadline_ms - now_ms) < emergency_threshold_ms`
       - `health`: `(deadline_ms - now_ms) >= emergency_threshold_ms`
    3. Emergency Zone Pass (highest precedence):
       - Sort strictly by `(deadline_ms, priority_urgency, chunk_index)` (EDF!).
       - Assign each chunk to the **lowest-RTT** unchoked, unbanned peer that holds it
         and has spare in-flight capacity.
    4. Swarm Health Zone Pass (uses remaining bandwidth / slots):
       - Compute swarm-wide availability count for every chunk from peers' `WIQC_HAVE` maps.
       - Sort strictly by `(rarity_count, priority_urgency, deadline_ms)` (Rarest-First!).
       - Assign to an eligible unchoked peer holding the rare chunk, balancing load
         across peers so swarm piece diversity increases.
    """

    def __init__(
        self,
        live_discard_window_chunks: int = 64,
        emergency_threshold_ms: int = 150,
        max_inflight_per_peer: int = 8,
        reputation: PeerReputationManager | None = None,
    ) -> None:
        self.live_discard_window_chunks = live_discard_window_chunks
        self.emergency_threshold_ms = emergency_threshold_ms
        self.max_inflight_per_peer = max_inflight_per_peer
        self.reputation = reputation or PeerReputationManager()

        self.peers: dict[bytes, SwarmPeerState] = {}
        self.wanted_chunks: dict[int, ChunkRequirement] = {}
        self.verified_chunks: set[int] = set()
        self.discarded_chunks: set[int] = set()
        self.playhead_chunk: int = 0

    def register_peer(self, peer: SwarmPeerState) -> None:
        self.peers[peer.peer_id] = peer

    def register_wanted_chunk(self, req: ChunkRequirement) -> None:
        if req.chunk_index in self.verified_chunks:
            return
        if req.chunk_index < self.playhead_chunk:
            self.discarded_chunks.add(req.chunk_index)
            return
        self.wanted_chunks[req.chunk_index] = req

    def mark_chunk_verified(self, chunk_index: int) -> None:
        self.verified_chunks.add(chunk_index)
        self.wanted_chunks.pop(chunk_index, None)
        for p in self.peers.values():
            p.in_flight_chunks.discard(chunk_index)

    def advance_playhead(self, new_playhead_chunk: int, now_ms: int) -> list[int]:
        """
        Advance the Live Discard Window and drop expired chunks whose playback
        deadline has already elapsed or whose index precedes the window floor.
        """
        if new_playhead_chunk > self.playhead_chunk:
            self.playhead_chunk = new_playhead_chunk
        window_floor = max(0, self.playhead_chunk)
        window_ceiling = window_floor + self.live_discard_window_chunks

        expired: list[int] = []
        for idx, req in list(self.wanted_chunks.items()):
            if idx < window_floor or req.deadline_ms < now_ms:
                expired.append(idx)
                self.wanted_chunks.pop(idx, None)
                self.discarded_chunks.add(idx)
                for p in self.peers.values():
                    p.in_flight_chunks.discard(idx)
            elif idx >= window_ceiling:
                # Keep registered but don't discard; scheduler skips chunks beyond window
                pass
        return expired

    def _eligible_peers_for(self, chunk_index: int) -> list[SwarmPeerState]:
        result: list[SwarmPeerState] = []
        for p in self.peers.values():
            if p.banned or p.choked or self.reputation.is_banned(p.peer_id, p.address):
                continue
            if chunk_index not in p.available_chunks:
                continue
            if len(p.in_flight_chunks) >= self.max_inflight_per_peer:
                continue
            result.append(p)
        return result

    def _chunk_rarity(self, chunk_index: int) -> int:
        count = 0
        for p in self.peers.values():
            if not p.banned and not self.reputation.is_banned(p.peer_id, p.address):
                if chunk_index in p.available_chunks:
                    count += 1
        return count

    def schedule_next_batch(
        self,
        now_ms: int,
        max_requests: int = 16,
    ) -> list[ScheduledRequest]:
        """
        Execute one Dual-Zone scheduling cycle and return the prioritized batch
        of `ScheduledRequest` instructions to dispatch via `WIQC_REQUEST`.
        """
        self.advance_playhead(self.playhead_chunk, now_ms)
        window_ceiling = self.playhead_chunk + self.live_discard_window_chunks

        # Determine currently in-flight chunks across healthy peers
        active_inflight: set[int] = set()
        for p in self.peers.values():
            if not p.banned and not self.reputation.is_banned(p.peer_id, p.address):
                active_inflight.update(p.in_flight_chunks)

        emergency: list[ChunkRequirement] = []
        swarm_health: list[ChunkRequirement] = []

        for req in self.wanted_chunks.values():
            if req.chunk_index >= window_ceiling:
                continue
            if req.chunk_index in active_inflight:
                continue
            time_left = req.deadline_ms - now_ms
            if time_left < self.emergency_threshold_ms:
                emergency.append(req)
            else:
                swarm_health.append(req)

        decisions: list[ScheduledRequest] = []

        # --- Pass 1: Emergency Priority Zone (Strictly EDF -> Lowest-RTT Peer) ---
        emergency.sort(key=lambda r: (r.deadline_ms, r.priority_urgency, r.chunk_index))
        for req in emergency:
            if len(decisions) >= max_requests:
                break
            candidates = self._eligible_peers_for(req.chunk_index)
            if not candidates:
                continue
            # Strictly select the lowest-RTT unchoked peer!
            candidates.sort(key=lambda p: (p.smoothed_rtt_ms, len(p.in_flight_chunks)))
            chosen = candidates[0]
            chosen.in_flight_chunks.add(req.chunk_index)
            decisions.append(
                ScheduledRequest(
                    peer_id=chosen.peer_id,
                    chunk_index=req.chunk_index,
                    bin_id=BinTreeMath.leaf_bin(req.chunk_index),
                    zone=SchedulingZone.EMERGENCY_EDF,
                    priority_urgency=req.priority_urgency,
                    deadline_ms=req.deadline_ms,
                    peer_rtt_ms=chosen.smoothed_rtt_ms,
                    rarity_count=self._chunk_rarity(req.chunk_index),
                )
            )

        # --- Pass 2: Swarm Health Zone (Rarest-First -> HAVE Bin Diversity) ---
        rarity_map = {r.chunk_index: self._chunk_rarity(r.chunk_index) for r in swarm_health}
        swarm_health.sort(
            key=lambda r: (
                rarity_map[r.chunk_index] if rarity_map[r.chunk_index] > 0 else 10**9,
                r.priority_urgency,
                r.deadline_ms,
                r.chunk_index,
            )
        )
        for req in swarm_health:
            if len(decisions) >= max_requests:
                break
            candidates = self._eligible_peers_for(req.chunk_index)
            if not candidates:
                continue
            # Balance load across peers for swarm diversity, then prefer lower RTT
            candidates.sort(key=lambda p: (len(p.in_flight_chunks), p.smoothed_rtt_ms))
            chosen = candidates[0]
            chosen.in_flight_chunks.add(req.chunk_index)
            decisions.append(
                ScheduledRequest(
                    peer_id=chosen.peer_id,
                    chunk_index=req.chunk_index,
                    bin_id=BinTreeMath.leaf_bin(req.chunk_index),
                    zone=SchedulingZone.SWARM_HEALTH_RAREST_FIRST,
                    priority_urgency=req.priority_urgency,
                    deadline_ms=req.deadline_ms,
                    peer_rtt_ms=chosen.smoothed_rtt_ms,
                    rarity_count=rarity_map[req.chunk_index],
                )
            )

        return decisions
