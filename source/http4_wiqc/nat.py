"""
Native WIQC NAT Traversal and UDP Hole-Punching Coordinator.

Implements Section 6.2 ("Native WIQC NAT Traversal", incorporating
`I-D.seemann-quic-nat-traversal` + RFC 9000 `PATH_CHALLENGE` / `PATH_RESPONSE`)
of `draft-enger-httpbis-http4-wiqc-00`.

Workflow for Direct Peer-to-Peer Hole Punching without External ICE/STUN/TURN:
1. Peer A and Peer B (behind NATs) each connect to a well-connected WIQC Relay/Seed Peer.
2. The Relay immediately observes each peer's external UDP socket address and sends
   an `OBSERVED_ADDRESS` frame informing Peer A of `pub_A` and Peer B of `pub_B`.
3. Peers advertise their candidate UDP endpoints over their swarm connections using
   `ADD_ADDRESS` (`0x3d7e90` IPv4 / `0x3d7e91` IPv6), and withdraw stale addresses
   with `REMOVE_ADDRESS` (`0x3d7e94`).
4. To establish a direct P2P path between A and B:
   - Peer A sends `PUNCH_REQUEST` (or `PUNCH_ME_NOW` `0x3d7e92`/`0x3d7e93`) via Relay.
   - Relay coordinates synchronized `PUNCH_ME_NOW` frames to both Peer A (targeting
     `pub_B`) and Peer B (targeting `pub_A`) with matching `round_num`.
   - Both peers simultaneously transmit UDP `PATH_CHALLENGE` (`0x1a`) packets directly
     to each other's external UDP addresses, punching pinholes in their NATs!
   - Upon receiving `PATH_CHALLENGE`, each peer replies with `PATH_RESPONSE` (`0x1b`)
     echoing the exact 8-byte token -> direct P2P path is cryptographically validated
     and active!
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from .frames import (
    AddAddressFrame,
    ObservedAddressFrame,
    PathChallengeFrame,
    PathResponseFrame,
    PunchMeNowFrame,
    PunchRequestFrame,
    RemoveAddressFrame,
)


@dataclass
class CandidateAddress:
    """Candidate UDP endpoint advertised via `ADD_ADDRESS`."""

    sequence: int
    host: str
    port: int
    added_at: float = field(default_factory=time.monotonic)


@dataclass
class PendingPunch:
    """Tracks an active simultaneous UDP hole-punch attempt and its PATH_CHALLENGE."""

    round_num: int
    target_addr: tuple[str, int]
    challenge_token: bytes
    started_at: float = field(default_factory=time.monotonic)
    validated: bool = False
    validated_rtt_ms: float | None = None
    event: asyncio.Event = field(default_factory=asyncio.Event)


class NATTraversalCoordinator:
    """
    Manages candidate addresses, observed external addresses, relay-coordinated
    `PUNCH_ME_NOW` / `PUNCH_REQUEST` rounds, and RFC 9000 `PATH_CHALLENGE` /
    `PATH_RESPONSE` validation for a WIQC endpoint.
    """

    def __init__(self) -> None:
        self.observed_external_address: tuple[str, int] | None = None
        self._next_seq: int = 1
        self._next_round: int = 1
        self.local_candidates: dict[int, CandidateAddress] = {}
        self.remote_candidates: dict[bytes, dict[int, CandidateAddress]] = {}
        self.pending_challenges: dict[bytes, PendingPunch] = {}  # 8-byte token -> PendingPunch
        self.validated_direct_paths: dict[tuple[str, int], float] = {}  # addr -> rtt_ms
        self.punch_history: list[str] = []

    # ---- Observed Address ----
    def build_observed_address(self, peer_addr: tuple[str, int], seq: int = 0) -> ObservedAddressFrame:
        return ObservedAddressFrame(host=peer_addr[0], port=peer_addr[1], sequence=seq)

    def handle_observed_address(self, frame: ObservedAddressFrame) -> tuple[str, int]:
        self.observed_external_address = (frame.host, frame.port)
        self.punch_history.append(f"OBSERVED_ADDRESS {frame.host}:{frame.port}")
        return self.observed_external_address

    # ---- Candidate Address Management (ADD_ADDRESS / REMOVE_ADDRESS) ----
    def add_local_candidate(self, host: str, port: int) -> AddAddressFrame:
        seq = self._next_seq
        self._next_seq += 1
        self.local_candidates[seq] = CandidateAddress(sequence=seq, host=host, port=port)
        return AddAddressFrame(sequence=seq, host=host, port=port)

    def remove_local_candidate(self, sequence: int) -> RemoveAddressFrame:
        self.local_candidates.pop(sequence, None)
        return RemoveAddressFrame(sequence=sequence)

    def handle_remote_add_address(self, peer_id: bytes, frame: AddAddressFrame) -> None:
        bucket = self.remote_candidates.setdefault(peer_id, {})
        bucket[frame.sequence] = CandidateAddress(
            sequence=frame.sequence, host=frame.host, port=frame.port
        )
        self.punch_history.append(
            f"ADD_ADDRESS peer={peer_id.hex()[:8]} seq={frame.sequence} {frame.host}:{frame.port}"
        )

    def handle_remote_remove_address(self, peer_id: bytes, frame: RemoveAddressFrame) -> None:
        bucket = self.remote_candidates.get(peer_id)
        if bucket is not None:
            bucket.pop(frame.sequence, None)
            self.punch_history.append(f"REMOVE_ADDRESS peer={peer_id.hex()[:8]} seq={frame.sequence}")

    # ---- Relay Coordination (PUNCH_REQUEST & PUNCH_ME_NOW) ----
    def create_punch_request(
        self,
        target_peer_id: bytes,
        candidate_addr: tuple[str, int],
        grant_token: bytes | None = None,
    ) -> PunchRequestFrame:
        token = secrets.token_bytes(16) if grant_token is None else grant_token
        return PunchRequestFrame(
            target_peer_id=target_peer_id,
            grant_token=token,
            candidate_host=candidate_addr[0],
            candidate_port=candidate_addr[1],
        )

    def coordinate_simultaneous_punch(
        self,
        peer_a_addr: tuple[str, int],
        peer_b_addr: tuple[str, int],
        seq_a: int = 1,
        seq_b: int = 1,
    ) -> tuple[PunchMeNowFrame, PunchMeNowFrame]:
        """
        Called by a WIQC Relay/Seed peer to generate synchronized `PUNCH_ME_NOW`
        frames for Peer A (telling it to punch Peer B) and Peer B (telling it to
        punch Peer A) in the same round.
        """
        round_num = self._next_round
        self._next_round += 1
        for_a = PunchMeNowFrame(
            round_num=round_num,
            paired_with_seq=seq_b,
            host=peer_b_addr[0],
            port=peer_b_addr[1],
        )
        for_b = PunchMeNowFrame(
            round_num=round_num,
            paired_with_seq=seq_a,
            host=peer_a_addr[0],
            port=peer_a_addr[1],
        )
        self.punch_history.append(
            f"COORDINATE_PUNCH round={round_num} {peer_a_addr} <-> {peer_b_addr}"
        )
        return for_a, for_b

    # ---- Direct Path Validation (PATH_CHALLENGE / PATH_RESPONSE) ----
    def start_path_challenge(
        self, target_addr: tuple[str, int], round_num: int = 0
    ) -> tuple[PathChallengeFrame, PendingPunch]:
        token = secrets.token_bytes(8)
        pending = PendingPunch(
            round_num=round_num,
            target_addr=target_addr,
            challenge_token=token,
        )
        self.pending_challenges[token] = pending
        self.punch_history.append(
            f"PATH_CHALLENGE -> {target_addr[0]}:{target_addr[1]} token={token.hex()}"
        )
        return PathChallengeFrame(data=token), pending

    def handle_path_challenge(self, frame: PathChallengeFrame) -> PathResponseFrame:
        self.punch_history.append(f"PATH_CHALLENGE_RX token={frame.data.hex()}")
        return PathResponseFrame(data=frame.data)

    def handle_path_response(
        self, frame: PathResponseFrame, from_addr: tuple[str, int]
    ) -> PendingPunch | None:
        pending = self.pending_challenges.pop(frame.data, None)
        if pending is None:
            return None
        rtt_ms = (time.monotonic() - pending.started_at) * 1000.0
        pending.validated = True
        pending.validated_rtt_ms = rtt_ms
        pending.event.set()
        self.validated_direct_paths[from_addr] = rtt_ms
        self.punch_history.append(
            f"PATH_RESPONSE_OK from={from_addr[0]}:{from_addr[1]} rtt={rtt_ms:.2f}ms"
        )
        return pending


class SimulatedRestrictedNAT:
    """
    Endpoint-Independent / Address-Restricted Cone NAT filter used for testing
    WIQC simultaneous UDP hole punching locally on loopback.

    Rule:
    - Outbound packet to `remote_addr` opens a pinhole allowing inbound packets
      from `remote_addr`.
    - Inbound packet from `remote_addr` is DROPPED unless an outbound packet to
      `remote_addr` has opened a pinhole first (proving simultaneous hole punching!).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.open_pinholes: set[tuple[str, int]] = set()
        self.dropped_packets: int = 0
        self.passed_packets: int = 0

    def allow_outbound(self, dest_addr: tuple[str, int]) -> None:
        self.open_pinholes.add(dest_addr)

    def filter_inbound(self, src_addr: tuple[str, int]) -> bool:
        if src_addr in self.open_pinholes:
            self.passed_packets += 1
            return True
        self.dropped_packets += 1
        return False
