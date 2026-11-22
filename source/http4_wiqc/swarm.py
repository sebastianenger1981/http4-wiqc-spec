"""
WIQC Swarm Capability Negotiation, Static BEP 52 & Live Unified Merkle Swarm Engines,
and Trackerless Peer Exchange (PEX).

Implements Section 3.2, Section 3.3, Section 5.2, and Section 8.1 of
`draft-enger-httpbis-http4-wiqc-00`:

1. **RFC 7574 Swarm Metadata Negotiation (`SwarmCapabilities`)**:
   - Option Code `2`: Swarm Identifier (32-byte BEP 52 pieces root or live pubkey fingerprint)
   - Option Code `3`: Content Integrity Protection Method:
     - `0x01`: BEP 52 Static Merkle Hash Tree (`merkle-v2`)
     - `0x03`: Unified Merkle Tree for Live Streaming (`unified-live`)
     - (`0x00` None is normatively rejected!)
   - Option Code `4`: Merkle Hash Tree Function — **FIXED to SHA-256 (`0x02`)**
   - Option Code `6`: Chunk Addressing Method (`0x02` = `bin32`, default `0x03` = `bin64`)
   - Option Code `7`: Live Discard Window (chunks)

2. **Static Content Swarm (`StaticSwarmStore`)**:
   - Holds verified 16 KiB leaf blocks + BEP 52 Merkle tree / uncle proofs.
   - Verifies incoming blocks deterministically before accepting or re-seeding.
   - Computes minimal RFC 7574 `WIQC_HAVE` bin announcements.
   - Answers BEP 52 Hash Wire Messages (`21` HASH_REQUEST -> `22` HASHES / `23` HASH_REJECT).

3. **Live Real-Time Swarm (`LiveSwarmChannel`)**:
   - Origin publisher creates MOQT Groups/Subgroups/Objects, signs munro hashes via
     `UnifiedMerklePublisher`, and emits `WIQC_SIGNED_INTEGRITY` + `WIQC_INTEGRITY`.
   - Receiving peers/relays verify every live chunk against the publisher's Ed25519
     public key via `UnifiedMerkleVerifier` BEFORE playback AND BEFORE re-seeding
     to downstream peers!

4. **Trackerless PEX Registry (`PEXRegistry`)**:
   - Maintains known swarm peer endpoints (`IPv4` and `IPv6`) per `swarm_id` and
     generates `WIQC_PEX` (`PEX_RESv4` / `PEX_RESv6`) replies upon `PEX_REQ`.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from enum import IntEnum

from .crypto import Ed25519PrivateKey, Ed25519PublicKey
from .exceptions import IntegrityVerificationError, SwarmNegotiationError, WireFormatError
from .frames import (
    FrameType,
    PeerEndpoint,
    PEXSubType,
    RawFrame,
    WIQCHaveFrame,
    WIQCPexFrame,
)
from .headers import WIQCSwarmInfo
from .media import MediaGroup, MediaObject, TrackIdentifier
from .merkle import (
    LEAF_BLOCK_SIZE,
    SHA256_LEN,
    BinTreeMath,
    SignedMunro,
    StaticMerkleTree,
    UncleProofEntry,
    UnifiedMerklePublisher,
    UnifiedMerkleVerifier,
)
from .varint import ByteReader, ByteWriter


# =============================================================================
# 1. RFC 7574 Swarm Metadata Negotiation (Section 3.2)
# =============================================================================


class SwarmOptionCode(IntEnum):
    """RFC 7574 Handshake Option Codes mandated by Section 3.2."""

    SWARM_IDENTIFIER = 2
    CONTENT_INTEGRITY_METHOD = 3
    MERKLE_HASH_FUNCTION = 4
    CHUNK_ADDRESSING_METHOD = 6
    LIVE_DISCARD_WINDOW = 7


class IntegrityProtectionMethod(IntEnum):
    NONE = 0x00  # Forbidden in WIQC
    MERKLE_HASH_TREE_STATIC = 0x01  # BEP 52 Static 16 KiB Merkle Mode
    SIGN_ALL = 0x02
    UNIFIED_MERKLE_TREE_LIVE = 0x03  # RFC 7574 CIPM 3 Live Mode


class MerkleHashFunction(IntEnum):
    SHA256 = 0x02  # Normatively FIXED to SHA-256 (0x02) in Section 3.2


class ChunkAddressingMethod(IntEnum):
    BIN32 = 0x02
    BIN64 = 0x03  # Default per Section 3.2


@dataclass(frozen=True)
class SwarmCapabilities:
    """
    Wire-encodable RFC 7574 swarm capability negotiation block exchanged during
    WIQC Swarm Control stream (`0x41`) initialization.
    """

    swarm_id: bytes
    integrity_method: IntegrityProtectionMethod = IntegrityProtectionMethod.MERKLE_HASH_TREE_STATIC
    merkle_hash_function: int = int(MerkleHashFunction.SHA256)
    chunk_addressing: ChunkAddressingMethod = ChunkAddressingMethod.BIN64
    live_discard_window: int = 64

    def validate(self) -> None:
        if len(self.swarm_id) != SHA256_LEN:
            raise SwarmNegotiationError(f"Swarm ID must be 32 bytes, got {len(self.swarm_id)}")
        if self.integrity_method == IntegrityProtectionMethod.NONE:
            raise SwarmNegotiationError("IntegrityProtectionMethod.NONE is forbidden in WIQC")
        if self.merkle_hash_function != int(MerkleHashFunction.SHA256):
            raise SwarmNegotiationError(
                f"WIQC mandates SHA-256 (code 0x02) for Option 4, got 0x{self.merkle_hash_function:02x}"
            )
        if self.chunk_addressing not in (ChunkAddressingMethod.BIN32, ChunkAddressingMethod.BIN64):
            raise SwarmNegotiationError(
                f"Unsupported Chunk Addressing Method: {self.chunk_addressing}"
            )
        if self.live_discard_window < 0:
            raise SwarmNegotiationError("Live Discard Window must be non-negative")

    def to_swarm_info_header(self) -> WIQCSwarmInfo:
        mode = (
            "unified-live"
            if self.integrity_method == IntegrityProtectionMethod.UNIFIED_MERKLE_TREE_LIVE
            else "merkle-v2"
        )
        addr = "bin64" if self.chunk_addressing == ChunkAddressingMethod.BIN64 else "bin32"
        win = self.live_discard_window if mode == "unified-live" else None
        return WIQCSwarmInfo(
            swarm_id=self.swarm_id,
            mode=mode,
            window=win,
            chunk_addr=addr,
        )

    def encode_frame(self) -> RawFrame:
        self.validate()
        w = ByteWriter()
        # Encode as RFC 7574 Option-Code TLV tuples
        w.write_u8(int(SwarmOptionCode.SWARM_IDENTIFIER))
        w.write_varbytes(self.swarm_id)

        w.write_u8(int(SwarmOptionCode.CONTENT_INTEGRITY_METHOD))
        w.write_u8(int(self.integrity_method))

        w.write_u8(int(SwarmOptionCode.MERKLE_HASH_FUNCTION))
        w.write_u8(self.merkle_hash_function)

        w.write_u8(int(SwarmOptionCode.CHUNK_ADDRESSING_METHOD))
        w.write_u8(int(self.chunk_addressing))

        w.write_u8(int(SwarmOptionCode.LIVE_DISCARD_WINDOW))
        w.write_varint(self.live_discard_window)

        return RawFrame(FrameType.WIQC_HANDSHAKE_CAPS, w.to_bytes())

    @classmethod
    def decode_payload(cls, payload: bytes) -> SwarmCapabilities:
        r = ByteReader(payload)
        swarm_id: bytes | None = None
        cipm = IntegrityProtectionMethod.MERKLE_HASH_TREE_STATIC
        hash_fn = int(MerkleHashFunction.SHA256)
        chunk_addr = ChunkAddressingMethod.BIN64
        window = 64

        while not r.eof():
            opt = r.read_u8()
            if opt == SwarmOptionCode.SWARM_IDENTIFIER:
                swarm_id = r.read_varbytes(64)
            elif opt == SwarmOptionCode.CONTENT_INTEGRITY_METHOD:
                cipm = IntegrityProtectionMethod(r.read_u8())
            elif opt == SwarmOptionCode.MERKLE_HASH_FUNCTION:
                hash_fn = r.read_u8()
            elif opt == SwarmOptionCode.CHUNK_ADDRESSING_METHOD:
                chunk_addr = ChunkAddressingMethod(r.read_u8())
            elif opt == SwarmOptionCode.LIVE_DISCARD_WINDOW:
                window = r.read_varint()
            else:
                raise WireFormatError(f"Unknown RFC 7574 Swarm Option Code: {opt}")

        if swarm_id is None:
            raise SwarmNegotiationError("Missing Option Code 2 (Swarm Identifier)")
        caps = cls(
            swarm_id=swarm_id,
            integrity_method=cipm,
            merkle_hash_function=hash_fn,
            chunk_addressing=chunk_addr,
            live_discard_window=window,
        )
        caps.validate()
        return caps

    @staticmethod
    def negotiate(local: SwarmCapabilities, remote: SwarmCapabilities) -> SwarmCapabilities:
        """Verify compatibility between two peers' swarm capabilities."""
        local.validate()
        remote.validate()
        if local.swarm_id != remote.swarm_id:
            raise SwarmNegotiationError("Swarm ID mismatch during capability negotiation")
        if local.integrity_method != remote.integrity_method:
            raise SwarmNegotiationError(
                f"Incompatible integrity methods: {local.integrity_method} vs {remote.integrity_method}"
            )
        # Prefer bin64 if both support it, otherwise bin32
        addr = (
            ChunkAddressingMethod.BIN64
            if (
                local.chunk_addressing == ChunkAddressingMethod.BIN64
                and remote.chunk_addressing == ChunkAddressingMethod.BIN64
            )
            else ChunkAddressingMethod.BIN32
        )
        return SwarmCapabilities(
            swarm_id=local.swarm_id,
            integrity_method=local.integrity_method,
            merkle_hash_function=int(MerkleHashFunction.SHA256),
            chunk_addressing=addr,
            live_discard_window=min(local.live_discard_window, remote.live_discard_window),
        )


# =============================================================================
# 2. Static Content Swarm Store (BEP 52 Merkle Mode)
# =============================================================================


class StaticSwarmResource:
    """
    A static HTTP/4 resource backed by a BEP 52 16 KiB SHA-256 Merkle tree.

    Supports both:
    - Origin/Full Seeder mode (initialized from complete bytes -> builds full tree),
    - Leecher/Partial Peer Seeder mode (initialized from `pieces_root` + `total_size`
      -> verifies each arriving 16 KiB block against `pieces_root` before storing
      and immediately makes verified blocks available to re-seed!).
    """

    def __init__(
        self,
        path: str,
        content_type: str,
        pieces_root: bytes,
        total_size: int,
        block_size: int = LEAF_BLOCK_SIZE,
        merkle_tree: StaticMerkleTree | None = None,
    ) -> None:
        self.path = path
        self.content_type = content_type
        self.pieces_root = pieces_root
        self.total_size = total_size
        self.block_size = block_size
        self.block_count = max(1, (total_size + block_size - 1) // block_size) if total_size > 0 else 1
        self.merkle_tree = merkle_tree
        self.verified_blocks: dict[int, bytes] = {}
        self.verified_proofs: dict[int, list[UncleProofEntry]] = {}

        if merkle_tree is not None:
            for idx in range(merkle_tree.block_count):
                self.verified_blocks[idx] = merkle_tree.get_block(idx)
                self.verified_proofs[idx] = merkle_tree.get_uncle_proof(idx)

    @classmethod
    def from_bytes(
        cls,
        path: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        block_size: int = LEAF_BLOCK_SIZE,
    ) -> StaticSwarmResource:
        tree = StaticMerkleTree(data, block_size=block_size)
        return cls(
            path=path,
            content_type=content_type,
            pieces_root=tree.pieces_root,
            total_size=len(data),
            block_size=block_size,
            merkle_tree=tree,
        )

    @property
    def swarm_id(self) -> bytes:
        return self.pieces_root

    @property
    def is_complete(self) -> bool:
        return len(self.verified_blocks) == self.block_count

    def missing_chunks(self) -> list[int]:
        return [i for i in range(self.block_count) if i not in self.verified_blocks]

    def verify_and_store_block(
        self,
        chunk_index: int,
        block_data: bytes,
        uncle_proof: list[UncleProofEntry] | tuple[UncleProofEntry, ...],
    ) -> None:
        """
        Verify a 16 KiB block against `pieces_root` via SHA-256 Merkle proof.
        Raises `IntegrityVerificationError` on ANY corruption without storing it.
        """
        if not (0 <= chunk_index < self.block_count):
            raise IntegrityVerificationError(f"Chunk index {chunk_index} out of bounds")
        ok = StaticMerkleTree.verify_block(
            chunk_index=chunk_index,
            block_data=block_data,
            uncle_proof=uncle_proof,
            expected_pieces_root=self.pieces_root,
            block_size=self.block_size,
        )
        if not ok:
            raise IntegrityVerificationError(
                f"BEP 52 Merkle proof FAILED for static chunk {chunk_index} "
                f"(swarm={self.swarm_id.hex()[:12]})"
            )
        self.verified_blocks[chunk_index] = block_data
        self.verified_proofs[chunk_index] = list(uncle_proof)

    def build_have_frame(self, use_bin64: bool = True) -> WIQCHaveFrame:
        bins = BinTreeMath.minimal_covering_bins(set(self.verified_blocks.keys()))
        return WIQCHaveFrame(swarm_id=self.swarm_id, bins=tuple(bins), use_bin64=use_bin64)

    def reassemble(self) -> bytes:
        """Reassemble the verified HTTP/4 representation once all blocks are verified."""
        if not self.is_complete:
            raise IntegrityVerificationError(
                f"Cannot reassemble incomplete static swarm: "
                f"{len(self.verified_blocks)}/{self.block_count} blocks verified"
            )
        raw = b"".join(self.verified_blocks[i] for i in range(self.block_count))
        return raw[: self.total_size]


# =============================================================================
# 3. Live Streaming Swarm Channel (Unified Merkle Tree Mode, RFC 7574 CIPM 3)
# =============================================================================


@dataclass
class VerifiedLiveChunk:
    """A cryptographically authenticated live media object ready for playback & re-seeding."""

    obj: MediaObject
    uncle_proof: list[UncleProofEntry]
    signed_munro: SignedMunro
    received_at: float = field(default_factory=time.monotonic)


class LiveSwarmChannel:
    """
    Holds state for a decentralized HTTP/4 real-time streaming track (`unified-live`).

    Can act as:
    - **Authoritative Origin Publisher** (holds `publisher_private_key`, creates
      MOQT Groups & signs munro hashes), OR
    - **Relay / Subscriber Peer** (holds `publisher_public_key`, verifies every
      arriving munro + chunk before delivering to playback AND caches verified
      chunks within the Live Discard Window for immediate P2P re-seeding!).
    """

    def __init__(
        self,
        track: TrackIdentifier,
        publisher_public_key: Ed25519PublicKey,
        publisher_private_key: Ed25519PrivateKey | None = None,
        munro_layer: int = 2,
        live_discard_window: int = 64,
    ) -> None:
        self.track = track
        self.publisher_public_key = publisher_public_key
        self.swarm_id = publisher_public_key.fingerprint()
        self.munro_layer = munro_layer
        self.chunks_per_group = 1 << munro_layer
        self.live_discard_window = live_discard_window

        self.publisher: UnifiedMerklePublisher | None = (
            UnifiedMerklePublisher(publisher_private_key, munro_layer=munro_layer)
            if publisher_private_key is not None
            else None
        )
        self.verifier = UnifiedMerkleVerifier(publisher_public_key)
        self.verified_chunks: dict[int, VerifiedLiveChunk] = {}
        self.signed_munros: dict[int, SignedMunro] = {}  # group_id -> SignedMunro
        self.latest_chunk_index: int = -1

    def publish_group(self, group: MediaGroup) -> tuple[SignedMunro, list[VerifiedLiveChunk]]:
        """
        Origin publisher commits a MOQT Group into the Unified Merkle Tree,
        signs its munro hash, and stores all chunks ready for swarm distribution.
        """
        if self.publisher is None:
            raise SwarmNegotiationError("Only the authoritative origin publisher can sign munros")
        ordered_objs = group.all_objects_ordered()
        if not ordered_objs:
            raise ValueError("Cannot publish empty MediaGroup")
        payloads = [o.payload for o in ordered_objs]
        signed_munro, proofs = self.publisher.commit_group(group.group_id, payloads)
        group.munro_bin = signed_munro.munro_bin
        self.signed_munros[group.group_id] = signed_munro
        self.verifier.accept_signed_munro(signed_munro)

        published: list[VerifiedLiveChunk] = []
        for obj in ordered_objs:
            vc = VerifiedLiveChunk(
                obj=obj,
                uncle_proof=proofs[obj.chunk_index],
                signed_munro=signed_munro,
            )
            self.verified_chunks[obj.chunk_index] = vc
            self.latest_chunk_index = max(self.latest_chunk_index, obj.chunk_index)
            published.append(vc)
        self._enforce_live_discard_window()
        return signed_munro, published

    def verify_and_accept_chunk(
        self,
        obj: MediaObject,
        uncle_proof: list[UncleProofEntry] | tuple[UncleProofEntry, ...],
        signed_munro: SignedMunro | None = None,
    ) -> VerifiedLiveChunk:
        """
        Strictly verify an incoming live chunk against the publisher's Ed25519
        signed munro BEFORE passing to playback or re-seeding to downstream peers!

        Raises `IntegrityVerificationError` on ANY tampering or forged signature.
        """
        if not self.verifier.verify_live_chunk(
            chunk_index=obj.chunk_index,
            payload=obj.payload,
            uncle_proof=uncle_proof,
            signed_munro=signed_munro,
        ):
            raise IntegrityVerificationError(
                f"Unified Merkle Tree live verification FAILED for chunk {obj.chunk_index} "
                f"(group={obj.group_id}, swarm={self.swarm_id.hex()[:12]})"
            )
        if signed_munro is not None:
            self.signed_munros[signed_munro.group_id] = signed_munro
        stored_munro = signed_munro or self.signed_munros.get(obj.group_id)
        if stored_munro is None:
            # Find cached munro via verifier bin lookup
            m_bin = BinTreeMath.bin_at(self.munro_layer, obj.group_id)
            stored_munro = self.verifier._verified_munros[m_bin]

        vc = VerifiedLiveChunk(
            obj=obj,
            uncle_proof=list(uncle_proof),
            signed_munro=stored_munro,
        )
        self.verified_chunks[obj.chunk_index] = vc
        self.latest_chunk_index = max(self.latest_chunk_index, obj.chunk_index)
        self._enforce_live_discard_window()
        return vc

    def _enforce_live_discard_window(self) -> None:
        """Evict historical live chunks older than the negotiated Live Discard Window."""
        if self.live_discard_window <= 0:
            return
        cutoff = self.latest_chunk_index - self.live_discard_window
        if cutoff < 0:
            return
        for idx in [k for k in self.verified_chunks if k <= cutoff]:
            self.verified_chunks.pop(idx, None)

    def build_have_frame(self, use_bin64: bool = True) -> WIQCHaveFrame:
        bins = BinTreeMath.minimal_covering_bins(set(self.verified_chunks.keys()))
        return WIQCHaveFrame(swarm_id=self.swarm_id, bins=tuple(bins), use_bin64=use_bin64)


# =============================================================================
# 4. Trackerless Peer Exchange (WIQC_PEX, 0x4104)
# =============================================================================


class PEXRegistry:
    """
    Trackerless decentralized peer discovery table backing `WIQC_PEX` (0x4104).
    Segregates IPv4 (`PEX_RESv4`) and IPv6 (`PEX_RESv6`) peer advertisements per swarm.
    """

    def __init__(self, max_peers_per_swarm: int = 128) -> None:
        self.max_peers_per_swarm = max_peers_per_swarm
        self._swarm_peers: dict[bytes, dict[tuple[str, int], PeerEndpoint]] = {}

    def register_peer(self, swarm_id: bytes, endpoint: PeerEndpoint) -> None:
        bucket = self._swarm_peers.setdefault(swarm_id, {})
        bucket[(endpoint.host, endpoint.port)] = endpoint
        if len(bucket) > self.max_peers_per_swarm:
            # Evict oldest inserted entry
            oldest_key = next(iter(bucket))
            bucket.pop(oldest_key, None)

    def remove_peer(self, swarm_id: bytes, address: tuple[str, int]) -> None:
        bucket = self._swarm_peers.get(swarm_id)
        if bucket is not None:
            bucket.pop(address, None)

    def get_peers(
        self,
        swarm_id: bytes,
        ip_version: int = 4,
        exclude_address: tuple[str, int] | None = None,
    ) -> list[PeerEndpoint]:
        bucket = self._swarm_peers.get(swarm_id, {})
        out: list[PeerEndpoint] = []
        for addr, ep in bucket.items():
            if exclude_address is not None and addr == exclude_address:
                continue
            try:
                ip = ipaddress.ip_address(ep.host)
            except ValueError:
                continue
            if ip.version == ip_version:
                out.append(ep)
        return out

    def build_pex_response(
        self,
        swarm_id: bytes,
        ip_version: int = 4,
        exclude_address: tuple[str, int] | None = None,
    ) -> WIQCPexFrame:
        peers = self.get_peers(swarm_id, ip_version=ip_version, exclude_address=exclude_address)
        subtype = PEXSubType.PEX_RESv4 if ip_version == 4 else PEXSubType.PEX_RESv6
        return WIQCPexFrame(subtype=subtype, swarm_id=swarm_id, peers=tuple(peers))
