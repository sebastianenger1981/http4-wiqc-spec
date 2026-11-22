"""
Cryptographic Content Integrity for HTTP/4 over WIQC:
- RFC 7574 64-bit / 32-bit Bin Tree Addressing,
- BEP 52 Static Content Mode (16 KiB SHA-256 Merkle Tree + Hash Wire Messages 21/22/23),
- RFC 7574 CIPM 3 Decentralized Real-Time Streaming Mode (Unified Merkle Tree + Munro Signatures).

Implements Section 2, Section 3.3, Section 5.2, and Section 8.1 of
`draft-enger-httpbis-http4-wiqc-00`.

Key Normative Constants:
- LEAF_BLOCK_SIZE = 16,384 bytes (16 KiB fixed per BEP 52).
- MERKLE_HASH_FUNCTION = SHA-256 (RFC 7574 Option Code 4 = 0x02).
- Static Mode (CIPM 1): Swarm ID = 32-byte BEP 52 SHA-256 pieces root.
- Live Mode (CIPM 3): Swarm ID = 32-byte SHA-256 fingerprint of publisher Ed25519 key.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

from .crypto import Ed25519PrivateKey, Ed25519PublicKey
from .exceptions import IntegrityVerificationError, WireFormatError
from .varint import ByteReader, ByteWriter

# Normative constants
LEAF_BLOCK_SIZE = 16_384  # 16 KiB fixed leaf block size (BEP 52)
SHA256_LEN = 32
ZERO_HASH = b"\x00" * SHA256_LEN

# BEP 52 Peer Wire Protocol Message IDs (Section 3.3)
BEP52_MSG_HASH_REQUEST = 21
BEP52_MSG_HASHES = 22
BEP52_MSG_HASH_REJECT = 23

# Domain separation prefix for Unified Merkle Tree Munro Signatures
MUNRO_SIG_DOMAIN = b"WIQC-MUNRO-V1:"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


# =============================================================================
# 1. RFC 7574 Bin Tree Mathematics (64-bit & 32-bit Bin Addressing)
# =============================================================================


class BinTreeMath:
    """
    Exact RFC 7574 Section 4.1 bin-numbering arithmetic for complete binary trees.

    Bin layout for 8 chunks (0..7):
        Layer 3:             7 (0..7)
                           /         \\
        Layer 2:       3 (0..3)     11 (4..7)
                      /       \\     /       \\
        Layer 1:   1(0..1) 5(2..3) 9(4..5) 13(6..7)
                   /   \\   /   \\   /   \\    /    \\
        Layer 0:  0     2 4     6 8    10 12     14   (chunk_idx * 2)

    A bin's layer equals its number of trailing 1-bits in binary!
    """

    MAX_BIN32 = (1 << 32) - 1
    MAX_BIN64 = (1 << 64) - 1

    @staticmethod
    def validate_bin(bin_id: int, bits: int = 64) -> None:
        max_val = BinTreeMath.MAX_BIN32 if bits == 32 else BinTreeMath.MAX_BIN64
        if bin_id < 0 or bin_id > max_val:
            raise WireFormatError(f"Bin ID {bin_id} out of {bits}-bit range")

    @staticmethod
    def layer(bin_id: int) -> int:
        """Number of trailing 1-bits in binary representation of `bin_id`."""
        if bin_id < 0:
            raise WireFormatError(f"Negative bin ID: {bin_id}")
        return ((bin_id ^ (bin_id + 1)) + 1).bit_length() - 2

    @staticmethod
    def width(bin_id: int) -> int:
        """Number of leaf chunks covered by `bin_id`."""
        return 1 << BinTreeMath.layer(bin_id)

    @staticmethod
    def is_leaf(bin_id: int) -> bool:
        return (bin_id & 1) == 0

    @staticmethod
    def leaf_bin(chunk_index: int) -> int:
        """Convert 0-based leaf chunk index to its layer-0 bin number (2 * index)."""
        if chunk_index < 0:
            raise WireFormatError(f"Negative chunk index: {chunk_index}")
        return chunk_index << 1

    @staticmethod
    def leaf_index(bin_id: int) -> int:
        """Convert a layer-0 leaf bin to its 0-based chunk index."""
        if not BinTreeMath.is_leaf(bin_id):
            raise WireFormatError(f"Bin {bin_id} is not a leaf bin")
        return bin_id >> 1

    @staticmethod
    def bin_at(layer: int, index_in_layer: int) -> int:
        """Compute bin number for `(layer, index_in_layer)`."""
        if layer < 0 or index_in_layer < 0:
            raise WireFormatError("Layer and index must be non-negative")
        return ((index_in_layer * 2 + 1) << layer) - 1

    @staticmethod
    def is_left_child(bin_id: int) -> bool:
        lvl = BinTreeMath.layer(bin_id)
        return ((bin_id >> (lvl + 1)) & 1) == 0

    @staticmethod
    def parent(bin_id: int) -> int:
        lvl = BinTreeMath.layer(bin_id)
        step = 1 << lvl
        return bin_id + step if BinTreeMath.is_left_child(bin_id) else bin_id - step

    @staticmethod
    def sibling(bin_id: int) -> int:
        lvl = BinTreeMath.layer(bin_id)
        return bin_id ^ (1 << (lvl + 1))

    @staticmethod
    def left_child(bin_id: int) -> int:
        lvl = BinTreeMath.layer(bin_id)
        if lvl == 0:
            raise WireFormatError(f"Leaf bin {bin_id} has no children")
        return bin_id - (1 << (lvl - 1))

    @staticmethod
    def right_child(bin_id: int) -> int:
        lvl = BinTreeMath.layer(bin_id)
        if lvl == 0:
            raise WireFormatError(f"Leaf bin {bin_id} has no children")
        return bin_id + (1 << (lvl - 1))

    @staticmethod
    def leaf_range(bin_id: int) -> tuple[int, int]:
        """Return inclusive `(first_chunk_index, last_chunk_index)` covered by `bin_id`."""
        lvl = BinTreeMath.layer(bin_id)
        first = (bin_id >> (lvl + 1)) << lvl
        last = first + (1 << lvl) - 1
        return first, last

    @staticmethod
    def contains(ancestor_bin: int, descendant_bin: int) -> bool:
        a_lo, a_hi = BinTreeMath.leaf_range(ancestor_bin)
        d_lo, d_hi = BinTreeMath.leaf_range(descendant_bin)
        return a_lo <= d_lo and d_hi <= a_hi

    @staticmethod
    def uncle_bins(leaf_or_node_bin: int, target_ancestor_bin: int) -> list[int]:
        """
        Return the ordered list of sibling (uncle) bin IDs required to walk
        from `leaf_or_node_bin` up to `target_ancestor_bin`.
        """
        if not BinTreeMath.contains(target_ancestor_bin, leaf_or_node_bin):
            raise IntegrityVerificationError(
                f"Bin {leaf_or_node_bin} is not a descendant of ancestor bin {target_ancestor_bin}"
            )
        uncles: list[int] = []
        cur = leaf_or_node_bin
        while cur != target_ancestor_bin:
            uncles.append(BinTreeMath.sibling(cur))
            cur = BinTreeMath.parent(cur)
        return uncles

    @staticmethod
    def minimal_covering_bins(chunk_indices: set[int] | list[int]) -> list[int]:
        """
        Compact a set of verified chunk indices into minimal RFC 7574 bin ranges
        for bandwidth-efficient `WIQC_HAVE` announcements.
        """
        if not chunk_indices:
            return []
        bins = {BinTreeMath.leaf_bin(i) for i in chunk_indices}
        changed = True
        while changed:
            changed = False
            for b in sorted(bins):
                if b not in bins:
                    continue
                sib = BinTreeMath.sibling(b)
                if sib in bins:
                    bins.remove(b)
                    bins.remove(sib)
                    bins.add(BinTreeMath.parent(b))
                    changed = True
                    break
        return sorted(bins)

    @staticmethod
    def expand_bins_to_chunks(bins: list[int] | tuple[int, ...]) -> set[int]:
        """Expand RFC 7574 bin IDs from a `WIQC_HAVE` frame into leaf chunk indices."""
        chunks: set[int] = set()
        for b in bins:
            lo, hi = BinTreeMath.leaf_range(b)
            chunks.update(range(lo, hi + 1))
        return chunks


# =============================================================================
# 2. BEP 52 Peer Wire Hash Messages (IDs 21, 22, 23) & Merkle Proof Structs
# =============================================================================


@dataclass(frozen=True)
class UncleProofEntry:
    """One `(bin_id, sha256_hash)` pair carried inside `WIQC_INTEGRITY` (0x4102)."""

    bin_id: int
    digest: bytes

    def __post_init__(self) -> None:
        if len(self.digest) != SHA256_LEN:
            raise IntegrityVerificationError(f"SHA-256 hash must be 32 bytes, got {len(self.digest)}")


@dataclass(frozen=True)
class BEP52HashRequest:
    """BEP 52 Hash Request message (Message ID 21)."""

    pieces_root: bytes
    base_layer: int
    index: int
    length: int
    proof_layers: int

    MSG_ID = BEP52_MSG_HASH_REQUEST

    def encode(self) -> bytes:
        if len(self.pieces_root) != SHA256_LEN:
            raise WireFormatError("pieces_root must be 32 bytes")
        w = ByteWriter()
        w.write_u8(self.MSG_ID)
        w.write_bytes(self.pieces_root)
        w.write_u32(self.base_layer)
        w.write_u32(self.index)
        w.write_u32(self.length)
        w.write_u32(self.proof_layers)
        return w.to_bytes()

    @classmethod
    def decode(cls, data: bytes) -> BEP52HashRequest:
        r = ByteReader(data)
        msg_id = r.read_u8()
        if msg_id != cls.MSG_ID:
            raise WireFormatError(f"Expected BEP52 HASH_REQUEST (21), got {msg_id}")
        return cls(
            pieces_root=r.read_bytes(SHA256_LEN),
            base_layer=r.read_u32(),
            index=r.read_u32(),
            length=r.read_u32(),
            proof_layers=r.read_u32(),
        )


@dataclass(frozen=True)
class BEP52Hashes:
    """BEP 52 Hashes response message (Message ID 22)."""

    pieces_root: bytes
    base_layer: int
    index: int
    length: int
    proof_layers: int
    hashes: tuple[bytes, ...]

    MSG_ID = BEP52_MSG_HASHES

    def encode(self) -> bytes:
        w = ByteWriter()
        w.write_u8(self.MSG_ID)
        w.write_bytes(self.pieces_root)
        w.write_u32(self.base_layer)
        w.write_u32(self.index)
        w.write_u32(self.length)
        w.write_u32(self.proof_layers)
        for h in self.hashes:
            if len(h) != SHA256_LEN:
                raise WireFormatError("Each BEP 52 hash must be 32 bytes")
            w.write_bytes(h)
        return w.to_bytes()

    @classmethod
    def decode(cls, data: bytes) -> BEP52Hashes:
        r = ByteReader(data)
        msg_id = r.read_u8()
        if msg_id != cls.MSG_ID:
            raise WireFormatError(f"Expected BEP52 HASHES (22), got {msg_id}")
        pieces_root = r.read_bytes(SHA256_LEN)
        base_layer = r.read_u32()
        index = r.read_u32()
        length = r.read_u32()
        proof_layers = r.read_u32()
        expected_hashes = length + proof_layers
        hashes = tuple(r.read_bytes(SHA256_LEN) for _ in range(expected_hashes))
        return cls(
            pieces_root=pieces_root,
            base_layer=base_layer,
            index=index,
            length=length,
            proof_layers=proof_layers,
            hashes=hashes,
        )


@dataclass(frozen=True)
class BEP52HashReject:
    """BEP 52 Hash Reject message (Message ID 23)."""

    pieces_root: bytes
    base_layer: int
    index: int
    length: int
    proof_layers: int

    MSG_ID = BEP52_MSG_HASH_REJECT

    def encode(self) -> bytes:
        w = ByteWriter()
        w.write_u8(self.MSG_ID)
        w.write_bytes(self.pieces_root)
        w.write_u32(self.base_layer)
        w.write_u32(self.index)
        w.write_u32(self.length)
        w.write_u32(self.proof_layers)
        return w.to_bytes()

    @classmethod
    def decode(cls, data: bytes) -> BEP52HashReject:
        r = ByteReader(data)
        msg_id = r.read_u8()
        if msg_id != cls.MSG_ID:
            raise WireFormatError(f"Expected BEP52 HASH_REJECT (23), got {msg_id}")
        return cls(
            pieces_root=r.read_bytes(SHA256_LEN),
            base_layer=r.read_u32(),
            index=r.read_u32(),
            length=r.read_u32(),
            proof_layers=r.read_u32(),
        )


# =============================================================================
# 3. Static Content Mode: BEP 52 16 KiB SHA-256 Merkle Tree
# =============================================================================


class StaticMerkleTree:
    """
    BEP 52 binary SHA-256 Merkle hash tree over fixed 16 KiB (16,384 byte) leaf blocks.

    Workflow:
    1. Split representation bytes into `N` blocks of at most 16 KiB (`LEAF_BLOCK_SIZE`).
    2. Hash each block with SHA-256.
    3. Pad layer 0 with 32-byte zero hashes (`ZERO_HASH`) up to `P = next_power_of_two(N)`.
    4. Compute parent nodes `SHA-256(left || right)` upward until reaching the single
       32-byte `pieces_root` (which serves as the static HTTP/4 `Swarm ID`).
    5. Answer both `WIQC_INTEGRITY` uncle proofs and BEP 52 `HASH_REQUEST (21)` queries.
    """

    def __init__(self, data: bytes, block_size: int = LEAF_BLOCK_SIZE) -> None:
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        self.block_size = block_size
        self.total_size = len(data)
        if not data:
            self._blocks: list[bytes] = [b""]
        else:
            self._blocks = [
                data[i : i + block_size] for i in range(0, len(data), block_size)
            ]
        self.block_count = len(self._blocks)
        self.padded_leaf_count = next_power_of_two(self.block_count)
        self.height = (self.padded_leaf_count - 1).bit_length()  # 0 if 1 leaf

        # Build all layers bottom-up: layers[0] = padded leaves, layers[height] = [root]
        leaf_hashes = [sha256(b) for b in self._blocks]
        leaf_hashes.extend(ZERO_HASH for _ in range(self.padded_leaf_count - self.block_count))
        self.layers: list[list[bytes]] = [leaf_hashes]
        cur = leaf_hashes
        while len(cur) > 1:
            nxt = [sha256(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
            self.layers.append(nxt)
            cur = nxt

        self.root_bin = BinTreeMath.bin_at(self.height, 0)

    @property
    def pieces_root(self) -> bytes:
        """32-byte BEP 52 pieces root (= HTTP/4 Static Swarm ID)."""
        return self.layers[-1][0]

    @property
    def swarm_id(self) -> bytes:
        return self.pieces_root

    def get_block(self, chunk_index: int) -> bytes:
        if not (0 <= chunk_index < self.block_count):
            raise IndexError(f"Chunk index {chunk_index} out of range [0, {self.block_count})")
        return self._blocks[chunk_index]

    def get_bin_hash(self, bin_id: int) -> bytes:
        """Fetch SHA-256 hash stored at RFC 7574 `bin_id`."""
        lvl = BinTreeMath.layer(bin_id)
        if lvl > self.height:
            raise IntegrityVerificationError(f"Bin {bin_id} exceeds tree height {self.height}")
        idx = bin_id >> (lvl + 1)
        if idx >= len(self.layers[lvl]):
            raise IntegrityVerificationError(f"Bin {bin_id} index {idx} out of bounds")
        return self.layers[lvl][idx]

    def get_uncle_proof(self, chunk_index: int) -> list[UncleProofEntry]:
        """
        Produce the ordered list of `(bin_id, sha256_hash)` uncle entries needed
        to verify `chunk_index` immediately against `pieces_root`.
        """
        if not (0 <= chunk_index < self.block_count):
            raise IntegrityVerificationError(f"Invalid chunk index {chunk_index}")
        leaf_bin = BinTreeMath.leaf_bin(chunk_index)
        uncles = BinTreeMath.uncle_bins(leaf_bin, self.root_bin)
        return [UncleProofEntry(bin_id=u, digest=self.get_bin_hash(u)) for u in uncles]

    def handle_bep52_hash_request(
        self, req: BEP52HashRequest
    ) -> BEP52Hashes | BEP52HashReject:
        """
        Fulfill a BEP 52 `HASH_REQUEST` (ID 21) by returning `HASHES` (ID 22)
        or `HASH_REJECT` (ID 23) if invalid/out-of-bounds.
        """
        reject = BEP52HashReject(
            pieces_root=req.pieces_root,
            base_layer=req.base_layer,
            index=req.index,
            length=req.length,
            proof_layers=req.proof_layers,
        )
        if not hmac.compare_digest(req.pieces_root, self.pieces_root):
            return reject
        if req.base_layer > self.height or req.length <= 0 or (req.length & (req.length - 1)) != 0:
            return reject
        if req.index % req.length != 0:
            return reject
        layer_nodes = self.layers[req.base_layer]
        if req.index + req.length > len(layer_nodes):
            return reject

        span_layers = req.length.bit_length() - 1
        max_proof_layers = max(0, self.height - (req.base_layer + span_layers))
        if req.proof_layers > max_proof_layers:
            return reject

        out_hashes: list[bytes] = list(layer_nodes[req.index : req.index + req.length])
        cur_layer = req.base_layer + span_layers
        cur_idx = req.index >> span_layers
        for _ in range(req.proof_layers):
            out_hashes.append(self.layers[cur_layer][cur_idx ^ 1])
            cur_layer += 1
            cur_idx >>= 1

        return BEP52Hashes(
            pieces_root=req.pieces_root,
            base_layer=req.base_layer,
            index=req.index,
            length=req.length,
            proof_layers=req.proof_layers,
            hashes=tuple(out_hashes),
        )

    @staticmethod
    def verify_bep52_hashes(resp: BEP52Hashes, expected_pieces_root: bytes) -> bool:
        """
        Verify a BEP 52 `HASHES` (ID 22) response up to `expected_pieces_root`.
        """
        if not hmac.compare_digest(resp.pieces_root, expected_pieces_root):
            return False
        if resp.length <= 0 or (resp.length & (resp.length - 1)) != 0:
            return False
        if len(resp.hashes) != resp.length + resp.proof_layers:
            return False

        # Fold requested base hashes upward into their subtree root
        cur_level = list(resp.hashes[: resp.length])
        while len(cur_level) > 1:
            cur_level = [
                sha256(cur_level[i] + cur_level[i + 1]) for i in range(0, len(cur_level), 2)
            ]
        h = cur_level[0]

        span_layers = resp.length.bit_length() - 1
        cur_idx = resp.index >> span_layers
        for uncle in resp.hashes[resp.length :]:
            if (cur_idx & 1) == 0:
                h = sha256(h + uncle)
            else:
                h = sha256(uncle + h)
            cur_idx >>= 1
        return hmac.compare_digest(h, expected_pieces_root)

    @staticmethod
    def verify_block(
        chunk_index: int,
        block_data: bytes,
        uncle_proof: list[UncleProofEntry] | tuple[UncleProofEntry, ...],
        expected_pieces_root: bytes,
        block_size: int = LEAF_BLOCK_SIZE,
    ) -> bool:
        """
        Immediately verify a single 16 KiB static block upon arrival against
        `expected_pieces_root` using its `WIQC_INTEGRITY` uncle proof.

        Raises no exception on mismatch; returns False so caller can discard the
        corrupt block and ban the offending peer.
        """
        if len(block_data) > block_size:
            return False
        cur_bin = BinTreeMath.leaf_bin(chunk_index)
        cur_hash = sha256(block_data)
        for entry in uncle_proof:
            expected_sib = BinTreeMath.sibling(cur_bin)
            if entry.bin_id != expected_sib:
                return False
            if BinTreeMath.is_left_child(cur_bin):
                cur_hash = sha256(cur_hash + entry.digest)
            else:
                cur_hash = sha256(entry.digest + cur_hash)
            cur_bin = BinTreeMath.parent(cur_bin)
        return hmac.compare_digest(cur_hash, expected_pieces_root)


# =============================================================================
# 4. Decentralized Real-Time Streaming Mode: Unified Merkle Tree & Munro Signing
# =============================================================================


@dataclass(frozen=True)
class SignedMunro:
    """
    Publisher-signed interior subtree root ("munro hash") transmitted via
    `WIQC_SIGNED_INTEGRITY` (Frame Type 0x4103) per RFC 7574 CIPM 3.
    """

    munro_bin: int
    munro_hash: bytes
    timestamp_us: int
    group_id: int
    signature: bytes

    def signing_payload(self, swarm_id: bytes) -> bytes:
        return (
            MUNRO_SIG_DOMAIN
            + swarm_id
            + struct.pack("!QQQ", self.munro_bin, self.timestamp_us, self.group_id)
            + self.munro_hash
        )


class UnifiedMerklePublisher:
    """
    Origin publisher's append-only Unified Merkle Tree (RFC 7574 CIPM 3).

    In HTTP/4 live streaming:
    - Each MOQT **Group** (starting at an IDR keyframe) maps directly to a
      power-of-two munro subtree of `2**munro_layer` chunks.
    - When a Group is emitted, the publisher computes its munro root hash, signs
      it with its Ed25519 private key (`SignedMunro`), and distributes both
      `WIQC_SIGNED_INTEGRITY` and per-chunk `WIQC_INTEGRITY` uncle proofs.
    - The live `Swarm ID` is the 32-byte SHA-256 fingerprint of the publisher's
      Ed25519 public key.
    """

    def __init__(
        self,
        publisher_private_key: Ed25519PrivateKey,
        munro_layer: int = 2,
    ) -> None:
        if munro_layer < 0 or munro_layer > 16:
            raise ValueError("munro_layer must be in [0, 16]")
        self._privkey = publisher_private_key
        self.public_key = publisher_private_key.public_key()
        self.swarm_id = self.public_key.fingerprint()
        self.munro_layer = munro_layer
        self.chunks_per_group = 1 << munro_layer

        # Stored hashes keyed by RFC 7574 bin_id
        self._bin_hashes: dict[int, bytes] = {}
        self._signed_munros: dict[int, SignedMunro] = {}  # munro_bin -> SignedMunro
        self._group_munro_bin: dict[int, int] = {}  # group_id -> munro_bin

    def commit_group(
        self,
        group_id: int,
        chunk_payloads: list[bytes],
        timestamp_us: int | None = None,
    ) -> tuple[SignedMunro, dict[int, list[UncleProofEntry]]]:
        """
        Commit a new live media Group into the Unified Merkle Tree.

        Pads trailing missing slots (if fewer than `chunks_per_group`) with
        `ZERO_HASH` so every munro covers a complete power-of-two bin range.

        Returns:
            `(signed_munro, {chunk_index: [UncleProofEntry, ...]})`
        """
        if len(chunk_payloads) > self.chunks_per_group:
            raise ValueError(
                f"Group payload count {len(chunk_payloads)} exceeds chunks_per_group {self.chunks_per_group}"
            )
        base_chunk_index = group_id * self.chunks_per_group
        munro_bin = BinTreeMath.bin_at(self.munro_layer, group_id)

        # Populate leaf layer for this munro subtree
        cur_level: list[tuple[int, bytes]] = []
        for offset in range(self.chunks_per_group):
            c_idx = base_chunk_index + offset
            c_bin = BinTreeMath.leaf_bin(c_idx)
            h = sha256(chunk_payloads[offset]) if offset < len(chunk_payloads) else ZERO_HASH
            self._bin_hashes[c_bin] = h
            cur_level.append((c_bin, h))

        # Hash upward to the munro bin
        while len(cur_level) > 1:
            nxt_level: list[tuple[int, bytes]] = []
            for i in range(0, len(cur_level), 2):
                left_bin, left_h = cur_level[i]
                _, right_h = cur_level[i + 1]
                p_bin = BinTreeMath.parent(left_bin)
                p_h = sha256(left_h + right_h)
                self._bin_hashes[p_bin] = p_h
                nxt_level.append((p_bin, p_h))
            cur_level = nxt_level

        assert cur_level[0][0] == munro_bin
        munro_hash = cur_level[0][1]

        # Maintain unified upper peak merges when sibling munro exists (RFC 7574 §6.4)
        cur_peak = munro_bin
        while True:
            sib = BinTreeMath.sibling(cur_peak)
            if sib not in self._bin_hashes:
                break
            p_bin = BinTreeMath.parent(cur_peak)
            if BinTreeMath.is_left_child(cur_peak):
                p_h = sha256(self._bin_hashes[cur_peak] + self._bin_hashes[sib])
            else:
                p_h = sha256(self._bin_hashes[sib] + self._bin_hashes[cur_peak])
            self._bin_hashes[p_bin] = p_h
            cur_peak = p_bin

        ts = int(time.time() * 1_000_000) if timestamp_us is None else timestamp_us
        unsigned = SignedMunro(
            munro_bin=munro_bin,
            munro_hash=munro_hash,
            timestamp_us=ts,
            group_id=group_id,
            signature=b"",
        )
        sig = self._privkey.sign(unsigned.signing_payload(self.swarm_id))
        signed = SignedMunro(
            munro_bin=munro_bin,
            munro_hash=munro_hash,
            timestamp_us=ts,
            group_id=group_id,
            signature=sig,
        )
        self._signed_munros[munro_bin] = signed
        self._group_munro_bin[group_id] = munro_bin

        # Build uncle proofs from each chunk up to `munro_bin`
        proofs: dict[int, list[UncleProofEntry]] = {}
        for offset in range(len(chunk_payloads)):
            c_idx = base_chunk_index + offset
            c_bin = BinTreeMath.leaf_bin(c_idx)
            uncles = BinTreeMath.uncle_bins(c_bin, munro_bin)
            proofs[c_idx] = [
                UncleProofEntry(bin_id=u, digest=self._bin_hashes[u]) for u in uncles
            ]
        return signed, proofs

    def get_signed_munro(self, group_id: int) -> SignedMunro | None:
        m_bin = self._group_munro_bin.get(group_id)
        return self._signed_munros.get(m_bin) if m_bin is not None else None


class UnifiedMerkleVerifier:
    """
    Receiving peer / relay verifier for live Unified Merkle Tree chunks (CIPM 3).

    Enforces Section 8.1 ("Stream Pollution Attacks in Decentralized Swarms"):
    - Every `WIQC_SIGNED_INTEGRITY` munro hash is verified against the publisher's
      Ed25519 public key (bound cryptographically to `Swarm ID`).
    - Every live chunk is verified against a verified munro hash via its
      `WIQC_INTEGRITY` uncle branch BEFORE playback or downstream re-seeding.
    - Sliding-window eviction prevents unbounded memory growth over long streams.
    """

    def __init__(self, publisher_public_key: Ed25519PublicKey, max_cached_munros: int = 512) -> None:
        self.publisher_public_key = publisher_public_key
        self.swarm_id = publisher_public_key.fingerprint()
        self.max_cached_munros = max_cached_munros
        self._verified_munros: dict[int, SignedMunro] = {}  # munro_bin -> SignedMunro
        self._munro_order: list[int] = []

    def accept_signed_munro(self, signed_munro: SignedMunro) -> bool:
        """
        Verify a publisher-signed munro hash (`WIQC_SIGNED_INTEGRITY`).
        Returns True if authentic (and caches it), False if forged/corrupted.
        """
        if len(signed_munro.munro_hash) != SHA256_LEN:
            return False
        payload = signed_munro.signing_payload(self.swarm_id)
        if not self.publisher_public_key.verify(signed_munro.signature, payload):
            return False
        if signed_munro.munro_bin not in self._verified_munros:
            self._munro_order.append(signed_munro.munro_bin)
            if len(self._munro_order) > self.max_cached_munros:
                oldest = self._munro_order.pop(0)
                self._verified_munros.pop(oldest, None)
        self._verified_munros[signed_munro.munro_bin] = signed_munro
        return True

    def verify_live_chunk(
        self,
        chunk_index: int,
        payload: bytes,
        uncle_proof: list[UncleProofEntry] | tuple[UncleProofEntry, ...],
        signed_munro: SignedMunro | None = None,
    ) -> bool:
        """
        Verify a live streaming chunk against a publisher-signed munro hash.

        If `signed_munro` is supplied alongside the chunk, verifies and caches it first.
        Then folds `SHA-256(payload)` upward through `uncle_proof` until reaching a
        cached verified `munro_bin`, confirming exact SHA-256 equality.
        """
        if signed_munro is not None:
            if not self.accept_signed_munro(signed_munro):
                return False

        cur_bin = BinTreeMath.leaf_bin(chunk_index)
        cur_hash = sha256(payload)
        for entry in uncle_proof:
            expected_sib = BinTreeMath.sibling(cur_bin)
            if entry.bin_id != expected_sib:
                return False
            if BinTreeMath.is_left_child(cur_bin):
                cur_hash = sha256(cur_hash + entry.digest)
            else:
                cur_hash = sha256(entry.digest + cur_hash)
            cur_bin = BinTreeMath.parent(cur_bin)

        verified = self._verified_munros.get(cur_bin)
        if verified is None:
            return False
        return hmac.compare_digest(cur_hash, verified.munro_hash)
