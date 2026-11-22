"""
Unit tests for RFC 7574 Bin Tree Addressing, BEP 52 Static 16 KiB Merkle Trees
(including Hash Messages 21/22/23), and RFC 7574 CIPM 3 Live Unified Merkle Tree
Munro Signatures.
"""

from __future__ import annotations

import os
import unittest

from http4_wiqc.crypto import Ed25519PrivateKey
from http4_wiqc.merkle import (
    LEAF_BLOCK_SIZE,
    BEP52Hashes,
    BEP52HashReject,
    BEP52HashRequest,
    BinTreeMath,
    SignedMunro,
    StaticMerkleTree,
    UnifiedMerklePublisher,
    UnifiedMerkleVerifier,
)


class TestRFC7574BinMath(unittest.TestCase):
    def test_layers_parents_siblings_and_ranges(self) -> None:
        # Check exact RFC 7574 binary tree layout for 8 leaves (0..7)
        self.assertEqual(BinTreeMath.layer(0), 0)
        self.assertEqual(BinTreeMath.layer(2), 0)
        self.assertEqual(BinTreeMath.layer(1), 1)
        self.assertEqual(BinTreeMath.layer(5), 1)
        self.assertEqual(BinTreeMath.layer(3), 2)
        self.assertEqual(BinTreeMath.layer(11), 2)
        self.assertEqual(BinTreeMath.layer(7), 3)

        self.assertEqual(BinTreeMath.parent(0), 1)
        self.assertEqual(BinTreeMath.parent(2), 1)
        self.assertEqual(BinTreeMath.parent(1), 3)
        self.assertEqual(BinTreeMath.parent(5), 3)
        self.assertEqual(BinTreeMath.parent(3), 7)
        self.assertEqual(BinTreeMath.parent(11), 7)
        self.assertEqual(BinTreeMath.sibling(9), 13)
        self.assertEqual(BinTreeMath.left_child(11), 9)
        self.assertEqual(BinTreeMath.right_child(11), 13)
        self.assertEqual(BinTreeMath.leaf_range(11), (4, 7))
        self.assertEqual(BinTreeMath.leaf_range(7), (0, 7))

    def test_minimal_covering_bins_roundtrip(self) -> None:
        chunks = {0, 1, 2, 3, 6, 7}
        bins = BinTreeMath.minimal_covering_bins(chunks)
        # {0,1,2,3} collapses into bin 3; {6,7} collapses into bin 13!
        self.assertEqual(bins, [3, 13])
        self.assertEqual(BinTreeMath.expand_bins_to_chunks(bins), chunks)


class TestBEP52StaticMerkleTree(unittest.TestCase):
    def test_16kib_block_verification_and_pollution_rejection(self) -> None:
        # 5.5 blocks -> 6 leaf blocks, padded to 8 leaves (height 3)
        data = os.urandom(LEAF_BLOCK_SIZE * 5 + 4096)
        tree = StaticMerkleTree(data)
        self.assertEqual(tree.block_count, 6)
        self.assertEqual(tree.padded_leaf_count, 8)
        self.assertEqual(tree.height, 3)

        for idx in range(tree.block_count):
            block = tree.get_block(idx)
            proof = tree.get_uncle_proof(idx)
            self.assertEqual(len(proof), 3)
            self.assertTrue(
                StaticMerkleTree.verify_block(idx, block, proof, tree.pieces_root)
            )
            # Single flipped bit must immediately fail Merkle verification
            tampered = bytearray(block)
            tampered[len(tampered) // 2] ^= 0x01
            self.assertFalse(
                StaticMerkleTree.verify_block(idx, bytes(tampered), proof, tree.pieces_root)
            )

    def test_bep52_hash_messages_21_22_23(self) -> None:
        data = os.urandom(LEAF_BLOCK_SIZE * 6)
        tree = StaticMerkleTree(data)

        # Valid request for 4 leaf hashes + 1 proof layer up to root
        req = BEP52HashRequest(
            pieces_root=tree.pieces_root,
            base_layer=0,
            index=0,
            length=4,
            proof_layers=1,
        )
        req_decoded = BEP52HashRequest.decode(req.encode())
        resp = tree.handle_bep52_hash_request(req_decoded)
        self.assertIsInstance(resp, BEP52Hashes)
        resp_decoded = BEP52Hashes.decode(resp.encode())
        self.assertTrue(StaticMerkleTree.verify_bep52_hashes(resp_decoded, tree.pieces_root))

        # Invalid pieces root or misaligned index must return HASH_REJECT (ID 23)
        bad_req = BEP52HashRequest(
            pieces_root=b"\xAA" * 32,
            base_layer=0,
            index=0,
            length=4,
            proof_layers=1,
        )
        rej = tree.handle_bep52_hash_request(bad_req)
        self.assertIsInstance(rej, BEP52HashReject)
        self.assertEqual(BEP52HashReject.decode(rej.encode()).pieces_root, b"\xAA" * 32)


class TestUnifiedMerkleLiveMode(unittest.TestCase):
    def test_munro_signing_verification_and_forgery_rejection(self) -> None:
        pub_priv = Ed25519PrivateKey()
        attacker_priv = Ed25519PrivateKey()

        publisher = UnifiedMerklePublisher(pub_priv, munro_layer=2)  # 4 chunks/group
        verifier = UnifiedMerkleVerifier(pub_priv.public_key())

        for grp_id in range(3):
            payloads = [f"live-group-{grp_id}-chunk-{j}".encode() for j in range(4)]
            signed_munro, proofs = publisher.commit_group(grp_id, payloads)
            self.assertTrue(verifier.accept_signed_munro(signed_munro))

            for offset, payload in enumerate(payloads):
                c_idx = grp_id * 4 + offset
                self.assertTrue(
                    verifier.verify_live_chunk(c_idx, payload, proofs[c_idx])
                )
                # Polluted chunk must fail verification immediately
                self.assertFalse(
                    verifier.verify_live_chunk(c_idx, payload + b"!", proofs[c_idx])
                )

        # Attacker forging a munro signature with wrong key must fail
        attacker_pub = UnifiedMerklePublisher(attacker_priv, munro_layer=2)
        forged_munro, _ = attacker_pub.commit_group(9, [b"fake0", b"fake1", b"fake2", b"fake3"])
        self.assertFalse(verifier.accept_signed_munro(forged_munro))


if __name__ == "__main__":
    unittest.main()
