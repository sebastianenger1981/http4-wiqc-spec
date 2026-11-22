"""
Unit tests for Pure-Python Cryptography (RFC 8032 Ed25519, RFC 7748 X25519,
RFC 5869 HKDF-SHA256, RFC 8439 ChaCha20-Poly1305) and Decentralized Mutual TLS 1.3
with libp2p-tls Self-Signed X.509 Certificates (OID 1.3.6.1.4.1.53594.1.1) and
WebTransport Certhash Binding.
"""

from __future__ import annotations

import hashlib
import time
import unittest

from http4_wiqc.crypto import (
    ChaCha20Poly1305,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    PeerIdentity,
    X25519KeyPair,
    x25519_scalarmult,
)
from http4_wiqc.exceptions import CryptoError, TLSAuthenticationError
from http4_wiqc.tls_libp2p import (
    ALPN_H4,
    ALPN_WIQC,
    LIBP2P_TLS_OID,
    MutualTLSHandshake,
    WebTransportCerthashBinding,
    generate_libp2p_self_signed_cert,
    verify_libp2p_certificate_chain,
)


class TestCryptographicRFCVectors(unittest.TestCase):
    """Verify pure-Python cryptography directly against official IETF RFC test vectors."""

    def test_ed25519_rfc8032_vector_1_empty_message(self) -> None:
        # RFC 8032 Section 7.1 TEST 1 (empty message)
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expected_pub = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        priv = Ed25519PrivateKey(secret)
        self.assertEqual(priv.public_bytes, expected_pub)
        sig = priv.sign(b"")
        self.assertEqual(sig, expected_sig)
        self.assertTrue(priv.public_key().verify(sig, b""))
        self.assertFalse(priv.public_key().verify(sig, b"tampered"))

    def test_ed25519_rfc8032_vector_2_one_byte(self) -> None:
        # RFC 8032 Section 7.1 TEST 2 (message = 0x72)
        secret = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        expected_pub = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        expected_sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        priv = Ed25519PrivateKey(secret)
        self.assertEqual(priv.public_bytes, expected_pub)
        self.assertEqual(priv.sign(b"\x72"), expected_sig)
        self.assertTrue(Ed25519PublicKey(expected_pub).verify(expected_sig, b"\x72"))

    def test_x25519_rfc7748_vector(self) -> None:
        # RFC 7748 Section 6.1 Diffie-Hellman Test Vector
        alice_priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        bob_priv = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )
        alice = X25519KeyPair(alice_priv)
        bob = X25519KeyPair(bob_priv)
        self.assertEqual(alice.shared_secret(bob.public_bytes), expected_shared)
        self.assertEqual(bob.shared_secret(alice.public_bytes), expected_shared)

        # Low-order point must be rejected
        with self.assertRaises(CryptoError):
            alice.shared_secret(b"\x00" * 32)

    def test_chacha20_poly1305_rfc8439_vector(self) -> None:
        # RFC 8439 Section 2.8.2 AEAD Test Vector
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, sunscreen would be it."
        )
        expected_ct = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
        )
        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

        aead = ChaCha20Poly1305(key)
        ct_and_tag = aead.encrypt(nonce, plaintext, aad=aad)
        self.assertEqual(ct_and_tag[:-16], expected_ct)
        self.assertEqual(ct_and_tag[-16:], expected_tag)
        self.assertEqual(aead.decrypt(nonce, ct_and_tag, aad=aad), plaintext)

        # Flipping 1 bit in AAD or ciphertext must fail authentication
        with self.assertRaises(CryptoError):
            aead.decrypt(nonce, ct_and_tag, aad=aad + b"\x00")
        bad = bytearray(ct_and_tag)
        bad[0] ^= 0x01
        with self.assertRaises(CryptoError):
            aead.decrypt(nonce, bytes(bad), aad=aad)


class TestLibp2pTLSAndMutualAuth(unittest.TestCase):
    """Verify Section 6.1 Mutual TLS 1.3 with Self-Signed libp2p X.509 certificates."""

    def test_self_signed_cert_contains_oid_and_verifies(self) -> None:
        identity = PeerIdentity.generate("test-node")
        bundle = generate_libp2p_self_signed_cert(identity, validity_seconds=3600)
        verified = verify_libp2p_certificate_chain([bundle.cert_der])
        self.assertEqual(verified.peer_id, identity.peer_id)
        self.assertEqual(verified.host_public_key.public_bytes, identity.public_bytes)
        self.assertEqual(verified.certhash, hashlib.sha256(bundle.cert_der).digest())

    def test_certificate_chain_longer_than_one_must_be_rejected(self) -> None:
        id1 = PeerIdentity.generate("node-1")
        id2 = PeerIdentity.generate("node-2")
        c1 = generate_libp2p_self_signed_cert(id1).cert_der
        c2 = generate_libp2p_self_signed_cert(id2).cert_der
        with self.assertRaises(TLSAuthenticationError):
            verify_libp2p_certificate_chain([c1, c2])
        with self.assertRaises(TLSAuthenticationError):
            verify_libp2p_certificate_chain([])

    def test_expired_certificate_rejected(self) -> None:
        identity = PeerIdentity.generate("expired-node")
        now = int(time.time())
        bundle = generate_libp2p_self_signed_cert(identity, validity_seconds=60, now=now - 500)
        with self.assertRaises(TLSAuthenticationError):
            verify_libp2p_certificate_chain([bundle.cert_der], now=now)

    def test_tampered_certificate_rejected(self) -> None:
        identity = PeerIdentity.generate("tampered-node")
        bundle = generate_libp2p_self_signed_cert(identity)
        bad = bytearray(bundle.cert_der)
        bad[-5] ^= 0xFF
        with self.assertRaises(TLSAuthenticationError):
            verify_libp2p_certificate_chain([bytes(bad)])

    def test_webtransport_certhash_inband_binding(self) -> None:
        identity = PeerIdentity.generate("browser-peer")
        bundle = generate_libp2p_self_signed_cert(identity)
        binding = WebTransportCerthashBinding.create(identity, bundle.cert_der)
        decoded = WebTransportCerthashBinding.decode(binding.encode())
        peer_id = decoded.verify(expected_certhash=bundle.certhash)
        self.assertEqual(peer_id, identity.peer_id)

        # Wrong certhash pin must fail
        with self.assertRaises(TLSAuthenticationError):
            decoded.verify(expected_certhash=b"\x00" * 32)

    def test_mutual_tls13_handshake_alpn_and_key_agreement(self) -> None:
        server_id = PeerIdentity.generate("server")
        client_id = PeerIdentity.generate("client")
        server_hs = MutualTLSHandshake(server_id, is_server=True, alpns=(ALPN_H4, ALPN_WIQC))
        client_hs = MutualTLSHandshake(client_id, is_server=False, alpns=(ALPN_H4,))

        ch = client_hs.create_client_hello()
        sh, s_auth = server_hs.process_client_hello(ch)
        c_auth = client_hs.process_server_flight(sh, s_auth)
        verified_client = server_hs.process_client_auth(c_auth)

        self.assertTrue(client_hs.completed and server_hs.completed)
        self.assertEqual(client_hs.negotiated_alpn, ALPN_H4)
        self.assertEqual(server_hs.negotiated_alpn, ALPN_H4)
        self.assertEqual(verified_client.peer_id, client_id.peer_id)
        self.assertEqual(client_hs.peer_cert.peer_id, server_id.peer_id)
        self.assertIsNotNone(client_hs.received_ticket)

        # Verify derived 1-RTT application keys decrypt symmetrically across sides
        ct = client_hs.app_keys.send_cipher.encrypt(client_hs.app_keys.send_iv, b"hello-h4", b"aad")
        pt = server_hs.app_keys.recv_cipher.decrypt(server_hs.app_keys.recv_iv, ct, b"aad")
        self.assertEqual(pt, b"hello-h4")

    def test_mutual_tls13_rejects_incompatible_alpn(self) -> None:
        server_hs = MutualTLSHandshake(PeerIdentity.generate(), is_server=True, alpns=(ALPN_H4,))
        client_hs = MutualTLSHandshake(PeerIdentity.generate(), is_server=False, alpns=(b"h3",))
        ch = client_hs.create_client_hello()
        with self.assertRaises(TLSAuthenticationError):
            server_hs.process_client_hello(ch)


if __name__ == "__main__":
    unittest.main()
