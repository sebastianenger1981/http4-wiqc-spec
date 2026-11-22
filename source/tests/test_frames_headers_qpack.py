"""
Unit tests for RFC 9000 VarInt, HTTP/4 & WIQC & NAT & Capsule Frames,
Section 7 ABNF `WIQC-Swarm-Info`, RFC 9421 Origin Signatures, RFC 9530 Digests,
RFC 7838 `Alt-Svc`, RFC 9460 `HTTPS`/`SVCB` Records, RFC 9218 Priority,
and QPACK with Section 8.3 Sensitive-Header Side-Channel Protection.
"""

from __future__ import annotations

import hashlib
import unittest

from http4_wiqc.crypto import Ed25519PrivateKey
from http4_wiqc.exceptions import (
    HeaderSyntaxError,
    IntegrityVerificationError,
    QPACKError,
    SwarmNegotiationError,
    WireFormatError,
)
from http4_wiqc.frames import (
    AddAddressFrame,
    DatagramCapsule,
    FrameType,
    NATFrameType,
    ObservedAddressFrame,
    PathChallengeFrame,
    PathResponseFrame,
    PeerEndpoint,
    PEXSubType,
    PunchMeNowFrame,
    PunchRequestFrame,
    RawFrame,
    RemoveAddressFrame,
    SettingsFrame,
    SettingsID,
    WIQCHaveFrame,
    WIQCIntegrityFrame,
    WIQCPexFrame,
    WIQCRequestFrame,
    WIQCSignedIntegrityFrame,
    WIQCSubgroupObjectFrame,
)
from http4_wiqc.headers import (
    AltSvcEntry,
    HTTP4Priority,
    HTTPSServiceRecord,
    WIQCSwarmInfo,
    format_alt_svc,
    format_repr_digest,
    format_swarm_root,
    parse_alt_svc,
    parse_repr_digest,
    parse_swarm_root,
    sign_http4_headers,
    verify_http4_headers,
)
from http4_wiqc.merkle import SignedMunro, UncleProofEntry
from http4_wiqc.qpack import QPACKDecoder, QPACKEncoder
from http4_wiqc.swarm import (
    ChunkAddressingMethod,
    IntegrityProtectionMethod,
    SwarmCapabilities,
)
from http4_wiqc.varint import ByteReader, decode_varint, encode_varint


class TestVarIntAndWireFrames(unittest.TestCase):
    def test_varint_all_four_widths(self) -> None:
        samples = [0, 1, 63, 64, 16383, 16384, 0x3D7E90, 1073741823, 1073741824, (1 << 62) - 1]
        for val in samples:
            enc = encode_varint(val)
            dec, pos = decode_varint(enc, 0)
            self.assertEqual(dec, val)
            self.assertEqual(pos, len(enc))
        with self.assertRaises(WireFormatError):
            encode_varint(-1)
        with self.assertRaises(WireFormatError):
            encode_varint(1 << 62)
        with self.assertRaises(WireFormatError):
            decode_varint(b"\x80\x01", 0)  # truncated 4-byte varint

    def test_wiqc_frames_and_nat_frames_roundtrip(self) -> None:
        sid = hashlib.sha256(b"swarm-x").digest()

        # WIQC_HAVE (0x4101)
        have = WIQCHaveFrame(swarm_id=sid, bins=(3, 13, 27), use_bin64=True)
        raw_have = RawFrame.decode_all(have.to_raw().encode())[0]
        self.assertEqual(raw_have.frame_type, FrameType.WIQC_HAVE)
        self.assertEqual(WIQCHaveFrame.from_payload(raw_have.payload), have)

        # WIQC_INTEGRITY (0x4102)
        integ = WIQCIntegrityFrame(
            swarm_id=sid,
            target_bin=4,
            uncles=(UncleProofEntry(6, b"\x11" * 32), UncleProofEntry(1, b"\x22" * 32)),
        )
        raw_int = RawFrame.decode_all(integ.to_raw().encode())[0]
        self.assertEqual(raw_int.frame_type, FrameType.WIQC_INTEGRITY)
        self.assertEqual(WIQCIntegrityFrame.from_payload(raw_int.payload), integ)

        # WIQC_SIGNED_INTEGRITY (0x4103)
        sm = SignedMunro(munro_bin=3, munro_hash=b"\x33" * 32, timestamp_us=123456, group_id=0, signature=b"\x44" * 64)
        si = WIQCSignedIntegrityFrame(swarm_id=sid, signed_munro=sm)
        raw_si = RawFrame.decode_all(si.to_raw().encode())[0]
        self.assertEqual(raw_si.frame_type, FrameType.WIQC_SIGNED_INTEGRITY)
        self.assertEqual(WIQCSignedIntegrityFrame.from_payload(raw_si.payload), si)

        # WIQC_PEX (0x4104) IPv4 and IPv6
        pex4 = WIQCPexFrame(
            subtype=PEXSubType.PEX_RESv4,
            swarm_id=sid,
            peers=(PeerEndpoint("192.0.2.10", 4433, b"peerA"),),
        )
        raw_p4 = RawFrame.decode_all(pex4.to_raw().encode())[0]
        self.assertEqual(WIQCPexFrame.from_payload(raw_p4.payload), pex4)

        pex6 = WIQCPexFrame(
            subtype=PEXSubType.PEX_RESv6,
            swarm_id=sid,
            peers=(PeerEndpoint("2001:db8::1", 4433, b"peerB"),),
        )
        raw_p6 = RawFrame.decode_all(pex6.to_raw().encode())[0]
        self.assertEqual(WIQCPexFrame.from_payload(raw_p6.payload), pex6)

        # Native NAT frames (0x3d7e90..0x3d7e94, OBSERVED_ADDRESS, PUNCH_REQUEST, PATH_CHALLENGE/RESPONSE)
        add4 = AddAddressFrame(sequence=1, host="198.51.100.5", port=51234)
        r = ByteReader(add4.encode())
        ft = r.read_varint()
        self.assertEqual(ft, NATFrameType.ADD_ADDRESS_V4)
        self.assertEqual(AddAddressFrame.decode(ft, r), add4)

        pmn6 = PunchMeNowFrame(round_num=3, paired_with_seq=1, host="2001:db8::42", port=5555)
        r2 = ByteReader(pmn6.encode())
        ft2 = r2.read_varint()
        self.assertEqual(ft2, NATFrameType.PUNCH_ME_NOW_V6)
        self.assertEqual(PunchMeNowFrame.decode(ft2, r2), pmn6)

        rem = RemoveAddressFrame(sequence=1)
        r3 = ByteReader(rem.encode())
        self.assertEqual(r3.read_varint(), NATFrameType.REMOVE_ADDRESS)
        self.assertEqual(RemoveAddressFrame.decode(r3), rem)

        obs = ObservedAddressFrame(host="203.0.113.9", port=60000, sequence=2)
        r4 = ByteReader(obs.encode())
        ft4 = r4.read_varint()
        self.assertEqual(ObservedAddressFrame.decode(ft4, r4), obs)

        # RFC 9297 DATAGRAM Capsule (0x00)
        cap = DatagramCapsule(quarter_stream_id=42, payload=b"loc-media-packet")
        self.assertEqual(DatagramCapsule.decode(cap.encode()), cap)

    def test_swarm_capabilities_rejects_non_sha256_and_none_cipm(self) -> None:
        sid = b"\x55" * 32
        good = SwarmCapabilities(
            swarm_id=sid,
            integrity_method=IntegrityProtectionMethod.UNIFIED_MERKLE_TREE_LIVE,
            merkle_hash_function=0x02,
            chunk_addressing=ChunkAddressingMethod.BIN64,
            live_discard_window=64,
        )
        decoded = SwarmCapabilities.decode_payload(good.encode_frame().payload)
        self.assertEqual(decoded, good)

        with self.assertRaises(SwarmNegotiationError):
            SwarmCapabilities(swarm_id=sid, merkle_hash_function=0x01).validate()  # SHA-1 forbidden!
        with self.assertRaises(SwarmNegotiationError):
            SwarmCapabilities(
                swarm_id=sid, integrity_method=IntegrityProtectionMethod.NONE
            ).validate()


class TestHeadersABNFAndQPACK(unittest.TestCase):
    def test_abnf_wiqc_swarm_info_strict_grammar(self) -> None:
        sid = hashlib.sha256(b"abnf-test").digest()
        info = WIQCSwarmInfo(swarm_id=sid, mode="unified-live", window=128, chunk_addr="bin64")
        formatted = info.format()
        parsed = WIQCSwarmInfo.parse(formatted)
        self.assertEqual(parsed, info)

        # Optional parameters omitted
        minimal = WIQCSwarmInfo(swarm_id=sid, mode="merkle-v2")
        self.assertEqual(WIQCSwarmInfo.parse(minimal.format()), minimal)

        # Invalid mode, invalid delimiter, or non-digit window MUST fail ABNF validation
        for bad in (
            f"swarm-id=:AAAA:;mode=unknown",
            f"swarm-id=notcolon;mode=merkle-v2",
            formatted.replace("window=128", "window=abc"),
            formatted.replace("chunk-addr=bin64", "chunk-addr=bin128"),
        ):
            with self.assertRaises(HeaderSyntaxError):
                WIQCSwarmInfo.parse(bad)

    def test_rfc9421_origin_signatures_and_rfc9530_digests(self) -> None:
        origin_key = Ed25519PrivateKey()
        body = b"authoritative-http4-content"
        pieces_root = hashlib.sha256(body).digest()
        headers = {
            ":status": "200",
            "content-type": "application/octet-stream",
            "repr-digest": format_repr_digest(body),
            "swarm-root": format_swarm_root(pieces_root),
            "wiqc-swarm-id": pieces_root.hex(),
        }
        signed = sign_http4_headers(headers, origin_key)
        self.assertTrue(verify_http4_headers(signed, origin_key.public_key()))
        self.assertEqual(parse_repr_digest(signed["repr-digest"]), hashlib.sha256(body).digest())
        self.assertEqual(parse_swarm_root(signed["swarm-root"]), pieces_root)

        # Malicious relay tampering with content-type or status must fail signature verification!
        tampered = dict(signed)
        tampered["content-type"] = "text/html"
        with self.assertRaises(IntegrityVerificationError):
            verify_http4_headers(tampered, origin_key.public_key())

    def test_alt_svc_svcb_and_priority(self) -> None:
        hdr = format_alt_svc([AltSvcEntry("h4", ":4433", 3600), AltSvcEntry("h3", ":443", 3600)])
        entries = parse_alt_svc(hdr)
        self.assertEqual(entries[0].protocol_id, "h4")
        self.assertEqual(entries[0].authority, ":4433")

        rr = HTTPSServiceRecord(1, "origin.http4.local.", ("h4", "wiqc"), 4433, ("127.0.0.1",))
        self.assertEqual(HTTPSServiceRecord.from_zone_text(rr.to_zone_text()), rr)

        prio = HTTP4Priority.parse("u=0, i")
        self.assertEqual(prio, HTTP4Priority(urgency=0, incremental=True))

    def test_qpack_dynamic_table_and_sensitive_header_side_channel_guard(self) -> None:
        enc = QPACKEncoder(max_table_capacity=4096)
        dec = QPACKDecoder(max_table_capacity=4096)

        headers = {
            ":method": "GET",
            ":path": "/live/stage1",
            "x-custom-track": "video-1080p",
            "authorization": "Bearer super-secret-token-xyz",
            "cookie": "session=topsecret",
        }
        section, enc_stream = enc.encode(headers)

        # Sensitive headers MUST NEVER enter the dynamic table (RFC 9114 §10.6)!
        for entry in enc.table._entries:
            self.assertNotIn(entry.name, ("authorization", "cookie"))
        self.assertIsNotNone(enc.table.lookup_pair("x-custom-track", "video-1080p"))

        # Explicitly attempting direct insertion of a sensitive header raises QPACKError
        with self.assertRaises(QPACKError):
            enc.table.insert("authorization", "Bearer leak")

        # Decoder processes encoder stream (0x02), decodes section, and emits ack (0x03)
        dec_inc = dec.process_encoder_stream(enc_stream)
        decoded_list, dec_ack = dec.decode(section, stream_id=4)
        self.assertEqual(dict(decoded_list), headers)
        enc.process_decoder_stream(dec_inc + dec_ack)
        self.assertIn(4, enc.acknowledged_streams)


if __name__ == "__main__":
    unittest.main()
