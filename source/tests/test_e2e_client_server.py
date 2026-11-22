"""
End-to-End Asyncio UDP Integration & Fault-Tolerance Test Suite for HTTP/4 over WIQC.

Exercises ALL proposed features of `draft-enger-httpbis-http4-wiqc-00` over real
loopback UDP sockets, including negative security tests and fault injection:
1. Mutual TLS 1.3 (libp2p self-signed cert + OID 1.3.6.1.4.1.53594.1.1) & chain>1 rejection
2. Anti-amplification (first-flight heavy payload rejection + 3x unvalidated budget cap)
3. Multi-peer BEP 52 static swarming, PEX discovery, Server Push, Hash IDs 21/22, pollution ban
4. Live MOQT Unified Merkle Tree streaming, Relay re-seeding, and live pollution defense
5. Zero Head-of-Line blocking across independent Subgroup streams (0x40) under targeted loss
6. 0-RTT idempotency enforcement (GET accepted; POST rejected with ReplayProtectionError / 425)
7. RFC 9221 unreliable QUIC DATAGRAMs & RFC 9297 DATAGRAM Capsules (0x00)
8. Seamless Connection Migration across UDP sockets (DCID preservation + PATH_CHALLENGE)
9. Native WIQC NAT Traversal through two simulated Address-Restricted Cone NATs
10. Fault tolerance: random UDP packet loss, malformed garbage datagrams, & peer crash failover
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import time
import unittest

from http4_wiqc import (
    ALPN_H4,
    FaultInjectionProfile,
    HTTP4WIQCClient,
    HTTP4WIQCServer,
    LiveSwarmChannel,
    MediaGroup,
    MediaObject,
    PeerEndpoint,
    PeerIdentity,
    ReplayProtectionError,
    SimulatedRestrictedNAT,
    StaticMerkleTree,
    TLSAuthenticationError,
    WIQCEndpoint,
    WIQCSwarmInfo,
    generate_libp2p_self_signed_cert,
    parse_alt_svc,
)
from http4_wiqc.transport import (
    PacketType,
    TransportFrameType,
    encode_long_packet,
)
from http4_wiqc.varint import ByteWriter


def _build_live_group(group_id: int, track, now_ms: int) -> MediaGroup:
    base = group_id * 4
    grp = MediaGroup(group_id=group_id, track=track, created_at_ms=now_ms)
    sg0 = grp.get_or_create_subgroup(0, priority_urgency=0, dependency_layer="base")
    sg0.add_object(MediaObject(group_id, 0, 0, base + 0, f"G{group_id}-BASE-IDR".encode() + b"\x11" * 128, now_ms + 80, True, 0))
    sg0.add_object(MediaObject(group_id, 0, 1, base + 1, f"G{group_id}-BASE-P1".encode() + b"\x22" * 128, now_ms + 160, False, 1))
    sg1 = grp.get_or_create_subgroup(1, priority_urgency=4, dependency_layer="enhancement")
    sg1.add_object(MediaObject(group_id, 1, 0, base + 2, f"G{group_id}-ENH-1".encode() + b"\x33" * 128, now_ms + 240, False, 4))
    sg1.add_object(MediaObject(group_id, 1, 1, base + 3, f"G{group_id}-ENH-2".encode() + b"\x44" * 128, now_ms + 320, False, 5))
    return grp


class TestHTTP4WIQCEndToEnd(unittest.IsolatedAsyncioTestCase):
    """Live UDP asyncio test suite verifying the full HTTP/4 over WIQC stack."""

    async def test_01_mutual_tls13_alpn_and_cert_chain_rejection(self) -> None:
        server = HTTP4WIQCServer(authority="tls.http4.local")
        addr = await server.start()
        client = HTTP4WIQCClient(label="tls-client")
        await client.start()
        try:
            # Valid 1-cert mutual auth succeeds
            sess = await client.connect(addr)
            self.assertEqual(sess.conn.negotiated_alpn, ALPN_H4)
            self.assertEqual(sess.conn.peer_id, server.peer_id)
            self.assertEqual(sess.conn.nat.observed_external_address, client.address)

            # Normative Section 6.1: certificate chain longer than 1 MUST terminate connection!
            extra_cert = generate_libp2p_self_signed_cert(PeerIdentity.generate("extra")).cert_der
            bad_client = HTTP4WIQCClient(label="bad-chain-client")
            await bad_client.start()
            try:
                with self.assertRaises(TLSAuthenticationError):
                    await bad_client.connect(
                        addr,
                        timeout=2.0,
                        override_client_cert_chain=[bad_client.endpoint.cert_bundle.cert_der, extra_cert],
                    )
            finally:
                await bad_client.close()
        finally:
            await client.close()
            await server.stop()

    async def test_02_anti_amplification_first_flight_and_3x_cap(self) -> None:
        server = HTTP4WIQCServer(authority="amp.http4.local")
        addr = await server.start()
        client = HTTP4WIQCClient(label="amp-attacker")
        await client.start()
        try:
            # 1) Send forbidden heavy STREAM payload in unvalidated INITIAL first flight
            fake_cid = secrets.token_bytes(8)
            w = ByteWriter()
            w.write_varint(int(TransportFrameType.STREAM))
            w.write_varint(0)
            w.write_varint(0)
            w.write_u8(1)
            w.write_varbytes(b"X" * 1024)
            bad_initial = encode_long_packet(
                pkt_type=PacketType.INITIAL,
                dcid=secrets.token_bytes(8),
                scid=fake_cid,
                channel_id=0,
                packet_number=1,
                payload=w.to_bytes(),
            )
            client.endpoint._transmit_udp(bad_initial, addr)
            await asyncio.sleep(0.1)
            # Server must have recorded anti-amplification block & closed connection
            blocked = sum(c.anti_amplification_blocks for c in server.endpoint._connections.values())
            # Also check even if already unregistered: server accepted zero established sessions!
            self.assertEqual(len(server.sessions), 0)

            # 2) Tiny unpadded spoofed ClientHello (~100B) hits server's 3x amplification budget!
            tiny_cid = secrets.token_bytes(8)
            from http4_wiqc.tls_libp2p import MutualTLSHandshake

            hs = MutualTLSHandshake(client.identity, is_server=False)
            ch = hs.create_client_hello()
            cw = ByteWriter()
            cw.write_varint(int(TransportFrameType.CRYPTO))
            cw.write_varbytes(ch)
            tiny_initial = encode_long_packet(
                pkt_type=PacketType.INITIAL,
                dcid=secrets.token_bytes(8),
                scid=tiny_cid,
                channel_id=0,
                packet_number=1,
                payload=cw.to_bytes(),  # NO 1200-byte RFC 9000 padding!
            )
            client.endpoint._transmit_udp(tiny_initial, addr)
            await asyncio.sleep(0.1)
            server_conn = server.endpoint._initial_by_client_cid.get(tiny_cid)
            self.assertIsNotNone(server_conn)
            self.assertGreaterEqual(server_conn.anti_amplification_blocks, 1)
            self.assertLessEqual(
                server_conn.unvalidated_bytes_sent, 3 * server_conn.unvalidated_bytes_received
            )
        finally:
            await client.close()
            await server.stop()

    async def test_03_static_bep52_multi_peer_pex_push_and_pollution_ban(self) -> None:
        payload = os.urandom(16_384 * 4 + 3210)  # 5 BEP 52 leaf blocks
        manifest = b'{"pushed":true,"protocol":"h4"}'

        origin = HTTP4WIQCServer(authority="origin.http4.local")
        honest = HTTP4WIQCServer(authority="honest.http4.local")
        rogue = HTTP4WIQCServer(
            authority="rogue.http4.local",
            pollute_static_chunks={0, 1, 2, 3, 4},
        )
        res = origin.publish_static_resource(
            "/video.bin", payload, push_companion=("/manifest.json", manifest, "application/json")
        )
        honest.publish_static_resource("/video.bin", payload)
        rogue.publish_static_resource("/video.bin", payload)

        origin_addr = await origin.start()
        honest_addr = await honest.start()
        rogue_addr = await rogue.start()

        # Register honest seeder in Origin's PEX table for trackerless discovery
        origin.pex.register_peer(
            res.swarm_id, PeerEndpoint(honest_addr[0], honest_addr[1], honest.peer_id)
        )

        client = HTTP4WIQCClient(label="swarm-leecher")
        await client.start()
        try:
            s_origin = await client.connect(origin_addr)
            s_rogue = await client.connect(rogue_addr)

            # Verify BEP 52 Hash Wire Messages (21 -> 22) over Stream 0x41
            hresp = await client.query_bep52_hashes(
                s_origin, res.pieces_root, base_layer=0, index=0, length=4, proof_layers=1
            )
            self.assertTrue(StaticMerkleTree.verify_bep52_hashes(hresp, res.pieces_root))
            self.assertEqual(origin.bep52_hash_requests_served, 1)

            # Download static swarm across Origin + PEX-discovered Honest + Rogue seeder
            got_bytes, resp, _ = await client.download_static_swarm(
                primary_session=s_origin,
                path="/video.bin",
                origin_public_key=origin.identity.public_key,
                extra_sessions=[s_rogue],
                discover_via_pex=True,
            )
            self.assertEqual(got_bytes, payload)
            self.assertTrue(resp.origin_signature_verified)
            self.assertEqual(WIQCSwarmInfo.parse(resp.headers["wiqc-swarm-info"]).mode, "merkle-v2")
            self.assertEqual(parse_alt_svc(resp.headers["alt-svc"])[0].protocol_id, "h4")
            # Server Push received!
            self.assertGreaterEqual(len(resp.pushed_resources), 1)
            pushed_hdrs, pushed_body = next(iter(resp.pushed_resources.values()))
            self.assertEqual(pushed_hdrs[":status"], "200")
            self.assertEqual(pushed_body, manifest)
            # Rogue peer caught and banned!
            self.assertGreaterEqual(client.pollution_attacks_blocked, 1)
            self.assertTrue(client.reputation.is_banned(peer_id=rogue.peer_id))
        finally:
            await client.close()
            await origin.stop()
            await honest.stop()
            await rogue.stop()

    async def test_04_live_unified_merkle_relay_reseeding_and_live_pollution(self) -> None:
        origin = HTTP4WIQCServer(authority="live-origin.http4.local")
        live_ch = origin.create_live_channel("/live/concert", "video-av1", munro_layer=2)
        origin_addr = await origin.start()

        relay = HTTP4WIQCServer(authority="live-relay.http4.local")
        relay_ch = LiveSwarmChannel(
            track=live_ch.track, publisher_public_key=origin.identity.public_key, munro_layer=2
        )
        relay.register_relay_live_channel(relay_ch)
        relay_addr = await relay.start()

        # Also a rogue live relay that pollutes live chunks!
        rogue_live = HTTP4WIQCServer(
            authority="rogue-live.http4.local", pollute_live_chunks={0, 1, 2, 3}
        )
        rogue_live_ch = LiveSwarmChannel(
            track=live_ch.track, publisher_public_key=origin.identity.public_key, munro_layer=2
        )
        rogue_live.register_relay_live_channel(rogue_live_ch)
        rogue_live_addr = await rogue_live.start()

        relay_client = HTTP4WIQCClient(label="relay-ingester")
        viewer = HTTP4WIQCClient(label="downstream-viewer")
        victim_check = HTTP4WIQCClient(label="anti-pollution-viewer")
        await relay_client.start()
        await viewer.start()
        await victim_check.start()

        try:
            s_origin = await relay_client.connect(origin_addr)
            s_relay = await viewer.connect(relay_addr)
            s_rogue = await victim_check.connect(rogue_live_addr)

            downstream_chunks: list[int] = []
            rogue_accepted: list[int] = []
            done_ev = asyncio.Event()

            def on_downstream(vc, sid: int) -> None:
                downstream_chunks.append(vc.obj.chunk_index)
                if len(downstream_chunks) >= 4:
                    done_ev.set()

            await viewer.subscribe_live_swarm(
                s_relay, "/live/concert", relay.identity.public_key, on_verified_chunk=on_downstream
            )
            await victim_check.subscribe_live_swarm(
                s_rogue,
                "/live/concert",
                rogue_live.identity.public_key,
                on_verified_chunk=lambda vc, sid: rogue_accepted.append(vc.obj.chunk_index),
            )

            def on_origin(vc, sid: int) -> None:
                relay_ch.verified_chunks[vc.obj.chunk_index] = vc
                relay.reseed_verified_live_chunk("/live/concert", vc)
                rogue_live_ch.verified_chunks[vc.obj.chunk_index] = vc
                rogue_live.reseed_verified_live_chunk("/live/concert", vc)

            await relay_client.subscribe_live_swarm(
                s_origin, "/live/concert", origin.identity.public_key, on_verified_chunk=on_origin
            )

            grp = _build_live_group(0, live_ch.track, int(time.monotonic() * 1000))
            await origin.publish_and_broadcast_live_group("/live/concert", grp)
            await asyncio.wait_for(done_ev.wait(), timeout=3.0)
            await asyncio.sleep(0.1)

            # Honest downstream viewer received all 4 origin-verified chunks via relay!
            self.assertEqual(sorted(downstream_chunks), [0, 1, 2, 3])
            # Victim connected to rogue live relay accepted ZERO corrupted chunks and banned rogue!
            self.assertEqual(rogue_accepted, [])
            self.assertGreaterEqual(victim_check.pollution_attacks_blocked, 1)
            self.assertTrue(victim_check.reputation.is_banned(peer_id=rogue_live.peer_id))
        finally:
            await relay_client.close()
            await viewer.close()
            await victim_check.close()
            await origin.stop()
            await relay.stop()
            await rogue_live.stop()

    async def test_05_zero_head_of_line_blocking_across_subgroups(self) -> None:
        # Drop the first 2 packets of the SECOND Subgroup stream (Enhancement Layer)
        # while allowing Base Layer Subgroup stream to arrive immediately!
        fault = FaultInjectionProfile()
        origin = HTTP4WIQCServer(authority="hol.http4.local", fault_profile=fault)
        live_ch = origin.create_live_channel("/live/hol", "video-svc", munro_layer=2)
        origin_addr = await origin.start()

        client = HTTP4WIQCClient(label="hol-viewer")
        await client.start()
        try:
            sess = await client.connect(origin_addr)
            arrival_order: list[tuple[int, float]] = []
            all_done = asyncio.Event()

            def on_chunk(vc, sid: int) -> None:
                arrival_order.append((vc.obj.subgroup_id, time.monotonic()))
                if len(arrival_order) >= 4:
                    all_done.set()

            await client.subscribe_live_swarm(
                sess, "/live/hol", origin.identity.public_key, on_verified_chunk=on_chunk
            )

            # Predict exact server unidirectional stream IDs for Subgroup 0 & Subgroup 1:
            # Server opened 3 uni streams (3=Control, 7=QPACK Enc, 11=QPACK Dec), so
            # next two server uni streams are 15 (Subgroup 0 Base) and 19 (Subgroup 1 Enhancement)!
            server_sess = next(iter(origin.sessions.values()))
            next_uni = server_sess.conn._next_uni_stream_id
            subgroup_1_sid = next_uni + 4
            # Drop first 2 UDP packets of Enhancement Layer Subgroup 1!
            fault.drop_stream_counts[subgroup_1_sid] = 2

            grp = _build_live_group(0, live_ch.track, int(time.monotonic() * 1000))
            await origin.publish_and_broadcast_live_group("/live/hol", grp)
            await asyncio.wait_for(all_done.wait(), timeout=3.0)

            base_times = [t for sg, t in arrival_order if sg == 0]
            enh_times = [t for sg, t in arrival_order if sg == 1]
            self.assertEqual(len(base_times), 2)
            self.assertEqual(len(enh_times), 2)
            # Base layer MUST arrive strictly BEFORE Enhancement layer recovers from packet loss!
            self.assertLess(max(base_times), min(enh_times))
        finally:
            await client.close()
            await origin.stop()

    async def test_06_zero_rtt_idempotency_and_replay_protection(self) -> None:
        server = HTTP4WIQCServer(authority="0rtt.http4.local")
        server.publish_static_resource("/doc.txt", b"idempotent-http4-resource")
        addr = await server.start()

        client = HTTP4WIQCClient(label="0rtt-client")
        await client.start()
        try:
            # First 1-RTT connection acquires a 0-RTT resumption ticket
            s1 = await client.connect(addr)
            self.assertIn(addr, client.tickets)
            await s1.conn.close()

            # 1) Idempotent GET over 0-RTT MUST succeed
            s2, resp_get = await client.request_0rtt(addr, "GET", "/doc.txt")
            self.assertEqual(resp_get.status, 200)
            self.assertEqual(resp_get.headers.get("x-wiqc-0rtt"), "accepted")
            self.assertEqual(server.zero_rtt_accepted, 1)
            await s2.conn.close()

            # 2) Non-idempotent POST over 0-RTT MUST be blocked client-side
            with self.assertRaises(ReplayProtectionError):
                await client.request_0rtt(addr, "POST", "/echo")

            # 3) Even if a misbehaving client bypasses its guard, server MUST reject with 425!
            s3, resp_post = await client.request_0rtt(
                addr, "POST", "/echo", bypass_client_guard=True
            )
            self.assertEqual(resp_post.status, 425)
            self.assertEqual(server.zero_rtt_rejected, 1)
            await s3.conn.close()
        finally:
            await client.close()
            await server.stop()

    async def test_07_rfc9221_datagrams_and_rfc9297_capsules(self) -> None:
        server = HTTP4WIQCServer(authority="dgram.http4.local")
        addr = await server.start()
        client = HTTP4WIQCClient(label="dgram-client")
        await client.start()
        try:
            sess = await client.connect(addr)
            client.send_unreliable_datagram(sess, quarter_stream_id=3, payload=b"AUDIO-FRAME-42")
            await asyncio.sleep(0.1)
            self.assertIn((3, b"ECHO-DGRAM:AUDIO-FRAME-42"), client.datagrams_received)

            cap_reply = await client.send_capsule_datagram(sess, 9, b"INTERMEDIARY-MEDIA")
            self.assertEqual(cap_reply.quarter_stream_id, 9)
            self.assertEqual(cap_reply.payload, b"ACK-CAPSULE:INTERMEDIARY-MEDIA")
            self.assertEqual(len(server.capsules_received), 1)
        finally:
            await client.close()
            await server.stop()

    async def test_08_seamless_connection_migration(self) -> None:
        server = HTTP4WIQCServer(authority="mig.http4.local")
        server.publish_static_resource("/ping", b"survived-migration")
        addr = await server.start()
        client = HTTP4WIQCClient(label="mobile-peer")
        await client.start()
        new_ep = WIQCEndpoint(identity=client.identity, host="127.0.0.1", port=0)
        await new_ep.start()
        try:
            sess = await client.connect(addr)
            rtt_ms = await sess.conn.migrate_to_new_local_endpoint(new_ep)
            self.assertGreaterEqual(rtt_ms, 0.0)

            server_sess = next(iter(server.sessions.values()))
            self.assertGreaterEqual(server_sess.conn.migration_count, 1)
            self.assertEqual(server_sess.conn.remote_addr, new_ep.local_address)

            resp = await client.request(
                sess, "GET", "/ping", verify_origin_key=server.identity.public_key
            )
            self.assertEqual(resp.status, 200)
        finally:
            await new_ep.stop()
            await client.close()
            await server.stop()

    async def test_09_native_nat_traversal_simultaneous_hole_punching(self) -> None:
        relay = HTTP4WIQCServer(authority="nat-relay.http4.local")
        relay_addr = await relay.start()

        nat_a = SimulatedRestrictedNAT("NAT-A")
        nat_b = SimulatedRestrictedNAT("NAT-B")
        peer_a = HTTP4WIQCClient(label="peer-A", fault_profile=FaultInjectionProfile(nat_filter=nat_a))
        peer_b = HTTP4WIQCClient(label="peer-B", fault_profile=FaultInjectionProfile(nat_filter=nat_b))
        await peer_a.start()
        await peer_b.start()
        try:
            # Verify unsolicited direct packet from B to A is blocked by Cone NAT-A before punching!
            self.assertFalse(nat_a.filter_inbound(peer_b.address))

            sa = await peer_a.connect(relay_addr)
            sb = await peer_b.connect(relay_addr)
            self.assertEqual(sa.conn.nat.observed_external_address, peer_a.address)
            self.assertEqual(sb.conn.nat.observed_external_address, peer_b.address)

            direct_addr, rtt_ms = await peer_a.initiate_nat_hole_punch(
                sa, target_peer_id=peer_b.peer_id, timeout=3.0
            )
            self.assertEqual(direct_addr, peer_b.address)
            self.assertGreaterEqual(rtt_ms, 0.0)
            self.assertEqual(relay.nat_punches_coordinated, 1)
            self.assertIn(peer_b.address, nat_a.open_pinholes)
            self.assertIn(peer_a.address, nat_b.open_pinholes)
        finally:
            await peer_a.close()
            await peer_b.close()
            await relay.stop()

    async def test_10_fault_tolerance_packet_loss_garbage_and_peer_crash_failover(self) -> None:
        payload = os.urandom(16_384 * 3 + 1000)  # 4 BEP 52 blocks
        # 10% outbound UDP loss on surviving seeder!
        lossy_origin = HTTP4WIQCServer(
            authority="lossy-origin.http4.local",
            fault_profile=FaultInjectionProfile(drop_rate=0.10),
        )
        doomed_peer = HTTP4WIQCServer(authority="doomed-peer.http4.local")
        lossy_origin.publish_static_resource("/resilient.bin", payload)
        doomed_peer.publish_static_resource("/resilient.bin", payload)

        origin_addr = await lossy_origin.start()
        doomed_addr = await doomed_peer.start()

        # Bombard server with malformed/random UDP garbage packets (must never crash!)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for garbage in (b"", b"\x00\x01\x02", b"\x80" + os.urandom(20), os.urandom(64)):
                raw_sock.sendto(garbage, origin_addr)
        finally:
            raw_sock.close()
        await asyncio.sleep(0.05)
        self.assertGreaterEqual(lossy_origin.endpoint.malformed_datagrams_dropped, 3)

        client = HTTP4WIQCClient(label="resilient-client")
        await client.start()
        try:
            s_origin = await client.connect(origin_addr)
            s_doomed = await client.connect(doomed_addr)
            # Crash/kill doomed peer right after connecting to test mid-swarm failover!
            await doomed_peer.stop()

            got_bytes, resp, _ = await client.download_static_swarm(
                primary_session=s_origin,
                path="/resilient.bin",
                origin_public_key=lossy_origin.identity.public_key,
                extra_sessions=[s_doomed],
                discover_via_pex=False,
                timeout=10.0,
            )
            self.assertEqual(got_bytes, payload)
            self.assertTrue(resp.origin_signature_verified)
        finally:
            await client.close()
            await lossy_origin.stop()


if __name__ == "__main__":
    unittest.main()
