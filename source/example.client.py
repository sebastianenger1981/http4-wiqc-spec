#!/usr/bin/env python3
"""
example.client.py — Runnable HTTP/4 over WIQC Client & Full-Feature Swarm Demo
===============================================================================

Demonstrates EVERY proposed protocol feature of `draft-enger-httpbis-http4-wiqc-00`
using object-oriented Python 3.14 / 3.15 over real UDP sockets:

Modes:
------
1. **Self-Contained Full Swarm Demo (default, `--self-contained`)**:
   Spins up an Origin Server + Honest Relay Peer + Malicious Polluting Peer +
   Simulated Cone NAT Peers on localhost UDP and walks through all 10 protocol
   workflows live:
   - Workflow 1: Mutual TLS 1.3 with Self-Signed libp2p X.509 Certs (OID `1.3.6.1.4.1.53594.1.1`)
                 and ALPN `"h4"` negotiation + RFC 9460 `HTTPS`/`SVCB` discovery.
   - Workflow 2: Signed HTTP/4 Static Metadata (`RFC 9421` Signatures, `RFC 9530`
                 `Repr-Digest`, `Swarm-Root`, Section 7 ABNF `WIQC-Swarm-Info`) +
                 HTTP/4 Server Push (`PUSH_PROMISE` `0x05` + Push Stream `0x01`) +
                 QPACK sensitive-header side-channel protection.
   - Workflow 3: Trackerless Peer Exchange (`WIQC_PEX` `0x4104`) + BEP 52 Hash Wire
                 Messages (`21` HASH_REQUEST -> `22` HASHES) verification.
   - Workflow 4: Multi-Peer Static BEP 52 Swarm Download + **Stream Pollution Attack
                 Defense** (rogue peer corrupts a 16 KiB block -> client deterministically
                 detects SHA-256 Merkle mismatch, bans rogue peer, finishes cleanly from
                 honest peers!).
   - Workflow 5: 0-RTT Resumption Idempotency Enforcement (idempotent `GET` accepted;
                 non-idempotent `POST` blocked per Section 8.3!).
   - Workflow 6: Unreliable HTTP Datagrams (`RFC 9221`) & `DATAGRAM Capsule (0x00)`
                 (`RFC 9297`).
   - Workflow 7: Decentralized Real-Time Live Streaming (MOQT Track/Group/Subgroup/Object,
                 RFC 7574 CIPM 3 Unified Merkle Tree munro signatures, per-Subgroup `0x40`
                 streams, Relay Peer immediate verified re-seeding to downstream client).
   - Workflow 8: Dual-Zone Sliding Window Scheduler (Emergency EDF `<150ms` -> lowest-RTT
                 peer vs Swarm Health Rarest-First `>=150ms`).
   - Workflow 9: Seamless WIQC Connection Migration across UDP sockets (`PATH_CHALLENGE` /
                 `PATH_RESPONSE`).
   - Workflow 10: Native WIQC NAT Traversal (`OBSERVED_ADDRESS`, `ADD_ADDRESS`,
                  `PUNCH_REQUEST`, synchronized `PUNCH_ME_NOW` simultaneous UDP hole
                  punching through two simulated Address-Restricted Cone NATs!).

2. **Remote Server Mode (`--host 127.0.0.1 --port 4433 --origin-key <hex>`)**:
   Connects to a running `example.server.py` instance over UDP and exercises
   Mutual TLS, signed static BEP 52 download, Server Push, BEP 52 hash messages,
   0-RTT idempotency check, Datagrams, Capsules, and live Unified Merkle streaming.

Usage:
    py -3.15 example.client.py
    py -3.14 example.client.py --self-contained
    py -3.15 example.client.py --host 127.0.0.1 --port 4433 --origin-key <64-hex-chars>
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from http4_wiqc import (
    ChunkRequirement,
    DualZoneSwarmScheduler,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    FaultInjectionProfile,
    HTTP4WIQCClient,
    HTTP4WIQCServer,
    LiveSwarmChannel,
    MediaGroup,
    MediaObject,
    PeerEndpoint,
    PeerIdentity,
    SchedulingZone,
    SimulatedRestrictedNAT,
    StaticMerkleTree,
    SwarmPeerState,
    WIQCEndpoint,
    WIQCSwarmInfo,
    parse_alt_svc,
)

DEMO_ORIGIN_SEED = hashlib.sha256(b"http4-wiqc-demo-origin-seed-v1").digest()


def _make_static_bytes() -> bytes:
    return b"".join(
        f"[WIQC-BLOCK-{i:02d}]".encode("ascii") + bytes([(i + j) & 0xFF for j in range(16_384 - 15)])
        for i in range(5)
    )


def _make_live_group(group_id: int, track, now_ms: int) -> MediaGroup:
    base = group_id * 4
    grp = MediaGroup(group_id=group_id, track=track, created_at_ms=now_ms)
    sg0 = grp.get_or_create_subgroup(0, priority_urgency=0, dependency_layer="base-idr")
    sg0.add_object(MediaObject(group_id, 0, 0, base + 0, f"G{group_id}-IDR".encode() + b"A" * 256, now_ms + 90, True, 0))
    sg0.add_object(MediaObject(group_id, 0, 1, base + 1, f"G{group_id}-P1".encode() + b"B" * 256, now_ms + 180, False, 1))
    sg1 = grp.get_or_create_subgroup(1, priority_urgency=4, dependency_layer="enhancement")
    sg1.add_object(MediaObject(group_id, 1, 0, base + 2, f"G{group_id}-ENH1".encode() + b"C" * 256, now_ms + 240, False, 4))
    sg1.add_object(MediaObject(group_id, 1, 1, base + 3, f"G{group_id}-ENH2".encode() + b"D" * 256, now_ms + 300, False, 5))
    return grp


async def run_self_contained_demo() -> None:
    print("=" * 78)
    print(" HTTP/4 over WIQC — Self-Contained End-to-End Protocol MVP Demonstration")
    print(" Specification: draft-enger-httpbis-http4-wiqc-00")
    print(f" Python Runtime: {sys.version.split()[0]}")
    print("=" * 78)

    # Set up Origin Server, Honest Peer Seeder, and Malicious Polluting Peer
    origin = HTTP4WIQCServer(authority="origin.http4.local")
    honest_seeder = HTTP4WIQCServer(authority="seeder-honest.http4.local")
    rogue_seeder = HTTP4WIQCServer(
        authority="seeder-rogue.http4.local",
        pollute_static_chunks={0, 1, 2, 3, 4},  # Intentionally corrupts served 16 KiB blocks!
    )

    static_payload = _make_static_bytes()
    push_manifest = b'{"catalog":"http4-wiqc-v0","codecs":["av1","opus"]}'
    static_res = origin.publish_static_resource(
        path="/assets/video-sample.bin",
        data=static_payload,
        content_type="application/octet-stream",
        push_companion=("/assets/manifest.json", push_manifest, "application/json"),
    )
    honest_seeder.publish_static_resource("/assets/video-sample.bin", static_payload)
    rogue_seeder.publish_static_resource("/assets/video-sample.bin", static_payload)

    live_ch = origin.create_live_channel("/live/stage1", "video-1080p", munro_layer=2)

    origin_addr = await origin.start()
    honest_addr = await honest_seeder.start()
    rogue_addr = await rogue_seeder.start()

    # Register honest peer in Origin's trackerless PEX table
    origin.pex.register_peer(
        static_res.swarm_id,
        PeerEndpoint(host=honest_addr[0], port=honest_addr[1], peer_id=honest_seeder.peer_id),
    )

    client = HTTP4WIQCClient(label="subscriber-peer-1")
    await client.start()

    try:
        # ---------------------------------------------------------------------
        # WORKFLOW 1: Mutual TLS 1.3 (libp2p-tls) + ALPN "h4" + Discovery
        # ---------------------------------------------------------------------
        print("\n[Workflow 1] Mutual TLS 1.3 (Self-Signed X.509 + OID 1.3.6.1.4.1.53594.1.1)")
        origin_sess = await client.connect(origin_addr)
        rogue_sess = await client.connect(rogue_addr)
        svcb = origin.build_https_svcb_record()
        print(f"  -> Negotiated ALPN       : {origin_sess.conn.negotiated_alpn!r}")
        print(f"  -> Verified Server PeerID: {origin_sess.conn.peer_id.hex()[:24]}...")
        print(f"  -> Observed External UDP : {origin_sess.conn.nat.observed_external_address}")
        print(f"  -> RFC 9460 HTTPS Record : {svcb.to_zone_text()}")

        # ---------------------------------------------------------------------
        # WORKFLOW 2 & 3 & 4: Signed HTTP/4 + Server Push + PEX + BEP52 + Anti-Pollution
        # ---------------------------------------------------------------------
        print("\n[Workflow 2-4] Signed Metadata + Server Push + PEX + Multi-Peer BEP 52 Download")
        print("               (Includes Active Stream Pollution Attack from Rogue Peer!)")
        # Exercise BEP 52 Hash Wire Messages (21 -> 22) directly first
        h_resp = await client.query_bep52_hashes(
            origin_sess,
            pieces_root=static_res.pieces_root,
            base_layer=0,
            index=0,
            length=4,
            proof_layers=1,
        )
        assert StaticMerkleTree.verify_bep52_hashes(h_resp, static_res.pieces_root)
        print(f"  -> BEP 52 HASH_REQUEST(21)->HASHES(22) verified! ({len(h_resp.hashes)} hashes)")

        # Download static swarm concurrently across Origin, PEX-discovered Honest Peer, & Rogue Peer
        downloaded, resp, _ = await client.download_static_swarm(
            primary_session=origin_sess,
            path="/assets/video-sample.bin",
            origin_public_key=origin.identity.public_key,
            extra_sessions=[rogue_sess],
            discover_via_pex=True,
        )
        assert downloaded == static_payload
        alt_entries = parse_alt_svc(resp.headers["alt-svc"])
        parsed_info = WIQCSwarmInfo.parse(resp.headers["wiqc-swarm-info"])
        print(f"  -> HTTP/4 Status         : {resp.status} (RFC 9421 Origin Sig Verified={resp.origin_signature_verified})")
        print(f"  -> WIQC-Swarm-Info ABNF  : mode={parsed_info.mode}, chunk-addr={parsed_info.chunk_addr}")
        print(f"  -> Alt-Svc Upgrade       : {[e.format() for e in alt_entries]}")
        print(f"  -> Server Push Received  : {len(resp.pushed_resources)} promised resource(s)")
        print(f"  -> Downloaded Bytes      : {len(downloaded):,} bytes (SHA-256 100% verified)")
        print(f"  -> Pollution Attacks Cut : {client.pollution_attacks_blocked} (banned peers={len(client.reputation.banned_peers)})")

        # ---------------------------------------------------------------------
        # WORKFLOW 5: 0-RTT Idempotency & Replay Protection (Section 8.3)
        # ---------------------------------------------------------------------
        print("\n[Workflow 5] 0-RTT Resumption & Non-Idempotent Replay Protection")
        sess_0rtt, resp_0rtt = await client.request_0rtt(
            origin_addr, method="GET", path="/assets/video-sample.bin"
        )
        print(f"  -> Idempotent 0-RTT GET  : status={resp_0rtt.status} x-wiqc-0rtt={resp_0rtt.headers.get('x-wiqc-0rtt')}")
        sess_bad, resp_425 = await client.request_0rtt(
            origin_addr, method="POST", path="/echo", bypass_client_guard=True
        )
        print(f"  -> Non-Idempotent POST   : status={resp_425.status} ({resp_425.body.decode()})")
        await sess_0rtt.conn.close()
        await sess_bad.conn.close()

        # ---------------------------------------------------------------------
        # WORKFLOW 6: Unreliable HTTP Datagrams (RFC 9221) & Capsules (RFC 9297)
        # ---------------------------------------------------------------------
        print("\n[Workflow 6] RFC 9221 Unreliable Datagrams & RFC 9297 DATAGRAM Capsules")
        client.send_unreliable_datagram(origin_sess, quarter_stream_id=7, payload=b"LIVE-TELEMETRY-FRAME-01")
        await asyncio.sleep(0.08)
        cap_reply = await client.send_capsule_datagram(origin_sess, quarter_stream_id=7, payload=b"INTERMEDIARY-LOC-OBJ")
        print(f"  -> RFC 9221 Datagram Rx  : {client.datagrams_received[-1]}")
        print(f"  -> RFC 9297 Capsule Echo : qsid={cap_reply.quarter_stream_id} payload={cap_reply.payload!r}")

        # ---------------------------------------------------------------------
        # WORKFLOW 7: Live MOQT Streaming (Unified Merkle Tree) + Relay Re-Seeding
        # ---------------------------------------------------------------------
        print("\n[Workflow 7] Live Decentralized Streaming (Unified Merkle Tree + Relay Re-Seed)")
        relay_server = HTTP4WIQCServer(authority="relay-peer.http4.local")
        relay_channel = LiveSwarmChannel(
            track=live_ch.track,
            publisher_public_key=origin.identity.public_key,
            munro_layer=2,
            live_discard_window=64,
        )
        relay_server.register_relay_live_channel(relay_channel)
        relay_addr = await relay_server.start()

        downstream_client = HTTP4WIQCClient(label="downstream-viewer-peer-2")
        await downstream_client.start()
        downstream_sess = await downstream_client.connect(relay_addr)

        downstream_received: list[int] = []
        await downstream_client.subscribe_live_swarm(
            downstream_sess,
            path="/live/stage1",
            origin_public_key=relay_server.identity.public_key,
            on_verified_chunk=lambda vc, sid: downstream_received.append(vc.obj.chunk_index),
        )

        # Primary client subscribes to Origin AND immediately re-seeds verified chunks through relay_server!
        primary_received: list[tuple[int, int]] = []

        def on_origin_chunk(vc, stream_id: int) -> None:
            primary_received.append((vc.obj.subgroup_id, vc.obj.chunk_index))
            relay_channel.verified_chunks[vc.obj.chunk_index] = vc
            relay_server.reseed_verified_live_chunk("/live/stage1", vc)

        await client.subscribe_live_swarm(
            origin_sess,
            path="/live/stage1",
            origin_public_key=origin.identity.public_key,
            on_verified_chunk=on_origin_chunk,
        )
        grp0 = _make_live_group(0, live_ch.track, int(time.monotonic() * 1000))
        munro0, _ = await origin.publish_and_broadcast_live_group("/live/stage1", grp0)
        await asyncio.sleep(0.2)
        print(f"  -> Origin Munro Signed   : bin={munro0.munro_bin} hash={munro0.munro_hash.hex()[:16]}...")
        print(f"  -> Relay Verified Chunks : {primary_received} (each Subgroup on separate 0x40 stream)")
        print(f"  -> Downstream Re-Seeded  : chunk indices {sorted(downstream_received)} verified against Origin PubKey!")
        await downstream_client.close()
        await relay_server.stop()

        # ---------------------------------------------------------------------
        # WORKFLOW 8: Dual-Zone Sliding Window Scheduler (EDF <150ms + Rarest-First)
        # ---------------------------------------------------------------------
        print("\n[Workflow 8] Dual-Zone Sliding Window Scheduler (EDF vs Rarest-First)")
        sched = DualZoneSwarmScheduler(live_discard_window_chunks=32, emergency_threshold_ms=150)
        fast_peer = SwarmPeerState(b"P" * 32, ("10.0.0.1", 4433), smoothed_rtt_ms=12.0, available_chunks={0, 1, 2, 3})
        slow_peer = SwarmPeerState(b"Q" * 32, ("10.0.0.2", 4433), smoothed_rtt_ms=95.0, available_chunks={0, 1, 2})
        sched.register_peer(fast_peer)
        sched.register_peer(slow_peer)
        now_ms = 10_000
        sched.register_wanted_chunk(ChunkRequirement(0, 0, 0, deadline_ms=now_ms + 80, priority_urgency=0))
        sched.register_wanted_chunk(ChunkRequirement(2, 0, 1, deadline_ms=now_ms + 600, priority_urgency=3))
        sched.register_wanted_chunk(ChunkRequirement(3, 0, 1, deadline_ms=now_ms + 650, priority_urgency=3))
        batch = sched.schedule_next_batch(now_ms=now_ms)
        for d in batch:
            print(
                f"  -> chunk={d.chunk_index} zone={d.zone.value:26s} "
                f"peer_rtt={d.peer_rtt_ms:4.1f}ms rarity={d.rarity_count}"
            )
        assert batch[0].zone == SchedulingZone.EMERGENCY_EDF and batch[0].peer_rtt_ms == 12.0
        assert batch[1].zone == SchedulingZone.SWARM_HEALTH_RAREST_FIRST and batch[1].chunk_index == 3

        # ---------------------------------------------------------------------
        # WORKFLOW 9: Seamless Connection Migration across UDP Sockets
        # ---------------------------------------------------------------------
        print("\n[Workflow 9] WIQC Seamless Connection Migration (DCID Preservation + PATH_CHALLENGE)")
        new_ep = WIQCEndpoint(identity=client.identity, host="127.0.0.1", port=0)
        new_addr = await new_ep.start()
        old_addr = client.address
        mig_rtt = await origin_sess.conn.migrate_to_new_local_endpoint(new_ep)
        post_mig = await client.request(origin_sess, "GET", "/assets/video-sample.bin", verify_origin_key=origin.identity.public_key)
        assert post_mig.status == 200
        print(f"  -> Migrated Socket       : {old_addr} -> {new_addr} (validated RTT={mig_rtt:.2f}ms)")
        print(f"  -> Post-Migration GET    : status={post_mig.status} (zero reconnect handshake!)")
        await new_ep.stop()

        # ---------------------------------------------------------------------
        # WORKFLOW 10: Native WIQC NAT Traversal (Simultaneous UDP Hole Punching)
        # ---------------------------------------------------------------------
        print("\n[Workflow 10] Native WIQC NAT Traversal (Two Simulated Cone NATs + Relay)")
        nat_a = SimulatedRestrictedNAT("NAT-A")
        nat_b = SimulatedRestrictedNAT("NAT-B")
        peer_a = HTTP4WIQCClient(label="nat-peer-A", fault_profile=FaultInjectionProfile(nat_filter=nat_a))
        peer_b = HTTP4WIQCClient(label="nat-peer-B", fault_profile=FaultInjectionProfile(nat_filter=nat_b))
        await peer_a.start()
        await peer_b.start()

        # Both NAT'd peers connect to Origin Relay (which informs each of OBSERVED_ADDRESS)
        sa = await peer_a.connect(origin_addr)
        sb = await peer_b.connect(origin_addr)
        # Peer A requests Relay to coordinate PUNCH_ME_NOW with Peer B!
        direct_addr, direct_rtt = await peer_a.initiate_nat_hole_punch(sa, target_peer_id=peer_b.peer_id)
        print(f"  -> Relay Coordinated     : {origin.nat_punches_coordinated} simultaneous punch round(s)")
        print(f"  -> Direct P2P Validated  : Peer A <-> {direct_addr} (RTT={direct_rtt:.2f}ms)")
        print(f"  -> Cone NAT Pinholes Open: NAT-A={len(nat_a.open_pinholes)}, NAT-B={len(nat_b.open_pinholes)}")
        await peer_a.close()
        await peer_b.close()

        print("\n" + "=" * 78)
        print(" ALL 10 HTTP/4 OVER WIQC PROTOCOL WORKFLOWS SUCCEEDED!")
        print("=" * 78)

    finally:
        await client.close()
        await origin.stop()
        await honest_seeder.stop()
        await rogue_seeder.stop()


async def run_remote_client(host: str, port: int, origin_key_hex: str) -> None:
    origin_pub = Ed25519PublicKey(bytes.fromhex(origin_key_hex))
    client = HTTP4WIQCClient(label="cli-http4-client")
    await client.start()
    try:
        print(f"[CLIENT] Connecting via Mutual TLS 1.3 (ALPN h4) to {host}:{port}...")
        sess = await client.connect((host, port))
        print(f"[CLIENT] Connected! ALPN={sess.conn.negotiated_alpn!r} PeerID={sess.conn.peer_id.hex()[:20]}...")

        print("[CLIENT] Downloading static BEP 52 Merkle swarm /assets/video-sample.bin...")
        data, resp, _ = await client.download_static_swarm(
            primary_session=sess,
            path="/assets/video-sample.bin",
            origin_public_key=origin_pub,
            discover_via_pex=True,
        )
        print(f"[CLIENT] Verified {len(data):,} bytes (RFC 9421 verified={resp.origin_signature_verified}, pushes={len(resp.pushed_resources)})")

        print("[CLIENT] Sending RFC 9221 Datagram & RFC 9297 Capsule...")
        client.send_unreliable_datagram(sess, 1, b"HELLO-WIQC-DATAGRAM")
        cap = await client.send_capsule_datagram(sess, 1, b"HELLO-WIQC-CAPSULE")
        print(f"[CLIENT] Capsule reply: {cap.payload!r}")

        print("[CLIENT] Subscribing to live Unified Merkle stream /live/stage1 for 3 seconds...")
        received_count = 0

        def on_live(vc, stream_id: int) -> None:
            nonlocal received_count
            received_count += 1
            print(
                f"  [LIVE VERIFIED] stream=0x{stream_id:x} group={vc.obj.group_id} "
                f"subgroup={vc.obj.subgroup_id} chunk={vc.obj.chunk_index} "
                f"keyframe={vc.obj.is_keyframe} bytes={len(vc.obj.payload)}"
            )

        await client.subscribe_live_swarm(
            sess, path="/live/stage1", origin_public_key=origin_pub, on_verified_chunk=on_live
        )
        await asyncio.sleep(3.0)
        print(f"[CLIENT] Total live verified chunks received: {received_count}")
    finally:
        await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP/4 over WIQC Client & Full Feature Demo")
    parser.add_argument("--self-contained", action="store_true", help="Run full local multi-peer demo")
    parser.add_argument("--host", default=None, help="Remote example.server.py host")
    parser.add_argument("--port", type=int, default=4433, help="Remote example.server.py port")
    parser.add_argument(
        "--origin-key",
        default=Ed25519PrivateKey(DEMO_ORIGIN_SEED).public_bytes.hex(),
        help="Hex-encoded 32-byte Ed25519 origin public key (defaults to --deterministic-key server key)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.host and not args.self_contained:
        asyncio.run(run_remote_client(args.host, args.port, args.origin_key))
    else:
        asyncio.run(run_self_contained_demo())


if __name__ == "__main__":
    main()
