#!/usr/bin/env python3
"""
example.server.py — Runnable HTTP/4 over WIQC Server Demonstration
===================================================================

Implements an authoritative HTTP/4 over WIQC Origin Publisher + Seeder +
Live MOQT Streamer + Trackerless PEX Node + Native NAT Traversal Relay
conforming to `draft-enger-httpbis-http4-wiqc-00`.

Workflow Performed by This Server:
----------------------------------
1. Generates a deterministic or fresh decentralized Ed25519 `PeerIdentity` and
   self-signed X.509 v3 certificate carrying libp2p OID `1.3.6.1.4.1.53594.1.1`
   (zero centralized PKIX CA required!).
2. Publishes a multi-block static resource (`/assets/video-sample.bin`, 80 KiB =
   5 x 16 KiB BEP 52 SHA-256 Merkle leaf blocks) alongside an HTTP/4 Server Push
   companion (`/assets/manifest.json`).
3. Creates a live decentralized streaming track (`/live/stage1`, track `video-1080p`)
   using RFC 7574 CIPM 3 Unified Merkle Tree munro signing (`munro_layer = 2`,
   4 chunks per MOQT Group, split into Base Layer Subgroup 0 [priority u=0] and
   Enhancement Layer Subgroup 1 [priority u=4]).
4. Binds a UDP WIQC endpoint advertising ALPNs `"h4"` and `"wiqc"` and prints its
   RFC 9460 DNS `HTTPS`/`SVCB` record and `WIQC-Swarm-Info` ABNF header.
5. Periodically publishes live MOQT Groups to all subscribed HTTP/4 clients on
   dedicated unidirectional WIQC Subgroup Streams (`0x40`) — ensuring packet loss
   on Enhancement Layer streams never blocks Base Layer delivery.
6. Gracefully sends HTTP/4 `GOAWAY` (`0x07`) on Ctrl-C / shutdown.

Usage:
    py -3.15 example.server.py --host 127.0.0.1 --port 4433
    py -3.14 example.server.py --host 127.0.0.1 --port 4433 --deterministic-key
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import signal
import sys
import time
from pathlib import Path

# Ensure package import works whether invoked from repo root or elsewhere
sys.path.insert(0, str(Path(__file__).resolve().parent))

from http4_wiqc import (
    Ed25519PrivateKey,
    HTTP4WIQCServer,
    MediaGroup,
    MediaObject,
    PeerIdentity,
    WIQCSwarmInfo,
)

# Deterministic demo seed (ONLY for convenient local testing when --deterministic-key is set!)
DEMO_ORIGIN_SEED = hashlib.sha256(b"http4-wiqc-demo-origin-seed-v1").digest()


def build_demo_static_payload() -> bytes:
    """Create an 80 KiB static test asset (5 BEP 52 16 KiB leaf blocks)."""
    chunks = []
    for i in range(5):
        header = f"[HTTP/4-WIQC-STATIC-BLOCK-{i:02d}]".encode("ascii")
        pattern = bytes(((i * 37 + j) & 0xFF) for j in range(16_384 - len(header)))
        chunks.append(header + pattern)
    return b"".join(chunks)


def build_demo_live_group(group_id: int, track, base_time_ms: int) -> MediaGroup:
    """
    Construct one MOQT Group aligned to a 4-chunk Unified Merkle Tree munro subtree:
    - Subgroup 0 (Base Layer, RFC 9218 urgency u=0): IDR Keyframe + Base P-frame
    - Subgroup 1 (Enhancement Layer, urgency u=4): Enhancement delta frames
    Each Subgroup is transmitted on its own independent unidirectional WIQC stream (0x40)!
    """
    base_chunk = group_id * 4
    group = MediaGroup(group_id=group_id, track=track, created_at_ms=base_time_ms)

    sg_base = group.get_or_create_subgroup(
        subgroup_id=0, priority_urgency=0, dependency_layer="base-idr"
    )
    sg_base.add_object(
        MediaObject(
            group_id=group_id,
            subgroup_id=0,
            object_id=0,
            chunk_index=base_chunk + 0,
            payload=f"GROUP-{group_id}:BASE-IDR-KEYFRAME-PAYLOAD".encode("utf-8") + b"\x11" * 512,
            playback_deadline_ms=base_time_ms + 120,
            is_keyframe=True,
            priority_urgency=0,
        )
    )
    sg_base.add_object(
        MediaObject(
            group_id=group_id,
            subgroup_id=0,
            object_id=1,
            chunk_index=base_chunk + 1,
            payload=f"GROUP-{group_id}:BASE-PFRAME-PAYLOAD".encode("utf-8") + b"\x22" * 512,
            playback_deadline_ms=base_time_ms + 220,
            is_keyframe=False,
            priority_urgency=1,
        )
    )

    sg_enh = group.get_or_create_subgroup(
        subgroup_id=1, priority_urgency=4, dependency_layer="enhancement-4k"
    )
    sg_enh.add_object(
        MediaObject(
            group_id=group_id,
            subgroup_id=1,
            object_id=0,
            chunk_index=base_chunk + 2,
            payload=f"GROUP-{group_id}:ENHANCEMENT-L1-PAYLOAD".encode("utf-8") + b"\x33" * 512,
            playback_deadline_ms=base_time_ms + 280,
            is_keyframe=False,
            priority_urgency=4,
        )
    )
    sg_enh.add_object(
        MediaObject(
            group_id=group_id,
            subgroup_id=1,
            object_id=1,
            chunk_index=base_chunk + 3,
            payload=f"GROUP-{group_id}:ENHANCEMENT-L2-PAYLOAD".encode("utf-8") + b"\x44" * 512,
            playback_deadline_ms=base_time_ms + 340,
            is_keyframe=False,
            priority_urgency=5,
        )
    )
    return group


async def run_server(
    host: str,
    port: int,
    deterministic_key: bool,
    live_interval: float,
    max_live_groups: int,
) -> None:
    identity = (
        PeerIdentity(Ed25519PrivateKey(DEMO_ORIGIN_SEED), label="origin.http4.local")
        if deterministic_key
        else PeerIdentity.generate(label="origin.http4.local")
    )

    server = HTTP4WIQCServer(
        host=host,
        port=port,
        authority="origin.http4.local",
        identity=identity,
    )

    # 1. Publish static BEP 52 Merkle-backed HTTP/4 resource + Server Push manifest
    static_payload = build_demo_static_payload()
    manifest_bytes = json.dumps(
        {
            "protocol": "HTTP/4 over WIQC (draft-enger-httpbis-http4-wiqc-00)",
            "static_asset": "/assets/video-sample.bin",
            "live_track": "/live/stage1",
            "leaf_block_bytes": 16384,
        },
        indent=2,
    ).encode("utf-8")
    static_res = server.publish_static_resource(
        path="/assets/video-sample.bin",
        data=static_payload,
        content_type="application/octet-stream",
        push_companion=("/assets/manifest.json", manifest_bytes, "application/json"),
    )

    # 2. Publish live decentralized MOQT track backed by Unified Merkle Tree (CIPM 3)
    live_ch = server.create_live_channel(
        path="/live/stage1",
        track_name="video-1080p",
        munro_layer=2,
        live_discard_window=64,
    )

    bound_host, bound_port = await server.start()
    svcb = server.build_https_svcb_record()

    print("=" * 78)
    print(" HTTP/4 over WIQC Server Started (draft-enger-httpbis-http4-wiqc-00)")
    print("=" * 78)
    print(f" UDP Endpoint        : {bound_host}:{bound_port}")
    print(f" Peer ID (SHA-256)   : {server.peer_id.hex()}")
    print(f" Origin Public Key   : {server.identity.public_bytes.hex()}")
    print(f" RFC 9460 HTTPS RR   : {svcb.to_zone_text()}")
    print(
        f" Static Swarm Header : "
        f"{WIQCSwarmInfo(static_res.swarm_id, 'merkle-v2', chunk_addr='bin64').format()}"
    )
    print(
        f" Live Swarm Header   : "
        f"{WIQCSwarmInfo(live_ch.swarm_id, 'unified-live', window=64, chunk_addr='bin64').format()}"
    )
    print("-" * 78)
    print(
        f" Run client against this server:\n"
        f"   py -3.15 example.client.py --host {bound_host} --port {bound_port} "
        f"--origin-key {server.identity.public_bytes.hex()}"
    )
    print("=" * 78)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows ProactorEventLoop does not support signal handlers; KeyboardInterrupt handles it
            pass

    group_id = 0
    try:
        while not stop_event.is_set():
            if max_live_groups > 0 and group_id >= max_live_groups:
                break
            now_ms = int(time.monotonic() * 1000)
            grp = build_demo_live_group(group_id, live_ch.track, now_ms)
            signed_munro, chunks = await server.publish_and_broadcast_live_group(
                "/live/stage1", grp
            )
            print(
                f"[LIVE PUBLISH] group={group_id:03d} munro_bin={signed_munro.munro_bin} "
                f"munro_hash={signed_munro.munro_hash.hex()[:16]}... "
                f"subgroups=2 chunks={len(chunks)} active_peers={len(server.sessions)}"
            )
            group_id += 1
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=live_interval)
            except asyncio.TimeoutError:
                pass
    except KeyboardInterrupt:
        print("\n[SERVER] Shutdown requested via Ctrl-C...")
    finally:
        print("[SERVER] Sending HTTP/4 GOAWAY (0x07) and closing WIQC endpoint...")
        await server.stop()
        print("[SERVER] Clean shutdown complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HTTP/4 over WIQC Origin Publisher, Seeder & NAT Relay Server"
    )
    parser.add_argument("--host", default="127.0.0.1", help="UDP bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4433, help="UDP bind port (default: 4433)")
    parser.add_argument(
        "--deterministic-key",
        action="store_true",
        help="Use deterministic demo Ed25519 origin keypair for reproducible CLI testing",
    )
    parser.add_argument(
        "--live-interval",
        type=float,
        default=1.0,
        help="Seconds between published live MOQT groups (default: 1.0)",
    )
    parser.add_argument(
        "--max-live-groups",
        type=int,
        default=0,
        help="Stop automatically after N live groups (0 = run indefinitely)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug protocol logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        asyncio.run(
            run_server(
                host=args.host,
                port=args.port,
                deterministic_key=args.deterministic_key,
                live_interval=args.live_interval,
                max_live_groups=args.max_live_groups,
            )
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
