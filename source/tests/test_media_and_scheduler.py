"""
Unit tests for the MOQT Data Model (Track, Group, Subgroup, Object),
Live Discard Window eviction, and Hybrid Dual-Zone Swarm Scheduler
(Emergency EDF <150ms -> Lowest-RTT Peers vs Swarm Health Rarest-First).
"""

from __future__ import annotations

import unittest

from http4_wiqc.media import (
    ChunkRequirement,
    DualZoneSwarmScheduler,
    MediaGroup,
    MediaObject,
    PeerReputationManager,
    SchedulingZone,
    SwarmPeerState,
    TrackIdentifier,
)


class TestDualZoneSwarmScheduler(unittest.TestCase):
    def test_edf_emergency_zone_picks_earliest_deadline_and_lowest_rtt_peer(self) -> None:
        rep = PeerReputationManager()
        sched = DualZoneSwarmScheduler(
            live_discard_window_chunks=32,
            emergency_threshold_ms=150,
            max_inflight_per_peer=4,
            reputation=rep,
        )
        fast_peer = SwarmPeerState(b"A" * 32, ("10.0.0.1", 4433), smoothed_rtt_ms=10.0, available_chunks={0, 1, 2, 3})
        med_peer = SwarmPeerState(b"B" * 32, ("10.0.0.2", 4433), smoothed_rtt_ms=45.0, available_chunks={0, 1, 2, 3})
        choked_fast = SwarmPeerState(b"C" * 32, ("10.0.0.3", 4433), smoothed_rtt_ms=2.0, choked=True, available_chunks={0, 1})
        banned_fast = SwarmPeerState(b"D" * 32, ("10.0.0.4", 4433), smoothed_rtt_ms=1.0, available_chunks={0, 1})
        rep.ban_peer(banned_fast.peer_id, "pollution")

        for p in (fast_peer, med_peer, choked_fast, banned_fast):
            sched.register_peer(p)

        now = 10_000
        # Chunk 1 has an earlier deadline (50ms) than Chunk 0 (120ms); both are < 150ms (EDF zone!)
        sched.register_wanted_chunk(ChunkRequirement(0, 0, 0, deadline_ms=now + 120, priority_urgency=1))
        sched.register_wanted_chunk(ChunkRequirement(1, 0, 0, deadline_ms=now + 50, priority_urgency=0))

        batch = sched.schedule_next_batch(now_ms=now)
        self.assertEqual([d.chunk_index for d in batch], [1, 0])
        for d in batch:
            self.assertEqual(d.zone, SchedulingZone.EMERGENCY_EDF)
            # Must choose fast_peer (10ms), skipping choked_fast (2ms) and banned_fast (1ms)!
            self.assertEqual(d.peer_id, fast_peer.peer_id)

    def test_swarm_health_zone_picks_rarest_first_chunks(self) -> None:
        sched = DualZoneSwarmScheduler(live_discard_window_chunks=64, emergency_threshold_ms=150)
        p1 = SwarmPeerState(b"1" * 32, ("10.0.0.1", 4433), smoothed_rtt_ms=30.0, available_chunks={10, 11, 12})
        p2 = SwarmPeerState(b"2" * 32, ("10.0.0.2", 4433), smoothed_rtt_ms=30.0, available_chunks={10, 11})
        p3 = SwarmPeerState(b"3" * 32, ("10.0.0.3", 4433), smoothed_rtt_ms=30.0, available_chunks={10})
        for p in (p1, p2, p3):
            sched.register_peer(p)

        now = 20_000
        # All chunks are well ahead of emergency zone (>= 500ms away)
        # Rarity: chunk 12 (count=1), chunk 11 (count=2), chunk 10 (count=3)
        for idx in (10, 11, 12):
            sched.register_wanted_chunk(ChunkRequirement(idx, 2, 0, deadline_ms=now + 500 + idx, priority_urgency=3))

        batch = sched.schedule_next_batch(now_ms=now)
        self.assertEqual([d.chunk_index for d in batch], [12, 11, 10])
        self.assertTrue(all(d.zone == SchedulingZone.SWARM_HEALTH_RAREST_FIRST for d in batch))

    def test_live_discard_window_evicts_expired_chunks(self) -> None:
        sched = DualZoneSwarmScheduler(live_discard_window_chunks=4, emergency_threshold_ms=150)
        now = 5_000
        sched.register_wanted_chunk(ChunkRequirement(0, 0, 0, deadline_ms=now - 10, priority_urgency=0))
        sched.register_wanted_chunk(ChunkRequirement(1, 0, 0, deadline_ms=now + 400, priority_urgency=0))
        expired = sched.advance_playhead(new_playhead_chunk=1, now_ms=now)
        self.assertEqual(expired, [0])
        self.assertIn(0, sched.discarded_chunks)
        self.assertIn(1, sched.wanted_chunks)

    def test_moqt_hierarchy_ordering(self) -> None:
        track = TrackIdentifier("live.h4", "/stage1", "video-1080p")
        grp = MediaGroup(group_id=0, track=track, created_at_ms=1000)
        sg1 = grp.get_or_create_subgroup(1, priority_urgency=4, dependency_layer="enhancement")
        sg0 = grp.get_or_create_subgroup(0, priority_urgency=0, dependency_layer="base")
        sg1.add_object(MediaObject(0, 1, 0, chunk_index=2, payload=b"enh", playback_deadline_ms=1200))
        sg0.add_object(MediaObject(0, 0, 0, chunk_index=0, payload=b"idr", playback_deadline_ms=1100, is_keyframe=True))
        sg0.add_object(MediaObject(0, 0, 1, chunk_index=1, payload=b"p1", playback_deadline_ms=1150))
        self.assertEqual([o.chunk_index for o in grp.all_objects_ordered()], [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
