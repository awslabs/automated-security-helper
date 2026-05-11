# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``automated_security_helper.cli.mcp.sessions``.

Covers:

* ``get_or_create`` returns the same instance on repeated calls (so the
  per-session lock identity is preserved).
* ``disconnect`` removes the entry and rmtrees the workspace.
* The per-session lock prevents concurrent same-session scans (measured
  via a Barrier + holding-time check).
* Cross-session scans don't block each other (Barrier rendezvous succeeds
  even while both locks are held).
* ``workspace_root`` resolves correctly per session and lives under the
  registry's parent.
* ``__contains__`` / ``__len__`` track registry state.

All disk I/O is scoped to ``tmp_path``.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sessions import (
    MCPSession,
    MCPSessionRegistry,
    get_default_registry,
    reset_default_registry_for_tests,
)


@pytest.fixture
def registry(tmp_path: Path) -> MCPSessionRegistry:
    """A fresh registry rooted under tmp_path so all I/O stays scoped."""
    return MCPSessionRegistry(workspace_parent=tmp_path / "sessions")


class TestGetOrCreate:
    def test_returns_same_instance_on_repeat(self, registry: MCPSessionRegistry):
        s1 = registry.get_or_create("conn-a")
        s2 = registry.get_or_create("conn-a")
        assert s1 is s2

    def test_distinct_ids_get_distinct_sessions(
        self, registry: MCPSessionRegistry
    ):
        s1 = registry.get_or_create("conn-a")
        s2 = registry.get_or_create("conn-b")
        assert s1 is not s2
        assert s1.lock is not s2.lock

    def test_lock_identity_preserved_across_calls(
        self, registry: MCPSessionRegistry
    ):
        s1 = registry.get_or_create("conn-a")
        s2 = registry.get_or_create("conn-a")
        # Identical lock object — critical for serialization correctness.
        assert s1.lock is s2.lock


class TestWorkspaceRoot:
    def test_workspace_root_resolves_per_session(
        self, registry: MCPSessionRegistry, tmp_path: Path
    ):
        s_a = registry.get_or_create("conn-a")
        s_b = registry.get_or_create("conn-b")
        assert s_a.workspace_root != s_b.workspace_root
        assert s_a.workspace_root.exists()
        assert s_b.workspace_root.exists()
        # Both live under the registry's workspace_parent.
        parent = tmp_path / "sessions"
        assert s_a.workspace_root.parent == parent
        assert s_b.workspace_root.parent == parent

    def test_workspace_id_matches_session_id(
        self, registry: MCPSessionRegistry
    ):
        s = registry.get_or_create("conn-a")
        assert s.workspace_root.name == "conn-a"


class TestDisconnect:
    def test_disconnect_removes_from_registry(
        self, registry: MCPSessionRegistry
    ):
        registry.get_or_create("conn-a")
        assert "conn-a" in registry
        registry.disconnect("conn-a")
        assert "conn-a" not in registry

    def test_disconnect_rmtrees_workspace(self, registry: MCPSessionRegistry):
        s = registry.get_or_create("conn-a")
        # Drop a marker file in the workspace so we can detect the rmtree.
        marker = s.workspace_root / "marker.txt"
        marker.write_text("hello")
        assert marker.exists()
        registry.disconnect("conn-a")
        assert not s.workspace_root.exists()
        assert not marker.exists()

    def test_disconnect_unknown_id_is_noop(
        self, registry: MCPSessionRegistry
    ):
        # Must not raise.
        registry.disconnect("never-existed")
        assert len(registry) == 0

    def test_disconnect_idempotent(self, registry: MCPSessionRegistry):
        registry.get_or_create("conn-a")
        registry.disconnect("conn-a")
        registry.disconnect("conn-a")
        assert "conn-a" not in registry


class TestRegistryDunder:
    def test_len_tracks_population(self, registry: MCPSessionRegistry):
        assert len(registry) == 0
        registry.get_or_create("a")
        registry.get_or_create("b")
        assert len(registry) == 2
        registry.disconnect("a")
        assert len(registry) == 1

    def test_contains_after_create(self, registry: MCPSessionRegistry):
        assert "a" not in registry
        registry.get_or_create("a")
        assert "a" in registry


class TestPerSessionLockSerializesScans:
    """The single-session lock must serialize concurrent scans on the same id."""

    def test_lock_blocks_second_acquire_until_first_releases(
        self, registry: MCPSessionRegistry
    ):
        session = registry.get_or_create("conn-a")
        first_acquired = threading.Event()
        first_release = threading.Event()
        second_acquired = threading.Event()
        order: list[str] = []

        def first_scan() -> None:
            with session.lock:
                order.append("first-acquired")
                first_acquired.set()
                # Hold the lock until the test signals release.
                first_release.wait(timeout=2.0)
                order.append("first-releasing")

        def second_scan() -> None:
            # Wait until first has the lock so we test contention, not ordering.
            first_acquired.wait(timeout=2.0)
            with session.lock:
                order.append("second-acquired")
                second_acquired.set()

        t1 = threading.Thread(target=first_scan)
        t2 = threading.Thread(target=second_scan)
        t1.start()
        t2.start()

        # While first holds the lock, second must NOT have acquired.
        first_acquired.wait(timeout=2.0)
        assert second_acquired.wait(timeout=0.2) is False, (
            "second scan acquired the lock while first still held it — "
            "per-session serialization broken"
        )

        # Release first; second should now proceed.
        first_release.set()
        assert second_acquired.wait(timeout=2.0) is True

        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        assert order == [
            "first-acquired",
            "first-releasing",
            "second-acquired",
        ]

    def test_lock_serialization_observable_via_holding_time(
        self, registry: MCPSessionRegistry
    ):
        """If two threads each hold the lock for ~50ms, total wall time must be
        at least ~100ms — proving they did not run in parallel."""
        session = registry.get_or_create("conn-a")
        hold_seconds = 0.05

        def scan() -> None:
            with session.lock:
                time.sleep(hold_seconds)

        threads = [threading.Thread(target=scan) for _ in range(2)]
        start = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)
        elapsed = time.monotonic() - start
        # Two serial 50ms holds — give a generous lower bound to dodge timer
        # jitter on busy CI.
        assert elapsed >= 2 * hold_seconds * 0.9, (
            f"Expected at least {2 * hold_seconds * 0.9:.3f}s of "
            f"serialized work, observed {elapsed:.3f}s"
        )


class TestCrossSessionParallelism:
    """Distinct sessions hold distinct locks — they do not contend."""

    def test_two_sessions_can_hold_locks_simultaneously(
        self, registry: MCPSessionRegistry
    ):
        s_a = registry.get_or_create("conn-a")
        s_b = registry.get_or_create("conn-b")

        # Barrier of 2 — both threads must reach it while both holding their
        # respective locks. If the locks were shared, one thread would block
        # before reaching the barrier and the test would time out.
        barrier = threading.Barrier(parties=2, timeout=2.0)
        rendezvous_ok: list[bool] = []

        def hold_and_meet(session: MCPSession) -> None:
            with session.lock:
                try:
                    barrier.wait()
                    rendezvous_ok.append(True)
                except threading.BrokenBarrierError:
                    rendezvous_ok.append(False)

        t_a = threading.Thread(target=hold_and_meet, args=(s_a,))
        t_b = threading.Thread(target=hold_and_meet, args=(s_b,))
        t_a.start()
        t_b.start()
        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

        assert rendezvous_ok == [True, True], (
            "cross-session locks contended — sessions must not share a lock"
        )

    def test_parallel_holds_finish_in_one_hold_time(
        self, registry: MCPSessionRegistry
    ):
        """Two sessions, each holding for ~80ms — wall time must be roughly
        one hold (~80ms), not two (~160ms). Generous threshold for CI noise."""
        s_a = registry.get_or_create("conn-a")
        s_b = registry.get_or_create("conn-b")
        hold_seconds = 0.08

        def hold(session: MCPSession) -> None:
            with session.lock:
                time.sleep(hold_seconds)

        start = time.monotonic()
        t_a = threading.Thread(target=hold, args=(s_a,))
        t_b = threading.Thread(target=hold, args=(s_b,))
        t_a.start()
        t_b.start()
        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)
        elapsed = time.monotonic() - start

        # If they parallelized, elapsed ~= hold_seconds. Allow 1.5x to dodge
        # CI jitter — a serialized run would be ~2x and would fail this bound.
        assert elapsed < 1.5 * hold_seconds + 0.05, (
            f"Cross-session scans appear to have serialized: elapsed "
            f"{elapsed:.3f}s vs single-hold {hold_seconds:.3f}s"
        )


class TestDefaultRegistry:
    def test_singleton_returns_same_instance(self):
        reset_default_registry_for_tests()
        try:
            r1 = get_default_registry()
            r2 = get_default_registry()
            assert r1 is r2
        finally:
            reset_default_registry_for_tests()

    def test_reset_replaces_singleton(self):
        reset_default_registry_for_tests()
        try:
            r1 = get_default_registry()
            reset_default_registry_for_tests()
            r2 = get_default_registry()
            assert r1 is not r2
        finally:
            reset_default_registry_for_tests()


class TestSessionFieldDefaults:
    def test_optional_fields_default_to_none(
        self, registry: MCPSessionRegistry
    ):
        s = registry.get_or_create("conn-a")
        assert s.source_dir is None
        assert s.config is None
        assert s.profile_name is None
        assert s.patch_ops is None
        assert s.id == "conn-a"

    def test_created_at_is_set(self, registry: MCPSessionRegistry):
        s = registry.get_or_create("conn-a")
        assert s.created_at is not None
