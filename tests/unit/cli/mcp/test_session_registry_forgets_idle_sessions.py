# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The session registry does not grow without bound on a stateless server.

A stateless HTTP server started with ``--trust-upstream-session-id`` sees a new
id per client and never sees a session end, and a session that delivered nothing
has no workspace directory for the TTL sweep to find. Once the map is large, the
registry forgets entries nobody has asked for lately and nothing runs on.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import (
    profile_registry,
    sessions,
    source_delivery,
)
from automated_security_helper.cli.mcp.sessions import MCPSession, MCPSessionRegistry
from automated_security_helper.config.ash_config import AshConfig

THRESHOLD = 8
LONG_AGO = 10_000.0


@pytest.fixture
def registry(tmp_path: Path, monkeypatch) -> MCPSessionRegistry:
    monkeypatch.setattr(sessions, "SESSION_MAP_EVICT_ABOVE", THRESHOLD, raising=False)
    return MCPSessionRegistry(workspace_parent=tmp_path / "sessions")


def _unused_for_a_long_time(session: MCPSession) -> MCPSession:
    session._last_handed_out = time.monotonic() - LONG_AGO
    return session


def _fill_with_idle_sessions(registry: MCPSessionRegistry, count: int) -> None:
    for i in range(count):
        _unused_for_a_long_time(registry.session_for(f"idle-{i}"))


def test_a_stream_of_new_ids_does_not_grow_the_map_without_bound(registry) -> None:
    for i in range(THRESHOLD * 5):
        _unused_for_a_long_time(registry.session_for(f"client-{i}"))

    assert len(registry) <= THRESHOLD


def test_the_newest_session_is_always_present(registry) -> None:
    _fill_with_idle_sessions(registry, THRESHOLD)

    newest = registry.session_for("newest")

    assert registry.get("newest") is newest


def test_nothing_is_forgotten_while_the_map_is_small(registry) -> None:
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("one-more")

    assert len(registry) == THRESHOLD


def test_a_session_handed_out_lately_is_kept(registry) -> None:
    _fill_with_idle_sessions(registry, THRESHOLD - 1)
    recent = registry.session_for("recent")

    registry.session_for("newest")

    assert registry.get("recent") is recent


def test_asking_for_a_session_again_keeps_it(registry) -> None:
    again = _unused_for_a_long_time(registry.session_for("again"))
    _fill_with_idle_sessions(registry, THRESHOLD - 1)
    assert registry.session_for("again") is again

    registry.session_for("newest")

    assert registry.get("again") is again


def test_a_session_with_a_claimed_scan_is_kept(registry) -> None:
    claimed = _unused_for_a_long_time(registry.session_for("claimed"))
    assert claimed.try_claim_scan()
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("claimed") is claimed


def test_a_session_with_a_counted_scan_is_kept(registry) -> None:
    counted = _unused_for_a_long_time(registry.session_for("counted"))
    assert counted.try_start_scan(1)
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("counted") is counted


def test_a_session_whose_lock_is_held_is_kept(registry) -> None:
    held = _unused_for_a_long_time(registry.session_for("held"))
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    with held.lock:
        registry.session_for("newest")

    assert registry.get("held") is held


def test_a_session_with_a_write_in_progress_is_kept(registry) -> None:
    writing = _unused_for_a_long_time(registry.session_for("writing"))
    assert writing.try_begin_write()
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("writing") is writing


@pytest.fixture
def clean_session_state():
    """Scrub the process-wide delivered-source and profile stores around a test."""
    profile_registry.clear_session_state()
    yield
    profile_registry.clear_session_state()
    for session_id in ("bound", "bound-profile"):
        source_delivery._drop_session_source_dir(session_id)


def test_a_session_with_a_delivered_source_is_kept(
    registry, tmp_path, clean_session_state
) -> None:
    bound = _unused_for_a_long_time(registry.session_for("bound"))
    source_delivery._set_session_source_dir("bound", tmp_path)
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("bound") is bound


def test_a_session_with_a_bound_profile_is_kept(registry, clean_session_state) -> None:
    bound = _unused_for_a_long_time(registry.session_for("bound-profile"))
    profile_registry.bind_session_config(
        "bound-profile", config=AshConfig(), profile_name="strict"
    )
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("bound-profile") is bound


def test_a_session_that_only_looked_up_its_profile_state_is_forgotten(
    registry, clean_session_state
) -> None:
    looked_up = _unused_for_a_long_time(registry.session_for("bound-profile"))
    profile_registry.get_session_state("bound-profile")
    _fill_with_idle_sessions(registry, THRESHOLD - 1)

    registry.session_for("newest")

    assert registry.get("bound-profile") is None
    assert looked_up is not registry.session_for("bound-profile")


def test_a_forgotten_id_comes_back_as_a_working_session(registry) -> None:
    _fill_with_idle_sessions(registry, THRESHOLD)
    registry.session_for("newest")

    returned = registry.session_for("idle-0")

    assert returned.try_claim_scan()
    returned.release_scan()
    with returned.lock:
        pass
