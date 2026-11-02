# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sweep's bound on the presence guard covers the request that takes it for the end.

A sweep that releases a session with a pending end completes the end itself
when the guard is free, and hands it to a thread of its own when another server
keeps the guard. It used to ask the question first (take the guard with the
sweep's bound and release it at once) and then run the end, whose own request
for the guard had no time limit. A server that took the guard between the two
held the sweep's thread for as long as it kept it, which the sweep promises not
to do. The bound is now carried by the end's own request, so there is no gap.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

STALE = "stale-session"
_SLACK_SECONDS = 3.0
#: How long the other server keeps the guard if the sweep does not return first.
_HOLD_SECONDS = 8.0


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions._ended_while_scanning.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


def _workspace_with_a_pending_end(root: Path) -> Path:
    sandbox = mark_session_workspace(root / STALE)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    then = time.time() - 3600
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    sessions._ended_while_scanning.add(STALE)
    return sandbox


def _take_the_guard_as_another_server(root: Path) -> Any:
    """Open the presence lock file and lock it, as a second server would."""
    registry = root / sessions.SCAN_PRESENCE_DIR
    registry.mkdir(exist_ok=True)
    handle = open(registry / sessions._SCAN_PRESENCE_LOCK, "a+b")
    sessions._lock_blocking(handle)
    return handle


@pytest.fixture
def another_server_takes_the_guard_once_it_is_released(
    root: Path, monkeypatch
) -> Iterator[Dict[str, Any]]:
    """The first request for the guard gets it and releases it; another server
    takes it right after and keeps it for ``_HOLD_SECONDS`` unless the test
    closes it sooner. A sweep that asks for the guard a second time, with no
    time limit, waits for that server."""
    taken: Dict[str, Any] = {}
    real_guard = sessions._scan_presence_guard

    @contextlib.contextmanager
    def guard(guard_root: Path, **kwargs: Any) -> Iterator[None]:
        with real_guard(guard_root, **kwargs):
            yield
        if "handle" not in taken:
            handle = _take_the_guard_as_another_server(guard_root)
            letting_go = threading.Timer(_HOLD_SECONDS, handle.close)
            letting_go.daemon = True
            letting_go.start()
            taken["handle"] = handle
            taken["timer"] = letting_go

    monkeypatch.setattr(sessions, "_scan_presence_guard", guard)
    try:
        yield taken
    finally:
        if "timer" in taken:
            taken["timer"].cancel()
        if "handle" in taken:
            taken["handle"].close()


def test_a_guard_taken_after_the_sweeps_first_ask_does_not_hold_the_sweep(
    root: Path, another_server_takes_the_guard_once_it_is_released
) -> None:
    sandbox = _workspace_with_a_pending_end(root)
    started = time.monotonic()

    # A cutoff in the past: the session was used after the sweep first read its
    # age, so the pass releases it without removing anything itself.
    removed = sessions._remove_if_still_stale(root, STALE, sandbox, 0.0)
    waited = time.monotonic() - started

    assert removed is False
    assert waited < sessions._SWEEP_LOCK_WAIT_SECONDS + _SLACK_SECONDS, (
        f"the sweep waited {waited:.1f} s for a guard another server took after "
        "the sweep had asked for it"
    )


def test_the_pending_end_is_complete_once_the_other_server_lets_go(
    root: Path, another_server_takes_the_guard_once_it_is_released
) -> None:
    sandbox = _workspace_with_a_pending_end(root)
    sessions._remove_if_still_stale(root, STALE, sandbox, 0.0)

    another_server_takes_the_guard_once_it_is_released["handle"].close()
    deadline = time.monotonic() + _SLACK_SECONDS * 2
    while sandbox.exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    assert not sandbox.exists(), "the pending end never completed"
    assert STALE not in sessions._ended_while_scanning


def test_a_bounded_end_that_meets_a_held_guard_raises_and_stays_pending(
    root: Path,
) -> None:
    """The bound is the end's own: a guard held for all of it raises, and the
    end is exactly as it was (marked pending, tree in place)."""
    sandbox = _workspace_with_a_pending_end(root)
    other_server = _take_the_guard_as_another_server(root)
    try:
        started = time.monotonic()
        with pytest.raises(sessions._PresenceLockHeld):
            sessions.end_session(STALE, guard_wait=0.2)
        waited = time.monotonic() - started
    finally:
        other_server.close()

    assert waited < _SLACK_SECONDS
    assert sandbox.is_dir()
    assert STALE in sessions._ended_while_scanning
