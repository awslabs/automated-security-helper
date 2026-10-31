# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pending end the sweep could not complete is completed off the sweep.

``end_session`` marks the session's end pending before it tries the session's
change; an end refused because the TTL sweep held that change stays pending, and
``_remove_if_still_stale`` completes it with ``finish_ended_session`` once the
sweep releases the session. When another server holds the presence guard for the
whole bounded wait, ``_remove_stale_session_state`` raises ``_PresenceLockHeld``
past that call: the sweep ends its pass, as the page promises, and nothing in
this process completed the end before the next sweep found the workspace stale
again, a whole TTL later when the ending request had touched it. The session's
bound profile, delivered-source record and workspace stayed that long.

The sweep now completes such an end on a thread of its own, which waits for the
guard as the ending request would have, and still raises, so its own pass ends
within the bound. An end that is not pending starts no thread.
"""

from __future__ import annotations

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


def _stale_workspace(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    then = time.time() - 3600
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    return sandbox


@pytest.fixture
def another_servers_lock(root: Path) -> Iterator[Any]:
    """The presence lock file, held as another server would hold it."""
    registry = root / sessions.SCAN_PRESENCE_DIR
    registry.mkdir(exist_ok=True)
    handle = open(registry / sessions._SCAN_PRESENCE_LOCK, "a+b")
    try:
        sessions._lock_blocking(handle)
        yield handle
    finally:
        handle.close()


@pytest.fixture
def held_lock_at_the_removal(monkeypatch) -> None:
    """``_remove_stale_session_state`` meeting the held guard, in one step."""

    def held(root: Path, session_id: str, sandbox: Path, cutoff: float) -> bool:
        raise sessions._PresenceLockHeld

    monkeypatch.setattr(sessions, "_remove_stale_session_state", held)


@pytest.fixture
def finishing(monkeypatch) -> Dict[str, Any]:
    """``finish_ended_session`` stood in for: records its caller's thread."""
    seen: Dict[str, Any] = {"done": threading.Event(), "threads": []}

    def record(session_id: str) -> None:
        seen["threads"].append((session_id, threading.current_thread()))
        seen["done"].set()

    monkeypatch.setattr(sessions, "finish_ended_session", record)
    return seen


def test_a_pending_end_is_completed_off_the_sweep_when_the_guard_is_held(
    root: Path, held_lock_at_the_removal, finishing
) -> None:
    sandbox = _stale_workspace(root, STALE)
    sessions._ended_while_scanning.add(STALE)

    with pytest.raises(sessions._PresenceLockHeld):
        sessions._remove_if_still_stale(root, STALE, sandbox, time.time() - 1.0)

    assert finishing["done"].wait(_SLACK_SECONDS), (
        "the pending end was left for the next sweep that finds the workspace stale"
    )
    (ended, thread), *rest = finishing["threads"]
    assert rest == []
    assert ended == STALE
    assert thread is not threading.main_thread(), (
        "the end was completed on the sweep's own thread, which the held guard "
        "would hold for as long as the other server keeps it"
    )


def test_an_end_that_is_not_pending_starts_nothing(
    root: Path, held_lock_at_the_removal, finishing
) -> None:
    """The control: no end_session was refused for this session, so the held
    guard ends the pass and nothing else happens."""
    sandbox = _stale_workspace(root, STALE)

    with pytest.raises(sessions._PresenceLockHeld):
        sessions._remove_if_still_stale(root, STALE, sandbox, time.time() - 1.0)

    assert not finishing["done"].wait(0.5)
    assert finishing["threads"] == []


def test_the_pending_end_removes_the_workspace_once_the_other_server_lets_go(
    root: Path, another_servers_lock: Any
) -> None:
    """The real path: the guard held on a second handle, the sweep's removal
    gives up within its bound and raises; the end completes on its thread once
    the handle closes, and the workspace, the one end_session would have
    removed, is gone."""
    sandbox = _stale_workspace(root, STALE)
    sessions._ended_while_scanning.add(STALE)
    started = time.monotonic()

    with pytest.raises(sessions._PresenceLockHeld):
        sessions._remove_if_still_stale(root, STALE, sandbox, time.time() - 1.0)
    waited = time.monotonic() - started
    assert waited < sessions._SWEEP_LOCK_WAIT_SECONDS + _SLACK_SECONDS, (
        "the sweep waited past its bound for the held guard"
    )
    assert sandbox.is_dir(), "the end completed while the other server held the guard"

    another_servers_lock.close()
    deadline = time.monotonic() + _SLACK_SECONDS * 2
    while sandbox.exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    assert not sandbox.exists(), (
        "the pending end never completed once the guard was free"
    )
    assert STALE not in sessions._ended_while_scanning
