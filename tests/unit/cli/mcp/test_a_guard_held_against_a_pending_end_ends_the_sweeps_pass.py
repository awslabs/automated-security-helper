# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A guard another server keeps against a pending end ends the sweep's pass.

The TTL sweep gives a presence guard another server holds about a second
(``_SWEEP_LOCK_WAIT_SECONDS``) and then stops: it removes nothing more this pass
and leaves the remaining sessions to the next one, so the request that set the
sweep off is not held up for as long as the other server keeps the guard. A
session the sweep released with its end pending is ended by the sweep through a
request for the guard that carries the same bound. When that request meets a
held guard the end is handed to a thread of its own, and the pass used to carry
on to the next stale session, whose end waited out a bound of its own: a pass
over k released sessions took about k seconds. The held guard now ends the pass
at the first session it is met by, as it does when it is met by a removal.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

FIRST = "stale-session-a"
SECOND = "stale-session-b"
#: A short bound, so a pass that waits it out once per session is still quick.
_BOUND_SECONDS = 0.2
_JOIN_SECONDS = 5.0
_THREAD_PREFIX = "ash-mcp-finish-ended-session-"


def _join_completion_threads() -> None:
    for thread in threading.enumerate():
        if thread.name.startswith(_THREAD_PREFIX):
            thread.join(_JOIN_SECONDS)


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sessions, "_SWEEP_LOCK_WAIT_SECONDS", _BOUND_SECONDS)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    sessions._completing_off_the_sweep.clear()
    yield workspace
    _join_completion_threads()
    sessions._ended_while_scanning.clear()
    sessions._completing_off_the_sweep.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


def _stale_workspace_with_a_pending_end(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    then = time.time() - 3600
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    sessions._ended_while_scanning.add(session_id)
    return sandbox


def _take_the_guard_as_another_server(root: Path) -> Any:
    """Open the presence lock file and lock it, as a second server would."""
    registry = root / sessions.SCAN_PRESENCE_DIR
    registry.mkdir(exist_ok=True)
    handle = open(registry / sessions._SCAN_PRESENCE_LOCK, "a+b")
    sessions._lock_blocking(handle)
    return handle


@pytest.fixture(autouse=True)
def the_removal_finds_each_session_used_again(monkeypatch) -> None:
    """The pass releases every session without removing it: its age, read again
    by the removal, is no longer past the cutoff. What is left is the end that
    was pending for it."""
    monkeypatch.setattr(
        sessions, "_remove_stale_session_state", lambda *args, **kwargs: False
    )


@pytest.fixture
def sweep_asks(monkeypatch) -> List[str]:
    """The sessions the sweep's own call asks to finish their end, with its bound.

    The completion thread calls ``finish_ended_session`` with no bound, so a
    call that carries ``guard_wait`` is the sweep's and no other.
    """
    asked: List[str] = []
    real_finish = sessions.finish_ended_session

    def recording(session_id: Any, **kwargs: Any) -> None:
        if "guard_wait" in kwargs:
            asked.append(session_id)
        real_finish(session_id, **kwargs)

    monkeypatch.setattr(sessions, "finish_ended_session", recording)
    return asked


@pytest.fixture
def another_server_takes_the_guard_after_the_passes_first_ask(
    root: Path, monkeypatch
) -> Iterator[Dict[str, Any]]:
    """The pass's own first request for the guard (before it looks at any
    session) gets it and releases it; another server takes it right after and
    keeps it until the test ends."""
    taken: Dict[str, Any] = {}
    real_guard = sessions._scan_presence_guard

    @contextlib.contextmanager
    def guard(guard_root: Path, **kwargs: Any) -> Iterator[None]:
        with real_guard(guard_root, **kwargs):
            yield
        if "handle" not in taken:
            taken["handle"] = _take_the_guard_as_another_server(guard_root)

    monkeypatch.setattr(sessions, "_scan_presence_guard", guard)
    try:
        yield taken
    finally:
        if "handle" in taken:
            taken["handle"].close()


def test_a_held_guard_ends_the_pass_at_the_first_session_it_meets(
    root: Path,
    sweep_asks: List[str],
    another_server_takes_the_guard_after_the_passes_first_ask,
) -> None:
    sandboxes = {
        session_id: _stale_workspace_with_a_pending_end(root, session_id)
        for session_id in (FIRST, SECOND)
    }

    removed = sessions.sweep_stale_workspaces(60.0)

    assert removed == []
    assert len(sweep_asks) == 1, (
        f"the pass went on to {sweep_asks} after the first session's end met a "
        "held guard, and each of those waits out a bound of its own"
    )
    assert len(sessions._completing_off_the_sweep) == 1, (
        sessions._completing_off_the_sweep
    )
    for session_id, sandbox in sandboxes.items():
        assert sandbox.is_dir(), f"{session_id} was removed under the held guard"
        assert session_id in sessions._ended_while_scanning


def test_a_free_guard_lets_the_pass_finish_every_pending_end(
    root: Path, sweep_asks: List[str]
) -> None:
    """The control: without the held guard nothing ends the pass early, so both
    ends are completed by the sweep's own calls."""
    sandboxes = {
        session_id: _stale_workspace_with_a_pending_end(root, session_id)
        for session_id in (FIRST, SECOND)
    }

    removed = sessions.sweep_stale_workspaces(60.0)

    assert removed == []
    assert sorted(sweep_asks) == [FIRST, SECOND]
    for session_id, sandbox in sandboxes.items():
        assert not sandbox.exists(), f"the end of {session_id} was not completed"
        assert session_id not in sessions._ended_while_scanning
