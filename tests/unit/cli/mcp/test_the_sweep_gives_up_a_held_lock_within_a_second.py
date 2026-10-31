# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep gives up the shared presence lock after about a second.

Servers that share one workspace root take a lock under the root before a
sweep removes a session. The MCP page says a sweep that cannot take that lock
within about a second, because another server holds it, removes nothing more
and leaves the remaining sessions to its next sweep, so another server cannot
hold up Ctrl-C or SIGTERM. The sweep took the lock with a blocking call that
waited for as long as the holder kept it: the request that set the sweep off
went unanswered, and an interrupt waited behind it, for the holder's whole life.

The sweep now asks for the lock for ``_SWEEP_LOCK_WAIT_SECONDS`` and gives up
with nothing removed. Registering a scan still waits for as long as it takes:
that is a different caller of the same guard.
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

#: Slack over the sweep's own bound for a loaded host. The sweep that still
#: waits for as long as it takes never returns while the holder lives, so the
#: bound this asserts is not a timing guess: it is finite against infinite.
_SLACK_SECONDS = 3.0


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


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
    """The sweep's lock file, held exclusively as another server would hold it.

    Held on a handle of this process's own: the lock calls the product uses
    refuse a second handle on the same file whoever opened it, so the sweep under
    test meets the same refusal it would meet from another process.
    """
    registry = root / sessions.SCAN_PRESENCE_DIR
    registry.mkdir(exist_ok=True)
    handle = open(registry / sessions._SCAN_PRESENCE_LOCK, "a+b")
    try:
        sessions._lock_blocking(handle)
        yield handle
    finally:
        handle.close()


def _sweep_in_the_background(ttl: float) -> tuple[threading.Thread, Dict[str, Any]]:
    result: Dict[str, Any] = {}

    def run() -> None:
        started = time.monotonic()
        try:
            result["removed"] = sessions.sweep_stale_workspaces(ttl)
        except BaseException as error:  # reported by the test
            result["error"] = error
        result["seconds"] = time.monotonic() - started

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def test_a_sweep_that_cannot_take_the_lock_returns_within_the_bound(
    root: Path, another_servers_lock: Any
) -> None:
    """With another server holding the lock, the sweep must return within about
    a second, having removed nothing; the stale workspace is left to the next
    sweep. The sweep that waited for as long as it takes never returned while
    the lock was held."""
    stale = _stale_workspace(root, STALE)

    sweeping, result = _sweep_in_the_background(ttl=1.0)
    sweeping.join(timeout=sessions._SWEEP_LOCK_WAIT_SECONDS + _SLACK_SECONDS)

    assert not sweeping.is_alive(), (
        "the sweep was still waiting for the lock another server holds "
        f"{sessions._SWEEP_LOCK_WAIT_SECONDS + _SLACK_SECONDS} s after it started"
    )
    assert "error" not in result, result
    assert result["removed"] == []
    assert stale.is_dir(), "the sweep removed a workspace without holding the lock"
    assert result["seconds"] >= sessions._SWEEP_LOCK_WAIT_SECONDS * 0.5, (
        "the sweep gave up before asking for the lock for about a second"
    )


def test_the_next_sweep_removes_the_workspace_once_the_lock_is_free(
    root: Path,
) -> None:
    """The control: the same stale workspace, the lock free, is removed."""
    stale = _stale_workspace(root, STALE)

    removed = sessions.sweep_stale_workspaces(1.0)

    assert removed == [STALE]
    assert not stale.exists()


def test_registering_a_scan_still_waits_for_the_lock(
    root: Path, another_servers_lock: Any
) -> None:
    """The bound is the sweep's alone: the guard a scan's registration takes
    waits for as long as it takes, so a scan never runs unregistered because a
    sibling held the lock for a second. Measured as the blocking guard still
    waiting past the sweep's bound, then returning once the holder releases it."""
    done = threading.Event()
    outcome: Dict[str, Any] = {}

    def take_the_guard_the_way_a_scan_does() -> None:
        # Recorded, as _sweep_in_the_background records: a guard that raised
        # (a timeout, a signature change) would otherwise pass the first wait
        # below and read as "did not take the lock once it was free".
        try:
            with sessions._scan_presence_guard(root):
                pass
        except BaseException as error:  # reported by the test
            outcome["error"] = error
        done.set()

    waiter = threading.Thread(target=take_the_guard_the_way_a_scan_does, daemon=True)
    waiter.start()
    assert not done.wait(sessions._SWEEP_LOCK_WAIT_SECONDS + 0.5), (
        "a scan's registration gave the lock up instead of waiting for it; "
        f"the guard raised {outcome.get('error')!r}"
        if "error" in outcome
        else "a scan's registration gave the lock up instead of waiting for it"
    )
    another_servers_lock.close()
    assert done.wait(_SLACK_SECONDS * 2), (
        "a scan's registration did not take the lock once it was free"
    )
    assert "error" not in outcome, outcome
