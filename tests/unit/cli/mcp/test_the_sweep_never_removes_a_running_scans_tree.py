# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep skips a session whose scan is running, in any server sharing the root.

``sweep_stale_workspaces`` removes session workspaces nobody used for longer than
the TTL. It must never remove one a running scan reads:

- In this process, a scan holds the session's claim or lock. The sweep takes the
  session's change (``MCPSession.try_begin_change``) and skips the session when
  that is refused. It does not queue the removal for when the scan returns, which
  would remove the tree and the results the scan just wrote. It reads the age
  again while holding the change, so a session used meanwhile is kept too.
- Another server sharing the root can't see this process's claim. A running scan
  therefore also holds a locked entry under ``<root>/.ash-mcp-scans/<session id>/``
  (``sessions.ScanPresence``), and every sweep skips a session with a live entry.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, KillAfter

DAY = 24 * 3600


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()


def _age(sandbox: Path, seconds: float) -> None:
    stamp = time.time() - seconds
    for path in [*sandbox.rglob("*"), sandbox]:
        os.utime(path, (stamp, stamp))


def _sandbox(root: Path, session_id: str, age: float = 400 * DAY) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    _age(sandbox, age)
    return sandbox


@pytest.mark.parametrize("hold", ["claim", "lock"])
def test_a_session_whose_scan_runs_is_skipped_not_queued(root, hold) -> None:
    sandbox = _sandbox(root, "busy")
    session = sessions.get_default_registry().session_for("busy")

    if hold == "claim":
        assert session.try_claim_scan()
        removed = sessions.sweep_stale_workspaces(DAY)
        session.release_scan()
    else:
        with session.lock:
            removed = sessions.sweep_stale_workspaces(DAY)
    # What a scan does when it returns.
    sessions.finish_ended_session("busy")

    assert removed == []
    assert (sandbox / "source" / "app.py").is_file(), (
        "the sweep queued the removal, and it ran when the scan returned"
    )


def test_a_delivery_that_starts_during_the_sweep_keeps_its_tree(
    root, monkeypatch
) -> None:
    """The delivery takes the session after the sweep read it as unused."""
    sandbox = _sandbox(root, "racing")
    real_last_used = sessions._last_used
    delivery = contextlib.ExitStack()

    def last_used(path):
        stamp = real_last_used(path)
        if path.name == "racing" and not delivery._exit_callbacks:
            delivery.enter_context(sd._no_scan_running("racing"))
        return stamp

    monkeypatch.setattr(sessions, "_last_used", last_used)

    removed = sessions.sweep_stale_workspaces(DAY)
    delivery.close()  # the delivery returns

    assert removed == []
    assert (sandbox / "source" / "app.py").is_file()


def test_a_session_used_after_the_sweep_read_its_age_is_kept(root, monkeypatch) -> None:
    """The age is read again while the sweep holds the session."""
    sandbox = _sandbox(root, "touched")
    real_last_used = sessions._last_used
    calls = []

    def last_used(path):
        stamp = real_last_used(path)
        if path.name == "touched" and not calls:
            calls.append(stamp)
            sessions.touch_session_workspace("touched")  # a request arrives
        return stamp

    monkeypatch.setattr(sessions, "_last_used", last_used)

    removed = sessions.sweep_stale_workspaces(DAY)

    assert removed == []
    assert (sandbox / "source" / "app.py").is_file()


def test_a_stale_session_nobody_holds_is_still_removed(root) -> None:
    sandbox = _sandbox(root, "stale")

    assert sessions.sweep_stale_workspaces(DAY) == ["stale"]
    assert not sandbox.exists()


_HOLDER = """
import sys
from automated_security_helper.cli.mcp.sessions import ScanPresence
with ScanPresence(sys.argv[1]):
    print("held", flush=True)
    sys.stdin.readline()
"""


@contextlib.contextmanager
def _scan_in_another_process(root: Path, session_id: str):
    env = dict(os.environ, ASH_MCP_WORKSPACE_ROOT=str(root))
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, session_id],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        # readline() and read() block until the child writes or exits; the kill
        # ends one that does neither.
        with KillAfter(child, "the process holding the scan presence"):
            line = child.stdout.readline()
            assert line.strip() == "held", child.stderr.read()
            yield
    finally:
        if child.stdin:
            child.stdin.close()
        try:
            child.wait(timeout=CHILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=CHILD_TIMEOUT_SECONDS)
            raise


def test_a_scan_in_another_server_keeps_its_tree(root) -> None:
    sandbox = _sandbox(root, "elsewhere")

    with _scan_in_another_process(root, "elsewhere"):
        removed_during = sessions.sweep_stale_workspaces(DAY)
        kept = (sandbox / "source" / "app.py").is_file()
    _age(sandbox, 400 * DAY)
    removed_after = sessions.sweep_stale_workspaces(DAY)

    assert removed_during == [] and kept, "another server's running scan was swept"
    assert removed_after == ["elsewhere"], "the sweep never removed it afterwards"
    assert not sandbox.exists()


def test_a_presence_left_by_a_server_that_died_does_not_hold(root) -> None:
    sandbox = _sandbox(root, "orphaned")
    holder = root / sessions.SCAN_PRESENCE_DIR / "orphaned"
    holder.mkdir(parents=True)
    (holder / "12345-deadbeef").write_bytes(b"")

    assert sessions.sweep_stale_workspaces(DAY) == ["orphaned"]
    assert not sandbox.exists()


def test_a_presence_is_registered_only_for_a_session_with_a_workspace(root) -> None:
    with sessions.ScanPresence("nothing-delivered"):
        made = sorted(p.name for p in root.iterdir())

    assert made == []


def test_the_presence_directory_is_no_session(root) -> None:
    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    assert is_reserved_session_id(sessions.SCAN_PRESENCE_DIR)
    assert is_reserved_session_id(sessions.SCAN_PRESENCE_DIR.upper())


def test_run_ash_scan_holds_a_presence_while_its_scan_runs(
    root, tmp_path, monkeypatch
) -> None:
    import asyncio

    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    _sandbox(root, "holder", age=0)
    project = root / "holder" / "source"
    started, release = threading.Event(), threading.Event()
    seen = {}

    def run_ash_scan(**kwargs):
        started.set()
        release.wait(30)
        return None

    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
        run_ash_scan,
    )

    async def main():
        result = await mcp_scan_directory(
            directory_path=str(project), session_id="holder"
        )
        assert result.get("success") is True, result
        await asyncio.to_thread(started.wait, 30)
        seen["during"] = await asyncio.to_thread(sessions.scan_presence_held, "holder")
        release.set()
        others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*others)
        seen["after"] = sessions.scan_presence_held("holder")

    asyncio.run(main())

    assert seen == {"during": True, "after": False}
