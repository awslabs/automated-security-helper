# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``end_session`` leaves the tree a scan in another server sharing the root is reading.

A scan holds its session's claim in the process that runs it, and a locked entry
under ``<root>/.ash-mcp-scans/<session id>/`` for every server sharing the root
(``sessions.ScanPresence``). Ending a session in a server that has no claim of its
own must still see that entry: removing the tree under a running scan can turn its
result into a clean one. Nothing in this process learns when the scan elsewhere
returns, so the deferred removal is the TTL sweep's. Whatever removes a session's
workspace also drops the entries of scans that died and the empty directory that
held them.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, KillAfter

_HOLDER = """
import sys
from automated_security_helper.cli.mcp.sessions import ScanPresence
with ScanPresence(sys.argv[1]):
    print("held", flush=True)
    sys.stdin.readline()
"""


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


def _sandbox(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return sandbox


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


def test_ending_a_session_defers_while_a_scan_in_another_server_runs(root) -> None:
    sandbox = _sandbox(root, "elsewhere")

    with _scan_in_another_process(root, "elsewhere"):
        removed_now = sessions.end_session("elsewhere")
        kept = (sandbox / "source" / "app.py").is_file()
        deferred = "elsewhere" in sessions._ended_while_scanning

    assert removed_now is False
    assert kept, "the tree a scan in another server was reading was removed"
    assert deferred


def test_the_ttl_sweep_removes_the_deferred_session_once_that_scan_is_gone(
    root,
) -> None:
    """Nothing in this process learns that the scan elsewhere returned: the sweep
    is the collector (see ``end_session``)."""
    sandbox = _sandbox(root, "elsewhere")
    with _scan_in_another_process(root, "elsewhere"):
        assert sessions.end_session("elsewhere") is False
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
        assert sandbox.is_dir(), "the sweep removed the tree under the running scan"

    removed = sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600)

    assert removed == ["elsewhere"]
    assert not sandbox.exists()
    assert not (root / sessions.SCAN_PRESENCE_DIR / "elsewhere").exists()
    assert "elsewhere" not in sessions._ended_while_scanning


def test_ending_a_session_drops_the_entry_a_dead_scan_left(root) -> None:
    sandbox = _sandbox(root, "orphaned")
    holder = root / sessions.SCAN_PRESENCE_DIR / "orphaned"
    holder.mkdir(parents=True)
    (holder / "12345-deadbeef").write_bytes(b"")

    assert sessions.end_session("orphaned") is True

    assert not sandbox.exists()
    assert not holder.exists(), "the dead scan's entry and its directory were kept"


def test_a_presence_guard_that_cannot_be_taken_defers_the_removal(
    root, monkeypatch
) -> None:
    """Unable to prove no scan holds the session, end_session removes nothing."""
    sandbox = _sandbox(root, "unreadable")

    def refused(_root):
        raise PermissionError("the presence registry cannot be opened")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    removed_now = sessions.end_session("unreadable")

    assert removed_now is False
    assert (sandbox / "source" / "app.py").is_file()
    assert "unreadable" in sessions._ended_while_scanning


def test_ending_an_unknown_session_creates_nothing_under_the_root(root) -> None:
    assert sessions.end_session("never-existed") is True

    assert sorted(p.name for p in root.iterdir()) == []
