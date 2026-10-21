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
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import (
    profile_registry,
    sessions,
    source_delivery,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.log import ASH_LOGGER
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


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def test_a_presence_guard_that_cannot_be_taken_clears_the_memory_and_warns(
    root, monkeypatch, ash_log
) -> None:
    """Unable to prove no scan holds the session, end_session leaves the tree on
    disk for the sweep, and does not keep the session's state in memory for the
    life of the process."""
    sandbox = _sandbox(root, "unreadable")
    profile_registry.bind_session_config(
        "unreadable", config=AshConfig(), profile_name="strict"
    )
    source_delivery._set_session_source_dir("unreadable", sandbox / "source")
    registry = sessions.get_default_registry()
    registry.session_for("unreadable")

    def refused(_root):
        raise PermissionError("the presence registry cannot be opened")

    try:
        with monkeypatch.context() as patched:
            patched.setattr(sessions, "_scan_presence_guard", refused)
            removed_now = sessions.end_session("unreadable")

        assert removed_now is False
        assert (sandbox / "source" / "app.py").is_file()
        assert "unreadable" not in registry
        assert not profile_registry.session_has_binding("unreadable")
        assert source_delivery.get_session_source_dir("unreadable") is None
        assert source_delivery.delivered_session_count() == 0
        assert "unreadable" not in sessions._ended_while_scanning
        warned = [r.getMessage() for r in ash_log if "presence lock" in r.getMessage()]
        assert len(warned) == 1, warned
        assert str(root / sessions.SCAN_PRESENCE_DIR / ".lock") in warned[0]

        removed = sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600)

        assert removed == ["unreadable"], "a sweep whose guard succeeds collects it"
        assert not sandbox.exists()
    finally:
        profile_registry.clear_session_state()
        source_delivery._drop_session_source_dir("unreadable")


def test_forgetting_a_session_drops_its_delivered_source_record(
    root, monkeypatch, ash_log
) -> None:
    """On a root that refuses the lock for good, the forget must drop the
    delivered-source record: every sweep's lookup re-creates the registry
    entry, and a record left behind would read that entry as bound, so it
    would never be evicted, ``delivered_session_count`` would stay inflated by
    ended sessions, and the forget would be undone."""
    sandbox = _sandbox(root, "unreadable")
    profile_registry.bind_session_config(
        "unreadable", config=AshConfig(), profile_name="strict"
    )
    source_delivery._set_session_source_dir("unreadable", sandbox / "source")
    registry = sessions.get_default_registry()
    registry.session_for("unreadable")
    assert source_delivery.delivered_session_count() == 1

    def refused(_root):
        raise PermissionError("the presence registry cannot be opened")

    # Permanent: the sweep below hits the same refusal.
    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    try:
        assert sessions.end_session("unreadable") is False

        assert source_delivery.get_session_source_dir("unreadable") is None
        assert source_delivery.delivered_session_count() == 0
        assert "unreadable" not in registry

        # The sweep's lookup re-creates an empty entry and its guard is
        # refused again, so it removes nothing; without the record the entry
        # holds no binding, and the registry can evict it.
        assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
        assert (sandbox / "source" / "app.py").is_file()
        entry = registry.get("unreadable")
        if entry is not None:
            entry._last_handed_out = (
                time.monotonic() - sessions.IDLE_SESSION_SECONDS - 1.0
            )
        with registry._lock:
            registry._forget_idle_sessions()

        assert "unreadable" not in registry, "the entry came back bound: forget undone"
        assert source_delivery.delivered_session_count() == 0
    finally:
        profile_registry.clear_session_state()
        source_delivery._drop_session_source_dir("unreadable")


def test_a_permanently_refused_guard_keeps_the_tree_and_the_sweep_warns_once(
    root, monkeypatch, ash_log
) -> None:
    """On a filesystem that refuses the lock for good, every sweep is refused
    the same way, so nothing removes the tree; the end_session warning says so
    plainly, and the sweep says it once per process, not once per pass."""
    sandbox = _sandbox(root, "refused")
    monkeypatch.setattr(sessions, "_sweep_guard_warned", False)

    def refused(_root):
        raise PermissionError("the presence registry cannot be opened")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    assert sessions.end_session("refused") is False
    ended = [r.getMessage() for r in ash_log if "scan presence lock" in r.getMessage()]
    assert len(ended) == 1, ended
    assert (
        "nothing removes it until the root's filesystem supports file locks" in ended[0]
    ), ended[0]

    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []
    assert sessions.sweep_stale_workspaces(60.0, now=time.time() + 3600) == []

    assert (sandbox / "source" / "app.py").is_file(), "nothing can remove the tree"
    swept = [r.getMessage() for r in ash_log if "TTL sweep" in r.getMessage()]
    assert len(swept) == 1, swept
    assert "No session workspace on this root is removed" in swept[0]


def test_ending_the_default_session_does_not_open_the_scan_presence_registry(
    root,
) -> None:
    """The reserved ``__default__`` never has a presence entry, so there is
    nothing for the guard to protect and no lock file to create."""
    default = mark_session_workspace(root / profile_registry.DEFAULT_SESSION_ID)
    (default / "source").mkdir()

    assert sessions.end_session(profile_registry.DEFAULT_SESSION_ID) is True

    assert not default.exists()
    assert not (root / sessions.SCAN_PRESENCE_DIR).exists()


def test_a_guard_that_cannot_be_taken_does_not_strand_the_default_workspace(
    root, monkeypatch
) -> None:
    default = mark_session_workspace(root / profile_registry.DEFAULT_SESSION_ID)

    def refused(_root):
        raise PermissionError("the presence registry cannot be opened")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    assert sessions.end_session(profile_registry.DEFAULT_SESSION_ID) is True
    assert not default.exists()


def test_ending_an_unknown_session_creates_nothing_under_the_root(root) -> None:
    assert sessions.end_session("never-existed") is True

    assert sorted(p.name for p in root.iterdir()) == []
