# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``end_session`` treats a filesystem error as "the workspace may exist".

``Path.is_dir()`` re-raises EACCES, EIO and ESTALE on Python <= 3.13 instead of
answering False, so an ``OSError`` from the stat of the session's directory says
nothing about whether the directory is there. ``ScanPresence`` reads the same
error as "the workspace may exist". ``end_session`` does the same: it takes the
guarded path (the presence lock, then the check for a scan that holds the
session) or, when the lock is refused, clears only the server's own state. Only
``ValueError`` and ``RuntimeError`` (an id that names no directory, no workspace
root) mean there is no workspace.

An ``OSError`` raised after the lock was taken (the check for a scan, the
removal) is logged with a warning and ends the call as a refused lock does: the
tree stays for the TTL sweep and the id is not recorded as held by a scan.
"""

from __future__ import annotations

import errno
import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()


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


def _sandbox(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return sandbox


class _StatRefused(type(Path())):
    """The session's directory, whose ``is_dir`` stat fails as a stale network
    handle does. A real path otherwise: the removal that follows the failed
    stat renames and deletes what stands at it (``_set_aside_for_removal``
    takes the path the caller resolved), which a stand-in that is no path
    could not have."""

    def is_dir(self) -> bool:
        raise OSError(errno.ESTALE, "FAKE stale file handle", "FAKE-sandbox")


def _stat_fails(monkeypatch, session_id: str) -> None:
    """Make the ``is_dir`` stat of every session directory fail from now on.

    The registry entry for ``session_id`` is made first: a new entry is built
    from the directory path as the server resolves it.
    """
    sessions.get_default_registry().session_for(session_id)
    monkeypatch.setattr(
        sessions, "session_directory", lambda root, sid: _StatRefused(root / sid)
    )


def _refuse_the_presence_guard(monkeypatch) -> None:
    def refused(_root):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)


def _warnings_about(ash_log, needle: str) -> List[str]:
    return [r.getMessage() for r in ash_log if needle in r.getMessage()]


def test_a_failed_stat_leaves_the_tree_a_registered_scan_holds(root, monkeypatch):
    sandbox = _sandbox(root, "held")

    with sessions.ScanPresence("held") as presence:
        assert presence._entry is not None, "the scan did not register"
        _stat_fails(monkeypatch, "held")

        removed_now = sessions.end_session("held")

        assert (sandbox / "source" / "app.py").is_file(), (
            "the tree a registered scan was reading was removed"
        )

    assert removed_now is False
    assert "held" in sessions._ended_while_scanning


def test_a_failed_stat_with_no_scan_still_removes_the_session_under_the_guard(
    root, monkeypatch
):
    sandbox = _sandbox(root, "idle")
    _stat_fails(monkeypatch, "idle")

    assert sessions.end_session("idle") is True

    assert not sandbox.exists()
    assert "idle" not in sessions._ended_while_scanning


def test_a_failed_stat_with_a_refused_guard_keeps_the_tree_and_warns_once(
    root, monkeypatch, ash_log
):
    sandbox = _sandbox(root, "refused")
    _stat_fails(monkeypatch, "refused")
    _refuse_the_presence_guard(monkeypatch)

    assert sessions.end_session("refused") is False

    assert (sandbox / "source" / "app.py").is_file(), (
        "the tree was removed without the presence lock"
    )
    assert "refused" not in sessions.get_default_registry()
    assert "refused" not in sessions._ended_while_scanning
    warned = _warnings_about(ash_log, "Could not take the scan presence lock")
    assert len(warned) == 1, warned
    assert "while ending session 'refused'" in warned[0], warned[0]
    assert f"errno {errno.EACCES} EACCES" in warned[0], warned[0]


@pytest.mark.parametrize("stat_fails", [False, True], ids=["stat-ok", "stat-estale"])
def test_a_failure_while_checking_for_a_scan_is_logged_and_not_recorded_as_held(
    stat_fails, root, monkeypatch, ash_log
):
    sandbox = _sandbox(root, "swallowed")
    if stat_fails:
        _stat_fails(monkeypatch, "swallowed")

    def unreadable(_holder):
        raise PermissionError(errno.EACCES, "Permission denied", "FAKE-holder")

    monkeypatch.setattr(sessions, "_a_scan_holds", unreadable)

    assert sessions.end_session("swallowed") is False

    assert (sandbox / "source" / "app.py").is_file()
    assert "swallowed" not in sessions._ended_while_scanning, (
        "a failed check was recorded as a scan holding the session"
    )
    assert "swallowed" not in sessions.get_default_registry()
    warned = _warnings_about(ash_log, "ending session 'swallowed'")
    assert len(warned) == 1, warned
    assert f"errno {errno.EACCES} EACCES" in warned[0], warned[0]
    assert "FAKE-holder" in warned[0], warned[0]


def test_no_workspace_root_means_no_workspace(root, monkeypatch, ash_log):
    def no_root() -> Path:
        raise RuntimeError("no workspace root")

    monkeypatch.setattr(sessions, "_workspace_root", no_root)

    assert sessions.end_session("granted") is True

    assert ash_log == [], [r.getMessage() for r in ash_log]
    assert not (root / sessions.SCAN_PRESENCE_DIR).exists()


def test_an_id_that_names_no_directory_means_no_workspace(root, ash_log):
    assert sessions.end_session("..") is True

    assert ash_log == [], [r.getMessage() for r in ash_log]
    assert not (root / sessions.SCAN_PRESENCE_DIR).exists()
