# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A presence registry whose guard cannot be locked warns instead of going silent.

``StdioServerPresence`` and ``ScanPresence`` carry on unregistered when the
registry's own guard lock is refused: the resulting state is safe (no server
can remove anything there), but without a warning an operator on such a root
has no sign the registry is out of use. The hard ``PresenceLockError`` is
reserved for the entry lock, which the filesystem can only refuse after it
granted the guard's, so the guard path is the one a lock-refusing mount
actually takes. The refusal is simulated with a monkeypatched lock, never a
real mount.

A scan reports a refused guard only when it would have registered: a session
with no workspace on disk, or a process with no workspace root, registers
nothing and says nothing.
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


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()


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


def _refused(_handle) -> None:
    raise OSError(errno.ENOLCK, "No locks available")


def _scan_warnings(ash_log) -> List[str]:
    return [
        r.getMessage()
        for r in ash_log
        if "Could not take the scan presence lock" in r.getMessage()
    ]


def _stat_warnings(ash_log) -> List[str]:
    return [
        r.getMessage()
        for r in ash_log
        if "Could not examine the workspace" in r.getMessage()
    ]


def test_a_stdio_server_whose_guard_cannot_lock_warns_and_runs_unregistered(
    root, monkeypatch, ash_log
) -> None:
    monkeypatch.setattr(sessions, "_lock_blocking", _refused)

    with sessions.StdioServerPresence() as presence:
        assert presence._entry is None, "the server registered without the guard"

    warned = [
        r.getMessage()
        for r in ash_log
        if "stdio server presence registry" in r.getMessage()
    ]
    assert len(warned) == 1, warned
    assert "runs unregistered" in warned[0]


def test_a_scan_whose_guard_cannot_lock_warns_and_runs_unregistered(
    root, monkeypatch, ash_log
) -> None:
    sandbox = mark_session_workspace(root / "scanned")
    (sandbox / "source").mkdir()
    monkeypatch.setattr(sessions, "_lock_blocking", _refused)

    with sessions.ScanPresence("scanned") as presence:
        assert presence._entry is None, "the scan registered without the guard"

    warned = _scan_warnings(ash_log)
    assert len(warned) == 1, warned
    assert "registering a scan of session 'scanned'" in warned[0], warned[0]
    assert f"errno {errno.ENOLCK} ENOLCK" in warned[0], warned[0]
    assert "a scan runs unregistered" in warned[0], warned[0]


def test_a_scan_with_no_workspace_root_registers_nothing_and_says_nothing(
    root, monkeypatch, ash_log
) -> None:
    """No HOME and no ASH_MCP_WORKSPACE_ROOT: the scan is of a directory the
    operator granted, which registers nothing either way."""

    def no_root() -> Path:
        raise RuntimeError("no workspace root")

    monkeypatch.setattr(sessions, "_workspace_root", no_root)

    with sessions.ScanPresence("granted") as presence:
        assert presence._entry is None

    assert ash_log == [], [r.getMessage() for r in ash_log]


def test_a_scan_of_a_session_with_no_workspace_never_takes_the_guard(
    root, monkeypatch, ash_log
) -> None:
    attempts: List[Path] = []

    def refused(guard_root):
        attempts.append(guard_root)
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)

    with sessions.ScanPresence("no-workspace-on-disk") as presence:
        assert presence._entry is None

    assert attempts == []
    assert ash_log == [], [r.getMessage() for r in ash_log]


def test_a_registry_mkdir_that_fails_names_the_directory(root, ash_log) -> None:
    """The guard's first step is the registry mkdir — a real failure here, from
    a file sitting where the directory goes. Its warning names the directory
    that could not be made, not only the lock file nobody got to open."""
    sandbox = mark_session_workspace(root / "scanned")
    (sandbox / "source").mkdir()
    (root / sessions.SCAN_PRESENCE_DIR).write_bytes(b"")

    with sessions.ScanPresence("scanned") as presence:
        assert presence._entry is None

    warned = _scan_warnings(ash_log)
    assert len(warned) == 1, warned
    assert f"errno {errno.EEXIST} EEXIST" in warned[0], warned[0]
    assert f": {root / sessions.SCAN_PRESENCE_DIR})" in warned[0], warned[0]


def test_a_sandbox_stat_that_fails_warns_and_the_scan_runs_unregistered(
    root, monkeypatch, ash_log
) -> None:
    """``Path.is_dir()`` re-raises EACCES, EIO and ESTALE on Python <= 3.13, so
    the workspace may exist: the scan runs unregistered with the warning as the
    one sign of it, while RuntimeError and ValueError (no workspace root, a bad
    id) keep the silent return."""
    planted = OSError(errno.ESTALE, "FAKE stale file handle", "FAKE-sandbox")

    class _StatRefused:
        def is_dir(self) -> bool:
            raise planted

    monkeypatch.setattr(
        sessions, "session_directory", lambda _root, _sid: _StatRefused()
    )

    with sessions.ScanPresence("stat-refused") as presence:
        assert presence._entry is None, "the scan registered without the stat"

    warned = _stat_warnings(ash_log)
    assert len(warned) == 1, warned
    assert "session 'stat-refused'" in warned[0], warned[0]
    assert f"errno {errno.ESTALE} ESTALE" in warned[0], warned[0]
    assert "FAKE-sandbox" in warned[0], warned[0]
    assert "the scan runs unregistered" in warned[0], warned[0]
    assert _scan_warnings(ash_log) == [], "the stat failure used the lock text"
    assert sessions._guard_refusal_warned is False, "the stat failure set the latch"


def test_a_guard_refusal_after_a_failed_stat_is_still_a_warning(
    root, monkeypatch, ash_log
) -> None:
    """The stat failure has its own warning and leaves the process-wide latch
    clear, so the first real refusal of the guard after it is logged at warning
    level and not at debug."""
    planted = OSError(errno.ESTALE, "FAKE stale file handle", "FAKE-sandbox")

    class _StatRefused:
        def is_dir(self) -> bool:
            raise planted

    with monkeypatch.context() as patched:
        patched.setattr(
            sessions, "session_directory", lambda _root, _sid: _StatRefused()
        )
        with sessions.ScanPresence("stat-refused") as presence:
            assert presence._entry is None

    sandbox = mark_session_workspace(root / "scanned")
    (sandbox / "source").mkdir()
    monkeypatch.setattr(sessions, "_lock_blocking", _refused)

    with sessions.ScanPresence("scanned") as presence:
        assert presence._entry is None, "the scan registered without the guard"

    warned = _scan_warnings(ash_log)
    assert len(warned) == 1, warned
    assert "registering a scan of session 'scanned'" in warned[0], warned[0]
    assert f"errno {errno.ENOLCK} ENOLCK" in warned[0], warned[0]


def test_an_entry_that_cannot_be_created_after_the_guard_warns_for_that_scan(
    root, ash_log
) -> None:
    """The guard is taken, so the process-wide latch stays clear: a failure to
    create this scan's own entry is a different condition, reported per scan."""
    sandbox = mark_session_workspace(root / "scanned")
    (sandbox / "source").mkdir()
    # A regular file where the scan's registry directory should be.
    (root / sessions.SCAN_PRESENCE_DIR).mkdir()
    (root / sessions.SCAN_PRESENCE_DIR / "scanned").write_bytes(b"")

    with sessions.ScanPresence("scanned") as presence:
        assert presence._entry is None

    entry_warnings = [
        r.getMessage() for r in ash_log if "presence entry" in r.getMessage()
    ]
    assert len(entry_warnings) == 1, entry_warnings
    assert "'scanned'" in entry_warnings[0] and "errno " in entry_warnings[0]
    assert _scan_warnings(ash_log) == [], "no guard refusal was reported"
    assert sessions._guard_refusal_warned is False
