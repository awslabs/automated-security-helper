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
"""

from __future__ import annotations

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
    yield workspace
    sessions.reset_default_registry_for_tests()


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
    raise PermissionError("the filesystem refuses file locks")


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

    warned = [
        r.getMessage() for r in ash_log if "scan presence registry" in r.getMessage()
    ]
    assert len(warned) == 1, warned
    assert "runs unregistered" in warned[0] and "'scanned'" in warned[0]
