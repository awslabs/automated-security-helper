# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep names a session it cannot remove once, not on every pass.

A workspace whose removal keeps failing (a file another account owns, a
filesystem error) was named by a warning on every sweep, at most every five
minutes, so an operator read the same line hundreds of times a day. The
sweep now says it once per session for as long as the failure lasts, the way
it already reports a leftover it cannot delete, and says so again only after
a pass has removed the session and a later failure of the same id is new.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

STUCK = "stuck-session"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sessions, "_sweep_failures_warned", set())
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()


def _aged_workspace(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    then = time.time() - 7200
    os.utime(sandbox, (then, then))
    return sandbox


def _warnings_naming(caplog, session_id: str) -> list:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and repr(session_id) in record.getMessage()
    ]


def test_a_removal_that_keeps_failing_is_named_once(root, monkeypatch, caplog):
    sandbox = _aged_workspace(root, STUCK)

    def cannot_remove(session_id: str) -> None:
        raise PermissionError(13, "Permission denied", str(sandbox))

    monkeypatch.setattr(sessions, "_remove_session_state", cannot_remove)

    with caplog.at_level(logging.WARNING):
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    named = _warnings_naming(caplog, STUCK)
    assert len(named) == 1, caplog.text
    assert "only warning" in named[0], named[0]
    assert sandbox.is_dir(), "the workspace was removed although the removal raised"


def test_a_removal_that_worked_makes_a_later_failure_new(root, caplog):
    with caplog.at_level(logging.WARNING):
        sessions._warn_sweep_failure_once(STUCK, "first")
        sessions._warn_sweep_failure_once(STUCK, "repeat")
        sessions._forget_sweep_failure(STUCK)
        sessions._warn_sweep_failure_once(STUCK, "after a removal")

    named = _warnings_naming(caplog, STUCK)
    assert len(named) == 2, caplog.text
    assert "first" in named[0] and "after a removal" in named[1], named
