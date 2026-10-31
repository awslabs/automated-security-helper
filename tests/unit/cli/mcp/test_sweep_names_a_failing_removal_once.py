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

    # The step the sweep runs under its guard for a session with a workspace
    # (the rename aside and the dropping of the session's state). A session
    # with none takes _remove_session_state, which this sweep does not.
    def cannot_remove(session_id: str, sandbox_path: Path) -> None:
        raise PermissionError(13, "Permission denied", str(sandbox))

    monkeypatch.setattr(sessions, "_set_session_state_aside", cannot_remove)

    with caplog.at_level(logging.WARNING):
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    named = _warnings_naming(caplog, STUCK)
    assert len(named) == 1, caplog.text
    assert "only warning" in named[0], named[0]
    assert sandbox.is_dir(), "the workspace was removed although the removal raised"


def test_a_sweep_that_removes_the_session_makes_its_next_failure_new(
    root, monkeypatch, caplog
):
    """The same case through the sweep itself. The test below calls the two
    helpers and shows only that forgetting works; nothing there shows the sweep
    forgets after a removal. A removal that fails twice is named once, the pass
    that removes the session forgets it, and when the id is used again and its
    removal fails again the warning comes again."""
    sandbox = _aged_workspace(root, STUCK)
    real_set_aside = sessions._set_session_state_aside
    failing = {"now": True}

    # The step the sweep runs under its guard for a session with a workspace;
    # when it works, the sweep goes on to forget the failure it named.
    def removal(session_id: str, sandbox_path: Path):
        if failing["now"]:
            raise PermissionError(13, "Permission denied", str(sandbox))
        return real_set_aside(session_id, sandbox_path)

    monkeypatch.setattr(sessions, "_set_session_state_aside", removal)

    with caplog.at_level(logging.WARNING):
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)
        assert len(_warnings_naming(caplog, STUCK)) == 1, caplog.text

        failing["now"] = False
        removed = sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)
        assert removed == [STUCK], removed
        assert not sandbox.exists(), "the removal that worked left the workspace"
        assert STUCK not in sessions._sweep_failures_warned, (
            "the pass that removed the session did not forget its failure"
        )

        # The id is used again and its removal fails again: a new failure.
        sandbox = _aged_workspace(root, STUCK)
        failing["now"] = True
        sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    assert len(_warnings_naming(caplog, STUCK)) == 2, caplog.text


def test_a_removal_that_worked_makes_a_later_failure_new(root, caplog):
    with caplog.at_level(logging.WARNING):
        sessions._warn_sweep_failure_once(STUCK, "first")
        sessions._warn_sweep_failure_once(STUCK, "repeat")
        sessions._forget_sweep_failure(STUCK)
        sessions._warn_sweep_failure_once(STUCK, "after a removal")

    named = _warnings_naming(caplog, STUCK)
    assert len(named) == 2, caplog.text
    assert "first" in named[0] and "after a removal" in named[1], named
