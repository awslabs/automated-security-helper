# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep finishes the end of a session that a DELETE left pending.

``end_session`` marks the session pending and relies on whichever of the two
parties finishes second to remove it. When the sweep's change refused the DELETE's
``end_session``, the sweep is the second party: a sweep that then keeps the session
(it is no longer stale, a write holds it, the presence guard is refused) releases
its change without removing anything, and the workspace the DELETE reported gone
stays on disk. Every cell works under ``tmp_path``.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

SESSION_ID = "ended-while-swept"


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


def _pending_workspace(root: Path) -> Path:
    sandbox = mark_session_workspace(root / SESSION_ID)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    sessions._ended_while_scanning.add(SESSION_ID)
    return sandbox


def test_a_sweep_that_finds_the_session_fresh_finishes_its_end(root) -> None:
    sandbox = _pending_workspace(root)

    # A cutoff in the past: the session was used after the sweep first read its age.
    removed = sessions._remove_if_still_stale(root, SESSION_ID, sandbox, 0.0)

    assert removed is False
    assert not sandbox.exists(), "the ended session was left on disk"
    assert SESSION_ID not in sessions._ended_while_scanning


def test_a_sweep_stepping_back_for_a_write_leaves_the_end_pending(root) -> None:
    sandbox = _pending_workspace(root)
    session = sessions.get_default_registry().session_for(SESSION_ID)
    assert session.try_begin_write() is None
    try:
        removed = sessions._remove_if_still_stale(
            root, SESSION_ID, sandbox, time.time() + 3600
        )
    finally:
        session.end_write()

    assert removed is False
    assert sandbox.is_dir(), "the tree went away under a write in progress"
    assert SESSION_ID in sessions._ended_while_scanning

    sessions.finish_ended_session(SESSION_ID)

    assert not sandbox.exists()
    assert SESSION_ID not in sessions._ended_while_scanning


def test_a_sweep_that_removes_the_session_still_returns_true(root) -> None:
    sandbox = _pending_workspace(root)

    removed = sessions._remove_if_still_stale(
        root, SESSION_ID, sandbox, time.time() + 3600
    )

    assert removed is True
    assert not sandbox.exists()
    assert SESSION_ID not in sessions._ended_while_scanning
