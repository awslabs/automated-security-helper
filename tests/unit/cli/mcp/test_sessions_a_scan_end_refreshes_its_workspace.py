# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The end of a scan counts as a use of its session's workspace.

The TTL sweep reads a workspace's liveness from its modification time. A scan
holds the sweep off while it runs (its claim and lock refuse the sweep's change),
but a scan that ran longer than the TTL on a workspace nothing else touched left
it older than the cutoff the moment it returned, so the first pass after that
removed the tree and the results the scan had just written under it.
``ScanPresence.__exit__`` sets the workspace's modification time to now, before
its presence entry goes.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.cli.mcp.sessions import (
    SCAN_PRESENCE_DIR,
    ScanPresence,
    sweep_stale_workspaces,
)

pytestmark = pytest.mark.unit

SESSION = "long-scan"
LONG_AGO_SECONDS = 10_000.0
TTL_SECONDS = 600.0


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


def _an_old_workspace(root: Path) -> Path:
    sandbox = mark_session_workspace(root / SESSION)
    (sandbox / "source").mkdir()
    then = time.time() - LONG_AGO_SECONDS
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    return sandbox


def test_a_scan_end_touches_the_workspace(root) -> None:
    sandbox = _an_old_workspace(root)
    before = time.time() - 60.0

    with ScanPresence(SESSION):
        pass

    assert sandbox.stat().st_mtime >= before


def test_a_workspace_a_long_scan_just_left_survives_the_next_sweep(root) -> None:
    sandbox = _an_old_workspace(root)

    with ScanPresence(SESSION):
        pass
    removed = sweep_stale_workspaces(TTL_SECONDS)

    assert removed == []
    assert sandbox.is_dir()


def test_a_scan_with_no_workspace_creates_nothing(root) -> None:
    with ScanPresence("absent"):
        pass

    assert not (root / "absent").exists()
    assert not (root / SCAN_PRESENCE_DIR).exists()
