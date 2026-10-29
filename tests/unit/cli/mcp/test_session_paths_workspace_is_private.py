# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session workspace, and the root it is created under, belong to the owner alone.

``mark_session_workspace`` created the session directory and any missing
ancestor with the process umask's default permissions, so under a 022 umask
every other account on the host could list the workspace root (the live
session ids) and read a session's delivered source. The directories this call
creates are now 0o700 whatever the umask; a directory that already exists keeps
the mode it has.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits"),
]


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_new_workspace_and_the_root_it_creates_are_private(tmp_path) -> None:
    root = tmp_path / "ws-root"
    previous = os.umask(0o022)
    try:
        sandbox = mark_session_workspace(root / "session-a")
    finally:
        os.umask(previous)

    assert _mode(sandbox) == 0o700, oct(_mode(sandbox))
    assert _mode(root) == 0o700, oct(_mode(root))
    assert (sandbox / SESSION_MARKER).is_file()


def test_an_existing_root_keeps_the_mode_it_has(tmp_path) -> None:
    root = tmp_path / "ws-root"
    root.mkdir()
    os.chmod(root, 0o755)
    previous = os.umask(0o022)
    try:
        sandbox = mark_session_workspace(root / "session-b")
    finally:
        os.umask(previous)

    assert _mode(root) == 0o755, "an existing directory's mode was changed"
    assert _mode(sandbox) == 0o700, oct(_mode(sandbox))


def test_marking_an_existing_workspace_again_changes_nothing(tmp_path) -> None:
    sandbox = tmp_path / "ws-root" / "session-c"
    sandbox.mkdir(parents=True)
    os.chmod(sandbox, 0o750)

    mark_session_workspace(sandbox)

    assert _mode(sandbox) == 0o750
    assert (sandbox / SESSION_MARKER).is_file()
