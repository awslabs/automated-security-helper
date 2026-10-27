# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace that cannot be examined is not reported as gone.

What the code does, by path
---------------------------
``source_delivery.remove_session_workspace`` first sets the workspace aside under a
hidden name (``_set_aside_for_removal``) and then deletes what it returned. The
function answered None, "nothing is on disk", from ``os.path.lexists``, which is
False for EACCES, EIO and ESTALE as much as for ENOENT. ``remove_session_workspace``
then reported the workspace gone and dropped the session's record while the tree
was still on disk under its own name, so ``end_session`` said everything was
removed and nothing logged the tree that stayed.

Only ``FileNotFoundError`` means nothing is there. Any other error from the stat
says nothing about the tree, so the workspace is returned and the delete is
attempted at its own path, as it is when the rename is refused.

How the tests work
------------------
``os.lstat`` is replaced by a double that refuses the first look at the workspace
path with the error the test names and calls the real one for everything else, so
the delete that follows runs for real. Every test is DISARMED: the workspace root is
the test's own tmp_path, and nothing runs git, a scanner or the network.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

SESSION = "ended-session"


@pytest.fixture
def workspace_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    return root


def _a_workspace(root: Path) -> Path:
    workspace = root / SESSION
    workspace.mkdir()
    (workspace / "tree.txt").write_text("delivered\n", encoding="utf-8")
    sd._set_session_source_dir(SESSION, workspace / "source")
    return workspace


def _the_next_stat_of_fails(
    monkeypatch: pytest.MonkeyPatch, path: Path, error: OSError
) -> List[str]:
    """Make the next ``os.lstat`` of ``path`` raise ``error``; later calls are real.

    Returns the list the refusal is recorded in, so a test can check that the
    stat it means was the one refused.
    """
    real_lstat = os.lstat
    wanted = os.fspath(path)
    refused: List[str] = []

    def lstat(target, *args, **kwargs):
        if not refused and os.fspath(target) == wanted:
            refused.append(wanted)
            raise error
        return real_lstat(target, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    return refused


def test_a_workspace_whose_stat_is_refused_is_returned_for_the_delete(
    workspace_root, monkeypatch
) -> None:
    workspace = _a_workspace(workspace_root)
    refused = _the_next_stat_of_fails(
        monkeypatch, workspace, PermissionError(errno.EACCES, "permission denied")
    )

    doomed = sd._set_aside_for_removal(workspace, SESSION)

    assert refused, "control: the stat of the workspace was never refused"
    assert doomed == workspace, doomed


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(PermissionError(errno.EACCES, "permission denied"), id="eacces"),
        pytest.param(OSError(errno.EIO, "input/output error"), id="eio"),
        pytest.param(OSError(errno.ESTALE, "stale file handle"), id="estale"),
    ],
)
def test_removing_a_workspace_deletes_it_when_the_first_stat_is_refused(
    workspace_root, monkeypatch, error
) -> None:
    """The tree is deleted, not reported gone while it stays on disk."""
    workspace = _a_workspace(workspace_root)
    real_workspace_path = sd._session_workspace
    refusals: List[List[str]] = []

    def build_the_path_then_refuse_the_next_stat_of_it(root: Path, session_id: str):
        path = real_workspace_path(root, session_id)
        refusals.append(_the_next_stat_of_fails(monkeypatch, path, error))
        return path

    monkeypatch.setattr(
        sd, "_session_workspace", build_the_path_then_refuse_the_next_stat_of_it
    )

    gone = sd.remove_session_workspace(SESSION, workspace_root=workspace_root)

    assert refusals and refusals[0], (
        "control: the stat of the workspace was never refused"
    )
    assert not workspace.exists(), "the tree was left on disk"
    assert gone is True
    assert sd.get_session_source_dir(SESSION) is None


def test_a_workspace_that_is_not_there_is_gone(workspace_root) -> None:
    """Control: ENOENT still means nothing is on disk, with no delete attempted."""
    missing = workspace_root / "never-made"

    assert sd._set_aside_for_removal(missing, "never-made") is None
    assert sd.remove_session_workspace("never-made", workspace_root=workspace_root)


def test_a_workspace_that_can_be_examined_is_still_set_aside_under_a_hidden_name(
    workspace_root,
) -> None:
    """Control: no double. The workspace is renamed first, and the rename is the
    name the delete runs on."""
    workspace = _a_workspace(workspace_root)

    doomed = sd._set_aside_for_removal(workspace, SESSION)

    assert doomed is not None and doomed != workspace, doomed
    assert (doomed / "tree.txt").is_file()
    assert not workspace.exists()
