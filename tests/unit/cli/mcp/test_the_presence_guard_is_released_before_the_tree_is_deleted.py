# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan presence guard is released before a session's tree is deleted.

The guard makes the check for a live scan's entry and the removal of the
workspace one step. It was held through the whole delete, in ``end_session``
(``_remove_unless_a_scan_elsewhere_holds``) and in the TTL sweep
(``_remove_stale_session_state``), so every other server sharing the root
waited out an rmtree of any size: their scans' registrations, their sweeps, and
the busy gate of a change to a session's tree, which now answers busy after its
bounded wait instead of waiting.

Once the workspace is renamed to its hidden delete name, a scan registering next
finds no marker at the session's path and registers nothing, so the delete of
the renamed tree needs no guard. Both callers now rename aside and drop the
session's state under the guard (``_set_session_state_aside``) and delete the
tree after releasing it (``_remove_set_aside_tree``).

Measured at the delete: ``source_delivery._remove_tree`` is stood in for by a
function that, before deleting, asks for the presence lock on a handle of its
own without waiting. A lock that is granted was free; one that is refused was
still held by the caller.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

ENDED = "ended-session"
STALE = "stale-session"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions._ended_while_scanning.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def delete_reads_the_lock(root: Path, monkeypatch) -> Dict[str, Any]:
    """``_remove_tree`` that records whether the presence lock was free when it ran."""
    real = sd._remove_tree
    seen: Dict[str, Any] = {"deleted": [], "lock_free": []}
    lock_path = root / sessions.SCAN_PRESENCE_DIR / sessions._SCAN_PRESENCE_LOCK

    def remove(path: Path) -> bool:
        with open(lock_path, "a+b") as probe:
            seen["lock_free"].append(sessions._try_lock(probe).error is None)
        seen["deleted"].append(path)
        return real(path)

    monkeypatch.setattr(sd, "_remove_tree", remove)
    return seen


def _workspace(root: Path, session_id: str, *, stale: bool) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    if stale:
        then = time.time() - 3600
        for path in (sandbox, *sandbox.iterdir()):
            os.utime(path, (then, then))
    return sandbox


def test_ending_a_session_deletes_its_tree_with_the_guard_released(
    root: Path, delete_reads_the_lock
) -> None:
    sandbox = _workspace(root, ENDED, stale=False)

    ended = sessions.end_session(ENDED)

    assert ended is True
    assert delete_reads_the_lock["deleted"], "the tree was never deleted"
    assert delete_reads_the_lock["lock_free"] == [True], (
        "the presence guard was still held while the tree was deleted"
    )
    assert not sandbox.exists()
    assert [
        p.name for p in root.iterdir() if p.name != sessions.SCAN_PRESENCE_DIR
    ] == []


def test_the_sweep_deletes_a_stale_tree_with_the_guard_released(
    root: Path, delete_reads_the_lock
) -> None:
    sandbox = _workspace(root, STALE, stale=True)

    removed = sessions.sweep_stale_workspaces(1.0)

    assert removed == [STALE]
    assert delete_reads_the_lock["lock_free"] == [True], (
        "the presence guard was still held while the sweep deleted the tree"
    )
    assert not sandbox.exists()


def test_the_delete_runs_under_the_hidden_name_not_the_sessions_path(
    root: Path, delete_reads_the_lock
) -> None:
    """What makes the released guard safe: by the time the tree is deleted it no
    longer stands at the session's path, so a scan registering meanwhile finds
    no workspace to register for."""
    sandbox = _workspace(root, ENDED, stale=False)

    sessions.end_session(ENDED)

    (deleted,) = delete_reads_the_lock["deleted"]
    assert deleted != sandbox
    assert deleted.parent == root
    assert deleted.name.startswith("."), deleted.name
    assert ENDED in deleted.name
