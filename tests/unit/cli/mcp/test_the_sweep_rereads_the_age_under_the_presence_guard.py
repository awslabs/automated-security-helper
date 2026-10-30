# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep reads a workspace's age again under the presence guard.

A scan of a session in another server sharing the workspace root ends in two
steps, in this order (``sessions.ScanPresence.__exit__``): it touches the
workspace, then takes the presence guard and drops its entry. A sweep in this
server that read the workspace's age before it took the guard, and was let in
right after that scan dropped its entry, saw a stale age and sees no entry: the
one check that was meant to keep a scanned workspace reads clear on both counts,
and the results the scan just wrote are removed.

The sweep now reads the age again under the guard, after the entry check. The
other scan always touches before it can drop its entry under that guard, so the
second read sees the touch whenever the first read missed it.

The other server's scan ending between the two checks is stood in for by the
entry check itself: ``_a_scan_holds`` is called under the guard, and a stand-in
that touches the workspace before answering False puts the touch exactly where
the real scan's end puts it, after the sweep's first age read and before its
removal.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator, List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

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


def _stale_workspace(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    then = time.time() - 3600
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    return sandbox


def test_a_workspace_touched_before_the_guard_was_taken_is_kept(
    root: Path, monkeypatch
) -> None:
    """The other scan's end, between the sweep's first age read and its guard:
    the workspace is touched and the entry is gone. The sweep keeps it."""
    stale = _stale_workspace(root, STALE)
    checked: List[Path] = []

    def ended_meanwhile(holder: Path) -> bool:
        checked.append(holder)
        os.utime(stale, None)  # the scan's end touched it, then dropped its entry
        return False

    monkeypatch.setattr(sessions, "_a_scan_holds", ended_meanwhile)

    removed = sessions.sweep_stale_workspaces(1.0)

    assert checked == [root / sessions.SCAN_PRESENCE_DIR / STALE], (
        "the sweep never reached the entry check"
    )
    assert removed == [], "the sweep removed a workspace a scan had just used"
    assert stale.is_dir()
    assert (stale / "source" / "app.py").is_file()


def test_a_workspace_still_stale_under_the_guard_is_removed(
    root: Path, monkeypatch
) -> None:
    """The control: no scan ended meanwhile, the age under the guard is the
    age read before it, and the removal goes on."""
    stale = _stale_workspace(root, STALE)

    monkeypatch.setattr(sessions, "_a_scan_holds", lambda holder: False)

    removed = sessions.sweep_stale_workspaces(1.0)

    assert removed == [STALE]
    assert not stale.exists()


def test_the_next_sweep_removes_the_kept_workspace_once_it_is_stale_again(
    root: Path, monkeypatch
) -> None:
    """Keeping the workspace costs one more TTL, not the workspace: a sweep
    after it has aged again removes it."""
    stale = _stale_workspace(root, STALE)
    touched_once = {"done": False}

    def ends_once(holder: Path) -> bool:
        if not touched_once["done"]:
            touched_once["done"] = True
            os.utime(stale, None)
        return False

    monkeypatch.setattr(sessions, "_a_scan_holds", ends_once)

    first = sessions.sweep_stale_workspaces(1.0)
    then = time.time() - 3600
    for path in (stale, *stale.iterdir()):
        os.utime(path, (then, then))
    second = sessions.sweep_stale_workspaces(1.0)

    assert (first, second) == ([], [STALE])
    assert not stale.exists()
