# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``set_source_git`` checks the clone depth before it creates anything.

The depth is a whole number of commits from 1 to ``MAX_CLONE_DEPTH``. Any other value
is refused with the module's refusal type, ``ValueError``, before the session
workspace or its ``source/`` directory is created, so a refused depth leaves nothing
behind and git never runs. The maximum is there because a depth larger than any
history is a full clone, which ``depth=0`` is refused for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

URL = "https://git.example.invalid/team/repo.git"
SESSION = "depth-session"
REFUSED = [0, -1, True, False, 1.5, "2", None, 2**31, 10**12]


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> Iterator[Path]:
    root = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.setattr(
        sd, "_run_git", lambda *a, **k: pytest.fail("git ran for a refused depth")
    )
    # A session already in the registry has its workspace already; each case
    # starts with none, so a refusal that takes the session is seen.
    reset_default_registry_for_tests()
    yield root
    reset_default_registry_for_tests()


@pytest.mark.parametrize("depth", REFUSED, ids=repr)
def test_a_refused_depth_creates_nothing(workspace, depth) -> None:
    with pytest.raises(ValueError, match="depth"):
        sd.set_source_git(url=URL, depth=depth, session_id=SESSION)

    assert not (workspace / SESSION).exists(), "a refused depth left a workspace"


@pytest.mark.parametrize("depth", REFUSED, ids=repr)
def test_the_tool_refuses_a_bad_depth_and_creates_nothing(workspace, depth) -> None:
    result = mcp_set_source_git(url=URL, depth=depth, session_id=SESSION)

    assert result.get("success") is False, result
    assert "depth" in result.get("error", ""), result
    assert not (workspace / SESSION).exists(), "a refused depth left a workspace"


def test_a_positive_depth_reaches_git(workspace, monkeypatch) -> None:
    calls = []

    class _Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def _record(cmd, **kwargs):
        calls.append(list(cmd))
        return _Done()

    monkeypatch.setattr(sd, "_run_git", _record)

    sd.set_source_git(url=URL, depth=3, session_id=SESSION)

    assert calls and calls[0][calls[0].index("--depth") + 1] == "3", calls


def test_the_maximum_depth_reaches_git(workspace, monkeypatch) -> None:
    """The boundary: the maximum itself is accepted and passed to git as given."""
    calls = []

    class _Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def _record(cmd, **kwargs):
        calls.append(list(cmd))
        return _Done()

    monkeypatch.setattr(sd, "_run_git", _record)

    sd.set_source_git(url=URL, depth=sd.MAX_CLONE_DEPTH, session_id=SESSION)

    clone = calls[0]
    assert clone[clone.index("--depth") + 1] == str(sd.MAX_CLONE_DEPTH), calls


def test_one_above_the_maximum_is_refused_and_creates_nothing(workspace) -> None:
    """The boundary: one more than the maximum is refused before anything is
    created, and the refusal names the maximum."""
    with pytest.raises(ValueError, match=str(sd.MAX_CLONE_DEPTH)):
        sd.set_source_git(url=URL, depth=sd.MAX_CLONE_DEPTH + 1, session_id=SESSION)

    assert not (workspace / SESSION).exists(), "a refused depth left a workspace"
