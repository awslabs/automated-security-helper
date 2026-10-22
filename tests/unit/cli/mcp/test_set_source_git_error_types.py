# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every way set_source_git can fail says which, in ``error_type``.

Why this file exists
--------------------
set_source_git returns ``{"success": False, "error": str}`` with an ``error_type``
on every path, as the other MCP tools return a stable ``error_type`` for each
refusal, so a client can tell "this URL is refused" from "the clone failed" from
"the ref does not exist" without parsing git's English:
``clone_url_not_permitted``, ``clone_ref_not_permitted``,
``invalid_clone_depth``, ``scan_target_not_permitted``, ``invalid_session_id``,
``git_clone_failed`` and ``git_checkout_failed``.

``depth=0`` is documented as a full clone, and git refuses ``--depth 0``
("depth 0 is not a positive number"), so for ``depth=0`` the clone leaves the
option out.

git runs for real here, against repositories made in the test's temporary
directory and cloned over ``file://``. Nothing reaches the network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools

SESSION = "session-a"


@pytest.fixture(autouse=True)
def _workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "repos"))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _repo(tmp_path: Path, commits: int = 1) -> Path:
    repo = tmp_path / "repos" / "project"
    repo.mkdir(parents=True)
    _git("init", "-q", cwd=repo)
    for n in range(commits):
        (repo / "app.py").write_text(f"x = {n}\n", encoding="utf-8")
        _git("add", "app.py", cwd=repo)
        _git("commit", "-q", "-m", f"commit {n}", cwd=repo)
    return repo


def _clone(url: str, **kwargs):
    return mcp_tools.mcp_set_source_git(url=url, session_id=SESSION, **kwargs)


@pytest.mark.parametrize(
    "url",
    ["--upload-pack=touch /tmp/x", "ext::sh -c touch% /tmp/x"],
    ids=["option-like", "ext-transport"],
)
def test_a_url_that_makes_git_run_a_command(url):
    result = _clone(url)
    assert (result["success"], result.get("error_type")) == (
        False,
        "clone_url_not_permitted",
    ), result


def test_an_option_like_ref():
    result = _clone("https://example.invalid/repo.git", ref="--output=/tmp/x")
    assert result.get("error_type") == "clone_ref_not_permitted", result


def test_a_negative_depth():
    result = _clone("https://example.invalid/repo.git", depth=-1)
    assert result.get("error_type") == "invalid_clone_depth", result


def test_a_local_source_outside_the_scan_roots(tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    result = _clone(outside.as_uri())
    assert result.get("error_type") == "scan_target_not_permitted", result


def test_an_invalid_session_id():
    result = mcp_tools.mcp_set_source_git(
        url="https://example.invalid/repo.git", session_id="../escape"
    )
    assert result.get("error_type") == "invalid_session_id", result


def test_a_clone_git_refuses(tmp_path):
    not_a_repo = tmp_path / "repos" / "plain"
    not_a_repo.mkdir(parents=True)
    result = _clone(not_a_repo.as_uri())
    assert (result["success"], result.get("error_type")) == (
        False,
        "git_clone_failed",
    ), result
    assert "git clone failed" in result["error"]


def test_a_ref_that_does_not_exist(tmp_path):
    repo = _repo(tmp_path)
    result = _clone(repo.as_uri(), ref="no-such-branch")
    assert (result["success"], result.get("error_type")) == (
        False,
        "git_checkout_failed",
    ), result


def test_depth_zero_clones_the_full_history(tmp_path):
    repo = _repo(tmp_path, commits=3)
    result = _clone(repo.as_uri(), depth=0)
    assert result["success"] is True, result
    count = _git("rev-list", "--count", "HEAD", cwd=Path(result["source_dir"]))
    assert count.strip() == "3"


def test_the_default_depth_is_shallow(tmp_path):
    repo = _repo(tmp_path, commits=3)
    result = _clone(repo.as_uri())
    assert result["success"] is True, result
    count = _git("rev-list", "--count", "HEAD", cwd=Path(result["source_dir"]))
    assert count.strip() == "1"


def _session_source(tmp_path: Path) -> Path:
    return tmp_path / "workspaces" / SESSION / "source"


def test_git_that_cannot_be_run(tmp_path, monkeypatch):
    """No git on PATH: the clone fails as a clone, not as a FileNotFoundError."""
    repo = _repo(tmp_path)
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    result = _clone(repo.as_uri())

    assert (result["success"], result.get("error_type")) == (
        False,
        "git_clone_failed",
    ), result
    assert "git" in result["error"]
    assert not _session_source(tmp_path).exists(), "an empty clone target was left"


def test_git_that_cannot_be_run_for_the_checkout(tmp_path, monkeypatch):
    from automated_security_helper.cli.mcp import source_delivery

    repo = _repo(tmp_path)
    real_run = source_delivery._run_git

    def run(cmd, *args, **kwargs):
        if "checkout" in cmd:
            raise FileNotFoundError(2, "No such file or directory", "git")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(source_delivery, "_run_git", run)
    result = _clone(repo.as_uri(), ref="HEAD")

    assert (result["success"], result.get("error_type")) == (
        False,
        "git_checkout_failed",
    ), result
    assert not _session_source(tmp_path).exists()


@pytest.mark.asyncio
async def test_the_tool_reports_missing_git_in_its_vocabulary(tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server

    repo = _repo(tmp_path)
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    ctx = MagicMock(spec=Context)
    ctx.headers = {"mcp-session-id": SESSION}

    result = await mcp_server.set_source_git(ctx, url=repo.as_uri())

    assert result.get("error_type") == "git_clone_failed", result
