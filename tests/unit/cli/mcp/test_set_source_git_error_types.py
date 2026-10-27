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
``invalid_clone_depth``, ``local_clone_source_refused``,
``clone_host_not_permitted``, ``invalid_session_id``, ``git_clone_failed`` and
``git_checkout_failed``.

The depth is a whole number of commits from 1 to ``MAX_CLONE_DEPTH``. ``depth=0`` is
refused as ``invalid_clone_depth`` before anything is created, like a negative one:
git itself refuses ``--depth 0`` ("depth 0 is not a positive number"), and a full
clone of an arbitrary repository is not something a delivery to a session's
workspace offers. A depth above the maximum is refused the same way, because a depth
larger than any history is a full clone by another name.

git runs for real here, against repositories made in the test's temporary
directory and cloned over ``file://`` (the tool refuses a local source, so the
tests give it REMOTE and swap the file url in below its checks; see
``_real_git_at``). Nothing reaches the network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery

SESSION = "session-a"
#: The remote the tool is given. set_source_git clones from a remote https or ssh
#: url on a host the operator listed, and from nothing else; the tests that run
#: git for real point that url at a repository in the temporary directory from
#: inside the command the tool runs (``_real_git_at``), below the tool's checks.
HOST = "git.example.invalid"
REMOTE = f"https://{HOST}/project.git"


@pytest.fixture(autouse=True)
def _workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "repos"))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", f"{HOST} example.invalid")
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _real_git_at(monkeypatch, local: Path) -> None:
    """Run every git command of the delivery for real, against ``local``.

    The tool validates REMOTE and builds its commands with it; this swaps the
    fixture repository's file:// url in for REMOTE in the argv git is started
    with, and lets git read the file protocol the delivery's own ``-c
    protocol.allow=never`` would otherwise refuse. Nothing above ``_run_git``
    sees a local source, so the tool's refusal of one is still measured by
    ``test_a_local_source_outside_the_scan_roots``.
    """
    real_run = source_delivery._run_git

    def run(cmd, *args, **kwargs):
        argv = [local.as_uri() if part == REMOTE else part for part in cmd]
        argv[1:1] = ["-c", "protocol.file.allow=always"]
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(source_delivery, "_run_git", run)


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


@pytest.mark.parametrize("depth", [1_000_001, 2**31, 10**12], ids=repr)
def test_a_depth_above_the_maximum_is_refused_like_one_below_one(tmp_path, depth):
    """Fails on a depth with no upper bound: ``depth=2**31`` was accepted and
    cloned the whole history, the full clone that ``depth=0`` is refused for."""
    result = _clone("https://example.invalid/repo.git", depth=depth)
    assert (result["success"], result.get("error_type")) == (
        False,
        "invalid_clone_depth",
    ), result
    assert str(source_delivery.MAX_CLONE_DEPTH) in result["error"], result
    assert not (tmp_path / "workspaces" / SESSION).exists()


def test_the_depth_just_above_the_maximum_is_refused(tmp_path):
    result = _clone(
        "https://example.invalid/repo.git", depth=source_delivery.MAX_CLONE_DEPTH + 1
    )
    assert result.get("error_type") == "invalid_clone_depth", result
    assert not (tmp_path / "workspaces" / SESSION).exists()


def test_a_local_source_outside_the_scan_roots(tmp_path):
    """A local source is refused whatever the scan roots allow: the tool clones
    from a remote only, so the refusal names the local source, not the roots."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    result = _clone(outside.as_uri())
    assert result.get("error_type") == "local_clone_source_refused", result


def test_an_invalid_session_id():
    result = mcp_tools.mcp_set_source_git(
        url="https://example.invalid/repo.git", session_id="../escape"
    )
    assert result.get("error_type") == "invalid_session_id", result


def test_a_clone_git_refuses(tmp_path, monkeypatch):
    not_a_repo = tmp_path / "repos" / "plain"
    not_a_repo.mkdir(parents=True)
    _real_git_at(monkeypatch, not_a_repo)
    result = _clone(REMOTE)
    assert (result["success"], result.get("error_type")) == (
        False,
        "git_clone_failed",
    ), result
    assert "git clone failed" in result["error"]


def test_a_ref_that_does_not_exist(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _real_git_at(monkeypatch, repo)
    result = _clone(REMOTE, ref="no-such-branch")
    assert (result["success"], result.get("error_type")) == (
        False,
        "git_checkout_failed",
    ), result


@pytest.mark.parametrize("depth", [0, -1])
def test_a_depth_that_is_not_a_positive_number_is_refused(tmp_path, depth):
    """The refusal comes before anything is created for the session, and git does not
    run."""
    result = _clone("https://example.invalid/repo.git", depth=depth)
    assert (result["success"], result.get("error_type")) == (
        False,
        "invalid_clone_depth",
    ), result
    assert "depth" in result["error"], result
    assert not (tmp_path / "workspaces" / SESSION).exists()


def test_the_default_depth_is_shallow(tmp_path, monkeypatch):
    repo = _repo(tmp_path, commits=3)
    _real_git_at(monkeypatch, repo)
    result = _clone(REMOTE)
    assert result["success"] is True, result
    count = _git("rev-list", "--count", "HEAD", cwd=Path(result["source_dir"]))
    assert count.strip() == "1"


def _session_source(tmp_path: Path) -> Path:
    return tmp_path / "workspaces" / SESSION / "source"


def test_git_that_cannot_be_run(tmp_path, monkeypatch):
    """No git on PATH: the clone fails as a clone, not as a FileNotFoundError."""
    _repo(tmp_path)
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    result = _clone(REMOTE)

    assert (result["success"], result.get("error_type")) == (
        False,
        "git_clone_failed",
    ), result
    assert "git" in result["error"]
    assert not _session_source(tmp_path).exists(), "an empty clone target was left"


def test_git_that_cannot_be_run_for_the_checkout(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _real_git_at(monkeypatch, repo)
    real_run = source_delivery._run_git

    def run(cmd, *args, **kwargs):
        if "checkout" in cmd:
            raise FileNotFoundError(2, "No such file or directory", "git")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(source_delivery, "_run_git", run)
    result = _clone(REMOTE, ref="HEAD")

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

    _repo(tmp_path)
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    ctx = MagicMock(spec=Context)
    ctx.headers = {"mcp-session-id": SESSION}

    result = await mcp_server.set_source_git(ctx, url=REMOTE)

    assert result.get("error_type") == "git_clone_failed", result
