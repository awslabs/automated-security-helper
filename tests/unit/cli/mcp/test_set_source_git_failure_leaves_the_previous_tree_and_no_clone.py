# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``set_source_git`` that fails leaves the previous tree and no clone behind.

A delivery clones into a staging directory of its own, beside ``source/``, and swaps
the clone in once it has worked. Until then the session's recorded source names the
tree it was delivered with, and that tree is whole. A delivery that fails has to leave
both as they were, and has to take its staging directory away again: a clone of a ref
the caller did not ask for, or a half-made one, must never be what a later
``run_ash_scan()`` with no ``source_dir`` reads. With nothing delivered before, a
failed delivery leaves no ``source/`` at all.

A git that exits non-zero and a git command that runs too long are covered by
controls here. The tests cover the other ways a delivery can end: git cannot be
started, a command raises while it runs, a command raises after the clone has put a
tree on disk, and a step raises something no handler of the delivery names, with the
delete of the partial clone working and with it leaving entries behind. ``_run_git``
is replaced with a stand-in, so no git runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests

URL = "https://git.example.invalid/team/repo.git"
SESSION = "failed-delivery-session"
#: What ``_git_executable`` answers, so the delivery needs no git on this machine.
GIT = "/opt/git/bin/git"

_Run = Callable[..., "subprocess.CompletedProcess[str]"]


def _completed(
    cmd: Any, returncode: int = 0, stderr: str = ""
) -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess(cmd, returncode, "", stderr)


def _clone_that_writes(name: str) -> _Run:
    """A ``_run_git`` whose clone writes ``name`` into the target and whose other
    commands succeed."""

    def run(cmd: Any, *, env: Any) -> "subprocess.CompletedProcess[str]":
        if "clone" in cmd:
            (Path(cmd[-1]) / name).write_text("x = 1\n", encoding="utf-8")
        return _completed(cmd)

    return run


@pytest.fixture
def delivered(tmp_path, monkeypatch) -> Iterator[Path]:
    """A session that already holds a delivered tree; yields its ``source/``."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    reset_default_registry_for_tests()

    with patch.object(sd, "_run_git", side_effect=_clone_that_writes("old.py")):
        first = sd.set_source_git(url=URL, session_id=SESSION)
    source = tmp_path / "workspaces" / SESSION / "source"
    assert first == source
    assert (source / "old.py").is_file(), "the first delivery did not put a tree there"
    assert sd.get_session_source_dir(SESSION) == source

    yield source

    sd.remove_session_workspace(SESSION)
    reset_default_registry_for_tests()


def _scratch_beside(source: Path) -> list:
    return sorted(
        p.name for p in source.parent.iterdir() if p.name.startswith(".source.")
    )


def _assert_the_previous_delivery_stands(source: Path) -> None:
    """The first tree is whole, nothing of the failed clone is in it or beside it, and
    a scan with no ``source_dir`` reads it."""
    assert (source / "old.py").is_file(), "the previous tree was removed"
    assert [p.name for p in source.iterdir()] == ["old.py"], "the clone reached source/"
    assert _scratch_beside(source) == [], "the failed clone was left beside source/"
    assert sd.get_session_source_dir(SESSION) == source
    resolution = mcp_server._resolve_omitted_source_dir(SESSION)
    assert resolution.error is None, resolution
    assert Path(resolution.source_dir) == source, resolution


@pytest.mark.parametrize(
    ("failure", "raised"),
    [
        (OSError("git could not be started"), sd.GitCommandError),
        (ValueError("embedded null byte"), sd.GitCommandError),
    ],
    ids=["git-cannot-be-started", "git-refuses-an-argument"],
)
def test_a_command_that_raises_leaves_the_previous_tree(
    delivered, failure, raised
) -> None:
    with (
        patch.object(sd, "_run_git", side_effect=failure),
        pytest.raises(raised, match=str(failure)),
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    _assert_the_previous_delivery_stands(delivered)


def test_a_failure_after_the_clone_leaves_the_previous_tree(delivered) -> None:
    """The clone is of the default branch; the ref the caller asked for never arrived."""

    def run(cmd: Any, *, env: Any) -> "subprocess.CompletedProcess[str]":
        if "clone" in cmd:
            (Path(cmd[-1]) / "default_branch.py").write_text(
                "y = 2\n", encoding="utf-8"
            )
            return _completed(cmd)
        raise OSError("git went away after the clone")

    with (
        patch.object(sd, "_run_git", side_effect=run),
        pytest.raises(sd.GitCommandError, match="git went away after the clone"),
    ):
        sd.set_source_git(url=URL, ref="release", session_id=SESSION)

    _assert_the_previous_delivery_stands(delivered)


def test_a_scan_with_no_source_dir_reads_the_previous_tree_after_a_failed_delivery(
    delivered,
) -> None:
    with (
        patch.object(sd, "_run_git", side_effect=OSError("git could not be started")),
        pytest.raises(sd.GitCommandError, match="git could not be started"),
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    resolution = mcp_server._resolve_omitted_source_dir(SESSION)

    assert resolution.error is None, resolution
    assert Path(resolution.source_dir) == delivered, resolution


def test_control_a_git_that_exits_non_zero_leaves_the_previous_tree(delivered) -> None:
    def run(cmd: Any, *, env: Any) -> "subprocess.CompletedProcess[str]":
        return _completed(cmd, returncode=128, stderr="fatal: repository not found")

    with (
        patch.object(sd, "_run_git", side_effect=run),
        pytest.raises(sd.GitCommandError),
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    _assert_the_previous_delivery_stands(delivered)


def test_control_a_command_that_runs_too_long_leaves_the_previous_tree(
    delivered,
) -> None:
    with (
        patch.object(
            sd, "_run_git", side_effect=sd.GitTimeoutError("git clone did not finish")
        ),
        pytest.raises(sd.GitTimeoutError),
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    _assert_the_previous_delivery_stands(delivered)


def test_control_a_delivery_that_succeeds_replaces_the_tree(delivered) -> None:
    with patch.object(sd, "_run_git", side_effect=_clone_that_writes("new.py")):
        target = sd.set_source_git(url=URL, session_id=SESSION)

    assert target == delivered
    assert (delivered / "new.py").is_file()
    assert not (delivered / "old.py").exists()
    assert sd.get_session_source_dir(SESSION) == delivered
    assert _scratch_beside(delivered) == []


@pytest.mark.parametrize(
    "broken_step",
    ["_run_git", "_git_environment"],
    ids=["a-git-command", "the-git-environment"],
)
def test_an_error_no_handler_names_leaves_the_previous_tree(
    delivered, broken_step
) -> None:
    """The step raises something the delivery has no handler for; it is raised as it was."""

    failure = RuntimeError("an error the delivery does not expect")

    with (
        patch.object(sd, broken_step, side_effect=failure),
        pytest.raises(RuntimeError) as raised,
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    assert raised.value is failure
    _assert_the_previous_delivery_stands(delivered)


def test_an_error_no_handler_names_after_the_clone_leaves_the_previous_tree(
    delivered,
) -> None:
    """The clone is of the default branch; the step after it raises what no handler names."""

    failure = RuntimeError("an error the delivery does not expect")

    def run(cmd: Any, *, env: Any) -> "subprocess.CompletedProcess[str]":
        if "clone" in cmd:
            (Path(cmd[-1]) / "default_branch.py").write_text(
                "y = 2\n", encoding="utf-8"
            )
            return _completed(cmd)
        raise failure

    with (
        patch.object(sd, "_run_git", side_effect=run),
        pytest.raises(RuntimeError) as raised,
    ):
        sd.set_source_git(url=URL, ref="release", session_id=SESSION)

    assert raised.value is failure
    _assert_the_previous_delivery_stands(delivered)


def test_a_partial_clone_that_cannot_be_deleted_never_reaches_source(delivered) -> None:
    """A delete that leaves entries behind leaves them in the clone's staging
    directory, under a name the next delivery deletes, and never at ``source/``."""

    failure = RuntimeError("an error the delivery does not expect")
    remove_tree = sd._remove_tree

    def clone_that_leaves_a_file_then_fails(
        url: str, ref: Any, *, depth: int, target: Path, env: Any, git: Any = None
    ) -> None:
        (target / "partial.py").write_text("p = 1\n", encoding="utf-8")
        raise failure

    def delete_that_leaves_entries(path: Path) -> bool:
        # The partial clone stays where it is; every other tree is deleted.
        staging = path.name.startswith(sd._STAGING_DIR_PREFIX)
        return False if staging else remove_tree(path)

    with (
        patch.object(sd, "_clone", side_effect=clone_that_leaves_a_file_then_fails),
        patch.object(sd, "_remove_tree", side_effect=delete_that_leaves_entries),
        pytest.raises(RuntimeError) as raised,
    ):
        sd.set_source_git(url=URL, session_id=SESSION)

    assert raised.value is failure
    assert (delivered / "old.py").is_file(), "the previous tree was removed"
    assert [p.name for p in delivered.iterdir()] == ["old.py"]
    leftovers = _scratch_beside(delivered)
    assert len(leftovers) == 1 and leftovers[0].startswith(sd._STAGING_DIR_PREFIX)
    assert (delivered.parent / leftovers[0] / "partial.py").is_file()
    assert sd.get_session_source_dir(SESSION) == delivered
    resolution = mcp_server._resolve_omitted_source_dir(SESSION)
    assert resolution.error is None, resolution
