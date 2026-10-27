# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A git re-delivery that fails leaves the previously delivered tree as it was.

Why this file exists
--------------------
A zip re-delivery extracts into a staging directory and swaps it in once the new tree
is complete, so a refused archive costs the client nothing. A git re-delivery used
to rename the previous tree aside and delete it before it ran git. A mistyped ref
(``git_checkout_failed``), a network error or a timeout then left the session with
no source at all: its next scan was refused as ``delivered_source_missing`` until the
client delivered again, and the clone it had was gone for no reason.

What the code does now
----------------------
The clone goes into a staging directory of the delivery's own
(``.source.incoming-<id>``), and the previous tree is renamed aside only once the
clone, and the checkout of a ref, have worked. Anything that ends the delivery before
that point (git exits non-zero, git cannot be started, a command runs too long, the
staging directory cannot be deleted) leaves the previous tree whole at ``source/``,
the session's recorded source naming it, and nothing beside it but, at worst, a
staging directory the next delivery deletes.

How the tests work
------------------
``_run_git`` is a double (no process starts). It writes a marker file into the clone
target, so a test can tell the first delivery's tree from the second's, and it fails
the step a test names the way the test names. Each test starts with a first delivery
that succeeded, so the failure is a re-delivery.
"""

from __future__ import annotations

import errno
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_server import _resolve_omitted_source_dir
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

HOST = "git.example.invalid"
URL = f"https://{HOST}/team/repo.git"
GIT = "/opt/git/bin/git"
SESSION = "git-redelivery"


@pytest.fixture(autouse=True)
def delivery(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", HOST)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    # A refused rename is tried again after a short wait; the tests do not wait for
    # it. Only that wait is removed: stubbing time.sleep would stop it for every thread.
    monkeypatch.setattr(sd, "_RENAME_WAIT_SECONDS", 0)
    # The record of a delivered tree is kept per process; each test starts empty.
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    yield workspace
    reset_default_registry_for_tests()


def _git(marker: str, *, fail_at: Optional[str] = None, how: str = "exit") -> Any:
    """A ``_run_git`` double.

    The clone writes ``cloned.txt`` holding ``marker`` into its target. Every command
    works except ``fail_at``, which fails the way ``how`` says: ``exit`` (git answers
    128), ``cannot-start`` (the program cannot be started) or ``timeout`` (the command
    runs past its limit).
    """

    def run_git(cmd, *, env):
        name = next(part for part in cmd if part in ("clone", "fetch", "checkout"))
        if name == "clone":
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "cloned.txt").write_text(f"{marker}\n")
        if name != fail_at:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if how == "timeout":
            raise sd.GitTimeoutError(
                f"git {name} did not finish within 600 seconds and was stopped"
            )
        if how == "cannot-start":
            raise OSError(errno.ENOEXEC, "exec format error")
        return subprocess.CompletedProcess(cmd, 128, "", "fatal: early EOF")

    return run_git


def _deliver(monkeypatch, marker: str, **failure: Any) -> Dict[str, Any]:
    """Deliver with a ref, so the clone, the fetch and the checkout all run."""
    monkeypatch.setattr(sd, "_run_git", _git(marker, **failure))
    return mcp_set_source_git(url=URL, ref="release", session_id=SESSION)


def _scratch_beside_source(source: Path) -> list:
    return sorted(
        p.name for p in source.parent.iterdir() if p.name.startswith(".source.")
    )


def _the_previous_tree_stands(first: Dict[str, Any]) -> None:
    source = Path(first["source_dir"])
    assert (source / "cloned.txt").read_text() == "first\n"
    assert sorted(p.name for p in source.iterdir()) == ["cloned.txt"]
    assert sd.get_session_source_dir(SESSION) == source
    resolution = _resolve_omitted_source_dir(SESSION)
    assert resolution.error is None, resolution.error
    assert Path(resolution.source_dir) == source


@pytest.mark.parametrize(
    ("step", "how", "error_type"),
    [
        pytest.param("clone", "exit", "git_clone_failed", id="clone-fails"),
        pytest.param(
            "fetch", "cannot-start", "git_clone_failed", id="fetch-cannot-start"
        ),
        pytest.param("checkout", "exit", "git_checkout_failed", id="mistyped-ref"),
        pytest.param("clone", "timeout", "clone_timed_out", id="clone-times-out"),
        pytest.param("checkout", "timeout", "clone_timed_out", id="checkout-times-out"),
    ],
)
def test_a_failed_redelivery_leaves_the_previous_tree_and_record_as_they_were(
    monkeypatch, step, how, error_type
) -> None:
    first = _deliver(monkeypatch, "first")
    assert first["success"] is True, first

    second = _deliver(monkeypatch, "second", fail_at=step, how=how)

    assert second["success"] is False, second
    assert second["error_type"] == error_type, second
    _the_previous_tree_stands(first)
    assert _scratch_beside_source(Path(first["source_dir"])) == []


def test_the_previous_tree_is_still_there_while_git_runs(monkeypatch) -> None:
    """Fails on a delivery that moves the previous tree aside, and deletes it, before
    the clone has worked: at the moment git runs, the first tree and its record are
    gone, and a clone that then fails cannot give them back."""
    first = _deliver(monkeypatch, "first")
    source = Path(first["source_dir"])
    seen: Dict[str, Any] = {}
    run_git = _git("second")

    def watching_run_git(cmd, *, env):
        if "clone" in cmd:
            seen["previous_tree"] = (source / "cloned.txt").read_text()
            seen["record"] = sd.get_session_source_dir(SESSION)
        return run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", watching_run_git)

    second = mcp_set_source_git(url=URL, ref="release", session_id=SESSION)

    assert second["success"] is True, second
    assert seen == {"previous_tree": "first\n", "record": source}, seen


@pytest.mark.parametrize(
    ("step", "how", "error_type"),
    [
        pytest.param("clone", "exit", "git_clone_failed", id="clone-fails"),
        pytest.param(
            "fetch", "cannot-start", "git_clone_failed", id="fetch-cannot-start"
        ),
        pytest.param("checkout", "exit", "git_checkout_failed", id="mistyped-ref"),
    ],
)
def test_a_partial_clone_that_cannot_be_deleted_still_gets_git_s_error_and_keeps_the_tree(
    monkeypatch, step, how, error_type
) -> None:
    """The failed clone's staging directory resists deletion. The answer is still
    git's own ``error_type`` (a mistyped ref is ``git_checkout_failed``, not a
    workspace error), the directory is deleted once by the delivery and not once more
    by the step that failed, the previous tree stays whole and recorded, the leftover
    is logged once and deleted by the next delivery."""
    first = _deliver(monkeypatch, "first")
    source = Path(first["source_dir"])
    real_remove_tree = sd._remove_tree
    resist = {"yes": True}
    attempts: list = []

    def remove_tree(path) -> bool:
        if resist["yes"] and Path(path).name.startswith(sd._STAGING_DIR_PREFIX):
            attempts.append(Path(path).name)
            return False
        return real_remove_tree(path)

    logger = MagicMock()
    monkeypatch.setattr(sd, "_remove_tree", remove_tree)
    monkeypatch.setattr(sd, "_logger", logger)

    second = _deliver(monkeypatch, "second", fail_at=step, how=how)

    assert second["success"] is False, second
    assert second["error_type"] == error_type, second
    assert f"git {step}" in second["error"], second
    assert len(attempts) == 1, attempts
    _the_previous_tree_stands(first)
    leftovers = _scratch_beside_source(source)
    assert len(leftovers) == 1 and leftovers[0].startswith(sd._STAGING_DIR_PREFIX)
    assert (source.parent / leftovers[0] / "cloned.txt").read_text() == "second\n"
    logger.warning.assert_called_once()
    assert leftovers[0] in str(logger.warning.call_args)

    # The next delivery deletes what stayed, and replaces the tree.
    resist["yes"] = False
    third = _deliver(monkeypatch, "third")
    assert third["success"] is True, third
    assert (source / "cloned.txt").read_text() == "third\n"
    assert _scratch_beside_source(source) == []


def test_a_previous_tree_that_cannot_be_renamed_aside_stays(monkeypatch) -> None:
    """The clone worked and the previous tree cannot be set aside for it: the
    delivery ends with ``session_workspace_unavailable``, the previous tree and its
    record stay, and the clone's staging directory is deleted."""
    first = _deliver(monkeypatch, "first")
    real_rename = Path.rename

    def rename(path, target):
        if path.name == "source":
            raise OSError(errno.EBUSY, "device or resource busy")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)

    second = _deliver(monkeypatch, "second")

    assert second["success"] is False, second
    assert second["error_type"] == "session_workspace_unavailable", second
    assert "busy" in second["error"], second
    _the_previous_tree_stands(first)
    assert _scratch_beside_source(Path(first["source_dir"])) == []


def test_a_clone_that_cannot_be_moved_into_place_puts_the_previous_tree_back(
    monkeypatch,
) -> None:
    first = _deliver(monkeypatch, "first")
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith(sd._STAGING_DIR_PREFIX):
            raise OSError(errno.EBUSY, "device or resource busy")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)

    second = _deliver(monkeypatch, "second")

    assert second["success"] is False, second
    assert second["error_type"] == "session_workspace_unavailable", second
    _the_previous_tree_stands(first)
    assert _scratch_beside_source(Path(first["source_dir"])) == []


def test_control_a_redelivery_that_works_replaces_the_tree_and_leaves_no_scratch(
    monkeypatch,
) -> None:
    first = _deliver(monkeypatch, "first")
    source = Path(first["source_dir"])

    second = _deliver(monkeypatch, "second")

    assert second["success"] is True, second
    assert Path(second["source_dir"]) == source
    assert (source / "cloned.txt").read_text() == "second\n"
    assert sd.get_session_source_dir(SESSION) == source
    assert _scratch_beside_source(source) == []


@pytest.mark.parametrize("step", ["clone", "checkout"])
def test_control_a_first_delivery_that_fails_leaves_no_tree_and_no_record(
    monkeypatch, delivery, step
) -> None:
    failed = _deliver(monkeypatch, "first", fail_at=step)

    assert failed["success"] is False, failed
    session_dir = delivery / SESSION
    assert not (session_dir / "source").exists()
    assert [
        p.name for p in session_dir.iterdir() if p.name.startswith(".source.")
    ] == []
    assert sd.get_session_source_dir(SESSION) is None
