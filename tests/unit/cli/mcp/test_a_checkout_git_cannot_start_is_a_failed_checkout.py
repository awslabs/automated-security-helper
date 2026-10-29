# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A checkout that git cannot be started for is a failed checkout.

When git runs the checkout and refuses it, the delivery deletes its staging directory
and raises ``GitCommandError`` with ``error_type`` ``git_checkout_failed``, which is
what the MCP tool answers a client. A checkout that git cannot be started for at all
(the program was removed after the clone ran, it is not executable, the host has no
process to give) is the same failure to the client: no tree, and
``git_checkout_failed``. Without that, the ``OSError`` from starting git leaves
``_clone`` as it is, the clone stays on disk, and the tool answers with the
exception's class name, which is not an ``error_type`` a client can branch on.

The clone and the fetch are real: a fixture repository cloned over ``file://``, with
``protocol.file.allow=always`` added to ``_GIT_ARGV`` as the other tests of the clone
step do. Only the checkout is replaced, by a runner that cannot start git. The
delivery under test is ``_clone_into_session``, which owns the staging directory the
clone is made in and deletes it when the delivery fails.
"""

from __future__ import annotations

import errno
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

SESSION = "checkout-cannot-start"

#: What starting a program can raise: it is gone, it is not executable, the host
#: cannot make another process. Every one is an OSError, and only the first is a
#: FileNotFoundError.
CANNOT_START = [
    pytest.param(
        FileNotFoundError(errno.ENOENT, "No such file or directory", "git"),
        id="program-gone",
    ),
    pytest.param(
        PermissionError(errno.EACCES, "Permission denied", "git"),
        id="not-executable",
    ),
    pytest.param(
        OSError(errno.ENOMEM, "Cannot allocate memory"),
        id="no-memory-for-a-process",
    ),
]


def _git_env(home: Path) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
    )
    return env


def _git(args: List[str], cwd: Path, env: Dict[str, str]) -> None:
    result = subprocess.run(  # nosec B603 -- list argv, fixture repository only
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture
def delivery(tmp_path, monkeypatch) -> Dict[str, Any]:
    """A repository with ``main`` at one commit, and the paths to deliver it to."""
    home = tmp_path / "fixture-home"
    home.mkdir()
    env = _git_env(home)
    repo = tmp_path / "source"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo, env)
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    _git(["add", "a.py"], repo, env)
    _git(["commit", "-q", "-m", "one"], repo, env)
    monkeypatch.setattr(sd, "_GIT_ARGV", ("git", "-c", "protocol.file.allow=always"))
    workspace = tmp_path / "workspaces"
    workspace.mkdir()
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    return {
        "url": repo.as_uri(),
        "workspace": workspace,
        "source": workspace / SESSION / "source",
    }


def _deliver(delivery: Dict[str, Any], ref: str) -> Path:
    """The clone, the fetch and the checkout of ``ref``, as ``set_source_git`` runs them."""
    return sd._clone_into_session(
        delivery["url"],
        ref,
        depth=1,
        workspace_root=delivery["workspace"],
        session_id=SESSION,
    )


def _subcommand(cmd: List[str]) -> str:
    return next(part for part in cmd if part in ("clone", "fetch", "checkout"))


def _nothing_left(delivery: Dict[str, Any]) -> List[str]:
    """The tree and the scratch a failed delivery must not leave in the session."""
    session_dir = delivery["workspace"] / SESSION
    return sorted(
        p.name
        for p in session_dir.iterdir()
        if p.name == "source" or p.name.startswith(".source.")
    )


@pytest.mark.parametrize("error", CANNOT_START)
def test_git_that_cannot_be_started_for_the_checkout_is_a_failed_checkout(
    delivery, monkeypatch, error
) -> None:
    real_run_git = sd._run_git
    clone_on_disk_at_the_checkout: List[bool] = []

    def run_git(cmd, *, env):
        if _subcommand(cmd) == "checkout":
            # The checkout runs in the staging directory: `git -C <dir> checkout`.
            staging = Path(cmd[cmd.index("-C") + 1])
            clone_on_disk_at_the_checkout.append((staging / "a.py").is_file())
            raise error
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    with pytest.raises(sd.GitCommandError) as failed:
        _deliver(delivery, "main")

    # The clone was there when git could not be started, so "no tree" below means
    # the delivery removed it rather than that it was never made.
    assert clone_on_disk_at_the_checkout == [True]
    assert failed.value.error_type == "git_checkout_failed"
    assert "checkout" in str(failed.value)
    assert error.strerror in str(failed.value)
    assert _nothing_left(delivery) == [], "the failed checkout left its clone"


def test_a_checkout_that_git_refuses_has_the_same_type_and_leaves_no_tree(
    delivery,
) -> None:
    """The control: git starts, runs the checkout and fails it."""
    with pytest.raises(sd.GitCommandError) as refused:
        _deliver(delivery, "no-such-branch")

    assert refused.value.error_type == "git_checkout_failed"
    assert "exit" in str(refused.value)
    assert _nothing_left(delivery) == [], "the failed checkout left its clone"


def test_a_checkout_that_git_can_start_for_is_delivered(delivery, monkeypatch) -> None:
    """The control for the runner above: wrapped, with nothing raised, it delivers."""
    real_run_git = sd._run_git
    ran: List[str] = []

    def run_git(cmd, *, env):
        ran.append(_subcommand(cmd))
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    delivered = _deliver(delivery, "main")

    assert ran == ["clone", "fetch", "checkout"]
    assert delivered == delivery["source"]
    assert (delivered / "a.py").is_file()


def test_a_checkout_that_runs_past_its_time_is_still_a_timeout(
    delivery, monkeypatch
) -> None:
    """Catching the error of starting git does not take over the timeout's."""
    real_run_git = sd._run_git

    def run_git(cmd, *, env):
        if _subcommand(cmd) == "checkout":
            raise sd.GitTimeoutError("git checkout did not finish and was stopped")
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    with pytest.raises(sd.GitTimeoutError):
        _deliver(delivery, "main")

    assert _nothing_left(delivery) == [], "the timed-out checkout left its clone"
