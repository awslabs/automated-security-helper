# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A git that cannot be run fails the delivery at the clone and at the fetch.

``test_a_checkout_git_cannot_start_is_a_failed_checkout.py`` pins the checkout.
The clone and the fetch have the same condition and, without a handler, the same
outcome: the ``OSError`` from starting git leaves ``_clone`` as it is, the tree
stays on disk, and the tool answers with the exception's class name, not an
``error_type`` a client can branch on.

- At the clone, the directory the delivery made for it (``_clone_into_session``
  makes it before the clone runs) is removed, and the answer is
  ``git_clone_failed``, as for a git that is not on PATH.
- At the fetch, a git that cannot be run is not a fetch that exits non-zero. A
  non-zero fetch is tolerated, because the clone may already hold the ref; a git
  that cannot be started tells nothing about that. The clone is removed and the
  answer is ``git_clone_failed``: the tool reference names no fetch-specific
  ``error_type``.

The tests run the delivery as the tool does, through ``_clone_into_session``, with
a fixture repository cloned over ``file://`` (``protocol.file.allow=always`` is
added to ``_GIT_ARGV``, as the other tests of the clone step do). Only the step
under test is replaced, by a runner that cannot start git.
"""

from __future__ import annotations

import errno
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.integration

#: Not a session id another test delivers to: the record of a delivered source is
#: kept per process, and these tests read it.
SESSION = "session-cloneoserr2"

#: What starting a program can raise, as factories so no test raises an instance
#: another test raised: it is gone, it is not executable, the host cannot make
#: another process. Every one is an OSError, and only the first is a
#: FileNotFoundError.
CANNOT_START: List[Any] = [
    pytest.param(
        lambda: FileNotFoundError(errno.ENOENT, "No such file or directory", "git"),
        id="program-gone",
    ),
    pytest.param(
        lambda: PermissionError(errno.EACCES, "Permission denied", "git"),
        id="not-executable",
    ),
    pytest.param(
        lambda: OSError(errno.ENOMEM, "Cannot allocate memory"),
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
    """A repository with ``main`` at one commit, and where its delivery lands."""
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
    return {
        "url": repo.as_uri(),
        "workspace": workspace,
        "source": workspace / SESSION / "source",
    }


def _deliver(delivery: Dict[str, Any], ref: str | None, url: str | None = None) -> Path:
    """The delivery ``set_source_git`` runs once the url, ref and depth are accepted."""
    return sd._clone_into_session(
        url if url is not None else delivery["url"],
        ref,
        depth=1,
        workspace_root=delivery["workspace"],
        session_id=SESSION,
    )


def _subcommand(cmd: List[str]) -> str:
    return next(part for part in cmd if part in ("clone", "fetch", "checkout"))


def _left_by_the_delivery(delivery: Dict[str, Any]) -> List[str]:
    """The tree and the staging directories a failed delivery must not leave."""
    session_dir = delivery["source"].parent
    return sorted(
        p.name
        for p in session_dir.iterdir()
        if p.name == "source" or p.name.startswith(".source.")
    )


@pytest.mark.parametrize("step", ["clone", "fetch"])
@pytest.mark.parametrize("make_error", CANNOT_START)
def test_git_that_cannot_be_run_for_a_step_fails_the_delivery_as_a_failed_clone(
    delivery, monkeypatch, step, make_error
) -> None:
    error = make_error()
    real_run_git = sd._run_git
    on_disk_when_git_failed: List[bool] = []

    def run_git(cmd, *, env):
        if _subcommand(cmd) == step:
            # What the delivery has to remove: the staging directory it made
            # before the clone (the last argument of `git clone`), and at the fetch
            # the clone in it (`git -C <staging> fetch`).
            if step == "clone":
                on_disk_when_git_failed.append(Path(cmd[-1]).is_dir())
            else:
                staging = Path(cmd[cmd.index("-C") + 1])
                on_disk_when_git_failed.append((staging / "a.py").is_file())
            raise error
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    with pytest.raises(sd.GitCommandError) as failed:
        _deliver(delivery, "main")

    # The tree was there when git could not be run, so "no tree" below means the
    # delivery removed it rather than that it was never made.
    assert on_disk_when_git_failed == [True]
    assert failed.value.error_type == "git_clone_failed"
    assert f"git {step}" in str(failed.value)
    assert error.strerror in str(failed.value)
    assert _left_by_the_delivery(delivery) == [], f"the failed {step} left its tree"
    assert sd.get_session_source_dir(SESSION) is None


def test_a_clone_that_git_refuses_has_the_same_type_and_leaves_no_tree(
    delivery,
) -> None:
    """The control: git starts, runs the clone and fails it."""
    with pytest.raises(sd.GitCommandError) as refused:
        _deliver(delivery, None, url=delivery["url"] + "-missing")

    assert refused.value.error_type == "git_clone_failed"
    assert "exit" in str(refused.value)
    assert _left_by_the_delivery(delivery) == [], "the failed clone left its tree"


def test_a_fetch_that_exits_non_zero_is_still_tolerated(delivery, monkeypatch) -> None:
    """The control for the fetch: a fetch git ran and failed leaves the checkout to
    find the ref in the clone, as before."""
    real_run_git = sd._run_git
    ran: List[str] = []

    def run_git(cmd, *, env):
        step = _subcommand(cmd)
        ran.append(step)
        if step == "fetch":
            return subprocess.CompletedProcess(
                cmd, 128, "", "fatal: could not read from remote repository"
            )
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    delivered = _deliver(delivery, "main")

    assert ran == ["clone", "fetch", "checkout"]
    assert delivered == delivery["source"]
    assert (delivered / "a.py").is_file()
    assert sd.get_session_source_dir(SESSION) == delivered


def test_a_delivery_git_can_run_for_is_delivered(delivery, monkeypatch) -> None:
    """The control for the runner above: wrapped, with nothing raised, it delivers."""
    real_run_git = sd._run_git
    ran: List[str] = []

    def run_git(cmd, *, env):
        ran.append(_subcommand(cmd))
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    delivered = _deliver(delivery, "main")

    assert ran == ["clone", "fetch", "checkout"]
    assert (delivered / "a.py").is_file()


@pytest.mark.parametrize("step", ["clone", "fetch"])
def test_a_step_that_runs_past_its_time_is_still_a_timeout(
    delivery, monkeypatch, step
) -> None:
    """Catching the error of starting git does not take over the timeout's."""
    real_run_git = sd._run_git

    def run_git(cmd, *, env):
        if _subcommand(cmd) == step:
            raise sd.GitTimeoutError(f"git {step} did not finish and was stopped")
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    with pytest.raises(sd.GitTimeoutError):
        _deliver(delivery, "main")

    assert _left_by_the_delivery(delivery) == [], f"the timed-out {step} left its tree"
