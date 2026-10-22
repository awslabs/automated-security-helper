# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The git commands of ``set_source_git`` start no program a repository's config names.

A delivery runs up to three git commands: the clone, and for a ref a fetch and a
checkout inside the new clone. Two settings make git start a program:

- ``core.fsmonitor``, which git runs when it refreshes the index;
- hooks, from ``core.hooksPath`` or the clone's ``.git/hooks``, which git runs on
  checkout and on ref updates.

Every command of a delivery is built by ``utils/git_command.git_argv``, which puts
``-c core.fsmonitor=false`` and ``-c core.hooksPath=/dev/null`` ahead of the
subcommand. There they outrank the repository's config, and nothing is written into
the clone's ``.git/config``.

The tests clone a local fixture repository, so ``_GIT_ARGV`` is extended with
``protocol.file.allow=always``. It also names an ``init.templateDir`` whose
``post-checkout`` hook leaves a marker, so the clone itself has a hook to run.
After the clone, the fixture sets a repo-local ``core.fsmonitor`` and
``core.hooksPath`` in the new clone, for the fetch and the checkout. The controls
run the same delivery with one of the two options left out and find its marker.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.utils import git_command

FSMONITOR = ("-c", "core.fsmonitor=false")
HOOKS_PATH = ("-c", "core.hooksPath=/dev/null")


def _git_env(home: Path) -> Dict[str, str]:
    """The fixture's own git environment: no host config decides the outcome."""
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


def _git(args: List[str], cwd: Path, env: Dict[str, str]) -> str:
    result = subprocess.run(  # nosec B603 -- list argv, fixture repository only
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _hook(directory: Path, name: str, marker: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    hook = directory / name
    hook.write_text(
        f"#!/bin/sh\necho ran >> {shlex.quote(marker.as_posix())}\n", encoding="utf-8"
    )
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)


def _marks(marker: Path) -> int:
    return marker.read_text(encoding="utf-8").count("ran") if marker.exists() else 0


class _Fixture:
    def __init__(self, tmp_path: Path) -> None:
        self.env = _git_env(tmp_path / "fixture-home")
        (tmp_path / "fixture-home").mkdir()
        self.source = tmp_path / "source"
        self.source.mkdir()
        _git(["init", "-q", "-b", "main"], self.source, self.env)
        (self.source / "a.py").write_text("a = 1\n", encoding="utf-8")
        _git(["add", "a.py"], self.source, self.env)
        _git(["commit", "-q", "-m", "one"], self.source, self.env)
        _git(["checkout", "-q", "-b", "feature"], self.source, self.env)
        (self.source / "b.py").write_text("b = 2\n", encoding="utf-8")
        _git(["add", "b.py"], self.source, self.env)
        _git(["commit", "-q", "-m", "two"], self.source, self.env)
        _git(["checkout", "-q", "main"], self.source, self.env)

        self.clone_hook_ran = tmp_path / "clone-hook-ran.txt"
        self.repo_hook_ran = tmp_path / "repo-hook-ran.txt"
        self.fsmonitor_ran = tmp_path / "fsmonitor-ran.txt"
        self.template = tmp_path / "template"
        _hook(self.template / "hooks", "post-checkout", self.clone_hook_ran)
        self.repo_hooks = tmp_path / "repo-hooks"
        for name in ("post-checkout", "reference-transaction"):
            _hook(self.repo_hooks, name, self.repo_hook_ran)

        self.home = tmp_path / "session-home"
        self.home.mkdir()
        self.target = tmp_path / "session-home" / "source"

    def arm_the_clone(self, target: Path) -> None:
        """Give the new clone a repo-local fsmonitor and hooks directory."""
        command = f"echo ran >> {shlex.quote(self.fsmonitor_ran.as_posix())}; false"
        _git(["config", "core.fsmonitor", command], target, self.env)
        _git(["config", "core.hooksPath", str(self.repo_hooks)], target, self.env)


@pytest.fixture
def fixture(tmp_path, monkeypatch) -> _Fixture:
    built = _Fixture(tmp_path)
    monkeypatch.setattr(
        sd,
        "_GIT_ARGV",
        (
            "git",
            "-c",
            "protocol.file.allow=always",
            "-c",
            f"init.templateDir={built.template}",
        ),
    )
    real_run_git = sd._run_git

    def run_git(cmd, *, env, grows_in=None):
        result = real_run_git(cmd, env=env, grows_in=grows_in)
        if "clone" in cmd and result.returncode == 0:
            built.arm_the_clone(Path(cmd[-1]))
        return result

    monkeypatch.setattr(sd, "_run_git", run_git)
    return built


def _deliver(fixture: _Fixture) -> None:
    # A ref, so the delivery runs all three commands.
    sd._clone(
        fixture.source.as_uri(),
        "main",
        depth=1,
        target=fixture.target,
        env=sd._git_environment(fixture.home),
    )


def test_a_delivery_runs_no_hook_and_no_fsmonitor(fixture) -> None:
    _deliver(fixture)

    assert (fixture.target / "a.py").is_file(), "the ref was not checked out"
    assert _marks(fixture.clone_hook_ran) == 0, "the clone ran a hook"
    assert _marks(fixture.repo_hook_ran) == 0, "the fetch or checkout ran a hook"
    assert _marks(fixture.fsmonitor_ran) == 0, "a command ran the fsmonitor"


def _leave_out(monkeypatch, option) -> None:
    """Build the delivery's git commands without one of git_argv's two options."""
    options = list(git_command.GIT_SAFETY_OPTIONS)
    index = next(
        i for i in range(len(options) - 1) if options[i : i + 2] == list(option)
    )
    monkeypatch.setattr(
        git_command,
        "GIT_SAFETY_OPTIONS",
        tuple(options[:index] + options[index + 2 :]),
    )


def test_without_the_hooks_option_the_hooks_run(fixture, monkeypatch) -> None:
    """The control for the hooks: the same delivery without core.hooksPath."""
    _leave_out(monkeypatch, HOOKS_PATH)

    _deliver(fixture)

    assert _marks(fixture.clone_hook_ran) > 0
    assert _marks(fixture.repo_hook_ran) > 0


def test_without_the_fsmonitor_option_the_fsmonitor_runs(fixture, monkeypatch) -> None:
    """The control for the fsmonitor: the same delivery without core.fsmonitor."""
    _leave_out(monkeypatch, FSMONITOR)

    _deliver(fixture)

    assert _marks(fixture.fsmonitor_ran) > 0


def test_the_options_precede_every_subcommand_and_stay_off_the_clone(
    fixture, monkeypatch
) -> None:
    seen: List[List[str]] = []
    run_git = sd._run_git

    def recording(cmd, *, env, grows_in=None):
        seen.append(list(cmd))
        return run_git(cmd, env=env, grows_in=grows_in)

    monkeypatch.setattr(sd, "_run_git", recording)

    _deliver(fixture)

    subcommands = [
        next(part for part in cmd if part in ("clone", "fetch", "checkout"))
        for cmd in seen
    ]
    assert subcommands == ["clone", "fetch", "checkout"]
    for cmd, subcommand in zip(seen, subcommands):
        before = cmd[: cmd.index(subcommand)]
        for option in (FSMONITOR, HOOKS_PATH):
            pairs = [tuple(before[i : i + 2]) for i in range(len(before) - 1)]
            assert option in pairs, (subcommand, cmd)
    local = (fixture.target / ".git" / "config").read_text(encoding="utf-8")
    assert "/dev/null" not in local and "fsmonitor = false" not in local, local
