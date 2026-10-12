# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Git commands ASH runs do not start programs the repository's config names.

ASH runs git inside the directory it scans (``get_scan_set`` asks for the
repository root and for the files changed since a base ref). That directory's
``.git/config`` belongs to whoever wrote the repository, and two of its settings
make git start a program:

- ``core.fsmonitor``: git runs it whenever it refreshes the index. Measured with
  git 2.50.1: ``git status``, ``git ls-files`` and ``git diff`` against the working
  tree run it; ``git rev-parse --show-toplevel`` and ``git diff A...B`` do not.
- ``core.hooksPath``: the directory git runs hooks from, on checkout, commit,
  merge and others.

Every git command ASH runs is built by ``utils/git_command.git_argv``, which turns
both off on the command line, where they outrank the repository's config. The
tests here set each one to a command that leaves a marker, prove with plain git
that the marker mechanism works, and then show that ASH's commands leave none.
The last test keeps new call sites from starting git some other way.
"""

from __future__ import annotations

import ast
import os
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    get_changed_files,
    git_repository_root,
)
from automated_security_helper.utils.git_command import GIT_SAFETY_OPTIONS, git_argv

PACKAGE_ROOT = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _git_env(home: Path) -> dict[str, str]:
    """The test's own git environment: no host config decides the outcome."""
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
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


def _run(argv: list[str], repo: Path, env: dict[str, str]):
    return subprocess.run(  # nosec B603 -- list argv, fixture repository only
        argv, cwd=repo, env=env, capture_output=True, text=True, timeout=60
    )


def _marks(marker: Path) -> int:
    return marker.read_text(encoding="utf-8").count("ran") if marker.exists() else 0


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A repository with a ``base`` branch, one commit after it, and a dirty file."""
    home = tmp_path / "home"
    home.mkdir()
    env = _git_env(home)
    # ASH's own calls take the process environment.
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    for key, value in env.items():
        if key.startswith("GIT_") or key == "HOME":
            monkeypatch.setenv(key, value)
    path = tmp_path / "repo"
    path.mkdir()
    assert _run(["git", "init", "-q", "-b", "main"], path, env).returncode == 0
    (path / "a.py").write_text("a = 1\n", encoding="utf-8")
    assert _run(["git", "add", "a.py"], path, env).returncode == 0
    assert _run(["git", "commit", "-q", "-m", "one"], path, env).returncode == 0
    assert _run(["git", "branch", "base"], path, env).returncode == 0
    (path / "b.py").write_text("b = 2\n", encoding="utf-8")
    assert _run(["git", "add", "b.py"], path, env).returncode == 0
    assert _run(["git", "commit", "-q", "-m", "two"], path, env).returncode == 0
    (path / "a.py").write_text("a = 3\n", encoding="utf-8")
    return path, env


def _set_fsmonitor(repo: Path, env: dict[str, str], marker: Path) -> None:
    command = f"echo ran >> {shlex.quote(marker.as_posix())}; false"
    assert _run(["git", "config", "core.fsmonitor", command], repo, env).returncode == 0


class TestTheRepositorysFsmonitorCommand:
    def test_plain_git_runs_it(self, repo, tmp_path):
        """The control: without the options, the marker appears."""
        path, env = repo
        marker = tmp_path / "fsmonitor-ran.txt"
        _set_fsmonitor(path, env, marker)

        _run(["git", "status", "--porcelain"], path, env)

        assert _marks(marker) > 0

    @pytest.mark.parametrize(
        "args",
        [
            ("status", "--porcelain"),
            ("ls-files", "-z"),
            ("diff", "--name-only"),
        ],
        ids=["status", "ls-files", "diff-worktree"],
    )
    def test_git_argv_never_runs_it(self, repo, tmp_path, args):
        path, env = repo
        marker = tmp_path / "fsmonitor-ran.txt"
        _set_fsmonitor(path, env, marker)

        result = _run(git_argv(*args), path, env)

        assert result.returncode == 0, result.stderr
        assert _marks(marker) == 0

    def test_ash_asking_for_the_changed_files_never_runs_it(self, repo, tmp_path):
        """``git diff A...B`` does not refresh the index today; this keeps it so."""
        path, env = repo
        marker = tmp_path / "fsmonitor-ran.txt"
        _set_fsmonitor(path, env, marker)

        changed = get_changed_files(base_ref="base", cwd=path)
        root = git_repository_root(path)

        assert changed == [Path("b.py")]
        assert root == path.resolve()
        assert _marks(marker) == 0


class TestTheRepositorysHooks:
    def _hook_dir(self, tmp_path: Path, marker: Path) -> Path:
        hooks = tmp_path / "repo-hooks"
        hooks.mkdir()
        hook = hooks / "post-checkout"
        hook.write_text(
            f"#!/bin/sh\necho ran >> {shlex.quote(marker.as_posix())}\n",
            encoding="utf-8",
        )
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        return hooks

    def test_plain_git_runs_them(self, repo, tmp_path):
        path, env = repo
        marker = tmp_path / "hook-ran.txt"
        hooks = self._hook_dir(tmp_path, marker)
        _run(["git", "config", "core.hooksPath", str(hooks)], path, env)

        _run(["git", "checkout", "-q", "base", "--", "a.py"], path, env)
        _run(["git", "checkout", "-q", "base"], path, env)

        assert _marks(marker) > 0

    def test_git_argv_never_runs_them(self, repo, tmp_path):
        path, env = repo
        marker = tmp_path / "hook-ran.txt"
        hooks = self._hook_dir(tmp_path, marker)
        _run(["git", "config", "core.hooksPath", str(hooks)], path, env)

        _run(git_argv("checkout", "-q", "base", "--", "a.py"), path, env)
        result = _run(git_argv("checkout", "-q", "base"), path, env)

        assert result.returncode == 0, result.stderr
        assert _marks(marker) == 0


def test_the_options_turn_both_settings_off():
    assert git_argv("status") == [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "status",
    ]
    assert git_argv()[1:] == list(GIT_SAFETY_OPTIONS)


def test_a_resolved_git_keeps_the_options():
    """A caller that resolved git to an absolute path still gets both options."""
    assert git_argv("status", program="/opt/git/bin/git") == [
        "/opt/git/bin/git",
        *GIT_SAFETY_OPTIONS,
        "status",
    ]


#: Call sites that start git without ``git_argv``, each with the reason it is not
#: changed here. Empty: the MCP server's clone, fetch and checkout
#: (cli/mcp/source_delivery.py) are built by git_argv too. A new entry needs an
#: argument of its own.
_OUTSIDE_THIS_CHANGE: set[str] = set()


def _starts_with_git(element: ast.expr) -> bool:
    """``"git"`` itself, or a variable named ``git`` holding a resolved path."""
    if isinstance(element, ast.Constant):
        return element.value == "git"
    return isinstance(element, ast.Name) and element.id == "git"


def _git_argv_literals(path: Path) -> list[int]:
    """Lines where a list or tuple literal starting with ``"git"`` or ``git`` is written."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, (ast.List, ast.Tuple))
        and node.elts
        and _starts_with_git(node.elts[0])
    ]


def test_every_git_command_in_the_package_is_built_by_git_argv():
    """A literal ``["git", ...]`` outside ``git_command.py`` skips the options."""
    builder = PACKAGE_ROOT / "utils" / "git_command.py"
    found = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if path == builder or relative in _OUTSIDE_THIS_CHANGE:
            continue
        lines = _git_argv_literals(path)
        if lines:
            found[relative] = lines
    assert found == {}, found


def test_the_gate_sees_a_literal_git_argv(tmp_path):
    """The gate's own control: the pattern it looks for is found when present."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        'import subprocess\nsubprocess.run(["git", "status"])\n', encoding="utf-8"
    )
    assert _git_argv_literals(sample) == [2]


def test_the_gate_sees_a_resolved_git_argv(tmp_path):
    """The same control for a list that starts with a resolved ``git`` path."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        'import subprocess\ngit = "/usr/bin/git"\nsubprocess.run([git, "status"])\n',
        encoding="utf-8",
    )
    assert _git_argv_literals(sample) == [3]
