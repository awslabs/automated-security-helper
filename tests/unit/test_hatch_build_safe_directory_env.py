# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hatch_build passes a caller's safe.directory entries to git, and nothing else.

Why this file exists
--------------------
``_get_commit_sha`` runs git with every GIT_* variable of the caller removed except
GIT_CEILING_DIRECTORIES, so that the repository a `git commit` hook is running in
cannot be mistaken for this tree. That also removed GIT_CONFIG_COUNT,
GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n>, the way a container or CI build
commonly tells git that a checkout owned by another user is safe to read. git then
refused the tree, and the commit record read "unknown-commit".

Those variables can carry any config key, though, and some move the worktree or run a
program (test_hatch_build_records_commit.py pins that a core.worktree entry does not
reach git). So only the entries whose key is safe.directory are kept, renumbered
into a fresh count.

What is asserted
----------------
git is a stub that records the environment it is given and answers with a commit
id, so nothing here starts a process. The environment holds a core.worktree entry
between two safe.directory entries: git is given exactly the two safe.directory
entries, numbered from zero, and none of the other entry. A count that is not a
number, entries with no value, and a caller with no safe.directory entry give git no
GIT_CONFIG_* variable at all; GIT_DIR and GIT_CONFIG_PARAMETERS are still removed.

GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM and GIT_CONFIG_NOSYSTEM are removed too, with or
without a safe.directory entry beside them: they name whole config files, which cannot
be filtered to one key. That is a decision, and a test pins it so that a widening of
the allowlist is a visible change.

The entries only work where git reads safe.directory from the command scope, which is
believed to be git 2.38 and later. Every test here replaces git with a stub, so none
shows a real git accepting an entry (that needs an integration run on a host with a
second user and a git of each age); what these tests can pin is that the version
bound and the three variable names are module constants the code reads, and that a
failing git with entries passed names the bound from the constant.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / "hatch_build.py"


@pytest.fixture
def hook(monkeypatch, tmp_path):
    """hatch_build.py from a copy in tmp_path, with no GIT_* variable from the host."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copyfile(HOOK, tree / "hatch_build.py")
    spec = importlib.util.spec_from_file_location(
        "hatch_build_safe_directory", tree / "hatch_build.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _env_git_receives(monkeypatch, hook) -> dict:
    """Run the commit lookup against a git stub; return the environment it was given."""
    sha = hashlib.sha1(b"a commit", usedforsecurity=False).hexdigest()
    seen: dict = {}
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def run(*args, **kwargs):
        seen.update(kwargs.get("env") or {})
        return hook.subprocess.CompletedProcess(
            args[0], 0, stdout=b"\n" + sha.encode("ascii") + b"\n", stderr=b""
        )

    monkeypatch.setattr(hook.subprocess, "run", run)
    assert hook.CustomBuildHook._get_commit_sha(None) == sha
    return seen


def _git_config(env: dict) -> dict:
    return {k: v for k, v in env.items() if k.startswith("GIT_CONFIG")}


def test_only_the_safe_directory_entries_reach_git(monkeypatch, hook):
    """Red at the base: no GIT_CONFIG_* variable reached git, so the count read None."""
    for key, value in {
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "/srv/ash-first",
        "GIT_CONFIG_KEY_1": "core.worktree",
        "GIT_CONFIG_VALUE_1": "elsewhere",
        "GIT_CONFIG_KEY_2": "safe.directory",
        "GIT_CONFIG_VALUE_2": "/srv/ash-second",
    }.items():
        monkeypatch.setenv(key, value)

    seen = _env_git_receives(monkeypatch, hook)

    assert _git_config(seen) == {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "/srv/ash-first",
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_VALUE_1": "/srv/ash-second",
    }


def test_other_git_variables_are_still_removed(monkeypatch, hook):
    """The control: the rest of the isolation holds beside the safe.directory entry."""
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "safe.directory")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/srv/ash-first")
    monkeypatch.setenv("GIT_DIR", "elsewhere")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.worktree'='elsewhere'")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", "/srv")

    seen = _env_git_receives(monkeypatch, hook)

    assert "GIT_DIR" not in seen
    assert "GIT_CONFIG_PARAMETERS" not in seen
    assert seen["GIT_CEILING_DIRECTORIES"] == "/srv"
    assert seen["GIT_CONFIG_VALUE_0"] == "/srv/ash-first"


@pytest.mark.parametrize(
    "variables",
    [
        pytest.param({}, id="no-entries"),
        pytest.param(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.worktree",
                "GIT_CONFIG_VALUE_0": "elsewhere",
            },
            id="other-key-only",
        ),
        pytest.param(
            {
                "GIT_CONFIG_COUNT": "many",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": "/srv/ash-first",
            },
            id="count-not-a-number",
        ),
        pytest.param(
            {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory"},
            id="no-value",
        ),
        pytest.param(
            {
                "GIT_CONFIG_COUNT": "0",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": "/srv/ash-first",
            },
            id="count-zero",
        ),
    ],
)
def test_without_a_usable_safe_directory_entry_git_gets_no_config(
    monkeypatch, hook, variables
):
    """Green at the base and the fix: git is given no GIT_CONFIG_* variable."""
    for key, value in variables.items():
        monkeypatch.setenv(key, value)

    assert _git_config(_env_git_receives(monkeypatch, hook)) == {}


@pytest.mark.parametrize("with_entry", [False, True], ids=["alone", "with-entry"])
@pytest.mark.parametrize(
    "name", ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"]
)
def test_the_config_file_variables_are_still_removed(
    monkeypatch, hook, name, with_entry
):
    """Green at the base and the fix: the decision that these three stay dropped.
    They name whole config files, which cannot be filtered to safe.directory, so
    they are not passed even beside a safe.directory entry that is."""
    monkeypatch.setenv(name, "/srv/ci/gitconfig")
    if with_entry:
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "safe.directory")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/srv/ash-first")

    seen = _env_git_receives(monkeypatch, hook)

    assert name not in seen
    # The control: the safe.directory entry is passed in the same run.
    assert ("GIT_CONFIG_VALUE_0" in seen) is with_entry


def test_the_minimum_git_version_is_a_constant_the_code_reads(
    monkeypatch, capsys, hook
):
    """Red at the base: there was no constant, so the version bound lived only in
    docstring wording and nothing the code ran read it. When git fails with
    safe.directory entries passed, the build now names the bound it reads from
    the constant, so changing the constant changes the line and a reworded
    docstring changes nothing."""
    assert hook._SAFE_DIRECTORY_MIN_GIT == "2.38"
    assert (
        hook._GIT_CONFIG_COUNT,
        hook._GIT_CONFIG_KEY,
        hook._GIT_CONFIG_VALUE,
    ) == ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "safe.directory")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/srv/ash-first")
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def refuse(*args, **kwargs):
        raise hook.subprocess.CalledProcessError(128, args[0], stderr=b"dubious")

    monkeypatch.setattr(hook.subprocess, "run", refuse)
    monkeypatch.setattr(hook, "_SAFE_DIRECTORY_MIN_GIT", "9.99")

    assert hook._commit_from_git("/usr/bin/git") is None

    assert "older than 9.99" in capsys.readouterr().out


def test_no_version_line_without_a_forwarded_entry(monkeypatch, capsys, hook):
    """The control: a git failure with no safe.directory entry passed says nothing
    about the version bound."""
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def refuse(*args, **kwargs):
        raise hook.subprocess.CalledProcessError(128, args[0], stderr=b"dubious")

    monkeypatch.setattr(hook.subprocess, "run", refuse)

    assert hook._commit_from_git("/usr/bin/git") is None

    assert "older than" not in capsys.readouterr().out
