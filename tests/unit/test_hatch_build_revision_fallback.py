# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hatch_build reuses an earlier commit record only where it can belong to the tree.

Why this file exists
--------------------
When git cannot name the commit, ``_get_commit_sha`` falls back to the record an
earlier build left in assets/ASH_INSTALLED_REVISION. That fallback exists for a
wheel built from an sdist: the unpacked sdist has no .git, and the record it holds
is the commit the sdist was built from.

It ran in every tree, though. In a checkout where git refuses to answer (a
repository-ownership refusal is the usual cause), the record is whatever an earlier
build of that checkout left, at whatever commit it was on then, and the new build
recorded that commit as its own. And it accepted any text that was not one of three
placeholders: "HEAD" or a branch name from an older build, or any other string,
went into the package as the revision a container build installs.

What is asserted
----------------
Git is replaced by a stub that fails the way a refused repository does, so nothing
here starts a process. A tree with a .git (a directory, or the file a worktree has)
and a record of a commit id records "unknown-commit"; the same record in a tree with
no .git is kept, which is the sdist case. Only a 40-digit lowercase commit id is
reused; the placeholders, a branch name, "HEAD", and ids of any other length or case
read as no record.

A host with no git on PATH takes the same fallback: it keeps an sdist's record, and
records "no-git-available" only when there is none to keep.

A missing .git is not proof of an sdist, though. A source tree vendored inside another
repository (git answers, with a prefix that is not empty), a copy made with
``rsync --exclude .git`` and a docker build context (.dockerignore drops .git and does
not name the record) all have no .git and can hold the gitignored record of an earlier
build at another commit, which the new build then recorded as its own. Hatchling writes
a PKG-INFO at the root of every sdist, so the record is reused only where PKG-INFO
exists, beside the .git check. The tests below that expect a record to be reused make
the tree an sdist with ``_as_sdist``; the ones that expect it refused leave it off or
add a .git.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / "hatch_build.py"


def _commit_id() -> str:
    """A commit-shaped id, built at run time."""
    return hashlib.sha1(b"a commit", usedforsecurity=False).hexdigest()


def _hook_in(monkeypatch, tree: Path):
    """hatch_build.py, loaded from a copy in ``tree`` so its paths point there."""
    tree.mkdir()
    shutil.copyfile(HOOK, tree / "hatch_build.py")
    spec = importlib.util.spec_from_file_location(
        "hatch_build_revision_fallback", tree / "hatch_build.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _git_refuses(monkeypatch, hook) -> None:
    """git is found on PATH and fails, as it does on a repository it will not read."""
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def run(*args, **kwargs):
        raise hook.subprocess.CalledProcessError(
            128, args[0], stderr=b"fatal: detected dubious ownership in repository"
        )

    monkeypatch.setattr(hook.subprocess, "run", run)


def _record(hook, text: str) -> None:
    hook.ASH_INSTALLED_REVISION_PATH.parent.mkdir(parents=True, exist_ok=True)
    hook.ASH_INSTALLED_REVISION_PATH.write_text(text, encoding="utf-8")


def _as_sdist(hook) -> None:
    """The tree as an unpacked sdist has it: a PKG-INFO at the root, no .git."""
    hook.ASH_REPO_ROOT.joinpath("PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: automated-security-helper\n", encoding="utf-8"
    )


def _get(hook) -> str:
    return hook.CustomBuildHook._get_commit_sha(None)


@pytest.mark.parametrize("kind", ["directory", "worktree-file"])
def test_a_checkout_does_not_reuse_an_earlier_record_when_git_refuses(
    monkeypatch, tmp_path, kind
):
    """Red at the base: the fallback returned the earlier record unconditionally."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_refuses(monkeypatch, hook)
    _record(hook, _commit_id())
    # An sdist's PKG-INFO beside the .git: the .git alone must refuse the record.
    _as_sdist(hook)
    git_entry = hook.ASH_REPO_ROOT / ".git"
    if kind == "directory":
        git_entry.mkdir()
    else:
        git_entry.write_text("gitdir: ../elsewhere\n", encoding="utf-8")

    assert _get(hook) == "unknown-commit"


def test_a_tree_without_a_git_entry_keeps_the_record_an_sdist_left(
    monkeypatch, tmp_path
):
    """The control for the test above: the same record, no .git, is kept."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_refuses(monkeypatch, hook)
    sha = _commit_id()
    _record(hook, sha)
    _as_sdist(hook)
    assert not (hook.ASH_REPO_ROOT / ".git").exists()

    assert _get(hook) == sha


@pytest.mark.parametrize(
    "recorded",
    [
        pytest.param("main", id="branch-name"),
        pytest.param("HEAD", id="head"),
        pytest.param("ERROR: Failed to get commit SHA\nfatal", id="error-text"),
        pytest.param("unknown-commit", id="placeholder"),
        pytest.param("", id="empty"),
        pytest.param("UPPER", id="upper-case"),
        pytest.param("LONG", id="longer-id"),
        pytest.param("TWO", id="two-ids"),
    ],
)
def test_only_a_commit_id_is_reused(monkeypatch, tmp_path, recorded):
    """Red at the base for branch-name, head, upper-case, longer-id and two-ids:
    the fallback reused any text that was not a placeholder or an ERROR line."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_refuses(monkeypatch, hook)
    # An sdist, so that only the check of the recorded text can refuse it.
    _as_sdist(hook)
    sha = _commit_id()
    recorded = {
        "UPPER": sha.upper(),
        "LONG": sha + "0",
        "TWO": sha + "\n" + sha,
    }.get(recorded, recorded)
    _record(hook, recorded)

    assert _get(hook) == "unknown-commit"


def _git_is_not_installed(monkeypatch, hook) -> None:
    """No git on PATH; running anything would be a bug, so it fails the test."""
    monkeypatch.setattr(hook.shutil, "which", lambda name: None)

    def run(*args, **kwargs):
        raise AssertionError(f"nothing is run without git: {args!r}")

    monkeypatch.setattr(hook.subprocess, "run", run)


def test_a_host_without_git_keeps_the_record_an_sdist_left(monkeypatch, tmp_path):
    """Red at the base: the missing-git arm returned "no-git-available" before the
    record fallback was read, so a wheel built from an sdist on a host without git
    lost the commit the sdist recorded."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_is_not_installed(monkeypatch, hook)
    sha = _commit_id()
    _record(hook, sha)
    _as_sdist(hook)

    assert _get(hook) == sha


def test_a_host_without_git_and_without_a_record_says_so(monkeypatch, tmp_path):
    """The control: green at the base and the fix."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_is_not_installed(monkeypatch, hook)

    assert _get(hook) == "no-git-available"


def test_a_checkout_without_git_does_not_reuse_an_earlier_record(monkeypatch, tmp_path):
    """A tree with a .git entry never takes the record, git installed or not."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_is_not_installed(monkeypatch, hook)
    _record(hook, _commit_id())
    _as_sdist(hook)
    (hook.ASH_REPO_ROOT / ".git").mkdir()

    assert _get(hook) == "no-git-available"


def test_a_lowercase_commit_id_is_reused(monkeypatch, tmp_path):
    """The control for the test above: a 40-digit lowercase id passes the check."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    _git_refuses(monkeypatch, hook)
    _as_sdist(hook)
    sha = _commit_id()
    assert len(sha) == 40
    _record(hook, f"{sha}\n")

    assert _get(hook) == sha


def _git_in_another_repository(monkeypatch, hook) -> None:
    """git answers, for a tree vendored below the top level of another repository:
    the path below that top level is printed first, and it is not empty."""
    monkeypatch.setattr(hook.shutil, "which", lambda name: "/usr/bin/git")

    def run(*args, **kwargs):
        return hook.subprocess.CompletedProcess(
            args[0],
            0,
            stdout=b"vendor/ash/\n" + _commit_id().encode("ascii") + b"\n",
            stderr=b"",
        )

    monkeypatch.setattr(hook.subprocess, "run", run)


@pytest.mark.parametrize(
    ("git_state", "expected"),
    [
        pytest.param(_git_refuses, "unknown-commit", id="git-refuses"),
        pytest.param(_git_is_not_installed, "no-git-available", id="no-git"),
        pytest.param(_git_in_another_repository, "unknown-commit", id="vendored"),
    ],
)
def test_a_tree_that_is_no_sdist_does_not_reuse_a_record(
    monkeypatch, tmp_path, git_state, expected
):
    """Red before: a tree with no .git took any commit-id record, so a vendored
    tree, a copy made without its .git and a docker build context recorded the
    commit of an earlier build as their own."""
    hook = _hook_in(monkeypatch, tmp_path / "tree")
    git_state(monkeypatch, hook)
    _record(hook, _commit_id())
    # The control: no .git, as in the three trees named above, and no PKG-INFO.
    assert not (hook.ASH_REPO_ROOT / ".git").exists()
    assert not (hook.ASH_REPO_ROOT / "PKG-INFO").exists()

    assert _get(hook) == expected
