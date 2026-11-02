# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The package build records the commit it was built from.

Why this file exists
--------------------
hatch_build.py writes assets/ASH_INSTALLED_REVISION into every wheel and sdist, and
a container image built from an installed ASH that recorded no source in
direct_url.json (Homebrew, a package file, an index) installs that revision: not a
branch name, whose tip moves after the install, and not the literal "HEAD" of a
detached checkout, which `git clone --branch` cannot check out. The file holds the full
commit id, which the Dockerfile builds when a branch or tag of ASH reaches it, and
only when this source tree is the top level of its repository: an ASH tree unpacked
inside another repository is not a commit of ASH.
"""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess  # nosec B404 - builds throwaway git repositories, fixed argv
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _isolate_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Every git here, the build hook's included, with no system or user config.

    A developer's ``commit.gpgsign = true`` made ``_commit`` below try to sign, and
    fail where no key is set up, and any other setting in their config reached the
    build hook's ``git rev-parse`` too. The same isolation as
    test_release_line_workflow.py: no system config, and a home of the test's own.
    Every GIT_* variable goes too: with GIT_DIR naming another repository, as git
    sets it for a hook, _commit wrote three commits into that repository.
    """
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture(autouse=True)
def _no_git_config_from_the_host(monkeypatch, tmp_path):
    _isolate_git(monkeypatch, tmp_path)


@pytest.mark.unit
def test_no_git_variable_from_the_host_reaches_these_tests():
    """GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE and GIT_CONFIG_PARAMETERS point every
    git at another repository or configuration. git exports GIT_DIR to its hooks,
    so a run from a hook committed into the repository that ran it."""
    assert sorted(k for k in os.environ if k.startswith("GIT_")) == [
        "GIT_CONFIG_NOSYSTEM"
    ]


@pytest.mark.integration
def test_the_isolation_clears_a_git_dir_the_host_set(monkeypatch, tmp_path):
    """The check above only fails on a host that exports a GIT_* variable, and CI
    exports none, so this sets one and runs the isolation itself."""
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    _commit(decoy)
    before = _git(decoy, "rev-list", "--count", "HEAD")
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(decoy))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'commit.gpgsign'='true'")

    (tmp_path / "isolated").mkdir()
    _isolate_git(monkeypatch, tmp_path / "isolated")
    tree = tmp_path / "tree"
    tree.mkdir()
    _commit(tree)

    assert sorted(k for k in os.environ if k.startswith("GIT_")) == [
        "GIT_CONFIG_NOSYSTEM"
    ]
    assert _git(decoy, "rev-list", "--count", "HEAD") == before


def _load_hatch_build(monkeypatch, tree: Path):
    """hatch_build.py, loaded with its source tree pointed at ``tree``."""
    spec = importlib.util.spec_from_file_location(
        "hatch_build_under_test", REPO_ROOT / "hatch_build.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    tree.mkdir()
    monkeypatch.setattr(module, "ASH_REPO_ROOT", tree)
    monkeypatch.setattr(
        module, "ASH_INSTALLED_REVISION_PATH", tree / "ASH_INSTALLED_REVISION"
    )
    return module


@pytest.fixture
def hatch_build(monkeypatch, tmp_path):
    """hatch_build.py, loaded with its tree pointed at ``tmp_path / 'tree'``."""
    return _load_hatch_build(monkeypatch, tmp_path / "tree")


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # nosec B603 B607 - fixed git argv in a temporary directory
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _commit(repo: Path) -> str:
    _git(repo, "init", "--quiet")
    _git(repo, "commit", "--quiet", "--allow-empty", "-m", "init")
    return _git(repo, "rev-parse", "HEAD")


def _sha(hatch_build) -> str:
    return hatch_build.CustomBuildHook._get_commit_sha(None)


@pytest.mark.integration
def test_a_checkout_records_its_commit_id(hatch_build):
    sha = _commit(hatch_build.ASH_REPO_ROOT)

    assert _sha(hatch_build) == sha
    assert len(sha) == 40


#: Directory names Windows does not allow: control characters.
_NOT_ON_WINDOWS = pytest.mark.skipif(
    os.name == "nt", reason="Windows file names cannot hold control characters"
)


@pytest.mark.integration
@pytest.mark.parametrize(
    "name",
    [
        pytest.param("ash checkout", id="space"),
        pytest.param("ash" + chr(0x2028) + "checkout", id="line-separator"),
        pytest.param("ash" + chr(0x85) + "checkout", id="next-line"),
        pytest.param("ash\x0ccheckout", id="form-feed", marks=_NOT_ON_WINDOWS),
        pytest.param("ash\x0bcheckout", id="vertical-tab", marks=_NOT_ON_WINDOWS),
        pytest.param("ash\rcheckout", id="carriage-return", marks=_NOT_ON_WINDOWS),
        pytest.param("ash\ncheckout", id="newline", marks=_NOT_ON_WINDOWS),
        pytest.param("ash\tcheckout", id="tab", marks=_NOT_ON_WINDOWS),
        pytest.param("ash checkout ", id="trailing-space"),
    ],
)
def test_a_checkout_whose_path_has_an_odd_character_records_its_commit_id(
    monkeypatch, tmp_path, name
):
    """The commit is recorded whatever the checkout's path holds.

    The build asks git for `--show-prefix`, so no top level's path is read or
    split: a top level such as ``/home/me/my projects/ash``, or one holding a form
    feed, U+0085, U+2028 or a carriage return (which text mode turns into a
    newline), records its commit, not "unknown-commit".
    """
    hatch_build = _load_hatch_build(monkeypatch, tmp_path / name)
    sha = _commit(hatch_build.ASH_REPO_ROOT)

    assert _sha(hatch_build) == sha


@pytest.mark.integration
@_NOT_ON_WINDOWS
def test_a_subdirectory_named_like_a_commit_record_is_not_a_commit(
    monkeypatch, tmp_path
):
    """A tree below the top level, whose name holds a newline, records nothing.

    The path git prints for it spans two lines, which a reader taking any line
    shaped like a commit id would accept.
    """
    repository = tmp_path / "repository"
    repository.mkdir()
    hatch_build = _load_hatch_build(monkeypatch, repository / "ash\nchild")
    _commit(repository)

    assert _sha(hatch_build) == "unknown-commit"


@pytest.mark.integration
def test_a_detached_checkout_records_its_commit_id_not_head(hatch_build):
    """A tag checkout is detached, and records its commit id, not the literal "HEAD"."""
    sha = _commit(hatch_build.ASH_REPO_ROOT)
    _git(hatch_build.ASH_REPO_ROOT, "checkout", "--quiet", "--detach", sha)

    assert _sha(hatch_build) == sha


@pytest.mark.integration
def test_a_tree_inside_another_repository_is_not_a_commit_of_it(hatch_build, tmp_path):
    """The ASH tree is tmp_path/tree; the repository is tmp_path."""
    _commit(tmp_path)

    assert _sha(hatch_build) == "unknown-commit"


@pytest.mark.integration
def test_without_git_metadata_an_earlier_record_is_kept(hatch_build):
    """A wheel built from an sdist keeps the commit the sdist recorded.

    The tree is an unpacked sdist: no .git, and the PKG-INFO hatchling writes at the
    root of every sdist (test_hatch_build_revision_fallback.py pins that a record in
    a tree without it is not reused).
    """
    sha = "0123456789abcdef0123456789abcdef01234567"
    hatch_build.ASH_INSTALLED_REVISION_PATH.write_text(sha, encoding="utf-8")
    (hatch_build.ASH_REPO_ROOT / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\n", encoding="utf-8"
    )

    assert _sha(hatch_build) == sha


@pytest.mark.integration
def test_without_git_metadata_or_a_record_nothing_is_claimed(
    hatch_build, capsys, monkeypatch
):
    # git localizes its messages; the check below reads the English one.
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")
    assert _sha(hatch_build) == "unknown-commit"
    # git's own message, as text: it printed as b'fatal: ...' once the call
    # stopped decoding.
    printed = capsys.readouterr().out
    assert "stderr: fatal: not a git repository" in printed
    assert "stderr: b'" not in printed


def _another_repository(tmp_path: Path) -> tuple[Path, str]:
    other = tmp_path / "other-repository"
    other.mkdir()
    _commit(other)
    # A second commit, so its id differs from the tree's single empty commit, which
    # would otherwise be the same object made in the same second.
    _git(other, "commit", "--quiet", "--allow-empty", "-m", "other")
    return other, _git(other, "rev-parse", "HEAD")


@pytest.mark.integration
def test_a_git_dir_from_the_caller_does_not_choose_the_commit(
    hatch_build, monkeypatch, tmp_path
):
    """pre-commit runs hook environments inside `git commit`, and git exports
    GIT_DIR to its hooks: the build hook recorded that repository's HEAD."""
    sha = _commit(hatch_build.ASH_REPO_ROOT)
    other, other_sha = _another_repository(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))

    assert _sha(hatch_build) == sha != other_sha


@pytest.mark.integration
def test_a_git_dir_from_the_caller_is_no_commit_of_a_tree_with_none(
    hatch_build, monkeypatch, tmp_path
):
    other, other_sha = _another_repository(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))

    assert _sha(hatch_build) == "unknown-commit"


@pytest.mark.integration
def test_a_work_tree_from_the_caller_does_not_move_the_top_level(
    hatch_build, monkeypatch
):
    """GIT_WORK_TREE alone, naming the tree's parent, made git print the tree as
    "tree/" below the top level, and a real checkout recorded nothing."""
    sha = _commit(hatch_build.ASH_REPO_ROOT)
    monkeypatch.setenv("GIT_WORK_TREE", str(hatch_build.ASH_REPO_ROOT.parent))

    assert _sha(hatch_build) == sha


@pytest.mark.integration
def test_a_common_dir_from_the_caller_does_not_hide_the_repository(
    hatch_build, monkeypatch, tmp_path
):
    """GIT_COMMON_DIR naming a directory that is no repository made git fail."""
    sha = _commit(hatch_build.ASH_REPO_ROOT)
    elsewhere = tmp_path / "not-a-repository"
    elsewhere.mkdir()
    monkeypatch.setenv("GIT_COMMON_DIR", str(elsewhere))

    assert _sha(hatch_build) == sha


@pytest.mark.integration
@pytest.mark.parametrize(
    "variables",
    [
        {"GIT_INDEX_FILE": "elsewhere-index"},
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.worktree",
            "GIT_CONFIG_VALUE_0": "elsewhere",
        },
    ],
    ids=["GIT_INDEX_FILE", "GIT_CONFIG_COUNT"],
)
def test_other_git_variables_from_the_caller_do_not_reach_git(
    hatch_build, monkeypatch, variables
):
    """Measured with git 2.50: neither of these changes what `rev-parse
    --show-prefix HEAD` prints, so the recorded commit alone cannot show them
    stripped. The environment git is given can."""
    _commit(hatch_build.ASH_REPO_ROOT)
    for key, value in variables.items():
        monkeypatch.setenv(key, value)
    seen = {}
    real_run = hatch_build.subprocess.run

    def run(*args, **kwargs):
        seen.update(kwargs.get("env") or {})
        return real_run(*args, **kwargs)

    monkeypatch.setattr(hatch_build.subprocess, "run", run)

    _sha(hatch_build)

    assert not set(variables) & set(seen)


@pytest.mark.integration
def test_the_callers_ceiling_directories_reach_git(hatch_build, monkeypatch):
    """GIT_CEILING_DIRECTORIES only narrows where git looks for a repository, so
    it is the one GIT_* variable kept."""
    _commit(hatch_build.ASH_REPO_ROOT)
    ceiling = str(hatch_build.ASH_REPO_ROOT.parent)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", ceiling)
    seen = {}
    real_run = hatch_build.subprocess.run

    def run(*args, **kwargs):
        seen.update(kwargs.get("env") or {})
        return real_run(*args, **kwargs)

    monkeypatch.setattr(hatch_build.subprocess, "run", run)

    _sha(hatch_build)

    assert seen.get("GIT_CEILING_DIRECTORIES") == ceiling


@pytest.mark.unit
def test_a_git_message_the_console_cannot_encode_is_still_printed(
    hatch_build, monkeypatch
):
    """With stdout in cp1252 (a Windows console), printing git's non-ASCII stderr
    raised UnicodeEncodeError, which the build then recorded as "build-error"
    without trying the earlier record."""
    sha = "0123456789abcdef0123456789abcdef01234567"
    hatch_build.ASH_INSTALLED_REVISION_PATH.write_text(sha, encoding="utf-8")
    # An unpacked sdist, the only tree whose earlier record is reused.
    (hatch_build.ASH_REPO_ROOT / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\n", encoding="utf-8"
    )

    def run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            # A French git message ending in U+2717 (a ballot X), in UTF-8:
            # cp1252 has the accented letters but no form for the mark.
            128,
            args[0],
            stderr=b"fatal: d\xc3\xa9p\xc3\xb4t introuvable \xe2\x9c\x97",
        )

    monkeypatch.setattr(hatch_build.subprocess, "run", run)
    console = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", console)

    assert _sha(hatch_build) == sha
    console.flush()
    assert b"introuvable \\u2717" in console.buffer.getvalue()


@pytest.mark.integration
def test_a_tree_whose_path_the_console_cannot_encode_keeps_its_commit(
    monkeypatch, tmp_path
):
    """The hook prints the tree's paths as it stages them. On a cp1252 console a
    path holding a character cp1252 lacks does not stop it: the revision file
    holds the commit, not "build-error", including where the print naming the
    revision file comes after the commit is written."""
    hatch_build = _load_hatch_build(monkeypatch, tmp_path / ("ash" + chr(0x2717)))
    monkeypatch.setattr(
        hatch_build, "ASH_ASSETS_PATH", hatch_build.ASH_REPO_ROOT / "assets"
    )
    sha = _commit(hatch_build.ASH_REPO_ROOT)
    console = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", console)

    object.__new__(hatch_build.CustomBuildHook)._stage_assets()

    assert hatch_build.ASH_INSTALLED_REVISION_PATH.read_text() == sha


@pytest.mark.unit
def test_an_error_the_console_cannot_encode_still_records_build_error(
    hatch_build, monkeypatch
):
    """The handler prints the error before it records "build-error". With git at
    a path holding U+2717 that cannot be run, printing that error on a cp1252
    console does not raise inside the handler, and the build goes on."""
    monkeypatch.setattr(
        hatch_build, "ASH_ASSETS_PATH", hatch_build.ASH_REPO_ROOT / "assets"
    )
    git_path = "/opt/tools" + chr(0x2717) + "/git"
    monkeypatch.setattr(hatch_build.shutil, "which", lambda name: git_path)

    def run(*args, **kwargs):
        raise PermissionError(13, "Permission denied", git_path)

    monkeypatch.setattr(hatch_build.subprocess, "run", run)
    console = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", console)

    object.__new__(hatch_build.CustomBuildHook)._stage_assets()

    assert hatch_build.ASH_INSTALLED_REVISION_PATH.read_text() == "build-error"
    console.flush()
    assert b"/opt/tools\\u2717/git" in console.buffer.getvalue()
