# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The staged-file reader behind ``--mode precommit --staged``.

``get_staged_files`` turns ``git diff --cached`` into the staged file list, and
``staged_files_for_source`` respells it relative to the scanned directory. The
parsing tests fake the git subprocess, so they pin what ASH asks git for and how
it reads the answer; the repository tests run real git in a throwaway repository,
so the ``--diff-filter=ACMR`` semantics (a deletion is not scannable; a rename is
scanned at its new path) are measured against git itself.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import get_staged_files
from automated_security_helper.utils.staged_files import (
    matching_staged_files,
    staged_files_for_source,
)


class _Completed:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def fake_git(monkeypatch):
    """Replace the git subprocess; returns the list the fake was called with."""
    calls: list = []

    def install(returncode: int = 0, stdout: bytes = b""):
        def run(argv, **kwargs):
            calls.append(list(argv))
            return _Completed(returncode=returncode, stdout=stdout)

        monkeypatch.setattr(gss, "_git_executable", lambda: "git")
        monkeypatch.setattr(gss.subprocess, "run", run)
        return calls

    return install


@pytest.mark.unit
class TestStagedListParsing:
    def test_the_argv_asks_for_the_cached_nul_separated_acmr_names(self, fake_git):
        """The design is in the argv: --cached (the index, which a base-ref diff
        cannot see), --diff-filter=ACMR (no deletions; a rename's record is its
        new path under --name-only), -z and core.quotepath=false (names come back
        raw and NUL-separated, never C-quoted or split on a newline), and a
        trailing -- (the range is revisions, never a path)."""
        calls = fake_git(stdout=b"")
        assert get_staged_files() == []
        (argv,) = calls
        for needle in ("--cached", "--name-only", "--diff-filter=ACMR", "-z", "--"):
            assert needle in argv, f"{needle!r} missing from {argv!r}"
        assert "core.quotepath=false" in argv
        assert "diff.relative=false" in argv

    def test_nul_separated_names_are_read_whole(self, fake_git):
        """A name with a space, one with a newline and one non-ASCII: each is one
        entry, unsplit and unstripped, and the trailing NUL adds no empty one."""
        fake_git(stdout=b"a b.py\0dir/c\nd.tf\0" + "uü.md".encode("utf-8") + b"\0")
        assert get_staged_files() == [
            Path("a b.py"),
            Path("dir/c\nd.tf"),
            Path("uü.md"),
        ]

    def test_an_empty_index_is_an_empty_list_not_none(self, fake_git):
        fake_git(stdout=b"")
        assert get_staged_files() == []

    def test_a_failed_diff_is_none(self, fake_git):
        """None means "could not read", which --staged refuses; it is never an
        empty staged set, which exits clean."""
        fake_git(returncode=128)
        assert get_staged_files() is None

    def test_a_missing_git_is_none(self, monkeypatch):
        monkeypatch.setattr(gss, "_git_executable", lambda: None)
        assert get_staged_files() is None


def _git(repo: Path, *args: str) -> None:
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repo),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
        env=env,
    )


@pytest.fixture
def staged_repo(tmp_path) -> Path:
    """A repository with one commit and a staged add, modify, rename and delete."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "kept.py").write_text("x = 1\n")
    (repo / "old_name.py").write_text("y = 2\n")
    (repo / "doomed.py").write_text("z = 3\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed")
    # Staged, not committed: the state the pre-commit hook is called about.
    (repo / "added.md").write_text("new\n")
    (repo / "kept.py").write_text("x = 2\n")
    _git(repo, "mv", "old_name.py", "new_name.py")
    _git(repo, "rm", "-q", "doomed.py")
    _git(repo, "add", "added.md", "kept.py")
    return repo


@pytest.mark.integration
class TestAgainstRealGit:
    def test_acmr_keeps_add_modify_and_the_renames_new_path_and_drops_the_delete(
        self, staged_repo
    ):
        names = {path.as_posix() for path in get_staged_files(cwd=staged_repo)}
        assert names == {"added.md", "kept.py", "new_name.py"}
        assert "old_name.py" not in names, "a rename is scanned at its new path"
        assert "doomed.py" not in names, "a deleted file cannot be scanned"

    def test_source_relative_mapping_keeps_only_files_under_the_source_dir(
        self, staged_repo
    ):
        """A project below the repository root sees its own staged files, respelled
        relative to itself; a sibling's staged file is not its scan's business."""
        project = staged_repo / "proj"
        project.mkdir()
        (project / "inside.py").write_text("a = 1\n")
        _git(staged_repo, "add", "proj/inside.py")

        assert staged_files_for_source(project) == ["inside.py"]
        whole = staged_files_for_source(staged_repo)
        assert "proj/inside.py" in whole and "added.md" in whole

    def test_a_symlinked_checkout_path_still_sees_the_staged_files(
        self, staged_repo, tmp_path
    ):
        """The fail-open shape this guards: git prints real paths, so under a
        source reached through a symlink (a symlinked home or worktree, macOS
        /tmp) an unresolved source contained none of them, every relative_to
        raised, the list came back empty, and --staged exited 0 with no scanner
        run. The reader resolves the source, so the answer is the same through
        the link as at the real path."""
        link = tmp_path / "link-to-repo"
        link.symlink_to(staged_repo, target_is_directory=True)

        through_link = staged_files_for_source(link)

        assert through_link == staged_files_for_source(staged_repo)
        assert "added.md" in through_link

    def test_outside_a_repository_is_none(self, tmp_path):
        bare = tmp_path / "norepo"
        bare.mkdir()
        assert staged_files_for_source(bare) is None


@pytest.mark.unit
class TestMatching:
    def test_none_means_the_scanner_reads_any_file(self):
        staged = ["a.py", "b.md"]
        assert matching_staged_files(staged, None) == staged

    def test_patterns_match_the_whole_path_and_the_base_name(self):
        staged = ["pkg/app.py", "pkg/package-lock.json", "README.md"]
        assert matching_staged_files(staged, ("*.py",)) == ["pkg/app.py"]
        assert matching_staged_files(staged, ("package-lock.json",)) == [
            "pkg/package-lock.json"
        ]

    def test_matching_is_case_insensitive(self):
        assert matching_staged_files(["APP.PY"], ("*.py",)) == ["APP.PY"]

    def test_no_match_is_an_empty_list(self):
        assert matching_staged_files(["a.md"], ("*.py",)) == []
