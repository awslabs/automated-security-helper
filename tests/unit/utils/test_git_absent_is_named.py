# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""When git is missing, ASH says so, rather than calling the directory not a repository.

``git_repository_root`` returns None for "git is not installed", "not a
repository" and a timeout alike, and both ``--changed-files-only`` warnings read
that None as "is not inside a git repository" / "is not a git repository", so a
host without git was told to check a repository that was there.

Each test makes a real repository with the real git, then hides git by pointing
PATH at an empty directory.
"""

from __future__ import annotations

import logging
import shutil
import subprocess  # nosec B404 -- builds throwaway git repositories
from pathlib import Path

import pytest

from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    changed_file_set,
)
from automated_security_helper.workspace.plan import ProjectPlan

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="needs git to build a repository")


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run([GIT, "init", "-q", str(repo)], check=True)  # nosec B603
    (repo / "app.py").write_text("x = 1\n")
    return repo


@pytest.fixture
def no_git(tmp_path, monkeypatch):
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


def _project(path: Path) -> ProjectPlan:
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=path.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
    )


def test_the_workspace_warning_says_git_is_missing(
    repository, no_git, tmp_path, caplog
):
    settings = ProjectScanSettings(output_dir=tmp_path / "out", changed_files_only=True)
    with caplog.at_level(logging.WARNING):
        assert changed_file_set(_project(repository), settings) is None
    warned = " ".join(caplog.messages)
    assert "git is not installed or not on PATH" in warned, warned
    assert "is not a git repository" not in warned


def test_the_workspace_warning_names_a_directory_that_is_not_a_repository(
    tmp_path, caplog
):
    plain = tmp_path / "plain"
    plain.mkdir()
    settings = ProjectScanSettings(output_dir=tmp_path / "out", changed_files_only=True)
    with caplog.at_level(logging.WARNING):
        assert changed_file_set(_project(plain), settings) is None
    assert "is not inside a git repository" in " ".join(caplog.messages)


def test_the_problem_names_git_when_it_is_missing(repository, no_git):
    from automated_security_helper.utils.get_scan_set import (
        GIT_NOT_INSTALLED,
        git_repository_root,
        git_repository_root_problem,
    )

    assert git_repository_root(repository) is None
    assert git_repository_root_problem(repository) == GIT_NOT_INSTALLED


def test_a_missing_directory_is_not_reported_as_missing_git(tmp_path):
    from automated_security_helper.utils.get_scan_set import (
        git_repository_root_problem,
    )

    problem = git_repository_root_problem(tmp_path / "gone")
    assert "does not exist" in problem


def test_get_changed_files_says_git_is_missing(repository, no_git, caplog):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    with caplog.at_level(logging.WARNING):
        assert get_changed_files(cwd=repository) is None
    warned = " ".join(caplog.messages)
    assert "git is not installed or not on PATH" in warned
    assert "timed out" not in warned


def test_get_changed_files_with_a_missing_directory_does_not_blame_git(
    tmp_path, caplog
):
    """subprocess raises the same FileNotFoundError for a missing cwd."""
    from automated_security_helper.utils.get_scan_set import get_changed_files

    with caplog.at_level(logging.WARNING):
        assert get_changed_files(cwd=tmp_path / "gone") is None
    warned = " ".join(caplog.messages)
    assert "does not exist" in warned
    assert "git is not installed" not in warned


class _HungGit:
    """subprocess for get_scan_set, where every git run hits its timeout."""

    TimeoutExpired = subprocess.TimeoutExpired
    # get_scan_set runs git with stdin=subprocess.DEVNULL.
    DEVNULL = subprocess.DEVNULL

    def __init__(self):
        self.started = []

    def run(self, argv, **kwargs):
        self.started.append(list(argv))
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))


def test_a_hung_git_is_waited_for_once(tmp_path, monkeypatch):
    """The problem comes from the lookup that failed, not from running git again.

    git_repository_root_problem does not repeat ``git rev-parse --show-toplevel``,
    so a git that hangs costs one 30-second timeout before the warning, not two.
    """
    from automated_security_helper.utils import get_scan_set

    git = _HungGit()
    monkeypatch.setattr(get_scan_set, "subprocess", git)
    assert get_scan_set.git_repository_root(tmp_path) is None
    problem = get_scan_set.git_repository_root_problem(tmp_path)
    assert "timed out after 30 seconds" in problem, problem
    assert len(git.started) == 1, git.started


def test_the_workspace_warning_runs_git_once_when_it_hangs(
    tmp_path, monkeypatch, caplog
):
    from automated_security_helper.utils import get_scan_set

    git = _HungGit()
    monkeypatch.setattr(get_scan_set, "subprocess", git)
    settings = ProjectScanSettings(output_dir=tmp_path / "out", changed_files_only=True)
    with caplog.at_level(logging.WARNING):
        assert changed_file_set(_project(tmp_path), settings) is None
    assert "timed out" in " ".join(caplog.messages), caplog.messages
    assert len(git.started) == 1, git.started


def test_a_later_lookup_is_not_answered_by_an_earlier_failure(tmp_path, monkeypatch):
    """A problem is remembered only until the next lookup of the same directory."""
    from automated_security_helper.utils import get_scan_set

    monkeypatch.setattr(get_scan_set, "subprocess", _HungGit())
    assert get_scan_set.git_repository_root(tmp_path) is None
    monkeypatch.setattr(
        get_scan_set,
        "_rev_parse_toplevel",
        lambda path, *, values: (
            None,
            f"{Path(path).as_posix()} is not inside a git repository",
        ),
    )
    assert get_scan_set.git_repository_root(tmp_path) is None
    assert "is not inside a git repository" in (
        get_scan_set.git_repository_root_problem(tmp_path)
    )


def test_a_successful_lookup_forgets_the_earlier_failure(tmp_path, monkeypatch):
    """After a lookup that finds the root, the old cause must not be reported."""
    from automated_security_helper.utils import get_scan_set

    monkeypatch.setattr(get_scan_set, "subprocess", _HungGit())
    assert get_scan_set.git_repository_root(tmp_path) is None
    answers = iter(
        [
            (tmp_path, None),
            (None, f"{tmp_path.as_posix()} is not inside a git repository"),
        ]
    )
    monkeypatch.setattr(
        get_scan_set, "_rev_parse_toplevel", lambda path, *, values: next(answers)
    )
    assert get_scan_set.git_repository_root(tmp_path) == tmp_path
    # Nothing remembered now, so the cause is asked for afresh.
    problem = get_scan_set.git_repository_root_problem(tmp_path)
    assert "timed out" not in problem, problem
    assert "is not inside a git repository" in problem, problem


# ---------------------------------------------------------------------------
# The warnings carry paths and git's own text, which may hold Rich markup, and
# they say what the fallback does: every finding is reported.
# ---------------------------------------------------------------------------


@pytest.fixture
def markup_console(monkeypatch):
    """ASH_LOGGER through a markup-enabled RichHandler, as setup_logging builds it."""
    import io

    from rich.console import Console
    from rich.logging import RichHandler

    from automated_security_helper.utils.log import ASH_LOGGER

    # A buffer at width 400, off a terminal: a caller's FORCE_COLOR or
    # TTY_COMPATIBLE made Rich treat it as one, and under TERM=dumb lay it out at
    # 80 columns, which broke a long path across lines.
    for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)
    buffer = io.StringIO()
    handler = RichHandler(
        console=Console(file=buffer, width=400, color_system=None),
        markup=True,
        show_time=False,
        show_path=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [handler]
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield buffer
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)


def _bracketed(tmp_path: Path) -> Path:
    """A directory whose path reads as a closing Rich tag: .../a[/x]."""
    path = tmp_path / "a[" / "x]"
    path.mkdir(parents=True)
    return path


def _printed(buffer) -> str:
    return " ".join(buffer.getvalue().split())


def test_the_workspace_warning_prints_a_bracketed_path_verbatim(
    tmp_path, markup_console
):
    project = _bracketed(tmp_path)
    settings = ProjectScanSettings(output_dir=tmp_path / "out", changed_files_only=True)
    assert changed_file_set(_project(project), settings) is None
    printed = _printed(markup_console)
    assert f"{project.as_posix()} is not inside a git repository" in printed, printed
    assert "reporting all of its findings" in printed, printed
    assert "scanning it in full" not in printed, printed


def test_get_changed_files_prints_a_bracketed_path_verbatim(tmp_path, markup_console):
    from automated_security_helper.utils.get_scan_set import get_changed_files

    missing = _bracketed(tmp_path) / "gone"
    assert get_changed_files(cwd=missing) is None
    printed = _printed(markup_console)
    assert f"{missing.as_posix()} does not exist" in printed, printed
    assert "reporting every finding" in printed, printed
    assert "falling back" not in printed, printed


def test_an_invalid_base_ref_is_refused_and_named_verbatim(tmp_path, monkeypatch):
    """--base-ref is named in the refusal; "a[/x]" reads as a closing Rich tag.

    get_changed_files refuses a base ref it would not pass to git
    (validate_base_ref) instead of falling back to every finding, and starts no
    git process for it.
    """
    from automated_security_helper.utils import get_scan_set

    git = _HungGit()
    monkeypatch.setattr(get_scan_set, "subprocess", git)
    with pytest.raises(get_scan_set.InvalidBaseRefError) as refused:
        get_scan_set.get_changed_files(base_ref="a[/x]", cwd=tmp_path)
    assert "Refusing --base-ref 'a[/x]'" in str(refused.value), refused.value
    assert git.started == [], git.started


def test_a_hung_git_diff_is_named(tmp_path, monkeypatch, caplog):
    from automated_security_helper.utils import get_scan_set

    monkeypatch.setattr(get_scan_set, "subprocess", _HungGit())
    with caplog.at_level(logging.WARNING):
        assert (
            get_scan_set.get_changed_files(base_ref="origin/dev", cwd=tmp_path) is None
        )
    warned = " ".join(caplog.messages)
    assert "git diff against origin/dev timed out after 30 seconds" in warned, warned
    assert "reporting every finding" in warned, warned


def test_a_git_that_will_not_start_is_not_called_missing(tmp_path, monkeypatch, caplog):
    """FileNotFoundError while git is on PATH: say it could not be started."""
    from automated_security_helper.utils import get_scan_set

    class _Unstartable(_HungGit):
        def run(self, argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr(get_scan_set, "subprocess", _Unstartable())
    monkeypatch.setattr(get_scan_set.shutil, "which", lambda name: "/usr/bin/git")
    with caplog.at_level(logging.WARNING):
        assert get_scan_set.get_changed_files(cwd=tmp_path) is None
    warned = " ".join(caplog.messages)
    assert f"git could not be started in {tmp_path.as_posix()}" in warned, warned
    assert "git is not installed" not in warned, warned


def test_a_failed_git_diff_says_every_finding_is_reported(
    tmp_path, monkeypatch, caplog
):
    from automated_security_helper.utils import get_scan_set

    class _Failing(_HungGit):
        def run(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 128, "", "fatal: bad")

    monkeypatch.setattr(get_scan_set, "subprocess", _Failing())
    with caplog.at_level(logging.WARNING):
        assert (
            get_scan_set.get_changed_files(base_ref="origin/main", cwd=tmp_path) is None
        )
    warned = " ".join(caplog.messages)
    assert "reporting every finding" in warned, warned
    assert "falling back" not in warned, warned


def test_an_invalid_base_ref_is_refused_before_git_starts(tmp_path, monkeypatch):
    """A base ref with a space is not a fallback to every finding: it is refused."""
    from automated_security_helper.utils import get_scan_set

    git = _HungGit()
    monkeypatch.setattr(get_scan_set, "subprocess", git)
    with pytest.raises(get_scan_set.InvalidBaseRefError):
        get_scan_set.get_changed_files(base_ref="bad ref", cwd=tmp_path)
    assert git.started == [], git.started
