# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The repository each CI-runner pipeline runs in.

WHY THIS EXISTS
---------------
Each pipeline runs in a fresh git repository made from the docs fixture,
tests/test_data/docs_fixtures/sample-project, with the pipeline file committed beside
it. tests/integration/docs/ci_runners/fixture.py makes it:

* the fixture's files and the pipeline file in one base commit on ``main``, with a
  fixed author, committer and dates, so the same inputs give the same commit, and
  nothing of the invoking user's git configuration (identity, signing, hooks, default
  branch) reaches it;
* a bare repository holding ``main`` as ``origin``, so a pipeline can name
  ``origin/main`` as the base of a changed-files scan;
* for a pull request or merge request event, a branch that adds ``changed.py`` with
  exactly one finding, a ``subprocess`` call with ``shell=True``. A changed-files scan
  then has one finding to report, so a broken diff (which reports nothing) cannot pass
  as a clean scan;
* a new, empty HOME for every run, so tools installed by one pipeline are not found by
  the next.

The findings a run expects follow from that: a full scan finds the fixture's three in
``app.py``, and ``changed.py``'s one when the branch exists; a changed-files scan finds
only ``changed.py``'s.
"""

from __future__ import annotations

import ast
import getpass
import importlib
import importlib.util
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
PIPELINE = ".github/workflows/ash.yml"
PIPELINE_TEXT = "name: ASH\non:\n  pull_request:\njobs: {}\n"
AUTHOR = "Docs Example <docs-example@example.com>"
#: 2026-01-01T00:00:00Z, the date the docs runner commits its fixtures with.
EPOCH = "1767225600"


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(name: str):
    module = _module("fixture")
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/fixture.py defines no {name}")
    return getattr(module, name)


def _git(*args: str, cwd: Path | None = None) -> str:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(cwd or Path.cwd()),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


def _make(root: Path, event: str | None, pipeline_text: str = PIPELINE_TEXT):
    return _api("make_fixture")(
        root, pipeline_path=PIPELINE, pipeline_text=pipeline_text, event=event
    )


def test_the_base_commit_holds_the_fixture_and_the_pipeline(tmp_path):
    fixture = _make(tmp_path / "run", None)
    project = fixture.project
    assert _git("ls-tree", "-r", "--name-only", fixture.base_sha, cwd=project).split(
        "\n"
    ) == sorted([PIPELINE, "app.py", "notes.txt"])
    assert _git(
        "show", f"{fixture.base_sha}:{PIPELINE}", cwd=project
    ) == PIPELINE_TEXT.rstrip("\n")
    assert _git("show", f"{fixture.base_sha}:app.py", cwd=project) == (
        REPO_ROOT / "tests/test_data/docs_fixtures/sample-project/app.py"
    ).read_text(encoding="utf-8").rstrip("\n")
    assert _git(
        "log",
        "--format=%an <%ae>|%cn <%ce>|%at|%ct",
        "-1",
        fixture.base_sha,
        cwd=project,
    ) == (f"{AUTHOR}|{AUTHOR}|{EPOCH}|{EPOCH}")
    assert _git("rev-list", "--count", fixture.base_sha, cwd=project) == "1"
    assert _git("status", "--porcelain", cwd=project) == ""


def test_the_same_inputs_give_the_same_commits(tmp_path):
    first = _make(tmp_path / "one", "pull_request")
    second = _make(tmp_path / "two", "pull_request")
    assert first.base_sha == second.base_sha
    assert first.head_sha == second.head_sha
    third = _make(
        tmp_path / "three", "pull_request", pipeline_text=PIPELINE_TEXT + "# x\n"
    )
    assert third.base_sha != first.base_sha, (
        "the pipeline file is part of the base commit"
    )


def test_origin_is_a_bare_repository_holding_main(tmp_path):
    fixture = _make(tmp_path / "run", "pull_request")
    assert _git("rev-parse", "--is-bare-repository", cwd=fixture.origin) == "true"
    assert _git("rev-parse", "refs/heads/main", cwd=fixture.origin) == fixture.base_sha
    url = _git("remote", "get-url", "origin", cwd=fixture.project)
    assert url in (str(fixture.origin), fixture.origin.as_uri())
    assert (
        _git("rev-parse", "refs/remotes/origin/main", cwd=fixture.project)
        == fixture.base_sha
    )


@pytest.mark.parametrize("event", ["pull_request", "merge_request"])
def test_a_change_event_adds_one_file_with_exactly_one_finding(tmp_path, event):
    fixture = _make(tmp_path / "run", event)
    project = fixture.project
    changed_file = _api("CHANGED_FILE")
    assert changed_file == "changed.py"
    assert fixture.branch != "main"
    assert _git("symbolic-ref", "--short", "HEAD", cwd=project) == fixture.branch
    assert (
        _git("rev-parse", "HEAD", cwd=project) == fixture.head_sha != fixture.base_sha
    )
    assert _git("rev-list", "--count", f"{fixture.base_sha}..HEAD", cwd=project) == "1"
    assert (
        _git("diff", "--name-only", f"{fixture.base_sha}", "HEAD", cwd=project)
        == changed_file
    )
    assert _git("status", "--porcelain", cwd=project) == ""
    source = (project / changed_file).read_text(encoding="utf-8")
    calls = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and any(
            k.arg == "shell"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in node.keywords
        )
    ]
    assert len(calls) == 1 and source.count("shell=True") == 1, source
    func = calls[0].func
    assert isinstance(func, ast.Attribute) and func.attr == "call"
    assert isinstance(func.value, ast.Name) and func.value.id == "subprocess"
    assert "password" not in source.lower() and "secret" not in source.lower(), (
        "one finding, so nothing a secrets scanner would report either"
    )


@pytest.mark.parametrize("event", [None, "push"])
def test_other_events_scan_main_as_it_is(tmp_path, event):
    fixture = _make(tmp_path / "run", event)
    assert fixture.head_sha == fixture.base_sha
    assert _git("symbolic-ref", "--short", "HEAD", cwd=fixture.project) == "main"
    assert not (fixture.project / "changed.py").exists()


def test_an_event_no_page_uses_is_refused(tmp_path):
    with pytest.raises(ValueError):
        _make(tmp_path / "run", "merge_group")


def _refuse(*args, **kwargs):
    raise AssertionError(f"make_fixture went on to {args[:1]!r}")


def _nothing_made(patch: pytest.MonkeyPatch) -> None:
    """Fail the test, rather than make anything, if make_fixture runs a command or
    makes a directory: the roots below are refused before either."""
    patch.setattr(subprocess, "run", _refuse)
    patch.setattr(Path, "mkdir", _refuse)


@pytest.fixture
def nothing_made(monkeypatch):
    _nothing_made(monkeypatch)


def _unused_tmp_path(name: str) -> Path:
    """A path in /tmp, unique to this call, that does not exist."""
    path = Path("/tmp") / f"{name}-{uuid.uuid4().hex}"
    assert not os.path.lexists(path), path
    return path


@pytest.mark.skipif(not os.path.isdir("/tmp"), reason="no /tmp on this host")
def test_a_root_in_tmp_outside_a_pytest_directory_is_refused(nothing_made):
    """The tmp_path roots every other cell uses are the control: they are made."""
    probe = _unused_tmp_path("ci-fixture-probe")
    with pytest.raises(ValueError) as raised:
        _make(probe / "run", "pull_request")
    assert "under /tmp" in str(raised.value), str(raised.value)
    assert not os.path.lexists(probe), "refused before anything was made"


@pytest.mark.skipif(not os.path.isdir("/tmp"), reason="no /tmp on this host")
def test_a_root_that_resolves_into_tmp_through_a_link_is_refused(tmp_path):
    link = tmp_path / "link"
    link.symlink_to("/tmp", target_is_directory=True)
    probe = _unused_tmp_path("ci-fixture-probe")
    with pytest.raises(ValueError) as raised:
        with pytest.MonkeyPatch.context() as patch:
            _nothing_made(patch)
            _make(link / probe.name, None)
    assert "under /tmp" in str(raised.value), str(raised.value)
    assert not os.path.lexists(probe), "refused before anything was made"


def test_a_relative_root_is_refused(tmp_path, monkeypatch):
    """A relative root is read against the working directory, which can be inside
    another checkout; it is refused before anything is made."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError) as raised:
        with pytest.MonkeyPatch.context() as patch:
            _nothing_made(patch)
            _make(Path("ci-fixture-rel"), None)
    assert "is not an absolute path" in str(raised.value), str(raised.value)
    assert not os.path.lexists(tmp_path / "ci-fixture-rel")


def _unused_basetemp() -> Path:
    """A pytest-<n> directory under this user's pytest-of-<user>, that does not exist."""
    path = Path("/tmp") / f"pytest-of-{getpass.getuser()}"
    path /= f"pytest-{uuid.uuid4().int % 10**15}"
    assert not os.path.lexists(path), path
    return path


@pytest.mark.skipif(not os.path.isdir("/tmp"), reason="no /tmp on this host")
def test_a_root_in_a_pytest_directory_in_tmp_passes_the_root_check(nothing_made):
    """pytest's default basetemp is /tmp/pytest-of-<user>/pytest-<n>. An event no page
    uses is refused after the root check, so nothing is made here either."""
    basetemp = _unused_basetemp()
    with pytest.raises(ValueError) as raised:
        _make(basetemp / "test0" / "run", "merge_group")
    assert "no fixture for event" in str(raised.value), str(raised.value)
    assert not os.path.lexists(basetemp)


@pytest.mark.skipif(not os.path.isdir("/tmp"), reason="no /tmp on this host")
@pytest.mark.parametrize(
    "root",
    [
        lambda: _unused_tmp_path("ci-fixture-probe") / "pytest-x" / "run",
        lambda: (
            Path("/tmp")
            / f"pytest-of-{getpass.getuser()}x{uuid.uuid4().hex}"
            / "pytest-1"
            / "run"
        ),
        lambda: _unused_basetemp().with_name(f"pytest-x{uuid.uuid4().hex}") / "run",
    ],
    ids=[
        "a directory whose name only starts like pytest's",
        "another user's pytest directory",
        "a directory under this user's that is not a numbered basetemp",
    ],
)
def test_a_root_in_tmp_under_a_directory_pytest_did_not_make_is_refused(
    root, nothing_made
):
    path = root()
    with pytest.raises(ValueError) as raised:
        _make(path, None)
    assert "under /tmp" in str(raised.value), str(raised.value)
    assert not os.path.lexists(path.parent), "refused before anything was made"


def test_every_run_gets_a_new_empty_home(tmp_path):
    first = _make(tmp_path / "one", None)
    second = _make(tmp_path / "two", None)
    for fixture in (first, second):
        assert fixture.home.is_dir() and not any(fixture.home.iterdir())
        assert (
            fixture.project not in fixture.home.parents
            and fixture.home != fixture.project
        )
        assert fixture.home not in fixture.project.parents
    assert first.home != second.home


@pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; the hook is a sh script"
)
def test_the_invoking_user_s_git_configuration_does_not_reach_the_fixture(
    tmp_path, monkeypatch
):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("pre-commit", "commit-msg"):
        hook = hooks / name
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)
    config = tmp_path / "gitconfig"
    config.write_text(
        "[user]\n\tname = Someone Else\n\temail = someone@example.org\n"
        "[commit]\n\tgpgSign = true\n[gpg]\n\tprogram = /bin/false\n"
        f"[core]\n\thooksPath = {hooks}\n[init]\n\tdefaultBranch = trunk\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Someone Else")
    # Configuration from the environment, and a repository the environment points at.
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hooks))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.hooksPath'='{hooks}'")
    decoy = tmp_path / "decoy.git"
    _git("init", "-q", "--bare", str(decoy), cwd=tmp_path)
    monkeypatch.setenv("GIT_DIR", str(decoy))
    fixture = _make(tmp_path / "run", "pull_request")
    assert _git(
        "log", "--format=%an <%ae>|%cn <%ce>", "-1", "HEAD", cwd=fixture.project
    ) == (f"{AUTHOR}|{AUTHOR}")
    assert _git("rev-parse", "refs/heads/main", cwd=fixture.project) == fixture.base_sha
    assert _git("for-each-ref", cwd=decoy) == "", "nothing was written to GIT_DIR"


def _ignore_in(directory: Path, pattern: str) -> None:
    """Write the per-user ignore file git reads from ``directory`` when it is HOME."""
    ignore = directory / ".config" / "git" / "ignore"
    ignore.parent.mkdir(parents=True)
    ignore.write_text(pattern + "\n", encoding="utf-8")


def test_the_fixture_s_files_are_listed_with_an_empty_home(tmp_path):
    """git reads a per-user ignore file under HOME, so a source directory used as HOME
    would hide its own files from the listing."""
    source = tmp_path / "source"
    source.mkdir()
    _git("init", "-q", str(source), cwd=tmp_path)
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    (source / "extra.py").write_text("print(2)\n", encoding="utf-8")
    _ignore_in(source, "extra.py")
    fixture = _api("make_fixture")(
        tmp_path / "run",
        pipeline_path=PIPELINE,
        pipeline_text=PIPELINE_TEXT,
        event=None,
        source=source,
    )
    listed = _git(
        "ls-tree", "-r", "--name-only", fixture.base_sha, cwd=fixture.project
    ).split("\n")
    assert "app.py" in listed and "extra.py" in listed, listed


def test_the_fixture_s_commits_are_made_with_an_empty_home(tmp_path):
    """The directory a caller names for the run may already hold files; none of them
    is git's per-user configuration for the fixture's own commands."""
    root = tmp_path / "run"
    root.mkdir()
    _ignore_in(root, "app.py")
    fixture = _make(root, None)
    listed = _git(
        "ls-tree", "-r", "--name-only", fixture.base_sha, cwd=fixture.project
    ).split("\n")
    assert "app.py" in listed, listed
    assert fixture.home.is_dir() and not any(fixture.home.iterdir())


@pytest.mark.parametrize(
    "event,changed_files,expected",
    [
        (None, False, {"app.py": 3}),
        ("push", False, {"app.py": 3}),
        ("pull_request", False, {"app.py": 3, "changed.py": 1}),
        ("merge_request", False, {"app.py": 3, "changed.py": 1}),
        ("pull_request", True, {"changed.py": 1}),
        ("merge_request", True, {"changed.py": 1}),
    ],
)
def test_the_findings_each_run_expects(event, changed_files, expected):
    assert _api("expected_findings")(event, changed_files=changed_files) == expected


@pytest.mark.parametrize("event", [None, "push"])
def test_a_changed_files_scan_needs_a_change_event(event):
    with pytest.raises(ValueError):
        _api("expected_findings")(event, changed_files=True)
