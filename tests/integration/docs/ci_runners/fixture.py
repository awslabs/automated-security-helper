# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The git repository each CI-runner pipeline runs in.

make_fixture makes it from the docs fixture, tests/test_data/docs_fixtures/sample-project
by default, the way docs_runner.py makes a page's session:

* the fixture's files (from git's listing, not a directory walk) and the pipeline file
  in one base commit on ``main``, with the fixed author, committer and date the docs
  runner commits with, so the same inputs give the same commit;
* a bare repository holding ``main`` as ``origin``, so a pipeline can name
  ``origin/main`` as the base of a changed-files scan;
* for a pull request or merge request, a branch with one more commit that adds
  CHANGED_FILE, whose one finding is a ``subprocess.call`` with ``shell=True`` (bandit
  B602), and nothing a secrets scanner reports. A changed-files scan then has exactly
  one finding to report, so a broken diff, which reports nothing, cannot pass as a
  clean scan;
* a new, empty HOME for the run, beside the project, so tools one pipeline installs
  are not found by the next.

The root has to be an absolute path outside /tmp, or below a directory pytest makes there
for this user (pytest-of-<user>/pytest-<n>); any other root is refused before anything
runs.

git runs with an environment built from nothing: GIT_CONFIG_GLOBAL is the null device,
GIT_CONFIG_NOSYSTEM is set, HOME is a new, empty directory (so no per-user ignore or
attributes file is read), the identity and dates are fixed, repositories are created
without templates (so with no hooks), and commits skip hooks and signing. Nothing of
the invoking user's git configuration (identity, signing, hooks, default branch)
reaches the commits.

expected_findings says what a scan of the result finds: the fixture's two in
``app.py``, plus CHANGED_FILE's one when the branch exists; a changed-files scan finds
only CHANGED_FILE's.
"""

from __future__ import annotations

import getpass
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[4]

#: The file a pull request or merge request branch adds.
CHANGED_FILE = "changed.py"
#: Its content: exactly one finding, bandit B602.
CHANGED_SOURCE = """\
import subprocess


def run_in_a_shell(command):
    return subprocess.call(command, shell=True)
"""

#: The events a fixture is made for; None is a block with no event.
EVENTS = (None, "push", "pull_request", "merge_request")
#: The events whose pipelines run on a branch that changes CHANGED_FILE.
CHANGE_EVENTS = frozenset({"pull_request", "merge_request"})
MAIN = "main"
CHANGE_BRANCH = "add-changed-file"

#: The identity and date the docs runner commits its fixtures with.
AUTHOR_NAME = "Docs Example"
AUTHOR_EMAIL = "docs-example@example.com"
COMMIT_DATE = "2026-01-01T00:00:00Z"

#: What a full scan of the sample project finds, by file.
FIXTURE_FINDINGS: Mapping[str, int] = {"app.py": 2}
#: What CHANGED_FILE adds.
CHANGED_FINDINGS: Mapping[str, int] = {CHANGED_FILE: 1}

#: The directory every process on the host shares for temporary files, and the numbered
#: directories pytest makes in it: pytest-of-<user>/pytest-<n> (pytest-of-unknown when
#: the user name cannot be used).
SYSTEM_TMP = "/tmp"
_PYTEST_BASETEMP = re.compile(r"pytest-\d+")

#: Settings each git command gets, whatever configuration the environment holds.
_GIT_SETTINGS = (
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "core.autocrlf=false",
    "core.fsmonitor=false",
    "gc.auto=0",
    "maintenance.auto=false",
)


@dataclass(frozen=True)
class Fixture:
    #: The working tree the pipeline runs in.
    project: Path
    #: The bare repository that is the project's ``origin``.
    origin: Path
    #: A new, empty directory for the run's HOME.
    home: Path
    base_sha: str
    #: The commit HEAD is on: the change branch's tip, or base_sha.
    head_sha: str
    branch: str
    event: str | None
    pipeline_path: str


def _git_environment(home: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": AUTHOR_NAME,
        "GIT_AUTHOR_EMAIL": AUTHOR_EMAIL,
        "GIT_COMMITTER_NAME": AUTHOR_NAME,
        "GIT_COMMITTER_EMAIL": AUTHOR_EMAIL,
        "GIT_AUTHOR_DATE": COMMIT_DATE,
        "GIT_COMMITTER_DATE": COMMIT_DATE,
    }
    # Windows needs SYSTEMROOT to start a process at all.
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def _git(env: Mapping[str, str], cwd: Path, *args: str) -> str:
    settings = [word for setting in _GIT_SETTINGS for word in ("-c", setting)]
    done = subprocess.run(
        ["git", *settings, *args],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {cwd} ({done.returncode}): "
            f"{done.stderr.strip()}"
        )
    return done.stdout.strip()


def _listed_files(source: Path) -> list[Path]:
    """The files under ``source`` that git lists: tracked ones, and untracked ones it
    does not ignore, as docs_checks.listed_files reads them.

    git runs with the same environment built from nothing as the fixture's own
    commands, and HOME a new, empty directory, so nothing of the invoking user's
    environment (GIT_DIR, configuration from GIT_CONFIG_* or the global file) and no
    per-user file under HOME (``.config/git/ignore``, which git reads with
    ``--exclude-standard``) changes what is listed. The checkout's top is named as a
    safe directory on the command line, which a global setting would otherwise do
    when the checkout belongs to another user.
    """
    source = Path(source)
    top = next((p for p in (source, *source.parents) if (p / ".git").exists()), None)
    if top is None:
        raise RuntimeError(
            f"{source} is not inside a git checkout, so git cannot list it"
        )
    with tempfile.TemporaryDirectory(prefix="fixture-git-home-") as home:
        listing = _git(
            _git_environment(Path(home)),
            source,
            "-c",
            f"safe.directory={os.path.realpath(top)}",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            ".",
        )
    found = {source / entry for entry in listing.split("\0") if entry}
    # --cached still lists a tracked file deleted from the working tree.
    files = sorted(path for path in found if path.is_file() and path.name != ".keep")
    if not files:
        raise RuntimeError(f"git lists no files under {source}")
    return files


def _relative_file(path: str, what: str) -> PurePosixPath:
    relative = PurePosixPath(path)
    if (
        not path
        or "\\" in path
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:1] == (".git",)
        or str(relative) in ("", ".")
    ):
        raise ValueError(f"{what} {path!r} is not a relative path inside the project")
    return relative


def _write(project: Path, relative: PurePosixPath, content: str | bytes) -> None:
    target = project.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def _pytest_users() -> set[str]:
    """The names pytest gives this user's directory in /tmp: pytest-of-<user>, and
    pytest-of-unknown, which it uses when the user name cannot be used."""
    names = {"pytest-of-unknown"}
    try:
        names.add(f"pytest-of-{getpass.getuser()}")
    except (KeyError, OSError):
        pass
    return names


def _check_root(root: Path) -> None:
    """Refuse a relative root, which is read against the working directory and so can
    land inside another checkout, and a root that resolves into /tmp other than below
    a directory pytest makes for this user, /tmp/pytest-of-<user>/pytest-<n>: /tmp is
    shared by every process on the host, so a fixture there could be read or changed
    by another run. Any other absolute root is kept."""
    if not root.is_absolute():
        raise ValueError(
            f"the fixture root {root} is not an absolute path; make it under the "
            "test's tmp_path"
        )
    resolved = os.path.realpath(root)
    tmp = os.path.realpath(SYSTEM_TMP)
    try:
        inside = os.path.commonpath([resolved, tmp]) == tmp
    except ValueError:
        inside = False
    if not inside:
        return
    parts = Path(os.path.relpath(resolved, tmp)).parts
    if (
        len(parts) > 2
        and parts[0] in _pytest_users()
        and _PYTEST_BASETEMP.fullmatch(parts[1])
    ):
        return
    raise ValueError(
        f"the fixture root {root} resolves to {resolved}, under /tmp but not below a "
        "directory pytest makes for this user (pytest-of-<user>/pytest-<n>); make it "
        "under the test's tmp_path"
    )


def make_fixture(
    root: Path,
    *,
    pipeline_path: str,
    pipeline_text: str,
    event: str | None,
    source: Path | None = None,
    extra_files: Mapping[str, str | bytes] | None = None,
) -> Fixture:
    """A fresh repository under ``root`` for one pipeline run.

    ``root/project`` is the working tree, ``root/origin.git`` its origin and
    ``root/home`` the run's HOME. ``extra_files`` (relative path -> content) are
    committed in the base commit beside the pipeline, for files a pipeline calls, such
    as a reusable workflow. A relative root, and a root in /tmp outside a pytest
    temporary directory, are refused before anything runs or is made (_check_root).
    """
    _check_root(Path(root))
    if event not in EVENTS:
        raise ValueError(
            f"no fixture for event {event!r}; the pages' pipelines run on "
            + ", ".join(str(e) for e in EVENTS)
        )
    source = (
        Path(source)
        if source is not None
        else (REPO_ROOT / "tests" / "test_data" / "docs_fixtures" / "sample-project")
    )
    listed = _listed_files(source)
    fixture_files = {p.relative_to(source).as_posix() for p in listed}
    added: dict[str, str | bytes] = {
        pipeline_path: pipeline_text,
        **(extra_files or {}),
    }
    for path in added:
        _relative_file(path, "the file")
        if path in fixture_files or path == CHANGED_FILE:
            raise ValueError(f"{path!r} would replace a file of the fixture")
    if len(added) != 1 + len(extra_files or {}):
        raise ValueError("an extra file has the pipeline's path")

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    project, origin, home = root / "project", root / "origin.git", root / "home"
    for directory in (project, origin, home):
        directory.mkdir()
    # The run's HOME is new and empty, and git writes nothing there; ``root`` may
    # already hold files, such as a per-user ignore file git would read from HOME.
    env = _git_environment(home)

    _git(env, root, "init", "-q", "--template=", "-b", MAIN, str(project))
    for path in listed:
        target = project / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    for path, content in added.items():
        _write(project, _relative_file(path, "the file"), content)
    _git(env, project, "add", "-A")
    _git(
        env,
        project,
        "commit",
        "-q",
        "--no-verify",
        "--no-gpg-sign",
        "-m",
        "Add the sample project and the pipeline",
    )
    base_sha = _git(env, project, "rev-parse", "HEAD")

    _git(env, root, "init", "-q", "--bare", "--template=", "-b", MAIN, str(origin))
    _git(env, project, "remote", "add", "origin", str(origin))
    _git(env, project, "push", "-q", "--no-verify", "origin", MAIN)

    branch, head = MAIN, base_sha
    if event in CHANGE_EVENTS:
        branch = CHANGE_BRANCH
        _git(env, project, "checkout", "-q", "-b", branch)
        _write(project, PurePosixPath(CHANGED_FILE), CHANGED_SOURCE)
        _git(env, project, "add", "--", CHANGED_FILE)
        _git(
            env,
            project,
            "commit",
            "-q",
            "--no-verify",
            "--no-gpg-sign",
            "-m",
            f"Add {CHANGED_FILE}",
        )
        head = _git(env, project, "rev-parse", "HEAD")
    return Fixture(
        project=project,
        origin=origin,
        home=home,
        base_sha=base_sha,
        head_sha=head,
        branch=branch,
        event=event,
        pipeline_path=pipeline_path,
    )


def expected_findings(event: str | None, *, changed_files: bool) -> dict[str, int]:
    """The findings, by file, a scan of a fixture made for ``event`` reports.

    A changed-files scan needs a change event: without the branch there is no change
    to scan, and an empty result would prove nothing.
    """
    if event not in EVENTS:
        raise ValueError(f"no fixture for event {event!r}")
    change = event in CHANGE_EVENTS
    if changed_files and not change:
        raise ValueError(
            f"a changed-files scan on event {event!r} has no changed file to find"
        )
    if changed_files:
        return dict(CHANGED_FINDINGS)
    return {**FIXTURE_FINDINGS, **(CHANGED_FINDINGS if change else {})}
