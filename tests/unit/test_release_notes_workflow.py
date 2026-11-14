# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The release step of ash-tag-on-merge.yml: its body, its target, and its guards.

Why this file exists
--------------------
v3.8.0 ships breaking behavior changes as a minor release (release-line 3.x in
``ash-create-release.yml``). Its CHANGELOG entry opens with hand-written notes from
``.github/release-notes/v3.8.0.md``, included by ``.github/changelog/CHANGELOG.md.j2``.
``ash-tag-on-merge.yml`` used to publish the GitHub Release with ``--generate-notes``
alone, which lists PR titles and nothing else. So the release page, where users
pinned to ``<4`` look, would not have said what breaks or how to opt out.

The guard classes at the end of the file arrived from
``test_floating_major_tag_workflow.py`` when the floating major tag was retired and
that step, with its suite, was removed: they cover the surviving release step and
the job around it, so they live with the rest of that step's coverage.

What this asserts
-----------------
It runs the release step's own shell, extracted from the YAML, under two harnesses.
The first stubs ``gh`` to record its argv and gives the step a local bare
repository as ``origin``: the step's tag-collision guard reads the release tag off
the remote with ``git ls-remote origin`` before it creates anything, and an empty
origin answers "no such tag", as the remote does for a fresh release run.

* End to end: a scratch repository is bumped by a real commitizen through the real
  template and the real v3.8.0 notes file. The step then publishes a body that
  holds the notes file verbatim and the commitizen sections, and no other version.
* The real CHANGELOG.md: the v3.7.0 entry is extracted, bounded by the next heading.
* If a curated file exists but the entry lacks it, the step fails and publishes
  nothing.
* With no entry and no curated file, the step still publishes generated notes and
  warns.
* Control: the pre-change step, frozen below, passes no ``--notes`` on the same
  fixture, so the end-to-end case can tell the two apart.

The second harness (``_run_release_step``) stubs ``git`` as well, so it can answer
the tag-collision guard with a tag that already exists, at the merge commit or at
another one, annotated or lightweight. On it:

* The release is created at the pull request's merge commit, never at ``main``,
  which is resolved at creation time and may have moved.
* A release tag already on the remote at another commit fails the step before
  anything is published; one at the merge commit, or peeling to it, proceeds.
* The curated-notes failure directs the operator to a new ``chore(release):`` pull
  request, the one recovery that changes the input, never to a re-run that replays
  the same merge commit.
* Every workflow this one ``uses`` locally declares ``workflow_call``, or the
  caller fails to load and no release is created.

What it deliberately does not check
-----------------------------------
That gh prepends ``--notes`` to ``--generate-notes`` output. That is gh's documented
behavior (``gh release create --help``), and this harness never reaches GitHub.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-tag-on-merge.yml"
JOB = "tag-and-release"
VERSION_JOB = "resolve"  # reads the version from the merge commit's checkout
TEMPLATE = REPO_ROOT / ".github" / "changelog" / "CHANGELOG.md.j2"
NOTES_V380 = REPO_ROOT / ".github" / "release-notes" / "v3.8.0.md"
CZ_BIN = Path(sys.executable).parent / ("cz.exe" if os.name == "nt" else "cz")

# Applied to the classes that execute the step's shell; the YAML-reading unit tests
# near the end of the file must keep running everywhere. The mechanism and both
# conditions are taken from tests/unit/test_ash_bash_entrypoint_build_failure.py, so
# there is one skip idiom for this reason instead of two that can drift: on a GitHub
# Windows runner `bash` resolves to the WSL launcher stub, which is on PATH whether
# or not a distribution is installed, and the step under test only ever runs on
# ubuntu-latest.
_REQUIRES_BASH = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; the step under test runs on ubuntu-latest",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the step under test is a bash script"
    ),
    pytest.mark.skipif(
        shutil.which("git") is None,
        reason="the step under test reads the release tag off its remote with git",
    ),
]

_INTEGRATION_SHELL = [pytest.mark.integration, *_REQUIRES_BASH]


def _requires_bash(func):
    """Apply _REQUIRES_BASH to a single test, for classes that are not wholly skipped."""
    for mark in reversed(_REQUIRES_BASH):
        func = mark(func)
    return func


#: The release pull request's merge commit, as the workflow's env would carry it.
MERGE_SHA = "5555555555555555555555555555555555555555"

# `gh release view` answers "no such release"; every call's argv is logged as JSON.
GH_STUB = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["GH_CALL_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
sys.exit(1 if sys.argv[1:3] == ["release", "view"] else 0)
"""

# The release step's shell before the notes change, verbatim. Frozen so the control
# keeps failing after the working tree stops containing it.
FROZEN_PRE_CHANGE_SCRIPT = """TAG="v${VERSION}"

if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "::notice::Release $TAG already exists, skipping"
  exit 0
fi

gh release create "$TAG" \\
  --repo "$GITHUB_REPOSITORY" \\
  --target main \\
  --generate-notes \\
  --title "$TAG"

echo "Created release $TAG"
"""


def _release_script() -> str:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = [
        s
        for s in doc["jobs"][JOB]["steps"]
        if "gh release create" in (s.get("run") or "")
    ]
    assert len(steps) == 1, (
        f"expected one step running gh release create, found {len(steps)}"
    )
    script = steps[0]["run"]
    assert "${{" not in script, "the run block has an Actions expression"
    return script


# The job-level env the release step reads its --target from (ash-tag-on-merge.yml).
# Shaped like a commit SHA and nothing like a digest, so no entropy detector reads it as one.
RELEASE_SHA = "a1" * 20


class Result:
    def __init__(self, proc: subprocess.CompletedProcess, calls: list[list[str]]):
        self.proc = proc
        self.calls = calls

    @property
    def create(self) -> list[str] | None:
        made = [c for c in self.calls if c[:2] == ["release", "create"]]
        assert len(made) <= 1, made
        return made[0] if made else None

    @property
    def notes(self) -> str | None:
        argv = self.create or []
        return argv[argv.index("--notes") + 1] if "--notes" in argv else None

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\ncalls={self.calls}\n"
            f"stdout:\n{self.proc.stdout}\nstderr:\n{self.proc.stderr}"
        )


def _give_an_origin(workdir: Path, tmp_path: Path) -> None:
    """Make `workdir` a repository whose `origin` is an empty local bare repository.

    The step's tag-collision guard runs `git ls-remote origin` before anything else,
    so a workdir with no repository, or a repository with no origin, exits the script
    at 128 before the behavior under test. The origin holds no tag, which is the
    guard's passing case: the release tag does not exist yet.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    origin = tmp_path / "origin.git"
    if not origin.exists():
        origin.mkdir()
        _git(origin, "init", "-q", "--bare", ".", env=env)
    _git(workdir, "init", "-q", env=env)
    _git(workdir, "remote", "add", "origin", f"file://{origin}", env=env)


def _run(script: str, workdir: Path, version: str, tmp_path: Path) -> Result:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(GH_STUB, encoding="utf-8")
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log = tmp_path / "gh-calls.jsonl"
    log.write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    script_path = tmp_path / "step.sh"
    script_path.write_text(script, encoding="utf-8")
    _give_an_origin(workdir, tmp_path)

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "VERSION": version,
        "MERGE_SHA": MERGE_SHA,
        "GITHUB_REPOSITORY": "awslabs/automated-security-helper",
        "GH_TOKEN": "stub-token",
        "GH_CALL_LOG": str(log),
        "RUNNER_TEMP": str(runner_temp),
        "RELEASE_SHA": RELEASE_SHA,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    proc = subprocess.run(
        ["bash", "-e", str(script_path)],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]
    return Result(proc, calls)


def _git(repo: Path, *args: str, env: dict) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        timeout=CHILD_TIMEOUT_SECONDS,
    )


@pytest.fixture
def bumped_repo(tmp_path: Path) -> Path:
    """A repository commitizen has bumped 3.7.0 -> 3.8.0 through the real template."""
    if not CZ_BIN.exists() or shutil.which("git") is None:
        pytest.skip("needs git and commitizen")
    repo = tmp_path / "repo"
    (repo / ".github" / "changelog").mkdir(parents=True)
    (repo / ".github" / "release-notes").mkdir(parents=True)
    shutil.copy(TEMPLATE, repo / ".github" / "changelog" / TEMPLATE.name)
    shutil.copy(NOTES_V380, repo / ".github" / "release-notes" / NOTES_V380.name)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "3.7.0"\n\n'
        "[tool.commitizen]\n"
        'name = "cz_conventional_commits"\nversion = "3.7.0"\n'
        'version_files = ["pyproject.toml:^version"]\ntag_format = "v$version"\n'
        'changelog_file = "CHANGELOG.md"\n'
        'template = ".github/changelog/CHANGELOG.md.j2"\n'
        "update_changelog_on_bump = true\n",
        encoding="utf-8",
    )
    (repo / "CHANGELOG.md").write_text(
        "## v3.7.0 (2026-08-27)\n\n### Fix\n\n- an older fix\n", encoding="utf-8"
    )
    env = {
        "PATH": os.pathsep.join([str(CZ_BIN.parent), os.environ.get("PATH", "")]),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    _git(repo, "init", "-q", "-b", "main", env=env)
    for key, value in (
        ("user.name", "fixture"),
        ("user.email", "fixture@example.invalid"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
    ):
        _git(repo, "config", key, value, env=env)
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-q", "-m", "chore: initial", env=env)
    _git(repo, "tag", "v3.7.0", env=env)
    _git(
        repo,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "feat!: flip a default\n\nBREAKING CHANGE: the default flipped",
        env=env,
    )
    subprocess.run(
        [str(CZ_BIN), "bump", "--changelog", "--yes", "--increment", "MINOR"],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    return repo


class TestTheReleaseBody:
    pytestmark = _INTEGRATION_SHELL

    def test_it_carries_the_curated_notes_and_the_changelog_entry(
        self, bumped_repo: Path, tmp_path: Path
    ):
        result = _run(_release_script(), bumped_repo, "3.8.0", tmp_path)

        assert result.proc.returncode == 0, result.describe()
        assert result.create is not None, result.describe()
        assert "--generate-notes" in result.create
        notes = result.notes
        assert notes is not None, f"no --notes was passed\n{result.describe()}"
        curated = NOTES_V380.read_text(encoding="utf-8").strip()
        assert curated in notes, notes
        assert notes.lstrip().startswith("### Breaking behavior changes"), notes
        assert "### BREAKING CHANGE" in notes and "the default flipped" in notes
        assert "an older fix" not in notes, "the next version's entry leaked in"
        assert "## v3.8.0" not in notes, "the heading duplicates the release title"

    def test_the_real_changelog_entry_is_bounded_by_the_next_heading(
        self, tmp_path: Path
    ):
        work = tmp_path / "work"
        work.mkdir()
        shutil.copy(REPO_ROOT / "CHANGELOG.md", work / "CHANGELOG.md")

        result = _run(_release_script(), work, "3.7.0", tmp_path)

        assert result.proc.returncode == 0, result.describe()
        notes = result.notes
        assert notes, (
            f"v3.7.0 has an entry, but no --notes was passed\n{result.describe()}"
        )
        assert "## v3.6.0" not in notes and "## v3.7.0" not in notes, notes

    def test_a_curated_file_missing_from_the_entry_publishes_nothing(
        self, tmp_path: Path
    ):
        work = tmp_path / "work"
        (work / ".github" / "release-notes").mkdir(parents=True)
        shutil.copy(NOTES_V380, work / ".github" / "release-notes" / NOTES_V380.name)
        (work / "CHANGELOG.md").write_text(
            "## v3.8.0 (2026-10-02)\n\n### Feat\n\n- something\n", encoding="utf-8"
        )

        result = _run(_release_script(), work, "3.8.0", tmp_path)

        # Liveness: the step reached its own check, so the absence below is not a
        # harness that failed to start.
        assert "::error::" in result.proc.stdout, result.describe()
        assert result.proc.returncode != 0, result.describe()
        assert result.create is None, result.describe()

    def test_no_entry_still_publishes_generated_notes(self, tmp_path: Path):
        work = tmp_path / "work"
        work.mkdir()
        (work / "CHANGELOG.md").write_text(
            "## v3.7.0 (2026-08-27)\n\n- old\n", encoding="utf-8"
        )

        result = _run(_release_script(), work, "3.9.0", tmp_path)

        assert result.proc.returncode == 0, result.describe()
        assert result.create is not None and "--generate-notes" in result.create
        assert result.notes is None, result.describe()
        assert "::warning::" in result.proc.stdout, result.describe()

    def test_the_release_targets_the_pinned_commit_and_attaches_the_staged_set(
        self, tmp_path: Path
    ):
        # The tag goes on the commit the assets were built from, not on whatever
        # main is by then, and the files are the staged directory, unexpanded here
        # because the fixture has none (the shell passes an unmatched glob through).
        work = tmp_path / "work"
        work.mkdir()
        (work / "CHANGELOG.md").write_text("", encoding="utf-8")

        result = _run(_release_script(), work, "4.0.0", tmp_path)

        assert result.proc.returncode == 0, result.describe()
        argv = result.create or []
        assert argv[argv.index("--target") + 1] == RELEASE_SHA, result.describe()
        assert argv[-1] == "release-assets/*", result.describe()


class TestTheHarnessCanFail:
    pytestmark = _INTEGRATION_SHELL

    def test_the_pre_change_script_publishes_no_curated_notes(
        self, bumped_repo: Path, tmp_path: Path
    ):
        result = _run(FROZEN_PRE_CHANGE_SCRIPT, bumped_repo, "3.8.0", tmp_path)

        assert result.create is not None, result.describe()
        assert result.notes is None, (
            "the pre-change step is expected to pass no --notes; if it does, the "
            "end-to-end test above is not measuring the change"
        )


# ---------------------------------------------------------------------------
# The stubbed-git harness, and the guards it measures. Moved here from
# test_floating_major_tag_workflow.py when the floating major tag was retired:
# these cover the surviving release step, not the removed one.
# ---------------------------------------------------------------------------

# Any sha; the harness only needs to see it arrive at the `gh release create` call
# unchanged. Distinct from MERGE_SHA above so a leak between the two harnesses would
# be visible.
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
FAKE_REPO = "awslabs/automated-security-helper"
OTHER_SHA = "89abcdef0123456789abcdef0123456789abcdef"  # pragma: allowlist secret
TAG_OBJECT_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # pragma: allowlist secret

RELEASE_GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_CALL_LOG"
# `gh release view` finds no release, so the step goes on to create one.
if [ "$1" = "release" ] && [ "$2" = "view" ]; then exit 1; fi
exit 0
"""

# Answers the step's read of the release tag on the remote. STUB_TAG_SHA is the commit the
# tag points at; with STUB_TAG_OBJECT set the tag is annotated, so the remote lists the
# tag object first and the commit it peels to on the `^{}` line, as `git ls-remote` does.
# Unset STUB_TAG_SHA means the tag is absent.
RELEASE_GIT_STUB = """#!/usr/bin/env bash
if [ "$1" = "ls-remote" ]; then
  if [ -n "${STUB_TAG_SHA:-}" ]; then
    if [ -n "${STUB_TAG_OBJECT:-}" ]; then
      printf '%s\\trefs/tags/v3.8.0\\n' "$STUB_TAG_OBJECT"
      printf '%s\\trefs/tags/v3.8.0^{}\\n' "$STUB_TAG_SHA"
    else
      printf '%s\\trefs/tags/v3.8.0\\n' "$STUB_TAG_SHA"
    fi
  fi
  exit 0
fi
echo "harness: unexpected git invocation: $*" >&2
exit 1
"""


class StepResult:
    """What the step did under the stubbed-git harness: exit status and gh argv."""

    def __init__(self, proc: subprocess.CompletedProcess, calls: list[str]):
        self.proc = proc
        self.calls = calls

    @property
    def ok(self) -> bool:
        return self.proc.returncode == 0

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\n"
            f"gh calls:\n  " + ("\n  ".join(self.calls) or "(none)") + "\n"
            f"stdout: {self.proc.stdout.strip()}\n"
            f"stderr: {self.proc.stderr.strip()}"
        )


def _run_release_step(
    script: str,
    tmp_path: Path,
    tag_sha: str | None = None,
    tag_object: str | None = None,
    changelog: str = "",
    curated: str | None = None,
) -> StepResult:
    """Run the release step's shell with gh and git stubbed. ``tag_sha`` is the commit
    the release tag already points at on the remote, or None when the tag does not
    exist. ``changelog`` is the CHANGELOG.md the checkout holds (empty by default), and
    ``curated`` the content of ``.github/release-notes/v3.8.0.md`` when that file
    should exist."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-calls.log"
    log.write_text("", encoding="utf-8")
    for name, body in (("gh", RELEASE_GH_STUB), ("git", RELEASE_GIT_STUB)):
        stub = bin_dir / name
        stub.write_text(body, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    (work / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    if curated is not None:
        notes_dir = work / ".github" / "release-notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "v3.8.0.md").write_text(curated, encoding="utf-8")
    script_path = tmp_path / "release-step.sh"
    script_path.write_text(script, encoding="utf-8")

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "VERSION": "3.8.0",
        "MERGE_SHA": FAKE_SHA,
        "GITHUB_REPOSITORY": FAKE_REPO,
        "GH_TOKEN": "stub-token",
        "GH_CALL_LOG": str(log),
        "RUNNER_TEMP": str(tmp_path),
        "STUB_TAG_SHA": tag_sha or "",
        "STUB_TAG_OBJECT": tag_object or "",
    }
    proc = subprocess.run(
        ["bash", "-e", str(script_path)],
        env=env,
        cwd=work,
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    return StepResult(proc, calls)


class TestTheReleaseTargetsTheMergeCommit:
    """`--target main` is resolved when the release is created, so a pull request merged
    in between puts the release tag past the release pull request's merge commit.

    Only the test that runs the step's shell carries the bash skips: the two
    YAML-reading unit tests below must keep running everywhere.
    """

    @pytest.mark.integration
    @_requires_bash
    def test_release_create_targets_the_merge_commit(self, tmp_path: Path):
        result = _run_release_step(_release_script(), tmp_path)

        created = [c for c in result.calls if c.startswith("release create")]
        assert created, f"the step never ran `gh release create`\n{result.describe()}"
        assert f"--target {FAKE_SHA}" in created[0], (
            "the release must be created at the pull request's merge commit\n"
            f"{result.describe()}"
        )
        assert "--target main" not in created[0], result.describe()

    @pytest.mark.unit
    def test_the_version_is_read_from_the_merge_commit(self):
        """The checkout the version and changelog are read from is the merge commit.

        Reading them from the tip of main lets the run for an earlier release pull
        request see a later release's version and create that release at the older
        merge commit.

        The version is read in the `resolve` job, which pins the commit and hands the
        version and SHA to the jobs that build and publish; `tag-and-release` reads
        both through `needs`, so the read is checked where it happens.
        """
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = doc["jobs"][VERSION_JOB]["steps"]
        checkout = next(
            s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")
        )
        read_version = next(s for s in steps if s.get("id") == "version")

        assert steps.index(checkout) < steps.index(read_version)
        assert (
            checkout["with"]["ref"]
            == "${{ github.event.pull_request.merge_commit_sha }}"
        )

    @pytest.mark.unit
    def test_the_merge_commit_comes_from_the_event_payload(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        step = next(
            s
            for s in doc["jobs"][JOB]["steps"]
            if isinstance(s, dict) and "gh release create" in (s.get("run") or "")
        )
        assert (
            step["env"]["MERGE_SHA"]
            == "${{ github.event.pull_request.merge_commit_sha }}"
        )


@pytest.mark.integration
class TestAnExistingReleaseTagMustSitAtTheMergeCommit:
    """`gh release create --target` is ignored when the tag already exists, so a tag at
    another commit would publish the release there. The step reads the tag on the remote
    first and refuses unless it is absent or already at the merge commit."""

    pytestmark = _REQUIRES_BASH

    def _created(self, result: StepResult) -> list[str]:
        return [c for c in result.calls if c.startswith("release create")]

    def test_a_tag_at_another_commit_fails_the_step(self, tmp_path: Path):
        result = _run_release_step(_release_script(), tmp_path, tag_sha=OTHER_SHA)

        # Liveness: the step's own annotation, not a harness that failed to start.
        assert "::error::" in result.proc.stdout, result.describe()
        assert OTHER_SHA in result.proc.stdout and FAKE_SHA in result.proc.stdout, (
            f"the error must name both commits\n{result.describe()}"
        )
        assert not result.ok, (
            f"a release tag at another commit must fail the step\n{result.describe()}"
        )
        assert self._created(result) == [], (
            f"the release was created anyway\n{result.describe()}"
        )

    def test_a_tag_at_the_merge_commit_proceeds(self, tmp_path: Path):
        result = _run_release_step(_release_script(), tmp_path, tag_sha=FAKE_SHA)

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()

    def test_an_annotated_tag_is_judged_by_the_commit_it_peels_to(self, tmp_path: Path):
        result = _run_release_step(
            _release_script(),
            tmp_path,
            tag_sha=FAKE_SHA,
            tag_object=TAG_OBJECT_SHA,
        )

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()

    def test_an_absent_tag_proceeds(self, tmp_path: Path):
        result = _run_release_step(_release_script(), tmp_path, tag_sha=None)

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()


@pytest.mark.integration
class TestTheCuratedNotesFailureNamesTheRecovery:
    """The failure's advice must be an action that can change the outcome.

    The checkout is pinned to the pull request's merge commit, and a re-run replays
    the same event payload, so it reads the same CHANGELOG.md and fails identically.
    The one recovery that changes the input is a new chore(release): pull request
    whose regenerated entry includes the curated file, and the error must direct
    there rather than advise the re-run that cannot work.
    """

    pytestmark = _REQUIRES_BASH

    CURATED = "### Breaking behavior changes\n\n- a curated note\n"

    def test_the_error_directs_to_a_new_release_pull_request(self, tmp_path: Path):
        result = _run_release_step(
            _release_script(),
            tmp_path,
            changelog="## v3.8.0 (2026-10-02)\n\n### Feat\n\n- something\n",
            curated=self.CURATED,
        )

        # Liveness: the step's own annotation, not a harness that failed to start.
        assert "::error::" in result.proc.stdout, result.describe()
        assert not result.ok, result.describe()
        assert "chore(release)" in result.proc.stdout, (
            "the curated-notes error must direct to a new chore(release): pull "
            f"request, the only recovery that changes the input\n{result.describe()}"
        )
        assert "then rerun this job" not in result.proc.stdout, (
            "a re-run replays the same merge commit and reads the same unfixed "
            f"CHANGELOG.md, so advising one misdirects the operator\n"
            f"{result.describe()}"
        )

    def test_an_entry_that_carries_the_notes_still_publishes(self, tmp_path: Path):
        result = _run_release_step(
            _release_script(),
            tmp_path,
            changelog=(
                "## v3.8.0 (2026-10-02)\n\n"
                + self.CURATED
                + "\n### Feat\n\n- something\n"
            ),
            curated=self.CURATED,
        )

        assert result.ok, result.describe()
        created = [c for c in result.calls if c.startswith("release create")]
        assert len(created) == 1, result.describe()


@pytest.mark.unit
class TestEveryLocalWorkflowCallIsCallable:
    """A job that ``uses`` a workflow of this repository makes GitHub read that
    workflow when it loads the caller. If the callee declares no ``workflow_call``
    trigger, the caller fails to load and none of its jobs run, so the release is
    never created."""

    @staticmethod
    def _on(doc: dict) -> dict:
        # PyYAML reads the bare key ``on`` as the boolean True.
        triggers = doc.get("on", doc.get(True))
        return triggers if isinstance(triggers, dict) else {}

    def test_every_local_callee_declares_workflow_call(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        callees = [
            job["uses"]
            for job in doc["jobs"].values()
            if str(job.get("uses", "")).startswith("./")
        ]
        for uses in callees:
            callee = yaml.safe_load((REPO_ROOT / uses[2:]).read_text(encoding="utf-8"))
            assert "workflow_call" in self._on(callee), (
                f"{uses} is called from {WORKFLOW.name} but declares no "
                "workflow_call trigger"
            )

    def test_the_check_can_fail(self):
        """Controls for the helper: a callee with only push and dispatch triggers
        reads as missing, and one that declares the trigger reads as present, under
        both spellings of the ``on`` key."""
        without = yaml.safe_load("on:\n  push: {}\n  workflow_dispatch: {}\n")
        with_call = yaml.safe_load("on:\n  workflow_call:\n    inputs: {}\n")
        assert "workflow_call" not in self._on(without)
        assert "workflow_call" in self._on(with_call)
