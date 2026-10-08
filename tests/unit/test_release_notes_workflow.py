# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitHub Release body must carry the version's CHANGELOG entry and curated notes.

Why this file exists
--------------------
v3.8.0 ships breaking behavior changes as a minor release (release-line 3.x in
``ash-create-release.yml``). Its CHANGELOG entry opens with hand-written notes from
``.github/release-notes/v3.8.0.md``, included by ``.github/changelog/CHANGELOG.md.j2``.
``ash-tag-on-merge.yml`` used to publish the GitHub Release with ``--generate-notes``
alone, which lists PR titles and nothing else. So the release page, where users
pinned to ``<4`` look, would not have said what breaks or how to opt out.

What this asserts
-----------------
It runs the release step's own shell, extracted from the YAML, with ``gh`` stubbed
to record its argv.

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

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-tag-on-merge.yml"
JOB = "tag-and-release"
TEMPLATE = REPO_ROOT / ".github" / "changelog" / "CHANGELOG.md.j2"
NOTES_V380 = REPO_ROOT / ".github" / "release-notes" / "v3.8.0.md"
CZ_BIN = Path(sys.executable).parent / ("cz.exe" if os.name == "nt" else "cz")

pytestmark = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; the step under test runs on ubuntu-latest",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the step under test is a bash script"
    ),
]

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

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "VERSION": version,
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
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


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
    )
    return repo


class TestTheReleaseBody:
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
    def test_the_pre_change_script_publishes_no_curated_notes(
        self, bumped_repo: Path, tmp_path: Path
    ):
        result = _run(FROZEN_PRE_CHANGE_SCRIPT, bumped_repo, "3.8.0", tmp_path)

        assert result.create is not None, result.describe()
        assert result.notes is None, (
            "the pre-change step is expected to pass no --notes; if it does, the "
            "end-to-end test above is not measuring the change"
        )
