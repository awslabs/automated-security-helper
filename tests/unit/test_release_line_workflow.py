# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With release-line 3.x selected, the release workflow must not bump to 4.x.

Why this file exists
--------------------
``main`` carries ``feat!`` commits (#640, #696) whose changes ship as 3.x by
maintainer decision, because 4.0.0 is reserved for the v4 packaging work. Left to
itself, ``cz bump`` reads those commits and produces 4.0.0. The ``RELEASE_LINE``
setting in ``.github/workflows/ash-create-release.yml`` caps that to a minor. A
mistake there is silent in the worst direction: the workflow would open a 4.0.0
release PR, and a merge would publish a ``v4`` tag that the v4 work then collides
with.

What this asserts
-----------------
It runs the workflow's own ``Resolve release line`` and ``Determine bump`` shell,
extracted from the YAML by step id, against a real commitizen in a scratch git
repository whose history is built per test. Only ``uv`` is stubbed, and only to
drop its ``run`` prefix. So a pass means commitizen itself produced the version.

* 3.x with a breaking commit gives 3.8.0, and names the commit it overrode.
* auto with the same history gives 4.0.0. This is the control for the case above:
  without it, a fixture commitizen does not read as breaking would make 3.8.0
  look like the cap working.
* 3.x leaves a patch-only history as a patch.
* 3.x refuses to run once the current version is 4.x.
* The bump step's own backstop fails the job when 3.x is selected and the bump
  still lands on 4.x. That is tested by feeding it no increment, which is what a
  broken resolve step would hand it.

It also renders the changelog template with commitizen's own renderer, to show the
hand-written v3.8.0 notes land under the v3.8.0 heading and nowhere else.

What it deliberately does not check
-----------------------------------
That Actions passes the setting through, or that the release PR gets created. A pass
here means "given this setting and this history, the shell picks this version".
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-create-release.yml"
JOB = "create-release-pr"
NOTES_V380 = REPO_ROOT / ".github" / "release-notes" / "v3.8.0.md"

# The same skip idiom as tests/unit/test_floating_major_tag_workflow.py, for the
# same reason: on a Windows runner `bash` is the WSL stub, and the steps under test
# only ever run on ubuntu-latest.
_REQUIRES_BASH = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; the steps under test run on ubuntu-latest",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the steps under test are bash scripts"
    ),
    pytest.mark.skipif(shutil.which("git") is None, reason="needs git"),
]

CZ_BIN = Path(sys.executable).parent / ("cz.exe" if os.name == "nt" else "cz")

UV_STUB = """#!/usr/bin/env bash
if [ "$1" = "run" ]; then shift; fi
exec "$@"
"""

FIXTURE_PYPROJECT = """[project]
name = "fixture"
version = "{version}"

[tool.commitizen]
name = "cz_conventional_commits"
version = "{version}"
version_files = ["pyproject.toml:^version"]
tag_format = "v$version"
changelog_file = "CHANGELOG.md"
update_changelog_on_bump = true
"""


def _steps() -> list[dict]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return doc["jobs"][JOB]["steps"]


def _step_script(step_id: str) -> str:
    matches = [s for s in _steps() if s.get("id") == step_id]
    assert len(matches) == 1, (
        f"expected one step with id {step_id!r}, found {len(matches)}"
    )
    script = matches[0]["run"]
    assert "${{" not in script, (
        f"step {step_id!r} has an Actions expression in its run block, which this "
        "harness does not expand"
    )
    return script


def _git(repo: Path, *args: str, env: dict) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


class Fixture:
    """A scratch repository tagged at a version, plus the env the steps run under."""

    def __init__(self, tmp_path: Path, version: str = "3.7.0"):
        self.root = tmp_path
        self.repo = tmp_path / "repo"
        self.repo.mkdir()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        uv = bin_dir / "uv"
        uv.write_text(UV_STUB, encoding="utf-8")
        uv.chmod(uv.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        self.env = {
            "PATH": os.pathsep.join(
                [str(bin_dir), str(CZ_BIN.parent), os.environ.get("PATH", "")]
            ),
            "HOME": str(tmp_path),
            "GIT_CONFIG_NOSYSTEM": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        _git(self.repo, "init", "-q", "-b", "main", env=self.env)
        for key, value in (
            ("user.name", "fixture"),
            ("user.email", "fixture@example.invalid"),
            ("commit.gpgsign", "false"),
            ("tag.gpgsign", "false"),
        ):
            _git(self.repo, "config", key, value, env=self.env)
        (self.repo / "pyproject.toml").write_text(
            FIXTURE_PYPROJECT.format(version=version), encoding="utf-8"
        )
        (self.repo / "CHANGELOG.md").write_text("", encoding="utf-8")
        _git(self.repo, "add", "-A", env=self.env)
        _git(self.repo, "commit", "-q", "-m", "chore: initial", env=self.env)
        _git(self.repo, "tag", f"v{version}", env=self.env)

    def commit(self, message: str) -> str:
        path = self.repo / "work.txt"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(message + "\n")
        _git(self.repo, "add", "-A", env=self.env)
        _git(self.repo, "commit", "-q", "-m", message, env=self.env)
        return _git(self.repo, "rev-parse", "--short", "HEAD", env=self.env)

    def run_step(self, step_id: str, extra_env: dict) -> "StepResult":
        out = self.root / f"{step_id}.output"
        summary = self.root / f"{step_id}.summary"
        out.write_text("", encoding="utf-8")
        summary.write_text("", encoding="utf-8")
        script = self.root / f"{step_id}.sh"
        script.write_text(_step_script(step_id), encoding="utf-8")
        env = {
            **self.env,
            "GITHUB_OUTPUT": str(out),
            "GITHUB_STEP_SUMMARY": str(summary),
            "GH_TOKEN": "stub-token",
            **extra_env,
        }
        # `bash -e {0}` is what Actions runs a `run:` block with when the job sets
        # no shell, as this one does not.
        proc = subprocess.run(
            ["bash", "-e", str(script)],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        outputs = {}
        for line in out.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            outputs[key] = value
        return StepResult(proc, outputs, summary.read_text(encoding="utf-8"))

    def release(
        self, release_line: str, fold_unreleased: bool = True
    ) -> tuple["StepResult", "StepResult | None"]:
        """Run resolve, fold and bump, wired the way the workflow wires them.

        ``fold_unreleased=False`` skips the fold step. That is the mutation the
        Unreleased-preservation test below has to catch.
        """
        self.fold = None
        line = self.run_step("line", {"RELEASE_LINE": release_line})
        if line.proc.returncode != 0:
            return line, None
        increment = line.outputs.get("increment", "")
        if fold_unreleased:
            self.fold = self.run_step("unreleased", {"INCREMENT": increment})
            if self.fold.proc.returncode != 0:
                return line, None
        bump = self.run_step(
            "bump",
            {
                "INCREMENT": increment,
                "LINE_MAJOR": line.outputs.get("line_major", ""),
            },
        )
        return line, bump


class StepResult:
    def __init__(self, proc: subprocess.CompletedProcess, outputs: dict, summary: str):
        self.proc = proc
        self.outputs = outputs
        self.summary = summary

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\noutputs={self.outputs}\n"
            f"stdout:\n{self.proc.stdout}\nstderr:\n{self.proc.stderr}"
        )


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    if not CZ_BIN.exists():
        pytest.skip(f"commitizen is not installed next to {sys.executable}")
    return Fixture(tmp_path)


def _requires_bash(cls):
    for mark in reversed(_REQUIRES_BASH):
        cls = mark(cls)
    return cls


@_requires_bash
class TestTheThreeXLineCapsAMajor:
    def test_a_bang_commit_ships_as_a_minor_and_is_named(self, fixture: Fixture):
        fixture.commit("feat: something new")
        sha = fixture.commit("feat!: drop the old default")

        line, bump = fixture.release("3.x")

        assert bump is not None, line.describe()
        assert bump.proc.returncode == 0, bump.describe()
        assert bump.outputs.get("new_version") == "3.8.0", bump.describe()
        assert line.outputs.get("increment") == "MINOR", line.describe()
        assert (
            "::warning::" in line.proc.stdout
            and "MAJOR bump to MINOR" in line.proc.stdout
        )
        assert f"{sha} feat!: drop the old default" in line.proc.stdout, line.describe()
        assert sha in line.summary, line.summary

    def test_a_breaking_footer_alone_is_also_capped_and_named(self, fixture: Fixture):
        sha = fixture.commit(
            "fix: tighten ids\n\nBREAKING CHANGE: long ids are refused"
        )

        line, bump = fixture.release("3.x")

        assert bump is not None, line.describe()
        assert bump.outputs.get("new_version") == "3.8.0", bump.describe()
        assert f"{sha} fix: tighten ids" in line.proc.stdout, line.describe()

    def test_the_breaking_note_still_reaches_the_changelog(self, fixture: Fixture):
        fixture.commit(
            "feat!: drop the old default\n\nBREAKING CHANGE: the default flipped"
        )

        _line, bump = fixture.release("3.x")

        assert bump is not None and bump.proc.returncode == 0
        changelog = (fixture.repo / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## v3.8.0" in changelog, changelog
        assert "### BREAKING CHANGE" in changelog, changelog
        assert "the default flipped" in changelog, changelog

    def test_a_patch_history_stays_a_patch(self, fixture: Fixture):
        fixture.commit("fix: a small thing")

        line, bump = fixture.release("3.x")

        assert bump is not None, line.describe()
        assert line.outputs.get("increment") == "", line.describe()
        assert bump.outputs.get("new_version") == "3.7.1", bump.describe()


@_requires_bash
class TestTheCapIsBounded:
    def test_auto_lets_the_same_history_go_major(self, fixture: Fixture):
        """Control for the 3.x tests: this fixture really does read as breaking."""
        fixture.commit("feat!: drop the old default")

        line, bump = fixture.release("auto")

        assert bump is not None, line.describe()
        assert bump.proc.returncode == 0, bump.describe()
        assert bump.outputs.get("new_version") == "4.0.0", bump.describe()

    def test_three_x_refuses_once_the_project_is_on_four(self, tmp_path: Path):
        if not CZ_BIN.exists():
            pytest.skip("commitizen not installed")
        fx = Fixture(tmp_path, version="4.0.0")
        fx.commit("feat!: something for 5")

        line, bump = fx.release("3.x")

        assert bump is None
        assert line.proc.returncode != 0
        assert "::error::" in line.proc.stdout and "4.0.0" in line.proc.stdout, (
            line.describe()
        )

    def test_an_unknown_line_is_refused(self, fixture: Fixture):
        line, bump = fixture.release("2.x")

        assert bump is None
        assert line.proc.returncode != 0
        assert "::error::Unknown release-line" in line.proc.stdout, line.describe()


@_requires_bash
class TestTheBumpStepBackstop:
    def test_it_fails_when_three_x_is_selected_and_the_bump_lands_on_four(
        self, fixture: Fixture
    ):
        """What happens if the resolve step ever hands over no increment by mistake."""
        fixture.commit("feat!: drop the old default")

        bump = fixture.run_step("bump", {"INCREMENT": "", "LINE_MAJOR": "3"})

        # Liveness: commitizen ran and produced the major, so the guard had
        # something to refuse. Without this, a step that died early would also
        # exit non-zero.
        assert bump.outputs.get("new_version") == "4.0.0", bump.describe()
        assert bump.proc.returncode != 0, bump.describe()
        assert "::error::release-line 3.x is selected" in bump.proc.stdout, (
            bump.describe()
        )
        assert "bumped" not in bump.outputs, "the step went on to report a bump"


class TestTheReleaseLineSetting:
    def test_the_line_is_committed_as_auto(self):
        # v4 is at 4.0.0, where `3.x` refuses to run (see the guard tests above), so
        # the committed line is commitizen's own semver.
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        assert doc["env"]["RELEASE_LINE"] == "auto"

    def test_it_is_not_a_dispatch_input(self):
        """checkov's CKV_GHA_7 fails the repository scan on any dispatch input."""
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        # PyYAML reads the bare `on:` key as the boolean True.
        trigger = doc.get("on", doc.get(True))
        assert not (trigger["workflow_dispatch"] or {}).get("inputs")


class TestTheChangelogTemplate:
    """The v3.8.0 notes render under v3.8.0, and only there."""

    @staticmethod
    def _render(monkeypatch, version: str) -> str:
        from commitizen import changelog
        from jinja2 import PackageLoader

        # commitizen resolves the template and its includes against the cwd.
        monkeypatch.chdir(REPO_ROOT)
        tree = [
            {
                "version": version,
                "date": "2026-10-02",
                "changes": {"Feat": [{"scope": None, "message": "a feature"}]},
            }
        ]
        return changelog.render_changelog(
            tree,
            loader=PackageLoader("commitizen", "templates"),
            template=".github/changelog/CHANGELOG.md.j2",
        )

    def test_the_notes_sit_between_the_heading_and_the_commit_sections(
        self, monkeypatch
    ):
        out = self._render(monkeypatch, "v3.8.0")
        heading = out.index("## v3.8.0")
        notes = out.index("### Breaking behavior changes in a minor release")
        feat = out.index("### Feat")
        assert heading < notes < feat, out

    def test_another_version_gets_no_notes(self, monkeypatch):
        out = self._render(monkeypatch, "v3.8.1")
        assert "## v3.8.1" in out
        assert "Breaking behavior changes" not in out, out

    @pytest.mark.parametrize(
        "needle",
        [
            "--no-fail-on-incomplete-scanners",
            "--allow-stale-content-db",
            "content_db_staleness: warn",
            "`incomplete`",
            "128 characters",
        ],
    )
    def test_the_notes_name_each_change_and_its_opt_out(self, needle: str):
        assert needle in NOTES_V380.read_text(encoding="utf-8")


def _unreleased_body(changelog: str) -> list[str]:
    """Non-blank lines of the ``## Unreleased`` section, right-stripped."""
    lines = changelog.splitlines()
    start = lines.index("## Unreleased")
    body = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if line.strip():
            body.append(line.rstrip())
    return body


def _version_entry(changelog: str, tag: str) -> set[str]:
    """Every line of the ``## <tag>`` entry, right-stripped."""
    lines = changelog.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith(f"## {tag} "))
    entry = set()
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        entry.add(line.rstrip())
    return entry


REAL_CHANGELOG = REPO_ROOT / "CHANGELOG.md"
TEMPLATE = REPO_ROOT / ".github" / "changelog" / "CHANGELOG.md.j2"


@pytest.fixture
def real_changelog_fixture(tmp_path: Path) -> Fixture:
    """A scratch repo carrying the real CHANGELOG.md, template and v3.8.0 notes."""
    if not CZ_BIN.exists():
        pytest.skip(f"commitizen is not installed next to {sys.executable}")
    if "## Unreleased" not in REAL_CHANGELOG.read_text(encoding="utf-8").splitlines():
        pytest.skip("CHANGELOG.md has no Unreleased section on this checkout")
    fx = Fixture(tmp_path)
    (fx.repo / ".github" / "changelog").mkdir(parents=True)
    (fx.repo / ".github" / "release-notes").mkdir(parents=True)
    shutil.copy(TEMPLATE, fx.repo / ".github" / "changelog" / TEMPLATE.name)
    shutil.copy(NOTES_V380, fx.repo / ".github" / "release-notes" / NOTES_V380.name)
    shutil.copy(REAL_CHANGELOG, fx.repo / "CHANGELOG.md")
    pyproject = fx.repo / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8")
        + 'template = ".github/changelog/CHANGELOG.md.j2"\n',
        encoding="utf-8",
    )
    _git(fx.repo, "add", "-A", env=fx.env)
    _git(fx.repo, "commit", "-q", "-m", "chore: real changelog", env=fx.env)
    _git(fx.repo, "tag", "-f", "v3.7.0", env=fx.env)
    fx.commit("feat!: drop the old default")
    return fx


def _missing_after_release(fx: Fixture, before: list[str]) -> list[str]:
    after = (fx.repo / "CHANGELOG.md").read_text(encoding="utf-8")
    entry = _version_entry(after, "v3.8.0")
    return [ln for ln in before if ln not in entry]


@_requires_bash
class TestTheUnreleasedSectionSurvivesTheBump:
    """commitizen replaces `## Unreleased` wholesale; the fold step must save it."""

    def test_every_hand_written_line_lands_in_the_new_entry(
        self, real_changelog_fixture: Fixture
    ):
        fx = real_changelog_fixture
        before = _unreleased_body(REAL_CHANGELOG.read_text(encoding="utf-8"))
        assert len(before) > 100, "expected the real, long Unreleased section"

        line, bump = fx.release("3.x")

        failed = fx.fold if bump is None and fx.fold else line
        assert bump is not None, failed.describe()
        assert bump.proc.returncode == 0, bump.describe()
        assert bump.outputs.get("new_version") == "3.8.0", bump.describe()
        missing = _missing_after_release(fx, before)
        assert not missing, (
            f"{len(missing)} of {len(before)} Unreleased lines are missing from the "
            f"v3.8.0 entry, first: {missing[:3]}"
        )
        after = (fx.repo / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## Unreleased" not in after.splitlines()
        first_curated = NOTES_V380.read_text(encoding="utf-8").splitlines()[0]
        assert first_curated in _version_entry(after, "v3.8.0"), (
            "the curated notes were displaced"
        )

    def test_skipping_the_fold_step_loses_them(self, real_changelog_fixture: Fixture):
        """Mutation control: without the fold step, the same check must fail."""
        fx = real_changelog_fixture
        before = _unreleased_body(REAL_CHANGELOG.read_text(encoding="utf-8"))

        _line, bump = fx.release("3.x", fold_unreleased=False)

        assert bump is not None and bump.proc.returncode == 0, bump.describe()
        assert _missing_after_release(fx, before), (
            "commitizen kept the Unreleased text without the fold step, so the test "
            "above no longer shows the step does anything"
        )


@_requires_bash
class TestTheFoldStepEdges:
    @staticmethod
    def _set_changelog(fx: Fixture, text: str) -> None:
        (fx.repo / "CHANGELOG.md").write_text(text, encoding="utf-8")
        _git(fx.repo, "add", "-A", env=fx.env)
        _git(fx.repo, "commit", "-q", "-m", "docs: changelog", env=fx.env)

    def test_no_unreleased_section_is_a_no_op(self, fixture: Fixture):
        self._set_changelog(fixture, "## v3.7.0 (2026-08-27)\n\n- old\n")
        fixture.commit("feat: something")

        fold = fixture.run_step("unreleased", {"INCREMENT": ""})

        assert fold.proc.returncode == 0, fold.describe()
        assert "no Unreleased notes" in fold.proc.stdout, fold.describe()
        assert not (fixture.repo / ".github" / "release-notes").exists()

    def test_an_empty_unreleased_section_is_a_no_op(self, fixture: Fixture):
        text = "## Unreleased\n\n\n## v3.7.0 (2026-08-27)\n\n- old\n"
        self._set_changelog(fixture, text)
        fixture.commit("feat: something")

        fold = fixture.run_step("unreleased", {"INCREMENT": ""})

        assert fold.proc.returncode == 0, fold.describe()
        assert "no Unreleased notes" in fold.proc.stdout, fold.describe()
        assert (fixture.repo / "CHANGELOG.md").read_text(encoding="utf-8") == text

    @pytest.mark.parametrize("delimiter", ["{{ x }}", "{% if %}", "{# c #}"])
    def test_a_jinja_delimiter_fails_before_bumping(
        self, fixture: Fixture, delimiter: str
    ):
        text = (
            f"## Unreleased\n\n- uses {delimiter} literally\n\n## v3.7.0 (2026-08-27)\n"
        )
        self._set_changelog(fixture, text)
        fixture.commit("feat: something")

        fold = fixture.run_step("unreleased", {"INCREMENT": ""})

        assert fold.proc.returncode != 0, fold.describe()
        assert "::error::" in fold.proc.stdout, fold.describe()
        assert "Jinja delimiter" in fold.proc.stdout, fold.describe()
        assert (fixture.repo / "CHANGELOG.md").read_text(encoding="utf-8") == text

    def test_an_undeterminable_tag_fails(self, fixture: Fixture):
        text = "## Unreleased\n\n- a note\n\n## v3.7.0 (2026-08-27)\n"
        self._set_changelog(fixture, text)
        # Only a docs: commit since the tag, so commitizen has nothing to bump.
        _git(fixture.repo, "tag", "-f", "v3.7.0", "HEAD~1", env=fixture.env)

        fold = fixture.run_step("unreleased", {"INCREMENT": ""})

        assert fold.proc.returncode != 0, fold.describe()
        assert "next tag could not be determined" in fold.proc.stdout, fold.describe()
        assert (fixture.repo / "CHANGELOG.md").read_text(encoding="utf-8") == text

    def test_notes_are_appended_below_existing_curated_content(self, fixture: Fixture):
        notes = fixture.repo / ".github" / "release-notes" / "v3.8.0.md"
        notes.parent.mkdir(parents=True)
        notes.write_text("### Curated\n\nfirst\n", encoding="utf-8")
        text = (
            "## Unreleased\n\n### Fixes\n\n- hand written\n\n  indented\n\n\n"
            "## v3.7.0 (2026-08-27)\n"
        )
        self._set_changelog(fixture, text)
        fixture.commit("feat: something")

        fold = fixture.run_step("unreleased", {"INCREMENT": ""})

        assert fold.proc.returncode == 0, fold.describe()
        assert notes.read_text(encoding="utf-8") == (
            "### Curated\n\nfirst\n\n### Fixes\n\n- hand written\n\n  indented\n"
        )
        assert (fixture.repo / "CHANGELOG.md").read_text(encoding="utf-8") == (
            "## v3.7.0 (2026-08-27)\n"
        )
