# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/version_bump.py validate`` compares versions and says what it read.

Why this file exists
--------------------
``validate_consistency`` listed the template files, printed "Version consistency
validation passed" and returned True. Its own comment called it a basic check; it
compared no two versions, so a pyproject.toml whose ``[project]`` and
``[tool.commitizen]`` tables disagreed, or a generated page that still carried the
last release, passed. It also labeled the number it printed "from pyproject.toml"
although ``get_current_version`` falls back to the installed distribution's
metadata when the file is missing or belongs to another project.

What is asserted
----------------
* The command fails, naming what differs, when the two version tables disagree,
  when a generated page is not its template rendered for the current version, and
  when a template has no generated page.
* When the two tables disagree it reports that one line, with the 'set' command
  that writes both from [tool.commitizen] version, and does not compare the pages:
  rendered with either number they would all read as stale, and the advice would
  name whichever side was hand-edited. A page that does not exist is still reported.
* It passes on a tree where all of them agree.
* The version it prints comes from the pyproject.toml at the project root; with no
  such file it fails and prints no version that came from somewhere else.

Each test builds its tree under ``tmp_path`` and points the script's own-checkout
lookup elsewhere, so no run touches this repository's pyproject.toml.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_bump.py"
MODULE = "automated_security_helper.utils.version_management"

TEMPLATE = "pip install git+https://example.invalid/ash.git@v{{VERSION}}\n"


def _load_version_bump(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "version_bump_validate_under_test", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_pyproject(root: Path, project: str, commitizen: str | None) -> None:
    text = f'[project]\nname = "automated-security-helper"\nversion = "{project}"\n'
    if commitizen is not None:
        text += f'\n[tool.commitizen]\nversion = "{commitizen}"\n'
    root.joinpath("pyproject.toml").write_text(text, encoding="utf-8")


def _checkout(root: Path, version: str = "1.2.3") -> Path:
    """A tree whose pyproject.toml and one generated page agree on ``version``."""
    root.mkdir()
    _write_pyproject(root, version, version)
    root.joinpath("README.md.template").write_text(TEMPLATE, encoding="utf-8")
    root.joinpath("README.md").write_text(
        TEMPLATE.replace("{{VERSION}}", version), encoding="utf-8"
    )
    return root


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A consistent project root; the script's own checkout is a stand-in."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _write_pyproject(elsewhere, "0.0.1", "0.0.1")
    monkeypatch.setattr(f"{MODULE}.get_project_root", lambda: elsewhere)
    return _checkout(tmp_path / "project")


def _bumper(module, project: Path):
    bumper = module.VersionBumper(project)
    bumper.template_manager.target_files = ["README.md"]
    return bumper


class TestAConsistentTreePasses:
    def test_validate_passes_and_names_the_version_it_read(
        self, project, monkeypatch, capsys
    ):
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is True
        out = capsys.readouterr().out
        assert "Current version from pyproject.toml: 1.2.3" in out
        assert "Found 1 template files" in out
        assert "Version consistency validation passed" in out

    def test_the_installed_distribution_is_not_consulted(
        self, project, monkeypatch, capsys
    ):
        monkeypatch.setattr(f"{MODULE}._installed_version", lambda: "9.9.9")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is True
        assert "9.9.9" not in capsys.readouterr().out


class TestADisagreementFailsTheValidation:
    def test_the_two_version_tables_disagree(self, project, monkeypatch, capsys):
        # Red at the base: validate passed without reading either table.
        _write_pyproject(project, "1.2.3", "1.2.2")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[tool.commitizen] version is 1.2.2" in out
        assert "[project] version is 1.2.3" in out
        assert "validation passed" not in out
        assert "validation failed" in out

    def test_a_tree_with_no_commitizen_table_has_nothing_to_compare(
        self, project, monkeypatch
    ):
        _write_pyproject(project, "1.2.3", None)
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is True

    def test_a_generated_page_that_kept_the_last_release(
        self, project, monkeypatch, capsys
    ):
        # Red at the base: validate listed the template and passed.
        project.joinpath("README.md").write_text(
            TEMPLATE.replace("{{VERSION}}", "1.2.2"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "README.md is not its template rendered for 1.2.3" in out
        assert "validation passed" not in out

    def test_a_template_with_no_generated_page(self, project, monkeypatch, capsys):
        # Red at the base: validate listed the template and passed.
        project.joinpath("README.md").unlink()
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "README.md does not exist" in out
        assert "validation passed" not in out

    def test_every_disagreement_is_reported_not_only_the_first(
        self, project, monkeypatch, capsys
    ):
        # A page that does not exist is reported whatever the tables say: that
        # needs no version.
        _write_pyproject(project, "1.2.3", "1.2.2")
        project.joinpath("README.md").unlink()
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[tool.commitizen] version is 1.2.2" in out
        assert "README.md does not exist" in out


class TestDisagreeingTablesAreReportedOnceNotAsEveryPageStale:
    def test_a_hand_edited_project_version_reports_only_the_tables(
        self, project, monkeypatch, capsys
    ):
        # Red before: the pages were rendered with [project] version (1.2.4), so
        # README.md, which matches [tool.commitizen] (1.2.3), was reported as
        # stale and the advice was to run 'set 1.2.4', the hand edit.
        _write_pyproject(project, "1.2.4", "1.2.3")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[tool.commitizen] version is 1.2.3" in out
        assert "[project] version is 1.2.4" in out
        assert "not its template rendered" not in out
        assert "set 1.2.4" not in out
        assert "run 'set 1.2.3'" in out
        assert "validation failed" in out

    def test_a_stale_page_is_not_claimed_while_the_tables_disagree(
        self, project, monkeypatch, capsys
    ):
        _write_pyproject(project, "1.2.3", "1.2.2")
        project.joinpath("README.md").write_text("stale\n", encoding="utf-8")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "not its template rendered" not in out
        assert "The pages are not compared until the two agree" in out

    def test_the_pages_are_compared_again_once_the_tables_agree(
        self, project, monkeypatch, capsys
    ):
        _write_pyproject(project, "1.2.3", "1.2.3")
        project.joinpath("README.md").write_text("stale\n", encoding="utf-8")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        assert "README.md is not its template rendered for 1.2.3" in (
            capsys.readouterr().out
        )


class TestTheLabeledVersionComesFromThePyproject:
    def test_no_pyproject_fails_and_prints_no_borrowed_version(
        self, project, monkeypatch, capsys
    ):
        # Red at the base: get_current_version fell back to the installed
        # metadata, the line "Current version from pyproject.toml: 9.9.9" was
        # printed for a file that does not exist, and the pages in the tree were
        # not compared with anything, so validate returned True.
        project.joinpath("pyproject.toml").unlink()
        monkeypatch.setattr(f"{MODULE}._installed_version", lambda: "9.9.9")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "9.9.9" not in out
        assert "Current version from pyproject.toml" not in out
        assert "no pyproject.toml of automated-security-helper" in out

    def test_another_projects_pyproject_is_not_read_as_ours(
        self, project, monkeypatch, capsys
    ):
        project.joinpath("pyproject.toml").write_text(
            '[project]\nname = "something-else"\nversion = "4.5.6"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(f"{MODULE}._installed_version", lambda: "9.9.9")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "4.5.6" not in out
        assert "9.9.9" not in out
