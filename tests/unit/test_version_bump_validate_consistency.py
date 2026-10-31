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
* It checks every target the template manager lists, as ``set`` counts them, so a
  listed target whose template is missing fails here too; a template that is not
  listed is not looked at.
* The pyproject.toml version itself must be canonical (PEP 440, three release
  numbers, spelled as pip prints it). A spelling set refuses, or text that is not a
  version, fails with advice naming a command ``set`` accepts: the canonical
  spelling, or the final release for a pre-release set cannot write.
* The version must also be final. A canonical pre-release, post-release or
  development version (2.0.0rc1) fails, whatever its pages say, with the ``set``
  that finalizes it and no way to keep it, and no page is compared for it: the pins in
  the pages and the checks that read them match X.Y.Z alone, so ``generate`` would
  write a pin they read as another release. The template manager's ``generate`` is
  never the advice for it.
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
        assert "Found templates for 1 of 1 listed targets" in out
        assert "Version consistency validation passed" in out

    def test_the_installed_distribution_is_not_asked_for_its_version(
        self, project, monkeypatch
    ):
        # A tripwire, not a regression test: with a pyproject.toml present the old
        # code also read 1.2.3 and would pass this. The cases that tell old from new
        # are the two in TestTheLabeledVersionComesFromThePyproject, where the file
        # is missing or another project's and the old code printed the installed
        # 9.9.9. This one fails if validate ever asks the distribution at all.
        def asked():
            raise AssertionError("validate asked the installed distribution")

        monkeypatch.setattr(f"{MODULE}._installed_version", asked)
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is True


class TestWhatValidateExpectsIsWhatSetWrites:
    def test_a_tree_set_just_wrote_validates(self, project, monkeypatch):
        # The other tests build the page with TEMPLATE.replace("{{VERSION}}", v),
        # which repeats validate's own assumption. This one lets `set` write it:
        # if validate and generate drift apart (a header, another placeholder, the
        # field the version is read from), a tree `set` just wrote stops validating.
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        assert bumper.set_version("2.0.0") is True
        assert project.joinpath("README.md").read_text(
            encoding="utf-8"
        ) == TEMPLATE.replace("{{VERSION}}", "2.0.0")
        assert bumper.validate_consistency() is True

    def test_a_bump_then_validate_round_trips_and_a_hand_edit_does_not(
        self, project, monkeypatch
    ):
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        assert bumper.bump_version("minor") is True
        assert bumper.validate_consistency() is True
        project.joinpath("README.md").write_text("edited\n", encoding="utf-8")
        assert bumper.validate_consistency() is False


class TestAFileThatCannotBeReadIsReportedNotRaised:
    def test_a_page_that_is_not_utf8(self, project, monkeypatch, capsys):
        # Red before: UnicodeDecodeError ended validate with a traceback.
        project.joinpath("README.md").write_bytes(b"\xff\xfe\x00broken")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "could not read" in out
        assert "README.md" in out
        assert "validation failed" in out

    def test_a_page_that_is_a_directory(self, project, monkeypatch, capsys):
        project.joinpath("README.md").unlink()
        project.joinpath("README.md").mkdir()
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        assert "could not read" in capsys.readouterr().out

    def test_a_template_that_cannot_be_read_is_reported_and_the_rest_go_on(
        self, project, monkeypatch, capsys
    ):
        project.joinpath("README.md.template").unlink()
        project.joinpath("README.md.template").mkdir()
        project.joinpath("OTHER.md.template").write_text(TEMPLATE, encoding="utf-8")
        project.joinpath("OTHER.md").write_text("stale\n", encoding="utf-8")
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "OTHER.md"]
        assert bumper.validate_consistency() is False
        out = capsys.readouterr().out
        assert "could not render" in out
        assert "OTHER.md is not its template rendered for 1.2.3" in out


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


class TestEveryListedTargetIsChecked:
    def test_a_listed_target_with_no_template_fails_validate(
        self, project, monkeypatch, capsys
    ):
        # Red before: validate looped over the templates that exist, so a listed
        # target whose template is missing was never reached and the tree passed,
        # while `set` on the same tree fails with "1 of 2 targets were not
        # regenerated".
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.validate_consistency() is False
        out = capsys.readouterr().out
        assert "missing.md.template does not exist" in out
        assert "cannot be regenerated" in out
        assert "validation passed" not in out

    def test_validate_and_set_agree_about_a_missing_template(
        self, project, monkeypatch, capsys
    ):
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.set_version("1.2.4") is False
        assert bumper.validate_consistency() is False

    def test_a_template_that_is_not_listed_is_not_checked(
        self, project, monkeypatch, capsys
    ):
        # generate never renders it, so validate has nothing to say about it.
        project.joinpath("OTHER.md.template").write_text("x\n", encoding="utf-8")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is True
        out = capsys.readouterr().out
        assert "OTHER.md" not in out
        # list_templates already walks the listed targets, so the unlisted template
        # was never counted; the summary now also says how many targets are listed.
        assert "Found templates for 1 of 1 listed targets" in out

    def test_the_summary_counts_listed_targets_that_have_a_template(
        self, project, monkeypatch, capsys
    ):
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.validate_consistency() is False
        assert "Found templates for 1 of 2 listed targets" in capsys.readouterr().out

    def test_no_templates_at_all_still_names_each_target_and_the_summary(
        self, project, monkeypatch, capsys
    ):
        # Red before: validate returned at "No template files found" before the
        # per-target errors, and without the failure summary.
        project.joinpath("README.md.template").unlink()
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.validate_consistency() is False
        out = capsys.readouterr().out
        assert "No template files found" in out
        assert "README.md.template does not exist" in out
        assert "missing.md.template does not exist" in out
        assert "Found templates for 0 of 2 listed targets" in out
        assert "Version consistency validation failed" in out

    def test_a_version_error_is_followed_by_the_summary_when_no_template_exists(
        self, project, monkeypatch, capsys
    ):
        project.joinpath("README.md.template").unlink()
        _write_pyproject(project, "1.2.3", "1.2.2")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[tool.commitizen] version is 1.2.2" in out
        assert out.rstrip().endswith("Version consistency validation failed")

    def test_a_missing_template_is_reported_next_to_a_stale_page(
        self, project, monkeypatch, capsys
    ):
        project.joinpath("README.md").write_text("stale\n", encoding="utf-8")
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.validate_consistency() is False
        out = capsys.readouterr().out
        assert "README.md is not its template rendered for 1.2.3" in out
        assert "missing.md.template does not exist" in out


class TestTheTemplatePathComesFromTheManager:
    def test_validate_walks_the_managers_own_target_list(
        self, project, monkeypatch, capsys
    ):
        # Every other test replaces target_files with ["README.md"]. This one keeps
        # the manager's real list, so a target whose type or layout validate
        # assumed wrongly (it builds no path of its own now) would raise here.
        module = _load_version_bump(monkeypatch)
        bumper = module.VersionBumper(project)
        manager = bumper.template_manager
        targets = list(manager.target_files)
        assert targets
        assert all(isinstance(target, str) for target in targets)

        assert bumper.validate_consistency() is False

        out = capsys.readouterr().out
        for target in targets:
            template = manager.template_path_for(target)
            if template.exists():
                assert f"{template} does not exist" not in out
            else:
                assert f"{template} does not exist" in out

    def test_the_manager_has_one_rule_for_where_a_template_sits(
        self, project, monkeypatch
    ):
        module = _load_version_bump(monkeypatch)
        manager = module.VersionBumper(project).template_manager
        manager.target_files = ["README.md", "docs/missing.md"]

        assert manager.template_path_for("docs/missing.md") == (
            project / "docs" / "missing.md.template"
        )
        assert manager.list_templates() == [manager.template_path_for("README.md")]


class TestTheVersionItselfIsChecked:
    def test_a_spelling_set_refuses_is_reported_with_a_command_set_accepts(
        self, project, monkeypatch, capsys
    ):
        # Red before: validate compared the pages and the tables, never the version,
        # so this tree failed only on its stale page and the advice was
        # "run 'set 1.02.3'", which set refuses as an invalid version.
        _write_pyproject(project, "1.02.3", "1.02.3")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "'1.02.3' is not a canonical version" in out
        assert "run 'set 1.2.3'" in out
        assert "set 1.02.3" not in out
        assert "not its template rendered" not in out

    def test_a_hyphenated_pre_release_gets_its_final_release_as_the_advice(
        self, project, monkeypatch, capsys
    ):
        # An older set wrote this spelling; the current set refuses both it and
        # 3.8.0rc1, so the advice names the final release.
        _write_pyproject(project, "3.8.0-rc1", "3.8.0-rc1")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "'3.8.0-rc1' is not a canonical version" in out
        assert "run 'set 3.8.0'" in out
        assert "set 3.8.0-rc1" not in out
        assert "set 3.8.0rc1" not in out

    def test_text_that_is_not_a_version_is_reported_not_passed(
        self, project, monkeypatch, capsys
    ):
        # Red before: the pages matched the tables' text, so this passed.
        _write_pyproject(project, "not-a-version", "not-a-version")
        project.joinpath("README.md").write_text(
            TEMPLATE.replace("{{VERSION}}", "not-a-version"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "'not-a-version' is not a canonical version" in out
        assert "run 'set X.Y.Z' with a final version" in out
        assert "validation passed" not in out

    def test_a_canonical_pre_release_whose_pages_match_still_fails(
        self, project, monkeypatch, capsys
    ):
        # Red before: validate checked the spelling only, compared the pages for
        # 2.0.0rc1, found them equal and returned True, for a tree whose pins every
        # reader of the pages takes for 2.0.0.
        _write_pyproject(project, "2.0.0rc1", "2.0.0rc1")
        project.joinpath("README.md").write_text(
            TEMPLATE.replace("{{VERSION}}", "2.0.0rc1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[project] version 2.0.0rc1 is not a final release" in out
        assert "run 'set 2.0.0' to change 2.0.0rc1 to 2.0.0" in out
        assert "is not a canonical version" not in out
        assert "validation passed" not in out

    @pytest.mark.parametrize(
        ("version", "base"),
        [
            ("2.0.0a1", "2.0.0"),
            ("2.0.0b2", "2.0.0"),
            ("2.0.0.dev1", "2.0.0"),
            ("2.0.0rc1.dev2", "2.0.0"),
            ("3.8.0.post1", "3.8.0"),
        ],
    )
    def test_every_kind_of_non_final_version_fails_with_the_set_that_finalizes_it(
        self, project, monkeypatch, capsys, version, base
    ):
        _write_pyproject(project, version, version)
        project.joinpath("README.md").write_text(
            TEMPLATE.replace("{{VERSION}}", version), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert f"[project] version {version} is not a final release" in out
        assert f"run 'set {base}'" in out
        assert "validation passed" not in out

    def test_set_and_validate_name_different_things_for_a_pre_release(
        self, project, monkeypatch, capsys
    ):
        # Validate checks the spelling; set additionally requires a final version.
        module = _load_version_bump(monkeypatch)
        assert module.validate_version("2.0.0rc1") is True
        assert _bumper(module, project).set_version("2.0.0rc1") is False
        assert "is not a final release" in capsys.readouterr().out

    def test_a_stale_page_under_a_pre_release_is_not_compared_or_advised_generate(
        self, project, monkeypatch, capsys
    ):
        # Red before: the page was compared for 2.0.0rc1, reported stale, and the
        # advice was the template manager's generate, which writes @v2.0.0rc1 into
        # every page. Now the version is reported and no page is compared.
        _write_pyproject(project, "2.0.0rc1", "2.0.0rc1")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "[project] version 2.0.0rc1 is not a final release" in out
        assert "not its template rendered" not in out
        assert "version_template_manager.py generate" not in out
        assert "set would change the version" not in out

    def test_a_stale_page_under_a_post_release_is_not_compared_or_advised_generate(
        self, project, monkeypatch, capsys
    ):
        # 3.8.0.post1 is later than 3.8.0, which may already be published; the
        # advice says the set changes the version, and offers no way to keep it.
        _write_pyproject(project, "3.8.0.post1", "3.8.0.post1")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "run 'set 3.8.0' to change 3.8.0.post1 to 3.8.0" in out
        assert "not its template rendered" not in out
        assert "version_template_manager.py generate" not in out

    def test_the_pin_generate_would_write_for_a_pre_release_reads_as_the_final_release(
        self, project, monkeypatch
    ):
        # The reason validate refuses the version: the page generate would render
        # for 2.0.0rc1 carries a pin that the readers of the pages (the template
        # manager's own _ash_pins is one) take for 2.0.0. If this changes, the
        # refusal is no longer needed and the advice may name generate again.
        module = _load_version_bump(monkeypatch)
        manager_module = importlib.import_module(
            type(_bumper(module, project).template_manager).__module__
        )
        page = (
            "pip install git+https://github.com/awslabs/automated-security-"
            "helper.git@v2.0.0rc1\n"
        )
        assert [number for _form, number, _start in manager_module._ash_pins(page)] == [
            "2.0.0"
        ]

    def test_the_set_advice_for_a_pre_release_says_it_changes_the_version(
        self, project, monkeypatch, capsys
    ):
        _write_pyproject(project, "3.8.0-rc1", "3.8.0-rc1")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "run 'set 3.8.0' to change 3.8.0-rc1 to 3.8.0" in out
        # No route that keeps the release candidate: validate fails every
        # spelling of it, so such a route would only lead back to this error.
        assert "to keep" not in out
        assert "3.8.0rc1" not in out

    def test_a_local_part_is_dropped_by_the_advice_not_offered_to_be_kept(
        self, project, monkeypatch, capsys
    ):
        # Red before: "to keep 1.2.3+local, edit both version fields by hand",
        # advice that leads to a tree validate rejects again for the local part.
        _write_pyproject(project, "1.2.3+local", "1.2.3+local")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "'1.2.3+local' is not a canonical version" in out
        assert "run 'set 1.2.3' to change 1.2.3+local to 1.2.3" in out
        assert "to keep" not in out
        assert "by hand" not in out

    def test_tables_that_disagree_on_a_pre_release_do_not_advise_a_silent_finalize(
        self, project, monkeypatch, capsys
    ):
        _write_pyproject(project, "2.0.0rc2", "2.0.0rc1")
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).validate_consistency() is False
        out = capsys.readouterr().out
        assert "run 'set 2.0.0' to change 2.0.0rc1 to 2.0.0" in out
        assert "to keep" not in out


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
