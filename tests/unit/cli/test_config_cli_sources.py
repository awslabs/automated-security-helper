# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""`ashx config validate|lint|update` and suppression writes, for pyproject.toml
[tool.ash] sources (#313) and configs that use `extends` (#289)."""

import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
)
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.models.core import AshSuppression


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


@pytest.fixture
def runner():
    return CliRunner()


def _pyproject(root: Path) -> Path:
    return _write(
        root / "pyproject.toml",
        """
        [project]
        name = "demo"

        [tool.ruff]
        line-length = 100

        [tool.ash]
        project_name = "from-pyproject"

        [tool.ash.global_settings]
        severity_threshold = "HIGH"
        """,
    )


class TestValidate:
    def test_validates_a_discovered_pyproject(self, runner, tmp_path, monkeypatch):
        _pyproject(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(config_app, ["validate"])
        assert result.exit_code == 0, result.output
        assert "pyproject.toml [tool.ash]" in result.output

    def test_pyproject_internal_field_is_reported(self, tmp_path):
        pyproject = _write(
            tmp_path / "pyproject.toml",
            """
            [tool.ash]
            project_name = "p"

            [tool.ash.scanners.bandit]
            tool_version = "1.0"
            """,
        )
        ok, errors = ConfigValidator.validate_config_file(pyproject)
        assert not ok
        assert any("internal-only field 'tool_version'" in e for e in errors)

    def test_pyproject_without_tool_ash_fails_validation(self, tmp_path):
        pyproject = _write(tmp_path / "pyproject.toml", '[project]\nname = "x"\n')
        ok, errors = ConfigValidator.validate_config_file(pyproject)
        assert not ok
        assert any("no [tool.ash] table" in e for e in errors)

    def test_extends_and_patch_are_known_top_level_fields(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        child = _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: add, path: /fail_on_findings, value: false}
            """,
        )
        ok, errors = ConfigValidator.validate_config_file(child, source_dir=tmp_path)
        assert ok, errors

    def test_required_field_may_come_from_a_base(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        child = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        ok, errors = ConfigValidator.validate_config_file(child, source_dir=tmp_path)
        assert ok, errors

    def test_prints_the_resolved_source_chain(self, runner, tmp_path, monkeypatch):
        _write(tmp_path / "org.yaml", "project_name: org\n")
        _write(tmp_path / "team.yaml", "extends: org.yaml\n")
        _write(tmp_path / ".ash" / ".ash.yaml", "extends: ../team.yaml\n")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(config_app, ["validate"])
        assert result.exit_code == 0, result.output
        assert "Resolved source chain" in result.output
        lines = [line.strip() for line in result.output.splitlines()]
        chain = [line for line in lines if line[:2] in ("1.", "2.", "3.")]
        assert [Path(line.split(" ", 1)[1]).name for line in chain] == [
            "org.yaml",
            "team.yaml",
            ".ash.yaml",
        ]

    def test_cycle_fails_validation_with_the_chain(self, runner, tmp_path):
        _write(tmp_path / "a.yaml", "project_name: a\nextends: b.yaml\n")
        _write(tmp_path / "b.yaml", "extends: a.yaml\n")
        result = runner.invoke(
            config_app, ["validate", "--config", str(tmp_path / "a.yaml")]
        )
        assert result.exit_code == 1
        assert "Config extends error" in result.output
        assert "cycle" in result.output

    def test_escape_fails_validation(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        _write(tmp_path / "outside.yaml", "project_name: x\n")
        _write(repo / ".ash.yaml", "project_name: p\nextends: ../outside.yaml\n")
        monkeypatch.chdir(repo)
        result = runner.invoke(config_app, ["validate"])
        assert result.exit_code == 1
        assert "outside the directory" in result.output


class TestLint:
    def test_missing_base_is_an_extends_error(self, tmp_path):
        child = _write(tmp_path / ".ash.yaml", "project_name: p\nextends: gone.yaml\n")
        result = ConfigLinter.lint(child, source_dir=tmp_path)
        extends_issues = [
            i for i in result.issues if i.category == LintCategory.EXTENDS_ERROR
        ]
        assert extends_issues, [str(i) for i in result.issues]
        assert "gone.yaml" in extends_issues[0].message
        assert result.has_errors

    def test_lints_pyproject_tool_ash(self, tmp_path):
        pyproject = _write(
            tmp_path / "pyproject.toml",
            """
            [tool.ash]
            project_name = "p"

            [[tool.ash.global_settings.suppressions]]
            rule_id = "B101"
            path = "src/app.py"
            reason = "reviewed"
            line_start = 3
            """,
        )
        result = ConfigLinter.lint(pyproject)
        assert any(
            i.category == LintCategory.SUPPRESSION_LINE_RANGE for i in result.issues
        ), [str(i) for i in result.issues]

    def test_fix_refuses_toml(self, runner, tmp_path):
        pyproject = _pyproject(tmp_path)
        before = pyproject.read_text()
        result = runner.invoke(
            config_app, ["lint", "--config", str(pyproject), "--fix", "--yes"]
        )
        assert result.exit_code == 1
        assert "edit" in result.output and "by hand" in result.output
        assert pyproject.read_text() == before
        with pytest.raises(ValueError, match="YAML and JSON"):
            ConfigLinter.fix(pyproject)


class TestRewritingCommandsRefuse:
    def test_update_refuses_an_extending_file(self, runner, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        child = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        before = child.read_text()
        result = runner.invoke(
            config_app, ["update", str(child), "--set", "fail_on_findings=false"]
        )
        assert result.exit_code == 1
        assert "flatten" in result.output
        assert child.read_text() == before

    def test_update_refuses_pyproject(self, runner, tmp_path):
        pyproject = _pyproject(tmp_path)
        before = pyproject.read_text()
        result = runner.invoke(
            config_app, ["update", str(pyproject), "--set", "fail_on_findings=false"]
        )
        assert result.exit_code == 1
        assert pyproject.read_text() == before


class TestSuppressionWrites:
    def _suppression(self) -> AshSuppression:
        return AshSuppression(rule_id="B101", path="src/app.py", reason="reviewed")

    def test_refuses_to_write_toml(self, tmp_path):
        pyproject = _pyproject(tmp_path)
        before = pyproject.read_text()
        with pytest.raises(ValueError, match="TOML"):
            add_suppression_to_config(pyproject, self._suppression())
        assert pyproject.read_text() == before

    def test_refuses_to_shadow_a_base_suppression_list(self, tmp_path):
        child = _write(tmp_path / ".ash.yaml", "extends: base.yaml\nproject_name: p\n")
        before = child.read_text()
        with pytest.raises(ValueError, match="replace the base's suppressions"):
            add_suppression_to_config(child, self._suppression())
        assert child.read_text() == before

    def test_appends_when_the_extending_file_has_its_own_list(self, tmp_path):
        child = _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            project_name: p
            global_settings:
              suppressions:
                - rule_id: B602
                  path: src/other.py
                  reason: reviewed
            """,
        )
        add_suppression_to_config(child, self._suppression())
        assert "B101" in child.read_text()
