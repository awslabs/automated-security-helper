# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the config lint command."""

import json
import time
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def valid_config(tmp_path):
    """Create a valid config file."""
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "severity_threshold": "MEDIUM",
            "suppressions": [],
        },
        "scanners": {
            "bandit": {"enabled": True},
        },
    }
    content = "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json\n"
    content += yaml.dump(config_data, default_flow_style=False, sort_keys=False)
    config_path.write_text(content)
    return config_path


@pytest.fixture
def config_with_internal_fields(tmp_path):
    """Create a config with internal-only fields (from old ash config init)."""
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = {
        "project_name": "test-project",
        "build": {"some": "value"},
        "mcp-resource-management": {"enabled": True},
        "scanners": {
            "bandit": {
                "enabled": True,
                "name": "bandit",
                "extension": "json",
                "tool_version": "1.0.0",
            },
        },
        "reporters": {
            "markdown": {
                "enabled": True,
                "name": "markdown",
                "extension": "md",
            },
        },
        "converters": {
            "sarif": {
                "enabled": True,
                "name": "sarif",
                "tool_version": "2.0.0",
                "install_timeout": 30,
            },
        },
    }
    content = yaml.dump(config_data, default_flow_style=False, sort_keys=False)
    config_path.write_text(content)
    return config_path


@pytest.fixture
def config_with_suppression_issues(tmp_path):
    """Create a config with suppression issues."""
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "severity_threshold": "MEDIUM",
            "suppressions": [
                {
                    "path": "src/app.py",
                    "rule_id": "B201",
                    "line_start": 42,
                    # Missing line_end
                    "reason": "False positive",
                },
                {
                    "path": "src/utils.py",
                    "rule_id": "B603",
                    "line_start": 10,
                    "line_end": 10,
                    "reason": "Safe usage",
                    "expiration": "2020-01-01",  # Expired
                },
                {
                    "path": "src/valid.py",
                    "rule_id": "B101",
                    "line_start": 5,
                    "line_end": 5,
                    "reason": "Test assertion",
                },
            ],
        },
    }
    content = yaml.dump(config_data, default_flow_style=False, sort_keys=False)
    config_path.write_text(content)
    return config_path


@pytest.fixture
def config_with_unused_suppressions(tmp_path):
    """Create a config with suppressions and a corresponding unused report."""
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "severity_threshold": "MEDIUM",
            "suppressions": [
                {
                    "path": "src/app.py",
                    "rule_id": "B201",
                    "line_start": 42,
                    "line_end": 42,
                    "reason": "False positive",
                },
                {
                    "path": "src/old_file.py",
                    "rule_id": "B603",
                    "line_start": 10,
                    "line_end": 10,
                    "reason": "File was deleted",
                },
                {
                    "path": "src/still_needed.py",
                    "rule_id": "B101",
                    "reason": "Still needed",
                },
            ],
        },
    }
    content = yaml.dump(config_data, default_flow_style=False, sort_keys=False)
    config_path.write_text(content)

    # Create the unused suppressions report
    output_dir = tmp_path / ".ash" / "ash_output" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    report_data = {
        "summary": {
            "total_suppressions": 3,
            "used_suppressions": 1,
            "unused_suppressions": 2,
        },
        "unused_suppressions": [
            {
                "path": "src/app.py",
                "rule_id": "B201",
                "line_start": 42,
                "line_end": 42,
                "reason": "False positive",
                "expiration": None,
            },
            {
                "path": "src/old_file.py",
                "rule_id": "B603",
                "line_start": 10,
                "line_end": 10,
                "reason": "File was deleted",
                "expiration": None,
            },
        ],
    }
    report_path = output_dir / "ash.unused-suppressions.json"
    report_path.write_text(json.dumps(report_data, indent=2))

    return config_path


class TestConfigLinterUnit:
    """Unit tests for the ConfigLinter class."""

    def test_lint_valid_config(self, valid_config):
        """A valid config should produce no issues."""
        result = ConfigLinter.lint(valid_config)
        assert not result.has_errors
        assert not result.has_warnings
        assert len(result.issues) == 0

    def test_lint_detects_internal_fields(self, config_with_internal_fields):
        """Should detect internal-only fields in scanners/reporters/converters."""
        result = ConfigLinter.lint(config_with_internal_fields)
        assert result.has_errors

        internal_issues = [
            i for i in result.issues if i.category == LintCategory.INTERNAL_FIELD
        ]
        # bandit has: name, extension, tool_version (3)
        # markdown has: name, extension (2)
        # sarif has: name, tool_version, install_timeout (3)
        assert len(internal_issues) == 8
        assert all(i.fixable for i in internal_issues)

    def test_lint_detects_invalid_sections(self, config_with_internal_fields):
        """Should detect invalid top-level sections like 'build'."""
        result = ConfigLinter.lint(config_with_internal_fields)

        invalid_section_issues = [
            i for i in result.issues if i.category == LintCategory.INVALID_SECTION
        ]
        assert len(invalid_section_issues) == 2
        paths = {i.path for i in invalid_section_issues}
        assert "build" in paths
        assert "mcp-resource-management" in paths
        assert all(i.fixable for i in invalid_section_issues)

    def test_lint_detects_missing_line_end(self, config_with_suppression_issues):
        """Should detect suppressions with line_start but no line_end."""
        result = ConfigLinter.lint(config_with_suppression_issues)

        line_range_issues = [
            i
            for i in result.issues
            if i.category == LintCategory.SUPPRESSION_LINE_RANGE
            and "missing 'line_end'" in i.message
        ]
        assert len(line_range_issues) == 1
        assert line_range_issues[0].fixable
        assert "42" in line_range_issues[0].message

    def test_lint_detects_expired_suppressions(self, config_with_suppression_issues):
        """Should detect expired suppressions."""
        result = ConfigLinter.lint(config_with_suppression_issues)

        expired_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_EXPIRED
        ]
        assert len(expired_issues) == 1
        assert expired_issues[0].fixable
        assert "2020-01-01" in expired_issues[0].message

    def test_lint_detects_unused_suppressions(self, config_with_unused_suppressions):
        """Should detect unused suppressions from the report."""
        result = ConfigLinter.lint(config_with_unused_suppressions, check_unused=True)

        unused_issues = [
            i
            for i in result.issues
            if i.category == LintCategory.SUPPRESSION_UNUSED
            and "Unused suppression:" in i.message
        ]
        assert len(unused_issues) == 2

    def test_fix_removes_internal_fields(self, config_with_internal_fields):
        """Fix should remove internal-only fields."""
        fixed_content, fixed_issues = ConfigLinter.fix(config_with_internal_fields)

        # Parse the fixed content
        # Skip the schema comment line
        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        # Internal fields should be gone
        assert "name" not in fixed_data["scanners"]["bandit"]
        assert "extension" not in fixed_data["scanners"]["bandit"]
        assert "tool_version" not in fixed_data["scanners"]["bandit"]
        assert "name" not in fixed_data["reporters"]["markdown"]
        assert "extension" not in fixed_data["reporters"]["markdown"]
        assert "name" not in fixed_data["converters"]["sarif"]

        # Valid fields should remain
        assert fixed_data["scanners"]["bandit"]["enabled"] is True
        assert fixed_data["reporters"]["markdown"]["enabled"] is True

    def test_fix_removes_invalid_sections(self, config_with_internal_fields):
        """Fix should remove invalid top-level sections."""
        fixed_content, fixed_issues = ConfigLinter.fix(config_with_internal_fields)

        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        assert "build" not in fixed_data
        assert "mcp-resource-management" not in fixed_data

    def test_fix_sets_missing_line_end(self, config_with_suppression_issues):
        """Fix should set line_end = line_start when line_end is missing."""
        fixed_content, fixed_issues = ConfigLinter.fix(config_with_suppression_issues)

        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        suppressions = fixed_data["global_settings"]["suppressions"]
        # First suppression had line_start=42, line_end should now be 42
        first_supp = suppressions[0]
        assert first_supp["line_start"] == 42
        assert first_supp["line_end"] == 42

    def test_fix_removes_expired_suppressions(self, config_with_suppression_issues):
        """Fix should remove expired suppressions."""
        fixed_content, fixed_issues = ConfigLinter.fix(config_with_suppression_issues)

        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        suppressions = fixed_data["global_settings"]["suppressions"]
        # The expired suppression (2020-01-01) should be removed
        # Original had 3 suppressions, one expired -> 2 remaining
        assert len(suppressions) == 2
        # Verify the expired one is gone
        for supp in suppressions:
            assert supp.get("expiration") != "2020-01-01"

    def test_fix_multiple_expired_suppressions(self, tmp_path):
        """Fix should correctly remove multiple expired suppressions (index shifting)."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "suppressions": [
                    {
                        "path": "src/a.py",
                        "rule_id": "B101",
                        "reason": "expired 1",
                        "expiration": "2020-01-01",
                    },
                    {
                        "path": "src/b.py",
                        "rule_id": "B201",
                        "reason": "keep this one",
                    },
                    {
                        "path": "src/c.py",
                        "rule_id": "B301",
                        "reason": "expired 2",
                        "expiration": "2021-06-15",
                    },
                    {
                        "path": "src/d.py",
                        "rule_id": "B401",
                        "reason": "also keep",
                    },
                ],
            },
        }
        config_path.write_text(
            yaml.dump(config_data, default_flow_style=False, sort_keys=False)
        )

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        suppressions = fixed_data["global_settings"]["suppressions"]
        # Two expired removed, two should remain
        assert len(suppressions) == 2
        assert suppressions[0]["path"] == "src/b.py"
        assert suppressions[1]["path"] == "src/d.py"

    def test_fix_unused_suppressions(self, config_with_unused_suppressions):
        """Should remove unused suppressions based on the report."""
        fixed_content, fixed_issues, timestamp = ConfigLinter.fix_unused_suppressions(
            config_with_unused_suppressions
        )

        assert len(fixed_issues) == 2
        assert timestamp is not None

        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        suppressions = fixed_data["global_settings"]["suppressions"]
        # Only the "still_needed" suppression should remain
        assert len(suppressions) == 1
        assert suppressions[0]["path"] == "src/still_needed.py"

    def test_report_age_detection(self, config_with_unused_suppressions, tmp_path):
        """Should detect the age of the unused suppressions report."""
        report_info = ConfigLinter.get_unused_report_age(
            config_with_unused_suppressions
        )
        assert report_info is not None
        report_path, report_timestamp, age_seconds = report_info
        # Report was just created, should be very recent
        assert age_seconds < 60

    def test_old_report_warning(self, tmp_path):
        """Should warn when the unused suppressions report is too old."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "suppressions": [
                    {"path": "src/app.py", "rule_id": "B201", "reason": "test"},
                ],
            },
        }
        config_path.write_text(
            yaml.dump(config_data, default_flow_style=False, sort_keys=False)
        )

        # Create an old report
        output_dir = tmp_path / ".ash" / "ash_output" / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "ash.unused-suppressions.json"
        report_data = {
            "summary": {
                "total_suppressions": 1,
                "used_suppressions": 0,
                "unused_suppressions": 1,
            },
            "unused_suppressions": [
                {
                    "path": "src/app.py",
                    "rule_id": "B201",
                    "line_start": None,
                    "line_end": None,
                    "reason": "test",
                    "expiration": None,
                }
            ],
        }
        report_path.write_text(json.dumps(report_data))

        # Make the file appear old by setting mtime to 2 hours ago
        import os

        old_time = time.time() - 7200  # 2 hours ago
        os.utime(report_path, (old_time, old_time))

        result = ConfigLinter.lint(config_path, check_unused=True)

        # Should have a warning about old report
        age_warnings = [i for i in result.issues if "hours old" in i.message]
        assert len(age_warnings) == 1

    def test_no_unused_report_info_message(self, valid_config):
        """Should show info message when no unused report exists."""
        # Use a custom output_dir that definitely doesn't have a report
        import tempfile

        with tempfile.TemporaryDirectory() as empty_dir:
            result = ConfigLinter.lint(
                valid_config, output_dir=Path(empty_dir), check_unused=True
            )

        info_issues = [
            i
            for i in result.issues
            if "No unused suppressions report found" in i.message
        ]
        assert len(info_issues) == 1
        assert info_issues[0].severity == LintSeverity.INFO


class TestConfigLintCLI:
    """Integration tests for the `ash config lint` CLI command."""

    def test_lint_valid_config_exits_zero(self, cli_runner, valid_config):
        """Linting a valid config should exit with code 0."""
        result = cli_runner.invoke(config_app, ["lint", "--config", str(valid_config)])
        assert result.exit_code == 0
        assert "clean" in result.output or "No issues" in result.output

    def test_lint_invalid_config_exits_one(
        self, cli_runner, config_with_internal_fields
    ):
        """Linting an invalid config should exit with code 1."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(config_with_internal_fields)]
        )
        assert result.exit_code == 1
        assert "issue" in result.output.lower()

    def test_lint_missing_config_exits_one(self, cli_runner, tmp_path):
        """Linting a non-existent config should exit with code 1."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(tmp_path / "nonexistent.yaml")]
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_lint_fix_applies_changes(self, cli_runner, config_with_internal_fields):
        """--fix should apply fixes and modify the file."""
        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_with_internal_fields),
                "--fix",
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0

        # Verify the file was fixed
        with open(config_with_internal_fields) as f:
            fixed_data = yaml.safe_load(f)

        assert "build" not in fixed_data
        assert "mcp-resource-management" not in fixed_data
        assert "name" not in fixed_data["scanners"]["bandit"]

    def test_lint_fix_suppression_line_end(
        self, cli_runner, config_with_suppression_issues
    ):
        """--fix should set missing line_end."""
        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_with_suppression_issues),
                "--fix",
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0

        with open(config_with_suppression_issues) as f:
            fixed_data = yaml.safe_load(f)

        suppressions = fixed_data["global_settings"]["suppressions"]
        # First suppression should now have line_end set
        first_supp = next(s for s in suppressions if s["path"] == "src/app.py")
        assert first_supp["line_end"] == 42

    def test_lint_fix_unused_removes_suppressions(
        self, cli_runner, config_with_unused_suppressions
    ):
        """--fix-unused should remove unused suppressions."""
        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_with_unused_suppressions),
                "--fix-unused",
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0

        with open(config_with_unused_suppressions) as f:
            fixed_data = yaml.safe_load(f)

        suppressions = fixed_data["global_settings"]["suppressions"]
        assert len(suppressions) == 1
        assert suppressions[0]["path"] == "src/still_needed.py"

    def test_lint_non_interactive_no_prompts(
        self, cli_runner, config_with_internal_fields
    ):
        """--non-interactive should not prompt for confirmation."""
        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_with_internal_fields),
                "--fix",
                "--non-interactive",
            ],
        )
        # Should complete without hanging for input
        assert result.exit_code == 0

    def test_lint_fix_and_fix_unused_together(
        self, cli_runner, config_with_unused_suppressions
    ):
        """--fix and --fix-unused should work together."""
        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_with_unused_suppressions),
                "--fix",
                "--fix-unused",
                "--non-interactive",
            ],
        )
        assert result.exit_code == 0

    def test_lint_shows_fixable_hint(self, cli_runner, config_with_internal_fields):
        """Without --fix, should show a hint about auto-fixable issues."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(config_with_internal_fields)]
        )
        assert "auto-fix" in result.output.lower() or "--fix" in result.output

    def test_lint_verbose_output(self, cli_runner, valid_config):
        """--verbose should not crash."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(valid_config), "--verbose"]
        )
        assert result.exit_code == 0
