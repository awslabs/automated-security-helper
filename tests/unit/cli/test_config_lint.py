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
from automated_security_helper.cli.config import INVALID_CONFIG_EXIT_CODE

pytestmark = pytest.mark.unit


def _option_default(segment: str, section: str, field_name: str):
    """The default of the option ``field_name`` of a built-in plugin's options model."""
    from automated_security_helper.base.plugin_config import _options_class
    from automated_security_helper.config.config_validator import (
        _built_in_section_classes,
    )

    options_class = _options_class(_built_in_section_classes(segment)[section])
    assert options_class is not None, (segment, section)
    return options_class.model_fields[field_name].default


# The two tool_version defaults these tests write as "the option's own default":
# read from the options models, so the next default bump does not turn them into
# pins the operator wrote by hand (which lint --fix keeps) and fail three tests
# in confusing ways.
BANDIT_TOOL_VERSION = _option_default("scanners", "bandit", "tool_version")
JUPYTER_TOOL_VERSION = _option_default("converters", "jupyter", "tool_version")


def _a_value_other_than(default):
    """A value of the default's kind that is not the default: a pin."""
    if isinstance(default, int):
        return default + 1
    pin = "==0.0.1"
    assert pin != default
    return pin


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
    """Create a config with internal-only fields.

    tool_version and install_timeout hold each plugin's own option default: a
    different value can be a pin the operator meant, which lint --fix leaves in
    place.
    """
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = {
        "project_name": "test-project",
        "build": {"some": "value"},
        "scanners": {
            "bandit": {
                "enabled": True,
                "name": "bandit",
                "extension": "json",
                "tool_version": BANDIT_TOOL_VERSION,
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
            "jupyter": {
                "enabled": True,
                "name": "jupyter",
                "tool_version": JUPYTER_TOOL_VERSION,
                "install_timeout": 300,
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
        # jupyter has: name, tool_version, install_timeout (3)
        assert len(internal_issues) == 8
        assert all(i.fixable for i in internal_issues)

    def test_lint_detects_invalid_sections(self, config_with_internal_fields):
        """Should detect invalid top-level sections like 'build'."""
        result = ConfigLinter.lint(config_with_internal_fields)

        invalid_section_issues = [
            i for i in result.issues if i.category == LintCategory.INVALID_SECTION
        ]
        assert len(invalid_section_issues) == 1
        paths = {i.path for i in invalid_section_issues}
        assert "build" in paths
        assert all(i.fixable for i in invalid_section_issues)

    def test_lint_detects_mcp_resource_management(self, tmp_path):
        """mcp-resource-management is a valid user-configurable field."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # Users can configure MCP resource management in their configs
        config_content = """project_name: my-project
mcp-resource-management:
  max_concurrent_scans: 5
  scan_timeout_seconds: 3600
  memory_warning_threshold_mb: 2048
scanners:
  bandit:
    enabled: true
"""
        config_path.write_text(config_content)

        result = ConfigLinter.lint(config_path)

        # mcp-resource-management should NOT be flagged as invalid
        mcp_issues = [
            i
            for i in result.issues
            if "mcp-resource-management" in (i.path or "")
            or "mcp-resource-management" in i.message
        ]
        assert len(mcp_issues) == 0
        assert not result.has_errors

    def test_lint_detects_mcp_underscore_variant(self, tmp_path):
        """mcp_resource_management is the field name of mcp-resource-management.

        A scan reads it as that key (the model accepts both spellings), so it
        is not an unknown field; lint says only the hyphenated key is documented.
        """
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_content = """project_name: my-project
mcp_resource_management:
  max_concurrent_scans: 5
scanners:
  bandit:
    enabled: true
"""
        config_path.write_text(config_content)

        result = ConfigLinter.lint(config_path)

        issues = [i for i in result.issues if "mcp_resource_management" in i.path]
        assert [i.category for i in issues] == [LintCategory.LEGACY_NAME_VARIANT]
        assert issues[0].severity == LintSeverity.WARNING
        assert "a scan reads it as 'mcp-resource-management'" in issues[0].message
        assert not result.has_errors

    def test_fix_removes_build_but_keeps_mcp(self, tmp_path):
        """--fix should remove 'build' but keep 'mcp-resource-management'."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_content = """project_name: my-project
build:
  some: value
mcp-resource-management:
  max_concurrent_scans: 5
  scan_timeout_seconds: 3600
global_settings:
  severity_threshold: MEDIUM
scanners:
  bandit:
    enabled: true
"""
        config_path.write_text(config_content)

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        # Parse the fixed content
        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        # build should be removed (internal-only)
        assert "build" not in fixed_data
        # mcp-resource-management should be preserved (valid user config)
        assert "mcp-resource-management" in fixed_data
        assert fixed_data["mcp-resource-management"]["max_concurrent_scans"] == 5
        assert fixed_data["project_name"] == "my-project"

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
        assert "name" not in fixed_data["converters"]["jupyter"]
        assert "tool_version" not in fixed_data["converters"]["jupyter"]

        # Valid fields should remain
        assert fixed_data["scanners"]["bandit"]["enabled"] is True
        assert fixed_data["reporters"]["markdown"]["enabled"] is True

    # Plugins that declare tool_version or install_timeout as an option, the
    # option's own default, and a value an operator wrote beside `enabled` by
    # hand.
    OPTION_NAMED_FIELDS = [
        ("scanners", "bandit", "tool_version", BANDIT_TOOL_VERSION, "==1.7.5"),
        ("scanners", "bandit", "install_timeout", 300, 900),
        ("scanners", "checkov", "tool_version", None, "==3.2.250"),
        ("scanners", "semgrep", "tool_version", None, "==1.50.0"),
        ("converters", "jupyter", "tool_version", JUPYTER_TOOL_VERSION, "==7.16.4"),
        # Loaded from ash_plugin_modules, so lint cannot read its options.
        ("scanners", "ferret-scan", "tool_version", None, "==1.2.3"),
    ]

    @pytest.mark.parametrize("written", ["default", "hand"])
    @pytest.mark.parametrize(
        "segment,section,field_name,default_value,pin", OPTION_NAMED_FIELDS
    )
    def test_an_option_named_field_is_removed_only_when_it_is_the_default(
        self, tmp_path, segment, section, field_name, default_value, pin, written
    ):
        """lint --fix removes the option's default, and keeps a pin written by hand.

        tool_version and install_timeout are real options of these plugins, so
        one written a level too high can be a version constraint the operator
        meant. Removing it would silently drop the pin, so lint leaves it and
        says to move it under options or remove it.
        """
        value = default_value if written == "default" else pin
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            yaml.dump(
                {"project_name": "demo", segment: {section: {field_name: value}}},
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        result = ConfigLinter.lint(config_path)
        issues = [
            i
            for i in result.issues
            if i.category == LintCategory.INTERNAL_FIELD
            and i.path == f"{segment}.{section}.{field_name}"
        ]
        assert len(issues) == 1, result.issues

        fixed_content, _ = ConfigLinter.fix(config_path)
        fixed = yaml.safe_load(
            "\n".join(
                line for line in fixed_content.split("\n") if not line.startswith("#")
            )
        )
        section_after = (fixed.get(segment) or {}).get(section) or {}
        if written == "default":
            assert issues[0].fixable, issues[0]
            assert field_name not in section_after, fixed
        else:
            assert not issues[0].fixable, issues[0]
            assert "under options" in issues[0].message, issues[0].message
            assert section_after.get(field_name) == pin, fixed

    @pytest.mark.parametrize(
        "segment,section,field_name",
        [row[:3] for row in OPTION_NAMED_FIELDS],
    )
    def test_a_null_option_named_field_is_removed_for_every_plugin(
        self, tmp_path, segment, section, field_name
    ):
        """A null pins nothing, whichever plugin it is under: --fix removes it.

        Kept, it was told to move under options, where a null install_timeout
        (an integer option) is refused; ferret-scan's null was already removed
        while bandit's and jupyter's were kept.
        """
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            yaml.dump(
                {"project_name": "demo", segment: {section: {field_name: None}}},
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        result = ConfigLinter.lint(config_path)
        issues = [
            i
            for i in result.issues
            if i.category == LintCategory.INTERNAL_FIELD
            and i.path == f"{segment}.{section}.{field_name}"
        ]
        assert len(issues) == 1, result.issues
        assert issues[0].fixable, issues[0]
        assert "under options" not in issues[0].message, issues[0].message

    @pytest.mark.parametrize(
        "text", ["", "- just\n- a list\n"], ids=["empty", "not-a-mapping"]
    )
    def test_a_file_that_is_not_a_mapping_gets_the_scans_message(self, tmp_path, text):
        """lint reports the model's refusal, as the scan prints it, not its own."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(text, encoding="utf-8")

        result = ConfigLinter.lint(config_path)

        blocking = [i.message for i in result.issues if i.blocks_scan]
        assert blocking == [
            (
                "Invalid value at '(top level)': Input should be a valid dictionary "
                "or instance of AshConfig"
            )
        ], result.issues

    def test_an_internal_field_from_an_extends_base_is_not_fixable_here(
        self, tmp_path, monkeypatch
    ):
        """lint --fix edits the linted file, which does not hold the base's field.

        The model's refusal stays an error that blocks the scan, not an
        auto-fixable issue that --fix then fails to fix, and validate does not
        promise that lint --fix removes it.
        """
        monkeypatch.chdir(tmp_path)
        (tmp_path / "base.yaml").write_text(
            "scanners:\n  bandit:\n    tool_version: '1.7.5'\n", encoding="utf-8"
        )
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "extends: base.yaml\nproject_name: demo\n", encoding="utf-8"
        )

        result = ConfigLinter.lint(config_path)

        assert not [
            i for i in result.issues if i.category == LintCategory.INTERNAL_FIELD
        ], result.issues
        blocking = [i for i in result.issues if i.blocks_scan]
        assert len(blocking) == 1, result.issues
        assert "contains internal-only field 'tool_version'" in blocking[0].message
        assert not blocking[0].fixable

        validate = CliRunner().invoke(
            config_app, ["validate", "--config", str(config_path)]
        )
        assert validate.exit_code == INVALID_CONFIG_EXIT_CODE, validate.output
        assert "lint --fix' removes internal-only fields" not in validate.output

    @pytest.mark.parametrize("written", ["the-default", "null", "a-hand-pin"])
    @pytest.mark.parametrize(
        "segment,section,field_name",
        [
            ("scanners", "bandit", "tool_version"),
            ("scanners", "bandit", "install_timeout"),
            ("converters", "jupyter", "tool_version"),
        ],
    )
    def test_validate_promises_lint_fix_exactly_when_lint_fix_removes_the_field(
        self, tmp_path, monkeypatch, segment, section, field_name, written
    ):
        """validate's "'ash config lint --fix' removes internal-only fields" and
        what `lint --fix` then does agree: the promise is printed exactly when
        --fix removes the field, and a relint after --fix no longer reports it.
        For a pin lint keeps, validate printed the promise and --fix left the
        field. The value is the plugin option's own default, a null, or a pin
        that differs from the default, read from the options model."""
        monkeypatch.chdir(tmp_path)
        default = _option_default(segment, section, field_name)
        assert default is not None, "the default and the null would be one case"
        value = {
            "the-default": default,
            "null": None,
            "a-hand-pin": _a_value_other_than(default),
        }[written]
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            yaml.dump(
                {"project_name": "demo", segment: {section: {field_name: value}}},
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        validate = CliRunner().invoke(
            config_app, ["validate", "--config", str(config_path)]
        )
        assert validate.exit_code == INVALID_CONFIG_EXIT_CODE, validate.output
        promised = "lint --fix' removes internal-only fields" in validate.output

        fix = CliRunner().invoke(
            config_app, ["lint", "--fix", "--yes", "--config", str(config_path)]
        )
        assert fix.exception is None or isinstance(fix.exception, SystemExit), (
            repr(fix.exception),
            fix.output,
        )
        after = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        removed = field_name not in ((after.get(segment) or {}).get(section) or {})
        still_reported = [
            issue
            for issue in ConfigLinter.lint(config_path).issues
            if issue.path == f"{segment}.{section}.{field_name}"
        ]

        assert promised == removed, (validate.output, fix.output)
        assert removed == (not still_reported), still_reported
        # Pinned too, so that the two cannot agree by both doing nothing.
        assert removed is (written != "a-hand-pin"), fix.output

    @pytest.mark.parametrize(
        "case",
        [
            "hand-pin-without-project-name",
            "pin-for-a-plugin-not-loaded",
            "pyproject",
            "environment-reference",
        ],
    )
    def test_validate_promises_lint_fix_only_for_a_field_lint_fix_removes(
        self, tmp_path, monkeypatch, case
    ):
        """Where lint --fix leaves the field, validate promises nothing.

        A hand pin lint keeps, beside another warning (no project_name); a pin
        under a section whose plugin is not loaded here, which lint keeps; and a
        field lint --fix cannot rewrite, because the file is TOML or reads the
        environment. validate promised --fix for each."""
        monkeypatch.chdir(tmp_path)
        default = _option_default("scanners", "bandit", "tool_version")
        file_name, text = {
            "hand-pin-without-project-name": (
                ".ash.yaml",
                yaml.dump(
                    {
                        "scanners": {
                            "bandit": {"tool_version": _a_value_other_than(default)}
                        }
                    }
                ),
            ),
            "pin-for-a-plugin-not-loaded": (
                ".ash.yaml",
                (
                    "project_name: demo\nscanners:\n  ferret-scan:\n"
                    "    tool_version: '9.9.9'\n"
                ),
            ),
            "pyproject": (
                "pyproject.toml",
                (
                    '[tool.ash]\nproject_name = "demo"\n\n'
                    f'[tool.ash.scanners.bandit]\ntool_version = "{default}"\n'
                ),
            ),
            "environment-reference": (
                ".ash.yaml",
                (
                    "project_name: demo\nscanners:\n  bandit:\n"
                    f"    tool_version: ${{ASH_TEST_PIN_VALUE:{default}}}\n"
                ),
            ),
        }[case]
        monkeypatch.setenv("ASH_TEST_PIN_VALUE", default)
        config_path = tmp_path / file_name
        config_path.write_text(text, encoding="utf-8")

        validate = CliRunner().invoke(
            config_app, ["validate", "--config", str(config_path)]
        )
        promised = "lint --fix' removes internal-only fields" in validate.output
        CliRunner().invoke(
            config_app, ["lint", "--fix", "--yes", "--config", str(config_path)]
        )
        removed = "tool_version" not in config_path.read_text(encoding="utf-8")

        assert not removed, "lint --fix removed it, so the case tests nothing"
        assert not promised, validate.output

    def test_validate_promises_lint_fix_for_an_internal_top_level_section(
        self, tmp_path, monkeypatch
    ):
        """The other half of the promise: lint --fix removes `build`."""
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "project_name: demo\nbuild:\n  mode: container\n", encoding="utf-8"
        )

        validate = CliRunner().invoke(
            config_app, ["validate", "--config", str(config_path)]
        )
        CliRunner().invoke(
            config_app, ["lint", "--fix", "--yes", "--config", str(config_path)]
        )

        assert "lint --fix' removes internal-only fields" in validate.output
        assert "build" not in yaml.safe_load(config_path.read_text(encoding="utf-8"))

    @pytest.mark.parametrize(
        "base_field,base_value",
        [("install_timeout", 901), ("tool_version", BANDIT_TOOL_VERSION)],
        ids=["another-field", "the-same-field"],
    )
    def test_a_base_field_beside_a_fixable_one_stays_an_issue(
        self, tmp_path, monkeypatch, base_field, base_value
    ):
        """The model refuses the root's and the base's internal-only fields of a
        section in one message. --fix removes the root's, and the base's still
        blocks the scan, so it stays a blocking issue that is not fixable here:
        lint does not call it auto-fixable, since with the base's field the scan
        exits 3 after --fix too. A field both files set is the same: removing the
        root's copy leaves the base's."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "base.yaml").write_text(
            yaml.dump({"scanners": {"bandit": {base_field: base_value}}}),
            encoding="utf-8",
        )
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "extends: base.yaml\nproject_name: demo\n"
            f"scanners:\n  bandit:\n    tool_version: '{BANDIT_TOOL_VERSION}'\n",
            encoding="utf-8",
        )

        before = ConfigLinter.lint(config_path)
        fixable = [i for i in before.issues if i.fixable]
        assert [i.path for i in fixable] == ["scanners.bandit.tool_version"], (
            before.issues
        )
        left = [i for i in before.issues if i.blocks_scan and not i.fixable]
        assert len(left) == 1, before.issues
        assert f"contains internal-only field '{base_field}'" in left[0].message

        fixed_content, _ = ConfigLinter.fix(config_path)
        config_path.write_text(fixed_content, encoding="utf-8")
        after = ConfigLinter.lint(config_path)
        blocking = [i for i in after.issues if i.blocks_scan]
        assert len(blocking) == 1, after.issues
        assert f"contains internal-only field '{base_field}'" in blocking[0].message
        assert not blocking[0].fixable

    def test_each_field_of_one_model_refusal_is_its_own_issue(self, tmp_path):
        """The model refuses a section's keys in one message; lint splits it.

        Each internal-only field is an auto-fixable issue that --fix removes, from
        the section as the file spells it (``cdk_nag``, which the model calls
        ``cdk-nag``), and the key that is not one stays an issue for the operator.
        """
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "project_name: demo\n"
            "scanners:\n"
            "  bandit:\n"
            # The options' defaults, which --fix may remove.
            f"    tool_version: '{BANDIT_TOOL_VERSION}'\n"
            "    severity_threshold: HIGH\n"
            "    install_timeout: 300\n"
            "  cdk_nag:\n"
            "    extension: txt\n",
            encoding="utf-8",
        )

        result = ConfigLinter.lint(config_path)

        internal = sorted(
            i.path for i in result.issues if i.category == LintCategory.INTERNAL_FIELD
        )
        assert internal == [
            "scanners.bandit.install_timeout",
            "scanners.bandit.tool_version",
            "scanners.cdk_nag.extension",
        ]
        others = [
            i
            for i in result.issues
            if i.category != LintCategory.INTERNAL_FIELD and i.blocks_scan
        ]
        assert [i.message for i in others] == [
            (
                "Invalid value at 'scanners.bandit': Value error, "
                "scanners.bandit.severity_threshold is not a section-level key; "
                "move severity_threshold under options."
            )
        ]
        assert not others[0].fixable

        fixed_content, _ = ConfigLinter.fix(config_path)
        fixed = yaml.safe_load(
            "\n".join(
                line for line in fixed_content.split("\n") if not line.startswith("#")
            )
        )
        assert fixed["scanners"]["bandit"] == {"severity_threshold": "HIGH"}
        assert "extension" not in (fixed["scanners"].get("cdk_nag") or {})

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
        """Should comment out unused suppressions based on the report."""
        fixed_content, fixed_issues, timestamp = ConfigLinter.fix_unused_suppressions(
            config_with_unused_suppressions
        )

        assert len(fixed_issues) == 2
        assert timestamp is not None

        # Verify the unused suppressions are commented out, not removed
        assert "# [ash-lint" in fixed_content
        assert "unused suppression" in fixed_content

        # The commented-out suppressions should still be in the file as comments
        assert (
            "# - path: src/app.py" in fixed_content
            or "# - path: 'src/app.py'" in fixed_content
        )
        assert (
            "# - path: src/old_file.py" in fixed_content
            or "# - path: 'src/old_file.py'" in fixed_content
        )

        # The "still_needed" suppression should remain active (not commented)
        # Parse only non-commented lines to verify
        active_yaml = "\n".join(
            line
            for line in fixed_content.split("\n")
            if not line.strip().startswith("#")
        )
        active_data = yaml.safe_load(active_yaml)

        suppressions = active_data["global_settings"]["suppressions"]
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

    # ------------------------------------------------------------------
    # Legacy snake/kebab name variants on built-in plugins (#82).
    # ------------------------------------------------------------------

    def test_lint_detects_snake_form_of_kebab_alias(self, tmp_path):
        """`scanners.cdk_nag` should be flagged — alias is `cdk-nag`."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\nscanners:\n  cdk_nag:\n    enabled: true\n"
        )

        result = ConfigLinter.lint(config_path)

        legacy_issues = [
            i for i in result.issues if i.category == LintCategory.LEGACY_NAME_VARIANT
        ]
        assert len(legacy_issues) == 1
        assert "cdk_nag" in legacy_issues[0].message
        assert "cdk-nag" in legacy_issues[0].message
        assert legacy_issues[0].fixable is True
        assert legacy_issues[0].severity == LintSeverity.WARNING

    def test_lint_passes_kebab_alias_form(self, tmp_path):
        """`scanners.cdk-nag` (canonical) should NOT be flagged."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\nscanners:\n  cdk-nag:\n    enabled: true\n"
        )

        result = ConfigLinter.lint(config_path)

        legacy_issues = [
            i for i in result.issues if i.category == LintCategory.LEGACY_NAME_VARIANT
        ]
        assert legacy_issues == []

    def test_lint_passes_third_party_plugin_name(self, tmp_path):
        """Third-party scanner names (no built-in collision) pass through."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\nscanners:\n  my-org-custom-scanner:\n    enabled: true\n"
        )

        result = ConfigLinter.lint(config_path)

        legacy_issues = [
            i for i in result.issues if i.category == LintCategory.LEGACY_NAME_VARIANT
        ]
        assert legacy_issues == []

    def test_lint_detects_multiple_legacy_variants(self, tmp_path):
        """All snake-form variants of kebab built-ins flagged."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\n"
            "scanners:\n"
            "  cdk_nag:\n"
            "    enabled: true\n"
            "  cfn_nag:\n"
            "    enabled: true\n"
            "  npm_audit:\n"
            "    enabled: true\n"
        )

        result = ConfigLinter.lint(config_path)

        flagged = {
            (i.path, i.message)
            for i in result.issues
            if i.category == LintCategory.LEGACY_NAME_VARIANT
        }
        # Three issues: cdk_nag, cfn_nag, npm_audit
        assert len(flagged) == 3
        flagged_msgs = "\n".join(m for _, m in flagged)
        assert "cdk-nag" in flagged_msgs
        assert "cfn-nag" in flagged_msgs
        assert "npm-audit" in flagged_msgs

    def test_lint_detects_legacy_variants_in_reporters(self, tmp_path):
        """Reporter snake-form variants also flagged."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\nreporters:\n  gitlab_cyclonedx:\n    enabled: true\n"
        )

        result = ConfigLinter.lint(config_path)

        legacy_issues = [
            i for i in result.issues if i.category == LintCategory.LEGACY_NAME_VARIANT
        ]
        assert len(legacy_issues) == 1
        assert "gitlab_cyclonedx" in legacy_issues[0].message
        assert "gitlab-cyclonedx" in legacy_issues[0].message

    def test_lint_detects_legacy_canonical_collision(self, tmp_path):
        """When BOTH legacy and canonical forms are present, say what a scan does.

        A scan accepts the file and merges the two sections key by key, the
        canonical form winning where both set a key (here ``severity_threshold``
        is set only under ``cdk_nag``, so it still applies), so this is a
        warning (lint gives the scan's verdict), and the message says the two
        are merged and which spelling wins. The fixer must still refuse to touch
        the file in this case (data loss otherwise), so the issue is not fixable.
        """
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\n"
            "scanners:\n"
            "  cdk_nag:\n"
            "    enabled: true\n"
            "    options:\n"
            "      severity_threshold: HIGH\n"
            "  cdk-nag:\n"
            "    enabled: false\n"
        )

        result = ConfigLinter.lint(config_path)

        # A LEGACY_NAME_CONFLICT issue must be emitted (a warning, not fixable)
        conflict_issues = [
            i for i in result.issues if i.category == LintCategory.LEGACY_NAME_CONFLICT
        ]
        assert len(conflict_issues) == 1
        assert conflict_issues[0].severity == LintSeverity.WARNING
        assert "a scan merges them key by key" in conflict_issues[0].message
        assert "'cdk-nag' wins" in conflict_issues[0].message
        assert conflict_issues[0].fixable is False
        assert "cdk_nag" in conflict_issues[0].message
        assert "cdk-nag" in conflict_issues[0].message

    def test_fix_refuses_to_overwrite_on_collision(self, tmp_path):
        """`--fix` must not silently overwrite when both forms exist.

        Pre-fix verification: data loss prevention.
        """
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\n"
            "scanners:\n"
            "  cdk_nag:\n"
            "    enabled: true\n"
            "    options:\n"
            "      severity_threshold: HIGH\n"
            "  cdk-nag:\n"
            "    enabled: false\n"
        )

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        # No legacy-variant fix should have been applied
        legacy_fixes = [
            i for i in fixed_issues if i.category == LintCategory.LEGACY_NAME_VARIANT
        ]
        assert legacy_fixes == []

        # Both keys must still be present in the output (no silent overwrite)
        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)
        scanners = fixed_data.get("scanners", {})
        assert "cdk_nag" in scanners
        assert "cdk-nag" in scanners
        # Distinct values preserved — not collapsed/overwritten
        assert scanners["cdk_nag"]["enabled"] is True
        assert scanners["cdk-nag"]["enabled"] is False

    def test_fix_renames_snake_to_kebab(self, tmp_path):
        """--fix renames `cdk_nag` → `cdk-nag` preserving the value."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\n"
            "scanners:\n"
            "  cdk_nag:\n"
            "    enabled: true\n"
            "    options:\n"
            "      severity_threshold: MEDIUM\n"
        )

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        # Parse fixed content (strip leading schema-comment line)
        yaml_content = "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
        fixed_data = yaml.safe_load(yaml_content)

        scanners = fixed_data.get("scanners", {})
        assert "cdk_nag" not in scanners
        assert "cdk-nag" in scanners
        # Value preserved
        assert scanners["cdk-nag"]["enabled"] is True
        assert scanners["cdk-nag"]["options"]["severity_threshold"] == "MEDIUM"
        # Issue was reported as fixed
        assert any(i.category == LintCategory.LEGACY_NAME_VARIANT for i in fixed_issues)


class TestConfigLintCLI:
    """Integration tests for the `ash config lint` CLI command."""

    def test_lint_valid_config_exits_zero(self, cli_runner, valid_config):
        """Linting a valid config should exit with code 0."""
        result = cli_runner.invoke(config_app, ["lint", "--config", str(valid_config)])
        assert result.exit_code == 0
        assert "clean" in result.output or "No issues" in result.output

    def test_lint_config_a_scan_refuses_exits_three(
        self, cli_runner, config_with_internal_fields
    ):
        """The fixture's `build: {some: value}` is refused by the model, so a scan
        exits 3 on it, and lint does too."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(config_with_internal_fields)]
        )
        assert result.exit_code == 3
        assert "issue" in result.output.lower()
        assert "build.some" in result.output

    def test_lint_warns_about_what_a_scan_accepts_and_exits_zero(
        self, cli_runner, tmp_path
    ):
        """An internal field is a warning: a scan accepts it, so lint exits 0."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            "project_name: demo\nscanners:\n  bandit:\n    name: bandit\n"
        )
        result = cli_runner.invoke(config_app, ["lint", "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert (
            "⚠️  Scanner 'bandit' contains internal-only field 'name'" in result.output
        )

    def test_lint_fix_leaves_what_it_cannot_fix_as_a_warning(
        self, cli_runner, tmp_path
    ):
        """--fix fixes what it can; what is left a scan accepts, so exit 0."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        # npm_audit next to npm-audit is a warning --fix leaves for a person.
        config_path.write_text(
            "project_name: demo\n"
            "scanners:\n"
            "  bandit:\n    name: bandit\n"
            "  npm-audit:\n    enabled: true\n"
            "  npm_audit:\n    enabled: false\n"
        )
        result = cli_runner.invoke(
            config_app,
            ["lint", "--config", str(config_path), "--fix", "--non-interactive"],
        )
        assert result.exit_code == 0, result.output
        assert "a scan merges them key by key" in result.output
        assert "'npm-audit' wins" in result.output
        assert (
            "name" not in yaml.safe_load(config_path.read_text())["scanners"]["bandit"]
        )
        assert "'scanners.npm_audit' (the legacy form)" in result.output

    def test_lint_missing_config_is_an_invalid_config(self, cli_runner, tmp_path):
        """A --config naming no file leaves no configuration to use: exit 3."""
        result = cli_runner.invoke(
            config_app, ["lint", "--config", str(tmp_path / "nonexistent.yaml")]
        )
        assert result.exit_code == INVALID_CONFIG_EXIT_CODE
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

    def test_lint_fix_unused_comments_out_suppressions(
        self, cli_runner, config_with_unused_suppressions
    ):
        """--fix-unused should comment out unused suppressions, not remove them."""
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

        raw_content = config_with_unused_suppressions.read_text()

        # Verify suppressions are commented out with a note
        assert "# [ash-lint" in raw_content
        assert "unused suppression" in raw_content

        # Parse only active (non-commented) YAML to verify
        active_yaml = "\n".join(
            line for line in raw_content.split("\n") if not line.strip().startswith("#")
        )
        active_data = yaml.safe_load(active_yaml)

        suppressions = active_data["global_settings"]["suppressions"]
        assert len(suppressions) == 1
        assert suppressions[0]["path"] == "src/still_needed.py"

    def test_lint_fix_unused_says_when_the_list_cannot_be_edited(
        self, cli_runner, tmp_path
    ):
        """A repeated suppressions key: lint lists the unused entries, and the
        fixer, which cannot tell the two lists apart, says so and leaves the
        file unchanged, instead of printing that there was nothing to comment
        out (exit 1, since the operator asked for an edit that could not be
        made)."""
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_text = (
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: src/x.py\n"
            "      rule_id: B101\n"
            "      reason: shadowed\n"
            "  suppressions:\n"
            "    - path: src/a.py\n"
            "      rule_id: B101\n"
            "      reason: one\n"
        )
        config_path.write_text(config_text, encoding="utf-8")
        reports = tmp_path / ".ash" / "ash_output" / "reports"
        reports.mkdir(parents=True)
        (reports / "ash.unused-suppressions.json").write_text(
            json.dumps(
                {
                    "unused_suppressions": [
                        {"path": "src/a.py", "rule_id": "B101", "reason": "one"}
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = cli_runner.invoke(
            config_app,
            [
                "lint",
                "--config",
                str(config_path),
                "--fix-unused",
                "--non-interactive",
            ],
        )

        assert result.exit_code == 1, result.output
        assert "could not be commented out" in result.output
        assert "written more than once" in result.output
        assert "No unused suppressions to comment out" not in result.output
        assert config_path.read_text(encoding="utf-8") == config_text

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

    def test_lint_fix_names_the_legacy_rename(self, cli_runner, tmp_path):
        """--fix must say what it is about to change for a legacy name.

        LEGACY_NAME_VARIANT issues were created with fixable=True and no
        fix_description, so the "Fixing N issue(s)" list printed a bare bullet
        for each one.
        """
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "project_name: t\nscanners:\n  cdk_nag:\n    enabled: true\n"
        )

        result = cli_runner.invoke(
            config_app,
            ["lint", "--config", str(config_path), "--fix", "--non-interactive"],
        )

        assert result.exit_code == 0
        bullets = [ln for ln in result.output.splitlines() if "•" in ln]
        assert bullets == [
            "  • Rename scanners.'cdk_nag' to the canonical form 'cdk-nag'"
        ]


class TestEveryFixableIssueDescribesItsFix:
    """Each fixable LintIssue the linter builds must carry a fix_description.

    The CLI prints fix_description as the bullet for each pending fix. Reading the
    source rather than linting fixtures covers every construction site, including
    ones no fixture here reaches.
    """

    def test_no_fixable_issue_is_built_without_a_description(self):
        import ast

        import automated_security_helper.config.config_linter as linter_module

        tree = ast.parse(Path(linter_module.__file__).read_text(encoding="utf-8"))
        undescribed = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "LintIssue"
            ):
                continue
            kwargs = {kw.arg: kw.value for kw in node.keywords}
            fixable = kwargs.get("fixable")
            if isinstance(fixable, ast.Constant) and fixable.value is True:
                if "fix_description" not in kwargs:
                    undescribed.append(node.lineno)
        assert undescribed == [], (
            f"LintIssue(fixable=True) without fix_description at lines {undescribed}"
        )


def _suppressions_block(indent: str, indentless: bool, bare_dash: bool = False) -> str:
    """The suppressions list, then an ignore_paths list after it, in one style.

    With ``bare_dash`` each entry starts with a `-` alone on its line and its
    first field on the next one, which YAML reads as the same list.
    """
    i = indent
    item = i if indentless else i + i
    start = f"{item}-\n{item}  " if bare_dash else f"{item}- "
    return (
        f"{i}suppressions:\n"
        f"{start}path: src/a.py\n{item}  rule_id: B101\n{item}  reason: one\n"
        f"{start}path: src/b.py\n{item}  rule_id: B102\n{item}  reason: two\n"
        f"{i}ignore_paths:\n"
        f"{start}path: vendor/**\n{item}  reason: third-party code\n"
    )


@pytest.mark.parametrize(
    "indent, indentless, bare_dash",
    [
        pytest.param("  ", False, False, id="two-space"),
        pytest.param("    ", False, False, id="four-space"),
        # `- ` at the key's own indent, which PyYAML writes and many people type.
        pytest.param("  ", True, False, id="indentless"),
        pytest.param("    ", True, False, id="indentless-four-space"),
        # A `-` alone on its line: at the key's indent it was taken for the end
        # of the section, and indented it was not counted as an entry, so
        # neither list had anything commented out.
        pytest.param("  ", False, True, id="bare-dash"),
        pytest.param("  ", True, True, id="bare-dash-indentless"),
    ],
)
def test_fix_unused_of_every_suppression_leaves_a_config_a_scan_loads(
    cli_runner, tmp_path, indent, indentless, bare_dash
):
    """Commenting out every entry leaves `suppressions:` holding an empty list.

    A scan refuses a null list (exit 3), so after `--fix-unused -y` on a config
    whose suppressions were all unused the next scan runs. The key holds
    an empty list, and the commented-out entries stay below it. The sibling
    block list after it is not part of the suppressions: with indentless lists
    its `- path: vendor/**` is not counted as a third suppression.
    """
    from automated_security_helper.config.resolve_config import resolve_config

    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        f"project_name: demo\nglobal_settings:\n{indent}severity_threshold: MEDIUM\n"
        + _suppressions_block(indent, indentless, bare_dash),
        encoding="utf-8",
    )
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(
            {
                "unused_suppressions": [
                    {"path": "src/a.py", "rule_id": "B101", "reason": "one"},
                    {"path": "src/b.py", "rule_id": "B102", "reason": "two"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = cli_runner.invoke(
        config_app, ["lint", "--config", str(config_path), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    text = config_path.read_text(encoding="utf-8")
    assert text.count("# [ash-lint") == 2, text
    # The scan's own loader, strict model and all.
    config = resolve_config(config_path=config_path, fallback_to_default=False)
    assert config.global_settings.suppressions == []
    assert config.global_settings.severity_threshold == "MEDIUM"
    assert [p.path for p in config.global_settings.ignore_paths] == ["vendor/**"]
    validate = cli_runner.invoke(config_app, ["validate", "--config", str(config_path)])
    assert validate.exit_code == 0, validate.output


@pytest.mark.parametrize("bare_dash", [False, True], ids=["dash-space", "bare-dash"])
def test_fix_unused_of_some_suppressions_keeps_the_rest_and_the_sibling(
    cli_runner, tmp_path, bare_dash
):
    """With an indentless list, only the unused entry is commented out."""
    from automated_security_helper.config.resolve_config import resolve_config

    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "project_name: demo\nglobal_settings:\n"
        + _suppressions_block("  ", True, bare_dash),
        encoding="utf-8",
    )
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(
            {
                "unused_suppressions": [
                    {"path": "src/b.py", "rule_id": "B102", "reason": "two"}
                ]
            }
        ),
        encoding="utf-8",
    )

    result = cli_runner.invoke(
        config_app, ["lint", "--config", str(config_path), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    config = resolve_config(config_path=config_path, fallback_to_default=False)
    assert [s.rule_id for s in config.global_settings.suppressions] == ["B101"]
    assert [p.path for p in config.global_settings.ignore_paths] == ["vendor/**"]


@pytest.mark.parametrize("item", ["-", "- x"])
def test_fix_unused_does_not_count_a_dash_inside_a_reason_as_an_entry(
    cli_runner, tmp_path, item
):
    """A line `-` (or `- x`) inside a block reason was counted as the next
    entry, so the entry after it was not commented out and the reason lost
    that line instead."""
    from automated_security_helper.config.resolve_config import resolve_config

    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        "    - path: src/a.py\n      rule_id: B101\n      reason: |\n"
        f"        first line\n        {item}\n        last line\n"
        "    - path: src/b.py\n      rule_id: B102\n      reason: two\n",
        encoding="utf-8",
    )
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(
            {
                "unused_suppressions": [
                    {"path": "src/b.py", "rule_id": "B102", "reason": "two"}
                ]
            }
        ),
        encoding="utf-8",
    )

    result = cli_runner.invoke(
        config_app, ["lint", "--config", str(config_path), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    config = resolve_config(config_path=config_path, fallback_to_default=False)
    (kept,) = config.global_settings.suppressions
    assert kept.rule_id == "B101"
    assert kept.reason.splitlines() == ["first line", item, "last line"]


def test_fix_refuses_a_file_with_environment_references(tmp_path):
    """ConfigLinter.fix itself refuses, not only the command that calls it."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: ${ASH_TEST_LINT_NAME:demo}\nbuild:\n  build_mode: ONLINE\n",
        encoding="utf-8",
    )
    before = config_path.read_bytes()

    with pytest.raises(ValueError, match="environment references"):
        ConfigLinter.fix(config_path)

    assert config_path.read_bytes() == before


def test_fix_unused_refuses_a_json_file(tmp_path):
    """fix_unused_suppressions itself refuses JSON, which cannot hold a comment."""
    config_path = tmp_path / "ash.json"
    config_path.write_text('{"project_name": "demo"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON"):
        ConfigLinter.fix_unused_suppressions(config_path)


def test_fix_help_says_which_files_it_leaves_alone():
    """--fix refuses a TOML file and a file that reads the environment; its help
    said only what it fixes, so the refusal came as a surprise."""
    result = CliRunner().invoke(config_app, ["lint", "--help"], env={"COLUMNS": "400"})

    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert "TOML" in flat, flat
    assert "${VAR}" in flat and "!ENV" in flat, flat


def _option_help(command: str, option: str) -> str:
    """The help text of one option of an ``ash config`` command, read from the
    command itself, so another option's help cannot satisfy a check of it."""
    import typer.main

    group = typer.main.get_command(config_app)
    [param] = [p for p in group.commands[command].params if option in p.opts]
    return " ".join((param.help or "").split())


def test_fix_unused_help_says_which_files_it_leaves_alone():
    """--fix-unused refuses a TOML file and a JSON file, which holds no
    comments; its help named neither."""
    text = _option_help("lint", "--fix-unused")

    assert "TOML" in text, text
    assert "JSON" in text, text


@pytest.mark.parametrize(
    "flags", [["--fix"], ["--fix-unused"], ["--fix", "--fix-unused"]]
)
def test_the_toml_refusal_says_what_each_flag_rewrites(tmp_path, flags):
    """The refusal said "--fix and --fix-unused rewrite YAML and JSON", but
    --fix-unused refuses JSON too. The file holds something --fix would rewrite
    (a suppression with line_start and no line_end): --fix refuses a TOML file
    only when it has a fix to make, since a clean one passes."""
    config_path = tmp_path / ".ashrc.toml"
    config_path.write_text(
        'project_name = "t"\n'
        "\n"
        "[[global_settings.suppressions]]\n"
        'rule_id = "B101"\n'
        'path = "a.py"\n'
        "line_start = 3\n"
        'reason = "r"\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        config_app,
        ["lint", "--config", str(config_path), *flags, "-y"],
        env={"COLUMNS": "400"},
    )

    assert result.exit_code == 1, result.output
    flat = " ".join(result.output.split())
    assert "--fix-unused rewrite YAML and JSON" not in flat, flat
    assert "--fix rewrites YAML and JSON config files" in flat, flat
    assert "--fix-unused YAML ones only" in flat, flat


def test_lint_fix_passes_a_clean_toml_file_without_the_refusal(tmp_path):
    """The documented pre-commit invocation, ``lint --fix -y`` on a TOML config
    with nothing to fix, exits 0 and prints no rewrite refusal. The test above
    swapped its clean file for one with a fix to make; without this one a
    regression here would break TOML users' pre-commit hooks with no test red."""
    config_path = tmp_path / ".ashrc.toml"
    config_path.write_text('project_name = "t"\n', encoding="utf-8")

    result = CliRunner().invoke(
        config_app,
        ["lint", "--config", str(config_path), "--fix", "-y"],
        env={"COLUMNS": "400"},
    )

    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert "rewrites YAML and JSON config files" not in flat, flat
