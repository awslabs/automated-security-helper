# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for config_linter delegation to config_validator."""

import textwrap
from unittest.mock import patch


from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.config.config_validator import ConfigValidator


class TestLinterUsesValidatorForRequiredFieldCheck:
    """Linter surfaces required-field errors that come from the validator."""

    def test_missing_project_name_reported_as_warning(self, tmp_path):
        # project_name has a default, so a scan accepts a config without it: the
        # linter reports it as a warning, not as a missing required field.
        cfg = tmp_path / "ash.yml"
        cfg.write_text("fail_on_findings: false\n")

        result = ConfigLinter.lint(cfg)

        issues = [i for i in result.issues if "project_name" in i.message]
        assert [i.severity for i in issues] == [LintSeverity.WARNING], (
            f"Expected one project_name warning, got: {result.issues}"
        )
        assert not result.scan_refuses

    def test_linter_uses_validator_for_required_field_check(self, tmp_path):
        """Monkeypatching check_config_file to inject an extra error propagates to linter."""
        cfg = tmp_path / "ash.yml"
        cfg.write_text("project_name: test\n")

        injected_error = "Invalid value at 'injected_field': Field required"

        original = ConfigValidator.check_config_file

        def patched(path, **kwargs):
            check = original(path, **kwargs)
            check.errors.append(injected_error)
            return check

        with patch.object(ConfigValidator, "check_config_file", side_effect=patched):
            result = ConfigLinter.lint(cfg)

        injected = [i for i in result.issues if "injected_field" in i.message]
        assert injected, (
            f"Expected injected error to surface in linter result, got: {result.issues}"
        )
        assert injected[0].category == LintCategory.SCHEMA_ERROR
        assert injected[0].path == "injected_field"
        assert result.scan_refuses


class TestLinterAddsSuppressionChecksOnTop:
    """A config that passes validator but has suppression issues is still flagged by linter."""

    def test_unused_suppression_warning_not_in_validator(self, tmp_path):
        """Validator has no concept of unused suppressions; linter adds it."""
        cfg = tmp_path / "ash.yml"
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            global_settings:
              suppressions:
                - path: src/
                  rule_id: TEST001
                  reason: test fixture
            """)
        )

        # Validator must pass cleanly
        is_valid, errors = ConfigValidator.validate_config_file(cfg)
        assert is_valid, f"Validator should pass: {errors}"

        # Provide a fake unused-suppressions report
        report_dir = tmp_path / ".ash" / "ash_output" / "reports"
        report_dir.mkdir(parents=True)
        report_file = report_dir.parent / "reports" / "ash.unused-suppressions.json"
        report_file.write_text(
            '{"unused_suppressions": [{"path": "src/", "rule_id": "TEST001"}]}'
        )

        result = ConfigLinter.lint(cfg, output_dir=report_dir.parent, check_unused=True)

        unused_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_UNUSED
        ]
        assert unused_issues, (
            "Linter should report unused suppression that validator ignores"
        )

    def test_expired_suppression_warning_not_in_validator(self, tmp_path):
        """Validator has no concept of expired suppressions; linter adds it."""
        cfg = tmp_path / "ash.yml"
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            global_settings:
              suppressions:
                - path: src/
                  rule_id: TEST001
                  reason: test fixture
                  expiration: "2020-01-01"
            """)
        )

        is_valid, errors = ConfigValidator.validate_config_file(cfg)
        assert is_valid, f"Validator should pass: {errors}"

        result = ConfigLinter.lint(cfg)

        expired_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_EXPIRED
        ]
        assert expired_issues, (
            "Linter should report expired suppression that validator ignores"
        )


class TestLinterDoesNotDuplicateValidatorErrors:
    """A config invalid against validator: linter reports each error exactly once."""

    def test_internal_field_error_reported_once(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            scanners:
              bandit:
                name: bandit
            """)
        )

        result = ConfigLinter.lint(cfg)

        # Collect messages about the internal field
        internal_msgs = [
            i.message
            for i in result.issues
            if "internal" in i.message.lower() and "bandit" in i.message
        ]
        assert len(internal_msgs) >= 1, "Should report internal field error"
        assert len(internal_msgs) == len(set(internal_msgs)), (
            f"Internal field error reported more than once: {internal_msgs}"
        )

    def test_missing_project_name_reported_once(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        cfg.write_text("fail_on_findings: false\n")

        result = ConfigLinter.lint(cfg)

        project_name_issues = [i for i in result.issues if "project_name" in i.message]
        assert len(project_name_issues) == 1, (
            f"Expected exactly 1 project_name issue, got {len(project_name_issues)}: "
            f"{[i.message for i in project_name_issues]}"
        )

    def test_directory_path_without_glob_reported_once(self, tmp_path):
        """The validator and the linter both check it; lint lists it once, with
        the location of the entry."""
        (tmp_path / "vendor").mkdir()
        cfg = tmp_path / "ash.yml"
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            global_settings:
              ignore_paths:
                - path: vendor
                  reason: third-party code
            """)
        )

        result = ConfigLinter.lint(cfg)

        vendor_issues = [i for i in result.issues if "'vendor'" in i.message]
        assert len(vendor_issues) == 1, [str(i) for i in vendor_issues]
        assert vendor_issues[0].path == "global_settings.ignore_paths[0].path"

    def test_directory_path_only_a_base_supplies_is_reported_once(self, tmp_path):
        """Lint's own check reads the file's entries only; the validator's warning,
        from the merged config, is then the one report of it."""
        (tmp_path / "vendor").mkdir()
        (tmp_path / "base.yml").write_text(
            textwrap.dedent("""\
            global_settings:
              ignore_paths:
                - path: vendor
                  reason: third-party code
            """)
        )
        cfg = tmp_path / "ash.yml"
        cfg.write_text("extends: base.yml\nproject_name: test\n")

        result = ConfigLinter.lint(cfg)

        vendor_issues = [i for i in result.issues if "'vendor'" in i.message]
        assert len(vendor_issues) == 1, [str(i) for i in vendor_issues]

    def test_invalid_top_level_field_reported_once(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        # 'build' is in INVALID_TOP_LEVEL_FIELDS. Its value is one the model
        # accepts, so the only problem is the internal section itself.
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            build:
              build_mode: ONLINE
            """)
        )

        result = ConfigLinter.lint(cfg)

        build_issues = [i for i in result.issues if "build" in i.message]
        assert len(build_issues) == 1, (
            f"Expected exactly 1 'build' field issue, got {len(build_issues)}: "
            f"{[i.message for i in build_issues]}"
        )
        # A scan accepts the section, so it is a warning, and --fix removes it.
        assert build_issues[0].severity == LintSeverity.WARNING
        assert build_issues[0].fixable
