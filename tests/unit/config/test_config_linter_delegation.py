# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for config_linter delegation to config_validator."""

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.config.config_validator import ConfigValidator


class TestLinterUsesValidatorForRequiredFieldCheck:
    """Linter surfaces required-field errors that come from the validator."""

    def test_missing_required_field_reported_as_error(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        # project_name is the only REQUIRED_TOP_LEVEL_FIELDS entry
        cfg.write_text("fail_on_findings: false\n")

        result = ConfigLinter.lint(cfg)

        error_msgs = [i.message for i in result.issues if i.severity == LintSeverity.ERROR]
        assert any("project_name" in m for m in error_msgs), (
            f"Expected missing-field error for 'project_name', got: {error_msgs}"
        )

    def test_linter_uses_validator_for_required_field_check(self, tmp_path):
        """Monkeypatching validate_config_file to inject an extra error propagates to linter."""
        cfg = tmp_path / "ash.yml"
        cfg.write_text("project_name: test\n")

        injected_error = "Missing required top-level field: 'injected_field'"

        original = ConfigValidator.validate_config_file

        def patched(path):
            ok, errors = original(path)
            return False, errors + [injected_error]

        with patch.object(ConfigValidator, "validate_config_file", side_effect=patched):
            result = ConfigLinter.lint(cfg)

        msgs = [i.message for i in result.issues]
        assert any("injected_field" in m for m in msgs), (
            f"Expected injected error to surface in linter result, got: {msgs}"
        )


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
        assert unused_issues, "Linter should report unused suppression that validator ignores"

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
                  expiration: "2020-01-01"
            """)
        )

        is_valid, errors = ConfigValidator.validate_config_file(cfg)
        assert is_valid, f"Validator should pass: {errors}"

        result = ConfigLinter.lint(cfg)

        expired_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_EXPIRED
        ]
        assert expired_issues, "Linter should report expired suppression that validator ignores"


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

    def test_missing_required_field_reported_once(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        cfg.write_text("fail_on_findings: false\n")

        result = ConfigLinter.lint(cfg)

        project_name_errors = [
            i for i in result.issues
            if "project_name" in i.message and i.severity == LintSeverity.ERROR
        ]
        assert len(project_name_errors) == 1, (
            f"Expected exactly 1 project_name error, got {len(project_name_errors)}: "
            f"{[i.message for i in project_name_errors]}"
        )

    def test_invalid_top_level_field_reported_once(self, tmp_path):
        cfg = tmp_path / "ash.yml"
        # 'build' is in INVALID_TOP_LEVEL_FIELDS
        cfg.write_text(
            textwrap.dedent("""\
            project_name: test
            build: internal_value
            """)
        )

        result = ConfigLinter.lint(cfg)

        build_errors = [
            i for i in result.issues
            if "build" in i.message and i.severity == LintSeverity.ERROR
        ]
        assert len(build_errors) == 1, (
            f"Expected exactly 1 'build' field error, got {len(build_errors)}: "
            f"{[i.message for i in build_errors]}"
        )
