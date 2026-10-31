# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lint, the age read and the fixer name the unused report from one config.

Why this file exists
--------------------
Lint names the report from the merged configuration it read, with the scanned
tree (``--source-dir``) in the chain's resolution. The report age and the fixer
resolved the chain again, each by itself and without the scanned tree, so
``--fix-unused`` could comment entries out from a different report than the one
lint listed, and each run resolved the chain four or five times. The merged
configuration lint read is now passed to the age read and the fixer
(``report_config``).
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintIssue,
    LintResult,
    LintSeverity,
)

pytestmark = pytest.mark.unit

CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)
REPORT = json.dumps(
    {"unused_suppressions": [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}]}
)
# What the merged configuration holds when a base sets the reporter's extension.
NAMED_BY_A_BASE = {"reporters": {"unused-suppressions": {"extension": "custom.json"}}}


def _layout(tmp_path: Path):
    config = tmp_path / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_bytes(CONFIG.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    return config, reports


def test_the_fixer_reads_the_report_the_given_config_names(tmp_path):
    """Red at the base: the fixer took no such argument, and named the report
    from the config file alone (the default name), where lint had named the
    report the merged configuration sets."""
    config, reports = _layout(tmp_path)
    (reports / "ash.custom.json").write_text(REPORT, encoding="utf-8")

    fixed, issues, stamp = ConfigLinter.fix_unused_suppressions(
        config, report_config=NAMED_BY_A_BASE
    )

    assert len(issues) == 1
    assert stamp is not None
    assert "# - path: src/a.py" in fixed


def test_the_fixer_without_it_names_the_report_from_the_file(tmp_path):
    """The positive control: no config passed, the default name stands, so a
    report written under the custom name alone is not found."""
    config, reports = _layout(tmp_path)
    (reports / "ash.custom.json").write_text(REPORT, encoding="utf-8")

    _fixed, issues, stamp = ConfigLinter.fix_unused_suppressions(config)

    assert issues == []
    assert stamp is None


def test_the_age_read_names_the_report_from_the_given_config(tmp_path):
    """Red at the base: the age read took no such argument."""
    config, reports = _layout(tmp_path)
    (reports / "ash.custom.json").write_text(REPORT, encoding="utf-8")

    found = ConfigLinter.get_unused_report_age(config, report_config=NAMED_BY_A_BASE)

    assert found is not None
    assert found[0] == reports / "ash.custom.json"
    assert ConfigLinter.get_unused_report_age(config) is None


def test_the_command_hands_the_config_lint_read_to_the_age_read_and_the_fixer(
    tmp_path, monkeypatch
):
    """Red at the base: the command called both with the output directory
    alone, so each resolved the chain again."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    merged = dict(NAMED_BY_A_BASE)
    issue = LintIssue(
        severity=LintSeverity.INFO,
        category=LintCategory.SUPPRESSION_UNUSED,
        message="Unused suppression: path='src/a.py', rule_id='B101'",
    )
    monkeypatch.setattr(
        ConfigLinter,
        "lint",
        staticmethod(
            lambda **_: LintResult(
                issues=[issue], config_path=config, resolved_data=merged
            )
        ),
    )
    seen = {}

    def age(config_path, output_dir=None, report_config=None):
        seen["age"] = report_config
        return (tmp_path / "report.json", datetime.now(), 0.0)

    def fix(config_path, output_dir=None, report_config=None):
        seen["fix"] = report_config
        return None, [], None

    monkeypatch.setattr(ConfigLinter, "get_unused_report_age", staticmethod(age))
    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fix))

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused", "-y"]
    )

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert seen["age"] is merged
    assert seen["fix"] is merged
