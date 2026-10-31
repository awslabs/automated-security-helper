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
    # Fixable, as lint marks an unused suppression it can list from a report.
    issue = LintIssue(
        severity=LintSeverity.INFO,
        category=LintCategory.SUPPRESSION_UNUSED,
        message="Unused suppression: path='src/a.py', rule_id='B101'",
        fixable=True,
    )
    monkeypatch.setattr(
        ConfigLinter,
        "lint",
        staticmethod(
            lambda *_a, **_k: LintResult(
                issues=[issue], config_path=config, resolved_data=merged
            )
        ),
    )
    seen = {}
    # What a call that names no report path would see, so a keyword left out of
    # the call is told from one passed as None.
    not_passed = "report_path was not passed"

    def age(config_path, output_dir=None, report_config=None, report_path=not_passed):
        seen["age"] = report_config
        seen["age_path"] = report_path
        return (tmp_path / "report.json", datetime.now(), 0.0)

    def fix(config_path, output_dir=None, report_config=None, report_path=not_passed):
        seen["fix"] = report_config
        seen["fix_path"] = report_path
        return None, [], None

    monkeypatch.setattr(ConfigLinter, "get_unused_report_age", staticmethod(age))
    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fix))

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    assert seen.get("age") is merged, seen
    assert seen.get("fix") is merged, seen
    # Lint did not look here (the result was built by hand), so no path is
    # pinned; the keyword is passed all the same, as None.
    assert seen.get("age_path") is None, seen
    assert seen.get("fix_path") is None, seen


def test_lint_records_the_report_it_read(tmp_path):
    """Red at the base: the result had no such field, so nothing downstream
    could take the file lint listed the entries from."""
    config, reports = _layout(tmp_path)
    report = reports / "ash.unused-suppressions.json"
    report.write_text(REPORT, encoding="utf-8")

    result = ConfigLinter.lint(
        config, output_dir=tmp_path / ".ash" / "ash_output", check_unused=True
    )

    assert result.unused_report_path == report


def test_lint_without_a_report_records_none(tmp_path):
    """The positive control: no report, so there is no file to hand on."""
    config, _reports = _layout(tmp_path)

    result = ConfigLinter.lint(
        config, output_dir=tmp_path / ".ash" / "ash_output", check_unused=True
    )

    assert result.unused_report_path is None
    # None is not "did not look": lint looked and found none.
    assert result.unused_report_checked is True


def test_lint_records_that_it_looked_for_the_report(tmp_path):
    """Red at the base: the result had no such field, so a path of None could not
    be told from a lint that never looked."""
    config, reports = _layout(tmp_path)
    (reports / "ash.unused-suppressions.json").write_text(REPORT, encoding="utf-8")

    result = ConfigLinter.lint(
        config, output_dir=tmp_path / ".ash" / "ash_output", check_unused=True
    )

    assert result.unused_report_checked is True


def test_lint_that_does_not_check_unused_records_that_it_did_not_look(tmp_path):
    """The positive control: without ``check_unused`` nothing is looked for, and
    the report that sits there is not recorded either."""
    config, reports = _layout(tmp_path)
    (reports / "ash.unused-suppressions.json").write_text(REPORT, encoding="utf-8")

    result = ConfigLinter.lint(
        config, output_dir=tmp_path / ".ash" / "ash_output", check_unused=False
    )

    assert result.unused_report_checked is False
    assert result.unused_report_path is None


def test_the_age_read_and_the_fixer_take_the_file_lint_read(tmp_path):
    """Red at the base: neither took a report path, and a lookup by name found
    nothing here (the report is not at the default place or under that name)."""
    config, _reports = _layout(tmp_path)
    elsewhere = tmp_path / "elsewhere" / "listed.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text(REPORT, encoding="utf-8")

    found = ConfigLinter.get_unused_report_age(config, report_path=elsewhere)
    fixed, issues, stamp = ConfigLinter.fix_unused_suppressions(
        config, report_path=elsewhere
    )

    assert found is not None
    assert found[0] == elsewhere
    assert len(issues) == 1
    assert stamp is not None
    assert "# - path: src/a.py" in fixed


def test_a_given_report_that_is_gone_is_not_replaced_by_a_lookup(tmp_path):
    """The report at the default place is not read in place of the one lint
    named when that one has since gone: the entries are lint's, from its file."""
    config, reports = _layout(tmp_path)
    (reports / "ash.unused-suppressions.json").write_text(REPORT, encoding="utf-8")
    gone = tmp_path / "elsewhere" / "listed.json"

    assert ConfigLinter.get_unused_report_age(config, report_path=gone) is None
    _fixed, issues, stamp = ConfigLinter.fix_unused_suppressions(
        config, report_path=gone
    )
    assert issues == []
    assert stamp is None
    # The control: without a path the lookup by name finds the report.
    assert ConfigLinter.get_unused_report_age(config) is not None


def test_the_command_hands_the_report_lint_read_to_the_age_read_and_the_fixer(
    tmp_path, monkeypatch
):
    """Red at the base: the result carried no report path (constructing it with
    one raised), and the command named the report again for each call."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    listed = tmp_path / "listed.json"
    issue = LintIssue(
        severity=LintSeverity.INFO,
        category=LintCategory.SUPPRESSION_UNUSED,
        message="Unused suppression: path='src/a.py', rule_id='B101'",
        fixable=True,
    )
    monkeypatch.setattr(
        ConfigLinter,
        "lint",
        staticmethod(
            lambda *_a, **_k: LintResult(
                issues=[issue], config_path=config, unused_report_path=listed
            )
        ),
    )
    seen = {}

    def age(config_path, output_dir=None, report_config=None, report_path=None):
        seen["age"] = report_path
        return (listed, datetime.now(), 0.0)

    def fix(config_path, output_dir=None, report_config=None, report_path=None):
        seen["fix"] = report_path
        return None, [], None

    monkeypatch.setattr(ConfigLinter, "get_unused_report_age", staticmethod(age))
    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fix))

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    assert seen.get("age") == listed, seen
    assert seen.get("fix") == listed, seen
