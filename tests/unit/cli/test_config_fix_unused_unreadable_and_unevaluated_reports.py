# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` says why it comments nothing out, for every such report.

Why this file exists
--------------------
The fixer comments nothing out of three kinds of report: one that lists scanners
which did not run, one whose scan evaluated no suppression (it ran with
``--ignore-suppressions``), and one that cannot be read. Only the first drew the
early warning (``test_config_fix_unused_scanners_not_run_message``). The other
two still went through the question about the report's age and ended in the
green "No unused suppressions to comment out", the misleading result that
warning was written to remove, and the command repeated a decision the fixer
makes. The fixer and the command now ask one check, ``unused_report_blocker``,
and the command prints its reason before the age question.
"""

import json
import os
import time

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import ConfigLinter

pytestmark = pytest.mark.unit

CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)
ENTRY = {"path": "src/a.py", "rule_id": "B101", "reason": "one"}


def _layout(tmp_path, report_text, age_seconds=0):
    config = tmp_path / ".ashrc.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    path = reports / "ash.unused-suppressions.json"
    path.write_text(report_text, encoding="utf-8")
    if age_seconds:
        then = time.time() - age_seconds
        os.utime(path, (then, then))
    return config, path


def test_the_blocker_names_each_reason_a_report_is_not_edited_from(tmp_path):
    _config, path = _layout(tmp_path, json.dumps({"unused_suppressions": [ENTRY]}))
    assert ConfigLinter.unused_report_blocker(path) is None

    path.write_text("not json", encoding="utf-8")
    assert "could not be read" in ConfigLinter.unused_report_blocker(path)
    missing = tmp_path / "missing.json"
    assert "could not be read" in ConfigLinter.unused_report_blocker(missing)

    path.write_text(
        json.dumps({"unused_suppressions": [], "not_evaluated": True}), encoding="utf-8"
    )
    assert "--ignore-suppressions" in ConfigLinter.unused_report_blocker(path)

    path.write_text(
        json.dumps({"unused_suppressions": [ENTRY], "scanners_not_run": ["bandit"]}),
        encoding="utf-8",
    )
    assert "(bandit)" in ConfigLinter.unused_report_blocker(path)


@pytest.mark.parametrize("age_seconds", [0, 7200], ids=["fresh", "two-hours-old"])
def test_an_unreadable_report_is_not_asked_about_and_the_reason_is_printed(
    tmp_path, age_seconds
):
    """Red at the base: a fresh one ended in the green "No unused suppressions
    to comment out", and an old one drew the age question first."""
    config, _path = _layout(tmp_path, "not json", age_seconds=age_seconds)

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input=""
    )

    assert result.exit_code == 0, result.output
    assert "Nothing is commented out" in result.output, result.output
    assert "could not be read" in result.output, result.output
    assert "Proceed with commenting out" not in result.output, result.output
    assert "No unused suppressions to comment out" not in result.output
    assert config.read_text(encoding="utf-8") == CONFIG


@pytest.mark.parametrize("age_seconds", [0, 7200], ids=["fresh", "two-hours-old"])
def test_a_report_that_evaluated_nothing_is_not_asked_about(tmp_path, age_seconds):
    """Red at the base, as for the unreadable report."""
    config, _path = _layout(
        tmp_path,
        json.dumps({"unused_suppressions": [], "not_evaluated": True}),
        age_seconds=age_seconds,
    )

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input=""
    )

    assert result.exit_code == 0, result.output
    assert "Nothing is commented out" in result.output, result.output
    assert "Proceed with commenting out" not in result.output, result.output
    assert "No unused suppressions to comment out" not in result.output
    assert config.read_text(encoding="utf-8") == CONFIG


def test_a_complete_report_still_reaches_the_fixer(tmp_path):
    """The positive control: a report with nothing in the way is edited from, so
    the tests above are not a command that refuses every report."""
    config, _path = _layout(tmp_path, json.dumps({"unused_suppressions": [ENTRY]}))

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    assert "Nothing is commented out" not in result.output, result.output
    assert "# [ash-lint" in config.read_text(encoding="utf-8")
