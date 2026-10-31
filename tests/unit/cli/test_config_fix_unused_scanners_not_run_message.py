# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` says why it comments nothing out of a partial report.

Why this file exists
--------------------
A report that lists scanners which did not run cannot say which of its entries
belong to them, so the fixer comments nothing out of it. The command still asked
whether to continue with an old report, and then ended in a green "No unused
suppressions to comment out" under lint's own note: the operator was asked a
question whose answer changed nothing and told there was nothing to do. The
command now reads the report's scanner list before the age question and says,
in one warning, that nothing is commented out and why.
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


def _layout(tmp_path, report, age_seconds=0):
    config = tmp_path / ".ashrc.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    path = reports / "ash.unused-suppressions.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    if age_seconds:
        then = time.time() - age_seconds
        os.utime(path, (then, then))
    return config, path


def test_the_helper_names_the_scanners_the_report_lists(tmp_path):
    _config, path = _layout(
        tmp_path, {"unused_suppressions": [ENTRY], "scanners_not_run": ["bandit"]}
    )

    assert ConfigLinter.unused_report_scanners_not_run(path) == ["bandit"]


def test_the_helper_is_empty_for_a_complete_or_unreadable_report(tmp_path):
    _config, path = _layout(tmp_path, {"unused_suppressions": [ENTRY]})
    assert ConfigLinter.unused_report_scanners_not_run(path) == []

    path.write_text("not json", encoding="utf-8")
    assert ConfigLinter.unused_report_scanners_not_run(path) == []
    assert ConfigLinter.unused_report_scanners_not_run(tmp_path / "missing.json") == []


def test_a_partial_report_is_not_asked_about_and_the_reason_is_printed(tmp_path):
    """Red at the base: a report two hours old drew the age question (answered
    here by an empty input, which aborts), and the green "No unused
    suppressions to comment out" followed when it was answered."""
    config, _path = _layout(
        tmp_path,
        {"unused_suppressions": [ENTRY], "scanners_not_run": ["bandit"]},
        age_seconds=7200,
    )

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input=""
    )

    assert result.exit_code == 0, result.output
    assert "Nothing is commented out" in result.output, result.output
    assert "bandit" in result.output, result.output
    assert "Proceed with commenting out" not in result.output, result.output
    assert "No unused suppressions to comment out" not in result.output
    assert config.read_text(encoding="utf-8") == CONFIG


def test_a_complete_old_report_is_still_asked_about(tmp_path):
    """The positive control: the same old report with no scanner left out draws
    the age question, so the test above is not a command that never asks."""
    config, _path = _layout(
        tmp_path, {"unused_suppressions": [ENTRY]}, age_seconds=7200
    )

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input="n\n"
    )

    assert "Proceed with commenting out" in result.output, result.output
    assert "Nothing is commented out" not in result.output
