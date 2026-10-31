# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` writes only the entries the operator was shown.

Why this file exists
--------------------
The text to write is computed again after the confirmation prompt, so an edit
made while the prompt waited is not written over. But the entries shown at the
prompt were those of the first computation, and a file that changed meanwhile
could now comment out others, which the operator never approved. The command
now compares the two lists and writes nothing, exit 1, when they differ.

The report the entries come from is lint's too. Lint returns no report path both
when it looked and found none and when it did not look; the command read the
first as "not pinned" and let the age read and the fixer look again, so a report
written between the two, or one lint's resolution did not reach, was edited from
without ever being listed (and with ``-y`` nothing is asked). The result now
records that lint looked, and the command stops where lint found none.
"""

from __future__ import annotations

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
    LintSeverity,
)

pytestmark = pytest.mark.unit

BEFORE = "project_name: before\n"


def _commented(index: int) -> LintIssue:
    return LintIssue(
        severity=LintSeverity.INFO,
        category=LintCategory.SUPPRESSION_UNUSED,
        message=f"Commented out unused suppression: path='src/{index}.py'",
        path=f"global_settings.suppressions[{index}]",
        fixable=True,
    )


def _run(tmp_path: Path, monkeypatch, shown, written, *, report_exists=True):
    """Run ``lint --fix-unused`` over a config, with the age read and the fixer
    stood in for. Returns the config, the result and the stand-ins' calls.

    ``report_exists`` puts the unused suppressions report where lint looks for
    it; without one, lint looks and finds none."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(BEFORE, encoding="utf-8")
    report = (
        tmp_path / ".ash" / "ash_output" / "reports" / "ash.unused-suppressions.json"
    )
    if report_exists:
        report.parent.mkdir(parents=True)
        report.write_text(json.dumps({"unused_suppressions": []}), encoding="utf-8")
    calls: list[str] = []

    def age(*_a, **_k):
        calls.append("age")
        return (report, datetime.now(), 0.0)

    answers = iter([("project_name: first\n", shown, None), written])

    def fix(*_a, **_k):
        calls.append("fix")
        return next(answers)

    monkeypatch.setattr(ConfigLinter, "get_unused_report_age", staticmethod(age))
    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fix))
    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input="y\n"
    )
    return config, result, calls


def test_a_list_that_changed_during_the_prompt_is_not_written(tmp_path, monkeypatch):
    """Red at the base: the second computation was written without a look at
    whether it named the entries the prompt showed."""
    config, result, _calls = _run(
        tmp_path,
        monkeypatch,
        shown=[_commented(0)],
        written=("project_name: second\n", [_commented(0), _commented(1)], None),
    )

    assert result.exit_code == 1, result.output
    assert "changed while the prompt was open" in result.output
    assert config.read_text(encoding="utf-8") == BEFORE


def test_the_same_list_after_the_prompt_is_written(tmp_path, monkeypatch):
    """The positive control: the text computed after the prompt is the one
    written when it names the entries that were shown, from a report lint
    found."""
    config, result, calls = _run(
        tmp_path,
        monkeypatch,
        shown=[_commented(0)],
        written=("project_name: second\n", [_commented(0)], None),
    )

    assert result.exit_code == 0, result.output
    assert config.read_text(encoding="utf-8") == "project_name: second\n"
    assert calls == ["age", "fix", "fix"], calls


def test_a_report_lint_did_not_find_is_not_edited_from(tmp_path, monkeypatch):
    """Red at the base: lint found no report and said so, the age read and the
    fixer then looked again (here they find one), and the file was written from
    a report the operator was never shown."""
    config, result, calls = _run(
        tmp_path,
        monkeypatch,
        shown=[_commented(0)],
        written=("project_name: second\n", [_commented(0)], None),
        report_exists=False,
    )

    assert result.exit_code == 0, result.output
    assert "No unused suppressions report found" in result.output
    assert "Commenting out" not in result.output
    assert config.read_text(encoding="utf-8") == BEFORE
    assert calls == [], calls
