# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` leaves alone what a partial scan could not evaluate.

Why this file exists
--------------------
The unused-suppressions report names the scanners that did not run
(``scanners_not_run``). A suppression carries no scanner name, so the report
cannot say which of the entries it lists belong to those scanners: a scan on a
host without semgrep lists every semgrep suppression as unused. The linter did
not read the key, so ``ash config lint --fix-unused`` commented those entries
out, and the next full scan, with semgrep, reported the findings they had held.
The fixer now comments nothing out for such a report, and lint offers none of
its entries to the fixer.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
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


def _write(tmp_path: Path, report: dict) -> Path:
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_bytes(CONFIG.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    return config_path


def _report(**extra) -> dict:
    return {
        "unused_suppressions": [
            {"path": "src/a.py", "rule_id": "B101", "reason": "one"}
        ],
        **extra,
    }


def test_a_report_that_lists_a_scanner_that_did_not_run_comments_nothing_out(tmp_path):
    """Red at the base: the fixer never read ``scanners_not_run`` and commented
    the entry out."""
    config_path = _write(tmp_path, _report(scanners_not_run=["semgrep"]))
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, timestamp = ConfigLinter.fix_unused_suppressions(
        config_path
    )

    assert fixed_issues == []
    assert fixed_content == before
    assert timestamp is not None


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({}, id="no-key"),
        pytest.param({"scanners_not_run": []}, id="empty-list"),
    ],
)
def test_a_report_with_every_scanner_run_still_comments_the_entry_out(tmp_path, extra):
    """The positive control: the same report without a scanner that did not run
    is fixed, so the test above does not pass because nothing is ever fixed."""
    config_path = _write(tmp_path, _report(**extra))
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 1
    assert fixed_content != before
    assert "# - path: src/a.py" in fixed_content


def test_lint_offers_no_entry_of_a_partial_report_to_the_fixer(tmp_path):
    """Red at the base: the entry was fixable, and no issue named the scanner."""
    config_path = _write(tmp_path, _report(scanners_not_run=["semgrep"]))

    result = ConfigLinter.lint(config_path, check_unused=True)

    unused = [i for i in result.issues if i.category == LintCategory.SUPPRESSION_UNUSED]
    entries = [i for i in unused if i.message.startswith("Unused suppression:")]
    assert len(entries) == 1, unused
    assert not entries[0].fixable
    assert any("semgrep" in i.message and "did not run" in i.message for i in unused)


def test_lint_still_offers_the_entry_of_a_complete_report(tmp_path):
    """The positive control for the test above."""
    config_path = _write(tmp_path, _report())

    result = ConfigLinter.lint(config_path, check_unused=True)

    entries = [
        i
        for i in result.issues
        if i.category == LintCategory.SUPPRESSION_UNUSED
        and i.message.startswith("Unused suppression:")
    ]
    assert len(entries) == 1
    assert entries[0].fixable
