# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under ``--ignore-suppressions`` the unused-suppressions report evaluates nothing.

Why this file exists
--------------------
The reporter subtracts ``model.used_suppressions`` from the configured list. A
scan run with ``--ignore-suppressions`` matches no suppression against any
finding, so that set is empty by construction and every configured entry read
as unused. ``ash config lint --fix-unused`` reads the report and commented every
one of them out: one flag on one scan removed every suppression from the config.

The report now says the suppressions were not evaluated, lists none as unused,
and the linter treats such a report as grounds for commenting nothing out.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)

pytestmark = pytest.mark.unit


def _context(tmp_path, *, ignore_suppressions: bool) -> PluginContext:
    config = AshConfig()
    config.global_settings.suppressions = [
        AshSuppression(path="src/app.py", rule_id="B201", reason="one"),
        AshSuppression(path="src/utils.py", rule_id="B603", reason="two"),
        AshSuppression(path="tests/**/*.py", rule_id="B101", reason="three"),
    ]
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
        ignore_suppressions=ignore_suppressions,
    )


def _report(context) -> dict:
    model = AshAggregatedResults()
    model.used_suppressions = set()
    return json.loads(UnusedSuppressionsReporter(context=context).report(model))


def test_an_ignored_run_lists_no_suppression_as_unused(tmp_path):
    """Red at the base: the list held all three configured entries."""
    report = _report(_context(tmp_path, ignore_suppressions=True))

    assert report["unused_suppressions"] == []
    assert report["summary"]["total_suppressions"] == 3
    assert report["summary"]["unused_suppressions"] == 0
    assert report["summary"]["used_suppressions"] == 0


def test_an_ignored_run_says_the_suppressions_were_not_evaluated(tmp_path):
    report = _report(_context(tmp_path, ignore_suppressions=True))

    assert report["summary"]["evaluated"] is False
    assert "--ignore-suppressions" in report["not_evaluated"]


def test_a_results_file_that_recorded_the_flag_reads_as_not_evaluated(tmp_path):
    """`ash report` re-renders a results file under a context with no flag;
    a scan that recorded `suppressions_ignored` in the results' metadata is
    still read as not evaluated."""
    context = _context(tmp_path, ignore_suppressions=False)
    model = AshAggregatedResults()
    model.used_suppressions = set()
    model.metadata.suppressions_ignored = True

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert report["unused_suppressions"] == []
    assert report["summary"]["evaluated"] is False


def test_a_normal_run_keeps_the_subtraction(tmp_path):
    """The control: without the flag an empty used set means every entry is unused."""
    report = _report(_context(tmp_path, ignore_suppressions=False))

    assert len(report["unused_suppressions"]) == 3
    assert "evaluated" not in report["summary"]
    assert "not_evaluated" not in report


def test_the_markdown_copy_says_nothing_was_evaluated(tmp_path):
    context = _context(tmp_path, ignore_suppressions=True)
    model = AshAggregatedResults()
    model.used_suppressions = set()
    UnusedSuppressionsReporter(context=context).report(model)

    markdown = (
        context.output_dir / "reports" / "ash.unused-suppressions.md"
    ).read_text(encoding="utf-8")
    assert "not evaluated" in markdown
    assert "All suppressions are being used" not in markdown
    assert "% of suppressions are unused" not in markdown


def _config_with_report(tmp_path, report: dict):
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/app.py\n"
        "      rule_id: B201\n"
        "      reason: one\n",
        encoding="utf-8",
    )
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    return config_path


def test_lint_names_the_ignored_run_instead_of_listing_unused_entries(tmp_path):
    """Red at the base: no issue mentioned ``--ignore-suppressions``."""
    config_path = _config_with_report(
        tmp_path,
        {
            "summary": {
                "total_suppressions": 1,
                "used_suppressions": 0,
                "unused_suppressions": 0,
                "evaluated": False,
            },
            "unused_suppressions": [],
            "not_evaluated": UnusedSuppressionsReporter.NOT_EVALUATED,
        },
    )

    result = ConfigLinter.lint(config_path, check_unused=True)

    issues = [
        i
        for i in result.issues
        if i.category == LintCategory.SUPPRESSION_UNUSED
        and "--ignore-suppressions" in i.message
    ]
    assert [i.severity for i in issues] == [LintSeverity.INFO], result.issues
    # The notice is the only unused-suppression issue, and it is not fixable: a
    # fixable one would have the CLI offer --fix-unused, which comments nothing
    # out on such a report.
    unused = [i for i in result.issues if i.category == LintCategory.SUPPRESSION_UNUSED]
    assert unused == issues, result.issues
    assert issues[0].fixable is False


def test_fix_unused_comments_nothing_out_on_a_not_evaluated_report(tmp_path):
    """A report that says it evaluated nothing names no entry, even when a stale
    or hand-edited one still lists some: nothing is commented out on its word."""
    config_path = _config_with_report(
        tmp_path,
        {
            "unused_suppressions": [
                {"path": "src/app.py", "rule_id": "B201", "reason": "one"}
            ],
            "not_evaluated": UnusedSuppressionsReporter.NOT_EVALUATED,
        },
    )
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before


def test_fix_unused_comments_the_listed_entry_out_on_an_evaluated_report(tmp_path):
    """The positive control for the test above: the same config and report
    location, the report evaluated, and the listed entry is commented out. A
    lookup that never found the report would pass the test above too."""
    config_path = _config_with_report(
        tmp_path,
        {
            "unused_suppressions": [
                {"path": "src/app.py", "rule_id": "B201", "reason": "one"}
            ]
        },
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert [i.path for i in fixed_issues] == ["global_settings.suppressions[0]"]
    assert "# - path: src/app.py" in fixed_content
