# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two more readings of the scan summary that disagreed with the exit code.

A scanner whose tool ASH could not stop fails the run whatever the severity gate
says, and the tool may still be writing after the report is rendered. The
summary ignored ``scan_incompleteness().could_not_stop``, so the HTML, Markdown
and text reports could read "No actionable findings" on a run that exits 1, and
no report said a tool was still running. Each report now names the tool.

A scanner that lost SOME of its targets ran against the rest. When one of its
target reports also carried ERROR, the status alone counted it as not completed
and listed it under "Scanners needing attention" beside the "Incomplete
coverage" row that already named it with its counts. A partial-loss scanner now
counts as having run; a total loss and an unknown-size loss do not.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

pytestmark = pytest.mark.unit

REASON = "the tool (pid 4242) did not exit after SIGTERM and SIGKILL"


def _model(reports: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.additional_reports = reports
    return model


class TestAToolThatCouldNotBeStoppedIsNamed:
    @staticmethod
    def _unstopped() -> AshAggregatedResults:
        return _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                        "could_not_stop": REASON,
                    }
                }
            }
        )

    def test_the_summary_is_not_a_clean_pass(self):
        summary = ReportContentEmitter(self._unstopped()).get_scan_summary()
        assert summary["title"] != "No actionable findings", summary
        assert summary["could_not_stop"] == [("bandit", REASON)]
        assert "may not be final" in summary["description"]

    @pytest.mark.parametrize(
        "reporter",
        [HtmlReporter, MarkdownReporter, TextReporter],
        ids=lambda r: r.__name__,
    )
    def test_every_human_report_names_the_tool(self, reporter, test_plugin_context):
        document = reporter(context=test_plugin_context).report(self._unstopped())
        assert "pid 4242" in document, document[:3000]
        assert "not stopped" in document.lower(), document[:3000]

    def test_a_run_whose_tools_stopped_carries_no_such_notice(
        self, test_plugin_context
    ):
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                }
            }
        )
        document = TextReporter(context=test_plugin_context).report(model)
        assert "NOT STOPPED" not in document
        assert ReportContentEmitter(model).get_scan_summary()["could_not_stop"] == []


class TestAPartialLossErrorScannerCountsAsRun:
    @staticmethod
    def _report(status: str, attempted: int, failed: int) -> dict:
        return {
            "cdk-nag": {
                "source": {
                    "scanner_name": "cdk-nag",
                    "status": status,
                    "duration": 1.0,
                    "targets_attempted": attempted,
                    "targets_failed": failed,
                }
            }
        }

    def test_a_partial_loss_in_error_is_completed_and_not_unavailable(self):
        summary = ReportContentEmitter(
            _model(self._report("ERROR", 3, 1))
        ).get_scan_summary()
        assert summary["completed"] == 1, summary
        assert "cdk-nag" not in summary["unavailable"], summary
        assert summary["shortfalls"] == [("cdk-nag", 3, 1)]
        assert summary["title"] == "Scan incomplete", summary

    def test_a_total_loss_in_error_still_needs_attention(self):
        summary = ReportContentEmitter(
            _model(self._report("ERROR", 3, 3))
        ).get_scan_summary()
        assert summary["completed"] == 0, summary
        assert "cdk-nag" in summary["unavailable"], summary
