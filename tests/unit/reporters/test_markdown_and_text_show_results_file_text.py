# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three places the Markdown and text reports wrote results-file text raw.

* The Markdown report rendered the "Stale content databases" section twice for
  the same records, and the second copy wrote each record's name, scanner and
  message without the literal escaping the first copy applies.
* The "Inputs not scanned" lines of both reports escaped only the path; the
  scanner's name and the reason, both read from the results file, were written
  raw.
* The text report's "Showing N of M" note compared against every finding
  (suppressed and below-threshold included) while the list it describes holds
  only actionable findings, so it printed numbers the list did not match, or
  appeared when nothing was cut.
"""

from datetime import datetime, timedelta, timezone

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
    TextReporterConfig,
    TextReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.content_db_staleness import (
    STALE_NOTIFICATION_ID,
    ContentDbAgeRecord,
)
from tests.utils.scanner_thresholds import without_scanner_thresholds

pytestmark = pytest.mark.unit


class TestTheStaleSectionIsWrittenOnceAndLiteral:
    @staticmethod
    def _model() -> AshAggregatedResults:
        measured_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = ContentDbAgeRecord(
            name="grype_db",
            scanner="grype*",
            built=measured_at - timedelta(days=400),
            measured_by="test",
            max_age=timedelta(days=1),
            measured_at=measured_at,
            policy="warn",
            bound_source="test",
            bound_is_tool_default=True,
            refresh="run `grype db update`",
        )
        model = AshAggregatedResults(ash_config=get_default_config())
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "grype"}},
                        "results": [],
                        "invocations": [
                            {
                                "executionSuccessful": True,
                                "toolConfigurationNotifications": [
                                    {
                                        "descriptor": {"id": STALE_NOTIFICATION_ID},
                                        "level": "warning",
                                        "message": {"text": "stale"},
                                        "properties": {
                                            "content_database": record.to_dict()
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        return model

    def test_the_heading_appears_once(self, test_plugin_context):
        out = MarkdownReporter(context=test_plugin_context).report(self._model())
        assert out.count("### Stale content databases") == 1, out

    def test_the_record_text_is_literal(self, test_plugin_context):
        out = MarkdownReporter(context=test_plugin_context).report(self._model())
        assert "grype\\_db" in out, out
        assert "grype\\*" in out, out
        assert "- **grype_db**" not in out, out


class TestInputsNotScannedShowsNameAndReason:
    @staticmethod
    def _model() -> AshAggregatedResults:
        model = AshAggregatedResults()
        model.additional_reports = {
            "npm-audit": {
                "source": {
                    "scanner_name": "npm-audit",
                    "target_type": "source",
                    "status": "MISSING",
                    "inputs_not_scanned": [
                        {
                            "path": "web/package-lock.json",
                            "reason": "not\x1b[31m audited\n## x",
                        }
                    ],
                }
            }
        }
        # The scanner's name reaches the line from the report's own key.
        model.additional_reports["npm*audit\x07"] = model.additional_reports.pop(
            "npm-audit"
        )
        model.additional_reports["npm*audit\x07"]["source"]["scanner_name"] = (
            "npm*audit\x07"
        )
        return model

    def test_the_text_line_shows_the_name_and_the_reason(self, test_plugin_context):
        out = TextReporter(context=test_plugin_context).report(self._model())
        (line,) = [l for l in out.splitlines() if "package-lock.json" in l]
        assert "\x1b" not in line and "\x07" not in line, repr(line)
        assert "\\x07" in line and "\\x1b" in line, repr(line)
        assert not any(l.startswith("## x") for l in out.splitlines())

    def test_the_markdown_line_shows_the_name_and_the_reason(self, test_plugin_context):
        out = MarkdownReporter(context=test_plugin_context).report(self._model())
        (line,) = [l for l in out.splitlines() if "package-lock.json" in l]
        assert "\x1b" not in line and "\x07" not in line, repr(line)
        assert "npm\\*audit" in line, repr(line)
        # The reason is shown, not dropped: the three checks above and below
        # would all pass for a line that held the name and no reason.
        assert "audited" in line, repr(line)
        assert not any(l.startswith("## x") for l in out.splitlines())


class TestTheShowingNoteCountsActionableFindings:
    @staticmethod
    def _model(actionable: int, below: int) -> AshAggregatedResults:
        results = [
            {
                "ruleId": f"ERR-{index}",
                "level": "error",
                "message": {"text": f"actionable {index}"},
                "properties": {"scanner_name": "bandit"},
            }
            for index in range(actionable)
        ] + [
            {
                "ruleId": f"INFO-{index}",
                "level": "none",
                "message": {"text": f"below {index}"},
                "properties": {"scanner_name": "bandit"},
            }
            for index in range(below)
        ]
        model = AshAggregatedResults(ash_config=get_default_config())
        # ``get_default_config`` honours ASH_CONFIG: a bandit threshold it set
        # would grade these findings by itself and not by the MEDIUM below.
        without_scanner_thresholds(model)
        model.ash_config.global_settings.severity_threshold = "MEDIUM"
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH"}},
                        "results": results,
                        "invocations": [],
                    }
                ],
            }
        )
        return model

    @staticmethod
    def _reporter(context, limit: int) -> TextReporter:
        return TextReporter(
            context=context,
            config=TextReporterConfig(
                options=TextReporterConfigOptions(
                    include_detailed_findings=True, max_detailed_findings=limit
                )
            ),
        )

    def test_no_note_when_every_actionable_finding_is_shown(self, test_plugin_context):
        """At the base: 26 findings over a limit of 20 printed "Showing 20 of 26"
        above a list of one finding."""
        out = self._reporter(test_plugin_context, 20).report(self._model(1, 25))
        assert "Note: Showing" not in out, out

    def test_the_note_counts_the_actionable_findings(self, test_plugin_context):
        out = self._reporter(test_plugin_context, 2).report(self._model(3, 25))
        assert "Note: Showing 2 of 3 actionable findings" in out, out
