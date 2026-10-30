# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The text report lines its tables up, keeps coverage in view and shows severity.

* The scanner table's Suppressed column was eight wide under a ten-character
  title, and the hotspot table's count column was twelve wide under a
  thirteen-character title, so each column sat one or two characters left of its
  title.
* The inputs no scanner or converter read stay in the report when the summary
  is turned off, as the coverage notices do.
* An additional report's severity is read as the gate reads it, so the findings
  overview and the detailed findings show one line, and none of a value that is
  not a severity name.
* A negative limit is refused when the option is read; it used to slice the
  findings from the end.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
    TextReporterConfig,
    TextReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit


def _model() -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            }
        )
    ]
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "FAILED", "duration": 1.0}
    }
    model._flat_cache = None
    return model


def _report(test_plugin_context, model, **options) -> str:
    return TextReporter(
        context=test_plugin_context,
        config=TextReporterConfig(options=TextReporterConfigOptions(**options)),
    ).report(model)


class TestEachColumnSitsUnderItsTitle:
    def test_the_suppressed_column(self, test_plugin_context):
        lines = _report(test_plugin_context, _model()).split("\n")

        # "Scanner Results:" above the table also starts with "Scanner ".
        header = next(
            line
            for line in lines
            if line.startswith("Scanner ") and "Suppressed" in line
        )
        rule = lines[lines.index(header) + 1]
        row = next(line for line in lines if line.startswith("bandit"))
        end = header.index("Suppressed") + len("Suppressed")

        # The control: the title is where this test expects it.
        assert header[:end].endswith("Suppressed"), header
        assert rule.split(" ")[1] == "-" * len("Suppressed"), rule
        assert row[end - 1].isdigit(), row
        assert row[end] == " ", row

    def test_the_hotspot_count_column(self, test_plugin_context):
        lines = _report(test_plugin_context, _model()).split("\n")

        header = next(line for line in lines if line.startswith("Finding Count"))
        rule = lines[lines.index(header) + 1]
        row = lines[lines.index(header) + 2]
        end = len("Finding Count")

        assert rule.split(" ")[0] == "-" * end, rule
        assert row[end - 1].isdigit(), row
        assert row[end] == " ", row
        assert row[end + 1 :].startswith("src/app.py"), row


class TestCoverageStaysWhenTheSummaryIsOff:
    @pytest.mark.parametrize("include_summary", [True, False])
    def test_the_inputs_not_scanned_section_is_present(
        self, include_summary, test_plugin_context
    ):
        model = _model()
        model.additional_reports["bandit"]["source"]["inputs_not_scanned"] = [
            {"path": "vendor/big.py", "reason": "file too large"}
        ]

        report = _report(test_plugin_context, model, include_summary=include_summary)

        assert "INPUTS NOT SCANNED" in report
        assert "vendor/big.py" in report
        assert "file too large" in report


class TestAnAdditionalReportsSeverityIsOneLine:
    def test_the_overview_and_the_detail_show_it_on_one_line(self, test_plugin_context):
        model = _model()
        model.sarif.runs[0].results = []
        model.additional_reports["custom-plugin"] = [
            {
                "title": "Odd severity",
                "description": "d",
                "severity": "HIGH\nINJECTED",
                "file_path": "app.py",
                "line_start": 3,
            }
        ]
        model._flat_cache = None

        report = _report(
            test_plugin_context,
            model,
            include_findings_table=True,
            include_detailed_findings=True,
        )

        # The control: both places print the finding.
        assert report.count("Odd severity") >= 2, report
        for line in report.split("\n"):
            assert not line.startswith("INJECTED"), line
        # Text that is not a severity name is graded as a result with no level,
        # so the detail line is one line of the graded value.
        assert "Severity: MEDIUM\n" in report, report


class TestANegativeLimitIsRefused:
    @pytest.mark.parametrize("option", ["max_detailed_findings", "top_hotspots_limit"])
    def test_a_negative_value_is_refused(self, option):
        with pytest.raises(ValidationError):
            TextReporterConfigOptions(**{option: -1})

    @pytest.mark.parametrize("option", ["max_detailed_findings", "top_hotspots_limit"])
    def test_zero_and_a_positive_value_are_accepted(self, option):
        assert getattr(TextReporterConfigOptions(**{option: 0}), option) == 0
        assert getattr(TextReporterConfigOptions(**{option: 5}), option) == 5
