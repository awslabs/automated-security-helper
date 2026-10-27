# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detailed findings list is ordered by severity, highest first.

``ReportContentEmitter.get_detailed_findings`` feeds the detailed findings of the
Markdown and Bedrock reports. Its order is the reader's triage order, so it puts
the most severe finding first whatever order the scanners reported them in, and
breaks ties by location. The LOW finding here is reported first and has the
earlier file path, so neither the input order nor a location-only order can put
HIGH first.
"""

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import Result


def _result(rule_id, severity, path):
    return Result.model_validate(
        {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": f"{severity} fixture"},
            "properties": {"scanner_name": "bandit", "issue_severity": severity},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
    )


def test_detailed_findings_put_the_highest_severity_first():
    model = AshAggregatedResults(ash_config=get_default_config())
    model.ash_config.global_settings.severity_threshold = "LOW"
    model.sarif.runs[0].results = [
        _result("LOW-RULE", "LOW", "a_first.py"),
        _result("HIGH-RULE", "HIGH", "b_second.py"),
    ]
    model._flat_cache = None

    details = ReportContentEmitter(model).get_detailed_findings()

    # The control: both are actionable at a LOW threshold.
    assert len(details) == 2, details
    assert [finding["severity"] for finding in details] == ["HIGH", "LOW"], details
    assert [finding["rule_id"] for finding in details] == ["HIGH-RULE", "LOW-RULE"]
