# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A human report's emitter reads copies of the flattened findings.

AshAggregatedResults.to_flat_vulnerabilities memoizes its rows, and every
reporter in a run builds a ReportContentEmitter from the same model. The human
reporters' emitters hand out copies of the rows, so a report that writes one
(sorting a field, filling one in for its own layout) never changes what a later
report, or the model's cache, holds.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit


def _model():
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
    model._flat_cache = None
    return model


def test_a_row_written_in_one_human_report_is_not_read_by_the_next():
    model = _model()
    first = ReportContentEmitter(model, human_presentation=True)
    severity = first.flat_vulns[0].severity
    # The control: the row has a severity other than the one written below.
    assert severity != "INFO", severity

    first.flat_vulns[0].severity = "INFO"
    second = ReportContentEmitter(model, human_presentation=True)

    assert second.flat_vulns[0].severity == severity
    assert model.to_flat_vulnerabilities()[0].severity == severity
