# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reloading saved scans must not invent observation timestamps."""

import csv
import json
from datetime import datetime, timezone
from io import StringIO

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.snapshot.support.fixture_model import pin_clock


def test_separate_saved_scan_loads_keep_per_finding_times(
    monkeypatch, test_plugin_context
):
    clock = pin_clock(monkeypatch)
    results = []
    for scanner, project, observed in [
        ("bandit", "backend", "2025-01-02T10:00:00+07:00"),
        ("npm-audit", "frontend", "2025-01-03T00:00:00Z"),
        ("other", "unknown", None),
    ]:
        results.append(
            {
                "ruleId": scanner,
                "message": {"text": "finding"},
                "properties": {
                    "scanner_name": scanner,
                    "workspace_project": project,
                    "scanner_details": {"tool_invocation": {"end_time": observed}},
                },
            }
        )
    saved = AshAggregatedResults(
        sarif=SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {"tool": {"driver": {"name": "aggregate"}}, "results": results}
                ],
            }
        )
    ).model_dump_json()
    outputs = []
    for year in (2026, 2030):
        clock.set(datetime(year, 1, 1, tzinfo=timezone.utc))
        model = AshAggregatedResults.model_validate_json(saved)
        outputs.append(
            (
                [item.detected_at for item in model.to_flat_vulnerabilities()],
                json.loads(FlatJSONReporter(context=test_plugin_context).report(model))[
                    "findings"
                ],
                list(
                    csv.DictReader(
                        StringIO(CsvReporter(context=test_plugin_context).report(model))
                    )
                ),
            )
        )
    assert outputs[0] == outputs[1]
    assert outputs[0][0] == [
        "2025-01-02T03:00:00+00:00",
        "2025-01-03T00:00:00+00:00",
        None,
    ]
    assert [row["detected_at"] for row in outputs[0][2]] == [
        "2025-01-02T03:00:00+00:00",
        "2025-01-03T00:00:00+00:00",
        "",
    ]
    assert "detected_at" not in outputs[0][1][2]
