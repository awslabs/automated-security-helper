# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``save_model`` fills ``summary_stats`` whatever ``scanner_results`` holds.

The scan phase writes the results file (the scan-complete marker) through
``save_model``, which populated the summary only when ``scanner_results`` was
empty. A skipped, missing, excluded or errored scanner has a row before the
metrics rebuild, so any such scanner left the file with all-zero
``summary_stats`` while its SARIF held findings, and ``get_scan_progress``
reported that as a completed scan's summary.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit


def _sarif_with_two_findings() -> SarifReport:
    # Each result names its scanner in its properties, as ASH's SARIF writers
    # do: the unified metrics attribute a finding to a scanner by that
    # property (or by scanner_details / tags), not by the run's tool name.
    def _result(rule_id: str, text: str) -> Result:
        return Result(
            ruleId=rule_id,
            level="error",
            message=Message(text=text),
            properties=PropertyBag(scanner_name="bandit"),
        )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=[_result("B101", "one"), _result("B102", "two")],
                properties=PropertyBag(),
            )
        ],
    )


def test_a_scanner_row_does_not_leave_the_summary_at_zero(tmp_path):
    model = AshAggregatedResults(sarif=_sarif_with_two_findings())
    # An excluded scanner has a row before the rebuild.
    model.scanner_results["checkov"] = ScannerStatusInfo(excluded=True)

    model.save_model(tmp_path)

    saved = json.loads(
        (tmp_path / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert saved["metadata"]["summary_stats"]["total"] == 2, saved["metadata"][
        "summary_stats"
    ]
