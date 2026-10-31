# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``to_flat_vulnerabilities`` never adds to the suppressed counts.

The unified metrics (``core.unified_metrics``) count every suppressed SARIF
result into ``summary_stats.suppressed`` and the scanner rows at the end of the
scan and in ``ash merge``. The flattening then bumped the same counters once
more per suppressed finding, so the saved results carried each suppressed
finding twice. The flat count now goes only where no count is recorded (see
``test_flat_counts_do_not_replace_the_metrics_counts``), which is idempotent
against the metrics pass and against repeat calls. The results carry the
scanner name the metrics attribute a finding by, so the rows these tests read
are the ones a real metrics pass would have counted into.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit


def _sarif_with_one_suppressed() -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=[
                    Result(
                        ruleId="B101",
                        level="error",
                        message=Message(text="assert used"),
                        properties=PropertyBag(scanner_name="bandit"),
                    ),
                    Result(
                        ruleId="B102",
                        level="warning",
                        message=Message(text="exec used"),
                        properties=PropertyBag(scanner_name="bandit"),
                        suppressions=[
                            Suppression(kind="external", justification="reviewed")
                        ],
                    ),
                ],
                properties=PropertyBag(),
            )
        ],
    )


def test_a_count_the_metrics_already_wrote_is_not_doubled():
    model = AshAggregatedResults(sarif=_sarif_with_one_suppressed())
    # What the unified metrics pass leaves behind before the reporters flatten.
    model.metadata.summary_stats.suppressed = 1
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED, suppressed_finding_count=1
    )

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 1
    row = model.scanner_results["bandit"]
    assert row.suppressed_finding_count == 1, row


def test_a_model_no_metrics_pass_visited_still_gets_its_count():
    model = AshAggregatedResults(sarif=_sarif_with_one_suppressed())
    # A row no metrics pass counted into: it records nothing yet.
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 1
    row = model.scanner_results["bandit"]
    assert row.suppressed_finding_count == 1, row
