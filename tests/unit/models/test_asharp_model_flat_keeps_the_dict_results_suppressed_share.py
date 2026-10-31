# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening keeps the suppressed findings a dict result recorded.

A scanner that returns a dict instead of SARIF has findings the merged SARIF never
holds. The unified metrics count them: a scanner's suppressed count is its
suppressed SARIF results plus the suppressed count its dict result recorded on the
per-target report. ``to_flat_vulnerabilities`` set ``summary_stats.suppressed`` and
the scanner rows from the SARIF results alone, so the first flatten after a metrics
pass lowered what the pass had written: a dict-only scanner with 3 suppressed
findings read 0 in the summary every reporter shows, and a scanner with one
suppressed SARIF result and two suppressed dict findings read 1 in its row. The
saved summary then no longer equalled the sum of the rows.

The controls say a scanner with SARIF alone is still counted from the SARIF alone,
that another scanner's report adds nothing, and that flattening again sets the same
counts.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
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

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "shape-tool"
OTHER = "other-tool"


def _dict_report(suppressed: int, scanner: str = SCANNER) -> dict:
    """The per-target report the processor writes for a graded dict result."""
    counts = {
        "suppressed": suppressed,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    return {
        "scanner_name": scanner,
        "target_type": "source",
        "status": "PASSED",
        "finding_count": suppressed,
        "severity_counts": counts,
        "raw_results": {"severity_counts": counts},
    }


def _suppressed_result(scanner: str, rule: str) -> Result:
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text=f"{rule} found"),
        properties=PropertyBag(scanner_name=scanner),
        suppressions=[Suppression(kind="external", justification="reviewed")],
    )


def _model(
    reports: dict[str, dict] | None = None,
    sarif_results: list[Result] | None = None,
) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if reports:
        model.additional_reports = {
            scanner: {"source": report} for scanner, report in reports.items()
        }
    if sarif_results:
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name=SCANNER, version="1.0.0")),
                    results=sarif_results,
                    properties=PropertyBag(),
                )
            ],
        )
    return model


def _row_total(model: AshAggregatedResults) -> int:
    return sum(row.suppressed_finding_count for row in model.scanner_results.values())


def test_a_dict_only_scanners_suppressed_findings_survive_the_flatten():
    model = _model(reports={SCANNER: _dict_report(3)})
    populate_metrics_from_unified_source(model)
    assert model.metadata.summary_stats.suppressed == 3, "the pass counts the dict"
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 3
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.scanner_results[SCANNER].severity_counts.suppressed == 3
    assert model.metadata.summary_stats.suppressed == _row_total(model)


def test_a_scanner_with_sarif_and_dict_findings_keeps_both_counts():
    model = _model(
        reports={SCANNER: _dict_report(2)},
        sarif_results=[_suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.scanner_results[SCANNER].severity_counts.suppressed == 3
    assert model.metadata.summary_stats.suppressed == 3
    assert model.metadata.summary_stats.suppressed == _row_total(model)


def test_flattening_again_sets_the_same_counts():
    model = _model(
        reports={SCANNER: _dict_report(2)},
        sarif_results=[_suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)
    model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.metadata.summary_stats.suppressed == 3


def test_a_scanner_with_sarif_alone_is_counted_from_the_sarif_alone():
    model = _model(
        sarif_results=[
            _suppressed_result(SCANNER, "R1"),
            _suppressed_result(SCANNER, "R2"),
        ]
    )
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2


def test_another_scanners_report_adds_nothing():
    model = _model(
        reports={OTHER: _dict_report(5, scanner=OTHER)},
        sarif_results=[_suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 1
    assert model.scanner_results[OTHER].suppressed_finding_count == 5
    assert model.metadata.summary_stats.suppressed == 6
