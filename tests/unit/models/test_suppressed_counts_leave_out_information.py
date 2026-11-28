# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppressed result that states no finding is in no suppressed total.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9), so there is nothing for a suppression to hide:
the reports list the row under Information, and no total counts it, the suppressed
total included. Flattening the results writes each scanner's suppressed count from
the flat rows, and wrote the count of this row too.

Two passes write the suppressed counts of a scanner that has a row: the metrics
pass, which counts the SARIF results, and the flattening, which counts the flat rows
and keeps the larger of its own count and the metrics'. They agree on the count only
when both leave a result that states no finding out, so the tests below run them in
both orders.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    metrics_consistency_discrepancies,
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

NOTE = "ASH-container-image-not-scanned"


def _suppressed(rule_id: str, **extra) -> dict:
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"result of {rule_id}"},
        "properties": {"scanner_name": "bandit"},
        "suppressions": [{"kind": "inSource", "justification": "accepted"}],
        **extra,
    }


def _model() -> AshAggregatedResults:
    """Two results of one scanner, both suppressed; the second states no finding."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        _suppressed("B602"),
                        _suppressed(NOTE, kind="informational", level="none"),
                    ],
                }
            ],
        }
    )
    return model


def test_the_suppressed_count_of_a_scanner_leaves_the_note_out():
    model = _model()
    flat = model.to_flat_vulnerabilities()

    assert [row.is_suppressed for row in flat] == [True, True]
    assert model._suppressed_by_scanner(flat) == {"bandit": 1}


def test_the_suppressed_total_of_the_summary_leaves_the_note_out():
    model = _model()

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 1


# ---------------------------------------------------------------------------
# A scanner with a row: the two writers of its suppressed count
# ---------------------------------------------------------------------------


def _model_with_a_scanner_row() -> AshAggregatedResults:
    """The same two suppressed results, a third that states a finding despite its
    kind (informational at level warning), and a row for the scanner that reported
    them."""
    model = _model()
    model.sarif.runs[0].results.append(
        type(model.sarif.runs[0].results[0]).model_validate(
            _suppressed("R-PAIR", kind="informational", level="warning")
        )
    )
    model.ash_config = AshConfig.model_validate(
        {
            "project_name": "non-finding-kinds",
            "global_settings": {"severity_threshold": "MEDIUM"},
        }
    )
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )
    return model


def _assert_the_suppressed_counts_agree(model: AshAggregatedResults) -> None:
    """Every place that reads the scanner's suppressed count reads one, and not two.

    The two suppressed results that state a finding count; the note does not.
    """
    row = model.scanner_results["bandit"]
    assert model.metadata.summary_stats.suppressed == 2
    assert (row.suppressed_finding_count, row.severity_counts.suppressed) == (2, 2)
    assert metrics_consistency_discrepancies(model) == []
    bandit = next(
        metrics
        for metrics in get_unified_scanner_metrics(model)
        if metrics.scanner_name == "bandit"
    )
    assert bandit.suppressed == 2


def test_the_suppressed_counts_agree_when_the_metrics_pass_runs_first():
    model = _model_with_a_scanner_row()

    populate_metrics_from_unified_source(aggregated_results=model)
    model.to_flat_vulnerabilities()

    _assert_the_suppressed_counts_agree(model)


def test_the_suppressed_counts_agree_when_the_flatten_runs_first():
    model = _model_with_a_scanner_row()

    model.to_flat_vulnerabilities()
    populate_metrics_from_unified_source(aggregated_results=model)

    _assert_the_suppressed_counts_agree(model)


def test_the_scan_summary_counts_the_suppressed_results_the_scanner_row_counts():
    """Guard: the report's scan summary, read from the scanner row, counts the two
    suppressed results that state a finding and leaves the note out, as the row
    does."""
    model = _model_with_a_scanner_row()
    populate_metrics_from_unified_source(aggregated_results=model)
    model.to_flat_vulnerabilities()

    summary = ReportContentEmitter(model, human_presentation=True).get_scan_summary()
    row = model.scanner_results["bandit"]

    assert row.suppressed_finding_count == 2
    assert summary["suppressed"] == row.suppressed_finding_count
