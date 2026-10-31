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

from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from tests.unit.models._suppressed_count_helpers import (
    OTHER,
    SCANNER,
    build_model,
    dict_report,
    row_total,
    suppressed_result,
)

pytestmark = pytest.mark.unit


def test_a_dict_only_scanners_suppressed_findings_survive_the_flatten():
    model = build_model(reports={SCANNER: dict_report(3)})
    populate_metrics_from_unified_source(model)
    assert model.metadata.summary_stats.suppressed == 3, "the pass counts the dict"
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 3
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.scanner_results[SCANNER].severity_counts.suppressed == 3
    assert model.metadata.summary_stats.suppressed == row_total(model)


def test_a_scanner_with_sarif_and_dict_findings_keeps_both_counts():
    model = build_model(
        reports={SCANNER: dict_report(2)},
        sarif_results=[suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)
    assert model.scanner_results[SCANNER].suppressed_finding_count == 3

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.scanner_results[SCANNER].severity_counts.suppressed == 3
    assert model.metadata.summary_stats.suppressed == 3
    assert model.metadata.summary_stats.suppressed == row_total(model)


def test_flattening_again_sets_the_same_counts():
    model = build_model(
        reports={SCANNER: dict_report(2)},
        sarif_results=[suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)
    model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 3
    assert model.metadata.summary_stats.suppressed == 3


def test_a_scanner_with_sarif_alone_is_counted_from_the_sarif_alone():
    model = build_model(
        sarif_results=[
            suppressed_result(SCANNER, "R1"),
            suppressed_result(SCANNER, "R2"),
        ]
    )
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2


def test_another_scanners_report_adds_nothing():
    model = build_model(
        reports={OTHER: dict_report(5, scanner=OTHER)},
        sarif_results=[suppressed_result(SCANNER, "R1")],
    )
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 1
    assert model.scanner_results[OTHER].suppressed_finding_count == 5
    assert model.metadata.summary_stats.suppressed == 6
