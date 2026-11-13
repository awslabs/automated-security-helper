# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening resets the suppressed count of a row whose findings are gone.

``to_flat_vulnerabilities`` sets ``summary_stats.suppressed`` to the sum over the
scanners that have suppressed findings now, and each of those scanners' rows to its
own count. A row of a scanner with none left was never touched: after the SARIF was
narrowed, the summary dropped while that row kept its old count, and the rows no
longer added up to the summary. A row with no suppressed finding now reads zero.

The controls say a row that already reads zero is left as the object it was, that
a row with suppressed findings keeps them, and that a row holding a dict (a shape
only a direct assignment produces) is not replaced.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from tests.unit.models._suppressed_count_helpers import (
    OTHER,
    SCANNER,
    build_model,
    row_total,
    suppressed_result,
)

pytestmark = pytest.mark.unit


def _sarif_of(*results) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=SCANNER, version="1.0.0")),
                results=list(results),
                properties=PropertyBag(),
            )
        ],
    )


def _two_scanners_one_suppressed_finding_each():
    model = build_model(
        sarif_results=[
            suppressed_result(SCANNER, "R1"),
            suppressed_result(OTHER, "R2"),
        ]
    )
    populate_metrics_from_unified_source(model)
    assert model.metadata.summary_stats.suppressed == 2
    assert model.scanner_results[OTHER].suppressed_finding_count == 1
    return model


def test_a_row_whose_findings_left_the_sarif_reads_zero():
    model = _two_scanners_one_suppressed_finding_each()
    model.sarif = _sarif_of(suppressed_result(SCANNER, "R1"))

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 1
    assert model.scanner_results[SCANNER].suppressed_finding_count == 1
    assert model.scanner_results[OTHER].suppressed_finding_count == 0
    assert model.scanner_results[OTHER].severity_counts.suppressed == 0
    assert model.metadata.summary_stats.suppressed == row_total(model)


def test_every_row_reads_zero_when_no_finding_is_suppressed_any_more():
    model = _two_scanners_one_suppressed_finding_each()
    model.sarif = _sarif_of()

    model.to_flat_vulnerabilities()

    assert model.metadata.summary_stats.suppressed == 0
    assert row_total(model) == 0


def test_a_row_that_reads_zero_is_left_as_the_object_it_was():
    model = _two_scanners_one_suppressed_finding_each()
    model.sarif = _sarif_of(suppressed_result(SCANNER, "R1"))
    model.to_flat_vulnerabilities()
    reset = model.scanner_results[OTHER]

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.scanner_results[OTHER] is reset
    assert reset.suppressed_finding_count == 0


def test_a_row_that_reads_zero_has_no_field_set_by_the_flatten():
    """The guard is what leaves a zero row alone: an assignment of zero to it would
    mark ``suppressed_finding_count`` as set, and a dump of the set fields would then
    carry a key the row never had."""
    model = _two_scanners_one_suppressed_finding_each()
    model.sarif = _sarif_of(suppressed_result(SCANNER, "R1"))
    # Item assignment: a row that holds nothing and has had nothing set.
    model.scanner_results[OTHER] = ScannerTargetStatusInfo()
    row = model.scanner_results[OTHER]
    row_fields = set(row.model_fields_set)
    count_fields = set(row.severity_counts.model_fields_set)

    model.to_flat_vulnerabilities()

    assert model.scanner_results[OTHER] is row
    assert row.model_fields_set == row_fields
    assert row.severity_counts.model_fields_set == count_fields
    assert "suppressed_finding_count" not in row.model_fields_set


def test_a_row_with_suppressed_findings_keeps_them():
    model = _two_scanners_one_suppressed_finding_each()
    kept = model.scanner_results[SCANNER]

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER] is kept
    assert kept.suppressed_finding_count == 1
    assert model.scanner_results[OTHER].suppressed_finding_count == 1
    assert model.metadata.summary_stats.suppressed == 2


def test_a_row_held_as_a_dict_is_not_replaced():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    stored = {"status": "PASSED", "suppressed_finding_count": 4}
    # Item assignment: pydantic does not validate a dict the field already holds.
    model.scanner_results[SCANNER] = ScannerTargetStatusInfo()
    model.scanner_results[OTHER] = stored

    model.to_flat_vulnerabilities()

    assert model.scanner_results[OTHER] is stored
    assert stored["suppressed_finding_count"] == 4
