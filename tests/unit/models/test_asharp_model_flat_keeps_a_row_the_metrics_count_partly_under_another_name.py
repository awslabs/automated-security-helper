# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening keeps a row whose suppressed findings are only partly named for it.

``to_flat_vulnerabilities`` sets each scanner row to the suppressed count it takes
from the flattened findings. A flattened finding names its scanner by the result's
``scanner_name``, then by the tool in ``scanner_details``, then by the run's tool
name; the unified metrics name it by the same two properties and then by the
result's tags, and never by the run's tool name.

A scanner whose suppressed results are split between the two readings (one result
carries ``scanner_name``, another only the scanner's tag) is therefore counted in
full by the metrics and in part by the flatten. Setting the row to the flattened
part lowered it, and the saved rows no longer added up to the summary.

A row that exists is now set to the larger of the flattened count and the count the
metrics give it. The controls say a row the flatten counts higher than the metrics
do is not lowered, and that a row the flatten and the metrics count alike is
unchanged.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import PropertyBag
from tests.unit.models._suppressed_count_helpers import (
    SCANNER,
    build_model,
    row_total,
    suppressed_result,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

TAGGED_SCANNER = "bandit"


def _mixed_model() -> AshAggregatedResults:
    """Two suppressed bandit results: one by scanner_name, one only by its tag."""
    named = suppressed_result(TAGGED_SCANNER, "R1")
    tagged = suppressed_result(TAGGED_SCANNER, "R2")
    tagged.properties = PropertyBag(tags=[TAGGED_SCANNER])
    return build_model(sarif_results=[named, tagged])


def test_a_row_the_metrics_count_partly_under_another_name_keeps_its_count():
    model = _mixed_model()
    populate_metrics_from_unified_source(model)
    assert model.scanner_results[TAGGED_SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2

    flat = model.to_flat_vulnerabilities()

    assert {vuln.scanner for vuln in flat} == {TAGGED_SCANNER, SCANNER}, (
        "the flatten names the tagged result for the run's tool"
    )
    row = model.scanner_results[TAGGED_SCANNER]
    assert row.suppressed_finding_count == 2
    assert row.severity_counts.suppressed == 2
    assert model.metadata.summary_stats.suppressed == 2
    assert model.metadata.summary_stats.suppressed == row_total(model)


def test_flattening_again_keeps_the_same_row_count():
    model = _mixed_model()
    populate_metrics_from_unified_source(model)
    model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.scanner_results[TAGGED_SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2


def test_a_row_the_flatten_counts_higher_than_the_metrics_is_not_lowered():
    model = _mixed_model()
    populate_metrics_from_unified_source(model)
    # The run's tool has a row the metrics never filled: the tagged result is
    # the run tool's for the flatten and nobody's for this row in the metrics.
    model.scanner_results[SCANNER] = ScannerTargetStatusInfo()

    model.to_flat_vulnerabilities()

    assert model.scanner_results[SCANNER].suppressed_finding_count == 1
    assert model.scanner_results[SCANNER].severity_counts.suppressed == 1
    assert model.scanner_results[TAGGED_SCANNER].suppressed_finding_count == 2


def test_a_row_both_readings_count_alike_is_unchanged():
    model = build_model(
        sarif_results=[
            suppressed_result(TAGGED_SCANNER, "R1"),
            suppressed_result(TAGGED_SCANNER, "R2"),
        ]
    )
    populate_metrics_from_unified_source(model)

    model.to_flat_vulnerabilities()

    row = model.scanner_results[TAGGED_SCANNER]
    assert row.suppressed_finding_count == 2
    assert row.severity_counts.suppressed == 2
    assert model.metadata.summary_stats.suppressed == 2
