# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flattening keeps a row whose suppressed findings the metrics count under a tag.

``to_flat_vulnerabilities`` resets the suppressed count of a scanner row that has no
entry in the counts it takes from the flattened findings. A flattened finding names
its scanner by the result's ``scanner_name``, then by the tool in the result's
``scanner_details``, then by the run's tool name. The unified metrics name it by the
same two properties and then by the result's tags, and never by the run's tool name.
A result with no scanner name and a scanner tag is therefore one scanner's for the
metrics (``bandit``, from the tag) and another's for the flatten (the run's tool),
so the row the metrics filled had no entry and was reset to zero while the summary
kept the count: the saved rows no longer added up to the summary, and a correct
count was thrown away.

A row missing from the flattened counts is now set to the count the metrics give it,
which is zero only when they find no suppressed finding for it either.

The controls say a row with a stale count and no finding under any name is still
reset, and that a finding appended from a list-form additional report is never
counted as suppressed, so taking the counts before it appends loses nothing.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
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

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

RUN_TOOL = "shape-tool"
TAGGED_SCANNER = "bandit"


def _suppressed(rule: str, properties: PropertyBag) -> Result:
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text=f"{rule} found"),
        properties=properties,
        suppressions=[Suppression(kind="external", justification="reviewed")],
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=RUN_TOOL, version="1.0.0")),
                results=list(results),
                properties=PropertyBag(),
            )
        ],
    )
    return model


def _tagged_model() -> AshAggregatedResults:
    """Two suppressed results with no scanner_name and the scanner's tag."""
    tagged = PropertyBag(tags=[TAGGED_SCANNER])
    return _model(_suppressed("R1", tagged), _suppressed("R2", tagged.model_copy()))


def _row_total(model: AshAggregatedResults) -> int:
    return sum(row.suppressed_finding_count for row in model.scanner_results.values())


def test_a_row_the_metrics_count_under_a_tag_keeps_its_count():
    model = _tagged_model()
    populate_metrics_from_unified_source(model)
    assert model.scanner_results[TAGGED_SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2

    flat = model.to_flat_vulnerabilities()

    assert {vuln.scanner for vuln in flat} == {RUN_TOOL}, "the flatten names the run"
    row = model.scanner_results[TAGGED_SCANNER]
    assert row.suppressed_finding_count == 2
    assert row.severity_counts.suppressed == 2
    assert model.metadata.summary_stats.suppressed == 2
    assert model.metadata.summary_stats.suppressed == _row_total(model)


def test_flattening_again_keeps_the_same_row_count():
    model = _tagged_model()
    populate_metrics_from_unified_source(model)
    model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()
    model.to_flat_vulnerabilities()

    assert model.scanner_results[TAGGED_SCANNER].suppressed_finding_count == 2
    assert model.metadata.summary_stats.suppressed == 2


def test_a_row_with_a_stale_count_and_no_finding_under_any_name_is_still_reset():
    model = _tagged_model()
    populate_metrics_from_unified_source(model)
    model.scanner_results["ghost-tool"] = ScannerTargetStatusInfo(
        suppressed_finding_count=4,
        severity_counts=ScannerSeverityCount(suppressed=4),
    )

    model.to_flat_vulnerabilities()

    ghost = model.scanner_results["ghost-tool"]
    assert ghost.suppressed_finding_count == 0
    assert ghost.severity_counts.suppressed == 0


def test_a_list_form_additional_report_finding_is_never_counted_as_suppressed():
    model = _model(_suppressed("R1", PropertyBag(scanner_name=RUN_TOOL)))
    populate_metrics_from_unified_source(model)
    model.additional_reports["list-tool"] = [
        {"id": "x1", "title": "T", "severity": "high", "suppressed": True}
    ]

    flat = model.to_flat_vulnerabilities()

    appended = [vuln for vuln in flat if vuln.scanner == "list-tool"]
    assert len(appended) == 1
    assert appended[0].is_suppressed is False
    assert model.metadata.summary_stats.suppressed == 1
    assert model.scanner_results[RUN_TOOL].suppressed_finding_count == 1
