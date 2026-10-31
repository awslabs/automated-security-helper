# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The metrics pass updates the summary_stats object the model holds.

``populate_metrics_from_unified_source`` (the pass before the report phase, and the
one ``ash merge`` runs) built a new ``SummaryStats`` and assigned it to the metadata,
so a reporter or a caller that held ``summary_stats`` across the pass kept reading the
counts from before it. ``save_model`` worked around that with a second field list that
copied every declared field, and the object's set fields became all of them, whatever
the helper had set. The helper now gives the object the metadata holds the fields that
were set on the new one, and its extras, and the copy in ``save_model`` is gone.

The controls say the dump of the set fields carries the keys it carried when the
object was replaced, that only what was set on the source reaches the target, and that
two models never share a summary object.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.unified_metrics import (
    _copy_set_fields,
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    SummaryStats,
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

SCANNER = "shape-tool"
SEVERITY_KEYS = {"suppressed", "critical", "high", "medium", "low", "info"}


def _result(rule: str, suppressed: bool = False) -> Result:
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text=f"{rule} found"),
        properties=PropertyBag(scanner_name=SCANNER),
        suppressions=(
            [Suppression(kind="external", justification="reviewed")]
            if suppressed
            else None
        ),
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=SCANNER, version="1.0.0")),
                results=list(results),
                properties=PropertyBag(),
            )
        ],
    )
    return model


def test_the_pass_keeps_the_object_a_holder_took_and_fills_it():
    model = _model(_result("R1"), _result("R2", suppressed=True))
    held = model.metadata.summary_stats
    assert held.critical == 0, "the model starts with an empty summary"

    populate_metrics_from_unified_source(model)

    assert model.metadata.summary_stats is held
    assert held.critical == 1
    assert held.suppressed == 1
    assert held.total == 1


def test_a_second_pass_after_a_new_finding_reaches_the_same_holder():
    model = _model(_result("R1"))
    held = model.metadata.summary_stats
    populate_metrics_from_unified_source(model)
    assert held.critical == 1

    model.sarif.runs[0].results.append(_result("R2"))
    populate_metrics_from_unified_source(model)

    assert model.metadata.summary_stats is held
    assert held.critical == 2


def test_the_dump_of_the_set_fields_carries_every_declared_key_after_the_pass():
    model = _model(_result("R1"))
    populate_metrics_from_unified_source(model)

    dumped = model.metadata.summary_stats.model_dump(exclude_unset=True)

    assert set(dumped) == set(SummaryStats.model_fields)
    assert set(dumped["severity_counts"]) == SEVERITY_KEYS


def test_only_what_was_set_on_the_source_reaches_the_target():
    target = SummaryStats()

    _copy_set_fields(target, SummaryStats(suppressed=3))

    dumped = target.model_dump(exclude_unset=True)
    assert set(dumped) == {"severity_counts"}
    assert set(dumped["severity_counts"]) == {"suppressed"}
    assert target.suppressed == 3


def test_the_off_host_payload_carries_the_severity_counts_after_the_pass():
    model = _model(_result("R1"), _result("R2", suppressed=True))
    held = model.metadata.summary_stats
    assert "severity_counts" not in held.model_fields_set

    populate_metrics_from_unified_source(model)

    sent = model.to_simple_dict()["metadata"]["summary_stats"]
    assert sent["severity_counts"]["critical"] == 1
    assert sent["severity_counts"]["suppressed"] == 1
    assert model.metadata.summary_stats is held


def test_the_counts_object_the_target_holds_is_kept_when_it_is_marked_set():
    target = SummaryStats()
    counts = target.severity_counts

    _copy_set_fields(target, SummaryStats(critical=2))

    assert target.severity_counts is counts
    assert "severity_counts" in target.model_fields_set
    assert counts.critical == 2


def test_an_extra_field_of_the_source_reaches_the_target():
    target = SummaryStats()

    _copy_set_fields(target, SummaryStats(suppressed=1, custom_note="kept"))

    assert target.custom_note == "kept"


def test_two_models_never_share_a_summary_object():
    first = _model(_result("R1"))
    second = _model(_result("R2"))
    assert first.metadata.summary_stats is not second.metadata.summary_stats

    populate_metrics_from_unified_source(first)

    assert first.metadata.summary_stats.critical == 1
    assert second.metadata.summary_stats.critical == 0
