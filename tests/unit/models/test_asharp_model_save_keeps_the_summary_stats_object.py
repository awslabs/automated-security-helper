# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A save leaves the summary_stats object the model held, with the final counts.

``save_model`` populates the final metrics on every save. The helper that does it
builds a new ``SummaryStats`` and assigns it to the metadata, so a reference taken
before the save (a reporter's, a caller's) kept reading the counts from before it.
The values are now copied into the object the model held and the metadata keeps
it, so the counts the file carries and the counts a holder reads are the same.

The controls say the file carries the counts, that a second save keeps the same
object and the same counts, and that a model whose metrics pass fails is saved
with the object untouched.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
)
from tests.unit.models._suppressed_count_helpers import (
    SCANNER,
    build_model,
    suppressed_result,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _open_result(rule: str) -> Result:
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text=f"{rule} found"),
        properties=PropertyBag(scanner_name=SCANNER),
    )


def _model_with_two_findings() -> AshAggregatedResults:
    model = build_model(
        sarif_results=[_open_result("R1"), suppressed_result(SCANNER, "R2")]
    )
    model.ash_config = get_default_config()
    return model


def test_a_save_keeps_the_object_and_fills_it_with_the_final_counts(tmp_path):
    model = _model_with_two_findings()
    held = model.metadata.summary_stats
    assert held.critical == 0, "the model starts with an empty summary"

    model.save_model(tmp_path)

    assert model.metadata.summary_stats is held
    assert held.critical == 1
    assert held.suppressed == 1


def test_the_file_carries_the_counts_a_holder_reads(tmp_path):
    model = _model_with_two_findings()
    held = model.metadata.summary_stats

    model.save_model(tmp_path)

    saved = json.loads((tmp_path / "ash_aggregated_results.json").read_text("utf-8"))
    counts = saved["metadata"]["summary_stats"]["severity_counts"]
    assert counts["critical"] == held.critical == 1
    assert counts["suppressed"] == held.suppressed == 1


def test_a_second_save_keeps_the_same_object_and_the_same_counts(tmp_path):
    model = _model_with_two_findings()
    model.save_model(tmp_path)
    held = model.metadata.summary_stats
    first = held.model_dump()

    model.save_model(tmp_path)

    assert model.metadata.summary_stats is held
    assert held.model_dump() == first


def test_a_failed_metrics_pass_leaves_the_object_untouched(tmp_path, monkeypatch):
    model = _model_with_two_findings()
    held = model.metadata.summary_stats

    def refuse(_results):
        raise RuntimeError("could not compute the metrics")

    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.get_unified_scanner_metrics",
        refuse,
    )

    model.save_model(tmp_path)

    assert model.metadata.summary_stats is held
    assert held.critical == 0
    assert (tmp_path / "ash_aggregated_results.json").is_file()
