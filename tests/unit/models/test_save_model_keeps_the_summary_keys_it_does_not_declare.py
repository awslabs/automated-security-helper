# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``save_model`` rebuilds the summary and keeps the keys it carries beyond its fields.

``summary_stats`` allows extra keys. The rebuild before the file is written
builds a new ``SummaryStats`` from the unified metrics, which has only the
declared fields. Its values are copied into the summary object the model held,
so every extra key that object carries stays in the saved file, and the counts
are still rebuilt from the SARIF the model holds now.
"""

from __future__ import annotations

import json

import pytest

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
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit


def _sarif_with_two_findings() -> SarifReport:
    def _result(rule_id: str) -> Result:
        return Result(
            ruleId=rule_id,
            level="error",
            message=Message(text=rule_id),
            properties=PropertyBag(scanner_name="bandit"),
        )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=[_result("B101"), _result("B102")],
                properties=PropertyBag(),
            )
        ],
    )


def _saved_summary(tmp_path) -> dict:
    return json.loads(
        (tmp_path / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )["metadata"]["summary_stats"]


def test_an_extra_key_of_the_summary_survives_the_save(tmp_path):
    model = AshAggregatedResults(sarif=_sarif_with_two_findings())
    model.metadata.summary_stats = SummaryStats(shard_note="two of three shards")

    model.save_model(tmp_path)

    summary = _saved_summary(tmp_path)
    assert summary["shard_note"] == "two of three shards", summary


def test_the_counts_are_still_rebuilt_from_the_sarif_beside_the_extra_key(tmp_path):
    """The control: keeping the extras does not keep a stale count."""
    model = AshAggregatedResults(sarif=_sarif_with_two_findings())
    model.metadata.summary_stats = SummaryStats(shard_note="kept", total=0)

    model.save_model(tmp_path)

    summary = _saved_summary(tmp_path)
    assert summary["total"] == 2, summary
    assert summary["shard_note"] == "kept", summary


def test_a_summary_with_no_extra_key_is_saved_as_before(tmp_path):
    model = AshAggregatedResults(sarif=_sarif_with_two_findings())

    model.save_model(tmp_path)

    summary = _saved_summary(tmp_path)
    assert summary["total"] == 2, summary
    assert "shard_note" not in summary, summary
