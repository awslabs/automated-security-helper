# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flattened findings are remembered, and forgotten when code that edits them says so.

``to_flat_vulnerabilities`` serves its memoized list for as long as the sarif and
the additional_reports it was made from are the same objects holding the same
number of results and entries, so a replaced sarif and an appended result are
picked up. An edit in place that keeps both (a result replaced by index, a
suppression set on one, masking) is not seen. Code that makes one calls
``_invalidate_flat_cache()``, and ``save_model`` does after masking.
"""

from __future__ import annotations

import pytest

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


def _result(rule: str, suppressed: bool = False) -> Result:
    extra = (
        {"suppressions": [Suppression(kind="external", justification="reviewed")]}
        if suppressed
        else {}
    )
    return Result(
        ruleId=rule, level="error", message=Message(text=f"{rule} found"), **extra
    )


def _model(*results: Result) -> AshAggregatedResults:
    report = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=list(results),
                properties=PropertyBag(),
            )
        ],
    )
    return AshAggregatedResults(sarif=report)


def test_a_result_replaced_by_index_is_flattened_again_once_the_cache_is_dropped():
    model = _model(_result("B101"))
    first = model.to_flat_vulnerabilities()
    assert [vuln.is_suppressed for vuln in first] == [False]

    # The same objects holding the same counts.
    model.sarif.runs[0].results[0] = _result("B101", suppressed=True)
    model._invalidate_flat_cache()

    again = model.to_flat_vulnerabilities()
    assert again is not first
    assert [vuln.is_suppressed for vuln in again] == [True]


def test_dropping_the_cache_changes_no_finding_that_did_not_change():
    model = _model(_result("B101"), _result("B102"))
    first = model.to_flat_vulnerabilities()

    model._invalidate_flat_cache()

    again = model.to_flat_vulnerabilities()
    assert again is not first
    assert [vuln.rule_id for vuln in again] == [vuln.rule_id for vuln in first]
    assert model.metadata.summary_stats.suppressed == 0


def test_the_cache_is_served_again_after_it_was_rebuilt():
    model = _model(_result("B101"))
    model._invalidate_flat_cache()

    rebuilt = model.to_flat_vulnerabilities()

    assert model.to_flat_vulnerabilities() is rebuilt


def test_save_model_drops_the_cache_after_masking(tmp_path):
    model = _model(_result("B101"))
    model.to_flat_vulnerabilities()
    assert model._flat_cache is not None

    model.save_model(tmp_path)

    assert model._flat_cache is None
    assert model._flat_cache_source is None
    assert (tmp_path / "ash_aggregated_results.json").is_file()
