# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression set or cleared on a result in place reaches the flat findings.

``to_flat_vulnerabilities`` serves its memoized list while the sarif, the
additional_reports and their counts stand. Applying a suppression edits a
result in place and keeps all of them, so the cache could not tell, and the
docstring left every editor to remember a private method. Nothing outside
``save_model`` called it. The cache key now includes how many suppression
records the results carry.
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


def _model(*rules: str) -> AshAggregatedResults:
    results = [
        Result(ruleId=rule, level="error", message=Message(text=f"{rule} found"))
        for rule in rules
    ]
    report = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=results,
                properties=PropertyBag(),
            )
        ],
    )
    return AshAggregatedResults(sarif=report)


def _suppression() -> Suppression:
    return Suppression(kind="external", justification="reviewed")


def test_a_suppression_set_on_a_result_is_flattened_again():
    model = _model("B101", "B102")
    first = model.to_flat_vulnerabilities()
    assert [vuln.is_suppressed for vuln in first] == [False, False]

    model.sarif.runs[0].results[0].suppressions = [_suppression()]

    again = model.to_flat_vulnerabilities()
    assert [vuln.is_suppressed for vuln in again] == [True, False]


def test_a_suppression_cleared_from_a_result_is_flattened_again():
    model = _model("B101")
    model.sarif.runs[0].results[0].suppressions = [_suppression()]
    first = model.to_flat_vulnerabilities()
    assert [vuln.is_suppressed for vuln in first] == [True]

    model.sarif.runs[0].results[0].suppressions = None

    again = model.to_flat_vulnerabilities()
    assert [vuln.is_suppressed for vuln in again] == [False]


def test_the_cache_is_still_served_while_nothing_changed():
    """The control: the fingerprint does not defeat the memoization."""
    model = _model("B101")
    model.sarif.runs[0].results[0].suppressions = [_suppression()]
    first = model.to_flat_vulnerabilities()

    assert model.to_flat_vulnerabilities() is first
