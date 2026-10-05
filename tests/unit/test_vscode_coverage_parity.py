# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's coverage verdict on the VS Code extension's fixtures matches what they record.

Why this file exists
--------------------
The VS Code extension reports a scan as incomplete from ``coverage_complete``. That value is
not a field of ``ash_aggregated_results.json``: ASH computes it on demand, in
``scan_tracking.assess_coverage`` and ``coverage_has_gap``, and the extension cannot import
Python. So editors/vscode/src/coverage.ts asks the same questions of the results file in
TypeScript, and that makes it a second reader of one rule, which can drift.

editors/vscode/test/fixtures/coverage-cases/cases.json is what holds the two together. Each case is
a results file captured from a real ``ashx scan`` plus a few edits, and the verdict expected of
it. The extension's jest suite asserts coverage.ts reaches each verdict; this file asserts ASH
does. A change to ASH's coverage rules that moves a verdict fails here, and the fix is to
update cases.json and coverage.ts together. A change to coverage.ts alone fails jest.

What this does not check
------------------------
That the fixtures still look like current output. They are captured, so a reshaped results
model would leave them valid but old; ``AshAggregatedResults(**doc)`` below at least fails on
a fixture the current model rejects.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.resource_management.scan_tracking import (
    assess_coverage,
    coverage_has_gap,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

FIXTURES = (
    Path(__file__).resolve().parents[2] / "editors" / "vscode" / "test" / "fixtures"
)
CASES: List[Dict[str, Any]] = json.loads(
    (FIXTURES / "coverage-cases" / "cases.json").read_text(encoding="utf-8")
)["cases"]


def _apply(document: Dict[str, Any], edits: List[List[Any]]) -> Dict[str, Any]:
    """Return a copy of *document* with each ``[path, value]`` edit applied."""
    edited = copy.deepcopy(document)
    for path, value in edits:
        target: Any = edited
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = copy.deepcopy(value)
    return edited


def test_the_case_list_is_not_empty() -> None:
    # A parametrized test over an empty list collects nothing and passes.
    assert len(CASES) >= 10


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_ash_reaches_the_recorded_verdict(case: Dict[str, Any]) -> None:
    raw = json.loads((FIXTURES / case["base"]).read_text(encoding="utf-8"))
    results = AshAggregatedResults(**_apply(raw, case["set"]))

    _, coverage = assess_coverage(results)

    observed = {
        "coverage_complete": not coverage_has_gap(coverage),
        "incomplete_scanners": [
            row["scanner"] for row in coverage["incomplete_scanners"]
        ],
        "no_scanner_ran": coverage["no_scanner_ran"],
        "incomplete_converters": [
            row["converter"] for row in coverage["incomplete_converters"]
        ],
        "unevaluated_rules": coverage["unevaluated_rules"],
        "stale_content_databases": [
            row["name"] for row in coverage["stale_content_databases"]
        ],
    }
    assert observed == case["expect"]
