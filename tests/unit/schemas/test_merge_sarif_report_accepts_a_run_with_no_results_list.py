# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run with no results list merges as a run with no results.

Why this file exists
--------------------
SARIF lets a run omit its ``results`` list, and the error report a scanner
leaves when its tool was killed does so. ``SarifReport.merge_sarif_report``
looped over that list without a guard, so merging such a report into the
aggregated SARIF raised ``TypeError: 'NoneType' object is not iterable``. The
scan phase caught it and recorded a failure with no target type, and the killed
target's own report never reached the results. The merge now treats a missing
list as an empty one, in both places it reads one: the run's results and, for a
tool already listed as an extension, the driver's rules.
"""

from __future__ import annotations

import pytest

from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport

pytestmark = pytest.mark.unit

FINDING = {
    "ruleId": "RULE-1",
    "message": {"text": "an earlier finding"},
    "level": "warning",
}


def _run(driver: str, results, invocations) -> Run:
    return Run(
        tool={"driver": {"name": driver}}, results=results, invocations=invocations
    )


@pytest.mark.parametrize(
    "later_driver",
    [
        pytest.param("recorder", id="same-tool-already-an-extension"),
        pytest.param("another", id="another-tool"),
    ],
)
def test_a_run_with_no_results_list_adds_nothing_and_keeps_the_earlier_results(
    later_driver,
):
    aggregated = SarifReport(runs=[_run("aggregate", [], [])])
    earlier = SarifReport(
        runs=[_run("recorder", [FINDING], [{"executionSuccessful": True}])]
    )
    aggregated.merge_sarif_report(earlier)
    assert [r.ruleId for r in aggregated.runs[0].results] == ["RULE-1"]

    later = SarifReport(
        runs=[_run(later_driver, None, [{"executionSuccessful": False}])]
    )
    assert later.runs[0].results is None, "the report must carry no results list"

    aggregated.merge_sarif_report(later)

    assert len(aggregated.runs) == 1
    assert [r.ruleId for r in aggregated.runs[0].results] == ["RULE-1"]
    assert len(aggregated.runs[0].invocations) == 2
