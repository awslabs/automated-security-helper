# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rule's ``security-severity`` is usable, and lands in the gate's bucket.

GitHub reads ``security-severity`` as a value greater than 0.0 up to 10.0 and
regards 0.0, or anything outside that range, as no security severity at all. A
scanner's rule can carry 0 (an advisory with no CVSS score), a non-numeric
string, or a score out of range; the reporter passed such a value through, so
the rule's alerts fell back to the SARIF level on GitHub where ASH graded them
CRITICAL.

A usable score is kept only when it lands in the same GitHub bucket as the
gate's grade of the rule's most severe emitted result: the scan fails a finding
at the gate's severity, every other report shows that severity, and a rule the
gate graded CRITICAL showing as Low on GitHub made one finding read two ways.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
    _usable_security_severity,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


def _rule_score(reporter, score, level=Level.error, issue_severity=None) -> str:
    """The emitted security-severity of rule R, whose scanner declared *score*
    and whose one result is at *level*, optionally with an ``issue_severity``."""
    rule = ReportingDescriptor(
        id="R", properties=PropertyBag(tags=[], **{"security-severity": score})
    )
    result_props = (
        PropertyBag(tags=[], issue_severity=issue_severity) if issue_severity else None
    )
    run = Run(
        tool=Tool(driver=ToolComponent(name="ASH", rules=[rule])),
        results=[
            Result(
                ruleId="R",
                level=level,
                message=Message(text="finding"),
                properties=result_props,
            )
        ],
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    doc = json.loads(reporter.report(model))
    (emitted,) = doc["runs"][0]["tool"]["driver"]["rules"]
    return emitted["properties"]["security-severity"]


class TestUnusableScoresFallToTheGate:
    @pytest.mark.parametrize("score", ["0", "0.0", 0, "abc", "", "11", "-1"])
    def test_an_unusable_scanner_score_gives_the_gates_score(self, reporter, score):
        assert _rule_score(reporter, score) == "9.5"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("9.8", "9.8"),
            (7.5, "7.5"),
            ("10.0", "10.0"),
            ("0.1", "0.1"),
            ("0", None),
            ("0.0", None),
            ("10.1", None),
            ("-3", None),
            ("high", None),
            ("", None),
            (None, None),
        ],
    )
    def test_usable_security_severity(self, value, expected):
        assert _usable_security_severity(value) == expected


class TestTheScannerScoreMustAgreeWithTheGatesBucket:
    def test_a_low_scanner_score_on_a_critical_result_gives_the_critical_score(
        self, reporter
    ):
        assert _rule_score(reporter, "3.1") == "9.5"

    def test_a_scanner_score_in_the_gates_bucket_is_kept(self, reporter):
        assert (
            _rule_score(reporter, "7.5", level=Level.warning, issue_severity="HIGH")
            == "7.5"
        )

    def test_a_scanner_score_in_the_critical_bucket_is_kept_as_is(self, reporter):
        assert _rule_score(reporter, "9.8") == "9.8"
