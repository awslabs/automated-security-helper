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
    Kind1,
    Level,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


def _result(level, issue_severity=None, suppressed=False) -> Result:
    return Result(
        ruleId="R",
        level=level,
        message=Message(text="finding"),
        properties=(
            PropertyBag(tags=[], issue_severity=issue_severity)
            if issue_severity
            else None
        ),
        suppressions=[Suppression(kind=Kind1.external)] if suppressed else None,
    )


def _rule_score(
    reporter, score, level=Level.error, issue_severity=None, results=None
) -> str:
    """The emitted security-severity of rule R, whose scanner declared *score*
    (None for no score at all) and whose results are *results*, rows of
    ``(level, issue_severity, suppressed)``, defaulting to one unsuppressed
    result at *level*, optionally with an ``issue_severity``."""
    rule_props = (
        PropertyBag(tags=[])
        if score is None
        else PropertyBag(tags=[], **{"security-severity": score})
    )
    rule = ReportingDescriptor(id="R", properties=rule_props)
    rows = results if results is not None else [(level, issue_severity, False)]
    run = Run(
        tool=Tool(driver=ToolComponent(name="ASH", rules=[rule])),
        results=[_result(*row) for row in rows],
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
            # float() parses these; the range test is what refuses them
            ("nan", None),
            ("inf", None),
            ("-inf", None),
            (" 5 ", "5"),
        ],
    )
    def test_usable_security_severity(self, value, expected):
        assert _usable_security_severity(value) == expected


class TestTheBucketIsTheMostSevereEmittedResult:
    """The docstring's rule, row by row: the gate's grade of the rule's most
    severe result that the file emits decides the bucket a scanner score must
    land in."""

    def test_the_most_severe_of_several_results_decides(self, reporter):
        rows = [(Level.warning, "HIGH", False), (Level.error, None, False)]

        assert _rule_score(reporter, "3.1", results=rows) == "9.5"

    def test_a_suppressed_result_left_out_of_the_file_does_not_score_the_rule(
        self, reporter
    ):
        """One suppressed CRITICAL and one emitted LOW: the LOW decides, so a
        scanner score in the critical bucket is replaced by the gate's LOW."""
        rows = [(Level.error, None, True), (Level.note, "LOW", False)]

        assert _rule_score(reporter, "9.8", results=rows) == "3.0"

    def test_a_rule_whose_only_result_is_suppressed_keeps_the_scanners_score(
        self, reporter
    ):
        """No emitted alert carries the rule, so there is no bucket to agree
        with; the scanner's usable score stands."""
        assert _rule_score(reporter, "3.1", results=[(Level.error, None, True)]) == (
            "3.1"
        )

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            ("9.0", "8.0"),  # 9.0 is the critical bucket's floor
            ("8.95", "8.95"),
            ("7.0", "7.0"),  # the high bucket's floor
            ("6.9", "8.0"),  # medium
        ],
    )
    def test_the_high_buckets_boundaries(self, reporter, score, expected):
        assert (
            _rule_score(reporter, score, level=Level.warning, issue_severity="HIGH")
            == expected
        )

    def test_nine_point_zero_is_in_the_critical_bucket(self, reporter):
        assert _rule_score(reporter, "9.0") == "9.0"

    @pytest.mark.parametrize(
        ("score", "level", "issue_severity", "expected"),
        [
            ("3.9", Level.note, None, "3.9"),  # LOW, low bucket
            ("4.0", Level.note, None, "3.0"),  # medium bucket against a LOW
            ("0.5", Level.note, "INFO", "0.5"),  # INFO shares the low bucket
            ("0.0", Level.note, "INFO", "1.0"),  # 0.0 is no severity: the gate's
        ],
    )
    def test_low_and_info_share_githubs_low_bucket(
        self, reporter, score, level, issue_severity, expected
    ):
        assert _rule_score(
            reporter, score, level=level, issue_severity=issue_severity
        ) == (expected)


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
