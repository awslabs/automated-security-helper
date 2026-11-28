# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``result_states_no_finding``: a result states no finding only when nothing in it
reports a problem.

A SARIF result of kind ``pass``, ``notApplicable`` or ``informational`` says that a
rule passed, did not apply, or reported information only
(``severity_ladder.NON_FINDING_KINDS``). SARIF asks for level ``none`` beside those
kinds. A result of such a kind states no finding when its level is ``none`` or not
stated and no ``issue_severity`` it declares is above INFO. One that carries a level
or an ``issue_severity`` that reports a problem contradicts its own kind, and a
scanner fails closed on contradictory data: it is a finding. A kind that asserts a
finding (``fail``, ``open``, ``review``, or none stated) is always a finding.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]

# The levels that report a problem. "severe" is a level SARIF does not define, which
# the ladder grades MEDIUM, so it reports one as well.
PROBLEM_LEVELS = ["note", "warning", "error", "severe"]
# The declared severities above INFO.
SEVERITIES_ABOVE_INFO = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _json(
    kind: str | None, *, level: str | None = "none", severity: str | None = None
) -> dict[str, Any]:
    """A cdk-nag result as reports/ash.sarif holds it, with *kind*, *level* and
    *severity*; a None leaves that key out."""
    result: dict[str, Any] = {
        "ruleId": "AwsSolutions-IAM4",
        "message": {"text": "the rule was not evaluated"},
        "properties": {"scanner_name": "cdk-nag"},
    }
    if kind is not None:
        result["kind"] = kind
    if level is not None:
        result["level"] = level
    if severity is not None:
        result["properties"]["issue_severity"] = severity
    return result


def _model(kind: str, **fields: Any) -> Result:
    """The same result as a model. Without a ``level`` field the level was never set."""
    return Result(
        ruleId="AwsSolutions-IAM4",
        kind=Kind(kind),
        message=Message(text="the rule was not evaluated"),
        properties=PropertyBag(scanner_name="cdk-nag"),
        **fields,
    )


# One builder per way a result reaches the predicate.
FORMS = [
    pytest.param(lambda kind: _json(kind), id="json-level-none"),
    pytest.param(lambda kind: _json(kind, level=None), id="json-no-level"),
    pytest.param(lambda kind: _model(kind, level=Level.none), id="model-level-none"),
    pytest.param(lambda kind: _model(kind), id="model-no-level"),
]


@pytest.mark.parametrize("build", FORMS)
@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_conformant_result_states_no_finding(kind, build):
    """A result of a non-finding kind at level none, or with no level, states no finding."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(build(kind)) is True


@pytest.mark.parametrize("level", PROBLEM_LEVELS)
@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_level_that_reports_a_problem_makes_it_a_finding(kind, level):
    """A result of a non-finding kind whose level reports a problem is a finding."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(_json(kind, level=level)) is False


@pytest.mark.parametrize("severity", SEVERITIES_ABOVE_INFO)
@pytest.mark.parametrize("kind", NON_FINDING)
def test_an_issue_severity_above_info_makes_it_a_finding(kind, severity):
    """A result of a non-finding kind at level none that declares a severity above INFO
    is a finding."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(_json(kind, severity=severity)) is False


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_issue_severity_is_read_in_any_case(kind):
    """A declared severity is read as the grader reads it, in any case."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(_json(kind, severity="high")) is False


@pytest.mark.parametrize("severity", ["INFO", "moderate"])
@pytest.mark.parametrize("kind", NON_FINDING)
def test_an_info_or_unnamed_issue_severity_changes_nothing(kind, severity):
    """INFO is no problem, and a value that names none of the five severities is ignored,
    as the grader ignores it."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(_json(kind, severity=severity)) is True


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_a_kind_that_asserts_a_finding_is_always_a_finding(kind):
    """The same result at level none, with a kind that asserts a finding, is a finding."""
    from automated_security_helper.utils.severity_ladder import (
        result_states_no_finding,
    )

    assert result_states_no_finding(_json(kind)) is False


def test_sarif_utils_hands_out_the_ladders_names():
    """The kind readings live in the ladder and sarif_utils re-exports them, so every
    caller reads the same objects."""
    from automated_security_helper.utils import sarif_utils, severity_ladder

    for name in (
        "NON_FINDING_KINDS",
        "FINDING_KINDS",
        "DEFAULT_RESULT_KIND",
        "result_kind",
        "is_not_a_finding",
        "result_states_no_finding",
    ):
        assert getattr(sarif_utils, name) is getattr(severity_ladder, name), name


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_row_helper_reads_a_kind_and_a_graded_severity(kind):
    """A record that kept only a row's kind and graded severity reads as the result would:
    INFO states no finding, anything above it does not."""
    from automated_security_helper.utils.severity_ladder import row_states_no_finding

    assert row_states_no_finding(kind, "INFO") is True
    assert row_states_no_finding(kind, "HIGH") is False
