# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unevaluated-rules gate is quieted only by a suppression in effect.

``unevaluated_rules`` reports a rule whose run-level notification says it could
not be evaluated unless every one of its not-evaluated results is suppressed. It
read "suppressed" as any non-empty ``suppressions`` list, the one presence-only
read left in ``run_ash_scan.py`` after the exit code's count and the
``--min-severity`` gate moved to ``sarif_utils.is_result_suppressed``. A
suppression whose ``state`` is ``rejected`` or ``underReview`` has not taken
effect (SARIF 3.35.4) and was never an approval, so a rule whose only suppression
a reviewer rejected was quieted and the scan exited 0 over a rule that never ran.
"""

from __future__ import annotations

import pytest

from automated_security_helper.interactions.run_ash_scan import unevaluated_rules
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Kind1,
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
    State,
    Suppression,
)

from tests.unit.interactions.test_exit_code_unevaluated_rules import (
    _exit_code,
    _model,
    _notification,
    _sarif,
)

pytestmark = pytest.mark.unit


def _thrown(rule: str, state) -> Result:
    return Result(
        ruleId=rule,
        kind=Kind.notApplicable,
        level=Level.none,
        message=Message(root=Message1(text="was NOT evaluated")),
        properties=PropertyBag(),
        suppressions=[
            Suppression(
                kind=Kind1.external, justification="awaiting review", state=state
            )
        ],
    )


@pytest.mark.parametrize("state", [State.rejected, State.underReview])
def test_a_suppression_not_in_effect_still_reports_the_rule(tmp_path, state):
    model = _model(
        _sarif(
            [_notification("AwsSolutions-EC26")],
            results=[_thrown("AwsSolutions-EC26", state)],
        )
    )

    # RED at the base: any non-empty suppressions list quieted the rule and the
    # scan exited 0 over a rule that never ran.
    assert unevaluated_rules(model) == ["AwsSolutions-EC26"]
    assert _exit_code(tmp_path, model) == 1


@pytest.mark.parametrize("state", [None, State.accepted])
def test_a_suppression_in_effect_still_quiets_the_rule(tmp_path, state):
    """Control: an accepted or stateless suppression is the escape hatch, as before."""
    model = _model(
        _sarif(
            [_notification("AwsSolutions-EC26")],
            results=[_thrown("AwsSolutions-EC26", state)],
        )
    )

    assert unevaluated_rules(model) == []
    assert _exit_code(tmp_path, model) == 0
