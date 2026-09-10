# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rule that did not run has to be visible as a condition of the RUN, not just a result.

WHY A RESULT IS NOT ENOUGH
--------------------------
Marking the individual finding ``kind=notApplicable`` with ``level=none`` is correct and is
covered by ``tests/unit/utils/test_cdk_nag_unevaluated_rule.py``. It is also easy to miss: that
result sits in the same array as the findings, at the lowest severity there is, and report
surfaces routinely sort or filter by severity. The fact an operator needs is coarser -- "part of
this scan did not run" -- and it belongs where facts about the run live.

SARIF already defines that place, in its own words. ``invocation.toolExecutionNotifications`` is
"A list of runtime conditions detected by the tool during the analysis", and
``notification.associatedRule`` is "A reference used to locate the rule descriptor associated
with this notification". A rule raising mid-evaluation is a runtime condition detected during
the analysis, and the rule it happened to is the thing to associate it with. So the
representation is SARIF's rather than a bespoke property bag key.

``tests/integration/scanners/test_cdk_nag_real_pack.py`` asserts the same thing end to end
through ``CdkNagScanner.scan`` against real cdk-nag; these tests pin the helper's behaviour on
inputs a live run is awkward to produce on demand, such as one rule raising on several resources.
"""

from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.cdk_nag_wrapper import NOT_EVALUATED


def _result(rule_id: str, compliance: str, resource: str = "ProbeResource") -> Result:
    """A Result shaped the way the wrapper emits one.

    ``cdk_nag_finding`` lands in ``model_extra`` because ``PropertyBag`` allows extras and does
    not declare it. The helper reads ``compliance`` out of that bag rather than off ``kind``,
    which is deliberate on its part -- the bag is the wrapper's own record and cannot be changed
    by a later reporting step.
    """
    return Result(
        ruleId=rule_id,
        kind=Kind.notApplicable if compliance == NOT_EVALUATED else Kind.fail,
        level=Level.none if compliance == NOT_EVALUATED else Level.error,
        message=Message(root=Message1(text=f"{rule_id} message")),
        properties=PropertyBag(
            cdk_nag_finding={
                "pack": "AwsSolutions",
                "rule_id": rule_id,
                "resource_id": resource,
                "compliance": compliance,
                "exception_reason": "N/A",
                "rule_level": "Error",
                "rule_info": f"{rule_id} could not be validated.",
            },
            tags=["aws", "cdk", "cdk-nag", "AwsSolutions", rule_id, resource],
        ),
    )


class TestUnevaluatedRuleNotifications:
    def test_an_unevaluated_rule_produces_a_notification_naming_that_rule(self):
        """The positive artifact: a notification whose ``associatedRule`` is the rule id.

        The rule id is asserted rather than just the notification count, because a notification
        that does not say which rule went unevaluated tells an operator nothing actionable.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _unevaluated_rule_notifications,
        )

        notifications = _unevaluated_rule_notifications(
            [
                _result("AwsSolutions-EC26", NOT_EVALUATED),
                _result("AwsSolutions-S1", "Non-Compliant"),
            ]
        )

        assert [n.associatedRule.root.id for n in notifications] == [
            "AwsSolutions-EC26"
        ]
        assert "could not be evaluated" in notifications[0].message.root.text
        assert "AwsSolutions" in notifications[0].message.root.text

    def test_the_notification_is_reported_at_error_level(self):
        """``error``, overriding the field's ``warning`` default.

        For a security scanner a rule that silently did not run is the more serious of the two
        things it can report -- a violation at least tells you what to fix. Asserted because
        ``Notification.level`` defaults to ``warning``, so getting this right requires passing it
        and a regression here would be invisible.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _unevaluated_rule_notifications,
        )

        notifications = _unevaluated_rule_notifications(
            [_result("AwsSolutions-EC26", NOT_EVALUATED)]
        )

        assert notifications[0].level == Level.error

    def test_one_rule_raising_on_several_resources_is_reported_once(self):
        """Deduplicated by rule id.

        A rule that cannot resolve a property raises for every construct sharing that shape, and
        the run-level statement is about the rule. The per-resource detail is already carried by
        the results. Two distinct rules must still produce two notifications, which is what stops
        the deduplication from collapsing everything to one.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _unevaluated_rule_notifications,
        )

        notifications = _unevaluated_rule_notifications(
            [
                _result("AwsSolutions-EC26", NOT_EVALUATED, resource="VolumeA"),
                _result("AwsSolutions-EC26", NOT_EVALUATED, resource="VolumeB"),
                _result("AwsSolutions-EC27", NOT_EVALUATED, resource="SecurityGroup"),
            ]
        )

        assert sorted(n.associatedRule.root.id for n in notifications) == [
            "AwsSolutions-EC26",
            "AwsSolutions-EC27",
        ]

    def test_a_scan_with_no_unevaluated_rule_produces_no_notifications(self):
        """The negative control.

        ``toolExecutionNotifications`` is written unconditionally into the invocation, so this is
        what keeps an ordinary clean scan from claiming a coverage gap it does not have.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _unevaluated_rule_notifications,
        )

        assert (
            _unevaluated_rule_notifications(
                [
                    _result("AwsSolutions-S1", "Non-Compliant"),
                    _result("AwsSolutions-S10", "Non-Compliant"),
                ]
            )
            == []
        )
