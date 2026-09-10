# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rule cdk-nag could not evaluate is a coverage gap, not a violation.

THE MECHANISM
-------------
cdk-nag 3.0.2's ``applyRule`` wraps each rule in a try/catch and, on an exception, calls the
same ``addViolation`` a real violation goes through -- passing the exception message as a third
argument. ``addViolation`` turns that into a description prefixed "Rule threw an error during
validation.", and leaves the severity as whatever the rule declared. Reached in practice
whenever a rule calls ``NagRules.resolveIfPrimitive`` on a property that resolves to a
non-primitive, which throws "therefore the rule could not be validated" -- a ``Ref`` to a
CloudFormation Parameter is exactly that.

So there is no structural marker in the report: the description prefix is the only thing that
separates "this rule found a problem" from "this rule never ran". A rule that never ran arrived
as ``severity: "error"``, which this module normalizes to ``"Error"``, which the SARIF mapping
rendered ``level=error, kind=fail`` -- CRITICAL on ASH's severity ladder. Two rules that did not
run were reported as two critical security findings, and the gap in coverage they represent was
invisible.

WHY notApplicable AND NOT open
------------------------------
SARIF 2.1.0 defines both, and the difference decides which one is a true statement. Quoting the
OASIS Standard incorporating Approved Errata 01, section 3.27.9:

  "notApplicable" : The rule specified by ruleId was not evaluated, because it does not apply
  to the analysis target.

  "open" : The specified rule was evaluated, and the tool concluded that there was insufficient
  information to decide whether a problem exists.

``open`` opens with "was evaluated", and its NOTE 1 scopes the value to proof-based tools that
completed an analysis and could not prove either direction. cdk-nag's rule did not complete --
it raised partway through -- so "was not evaluated" is the accurate half. Section 3.27.9's own
example for ``notApplicable`` is a result whose message reads "<target> was not evaluated for
rule <id> because <reason>", which is the shape this path now produces.

``level`` follows rather than being chosen: section 3.27.10 defines ``"none"`` as "The concept of
'severity' does not apply to this result because the kind property (3.27.9) has a value other
than 'fail'". ASH's ladder maps ``none`` to INFO, so the count inflation stops as a consequence
of getting the SARIF right rather than as a separate adjustment that could drift away from it.

The live-synthesis counterpart is ``TestRuleThatCouldNotBeEvaluated`` in
``tests/integration/scanners/test_cdk_nag_real_pack.py``, which makes real cdk-nag rules raise
and asserts the same properties -- so the fixture below cannot drift away from what cdk-nag
actually emits without something going red.
"""

import json
from pathlib import Path

import pytest


def _write_report(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "validation-report.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# cdk-nag's not-evaluated shape beside a genuine violation, in one report. Having both is
# load-bearing: every assertion below names what must change AND what must not, so a change that
# rewrites every finding cannot pass.
UNEVALUATED_REPORT = {
    "version": "2.1.0",
    "title": "Validation Report",
    "pluginReports": [
        {
            "pluginName": "AwsSolutions",
            "violations": [
                {
                    "ruleName": "AwsSolutions-EC26",
                    "description": (
                        "Rule threw an error during validation. The parameter resolved "
                        'to to a non-primitive value "{\\"Ref\\":\\"VolumeEncrypted\\"}", '
                        "therefore the rule could not be validated."
                    ),
                    "severity": "error",
                    "violatingConstructs": [
                        {"constructPath": "ASHCDKNagScanner/tpl/ProbeVolume"}
                    ],
                },
                {
                    "ruleName": "AwsSolutions-S1",
                    "description": "The S3 Bucket has server access logs disabled.",
                    "severity": "error",
                    "violatingConstructs": [
                        {"constructPath": "ASHCDKNagScanner/tpl/ProbeBucket"}
                    ],
                },
            ],
        }
    ],
}


class TestARuleThatCouldNotBeEvaluatedIsNotAViolation:
    def test_end_to_end_the_unevaluated_rule_does_not_render_as_a_critical_failure(
        self, tmp_path: Path
    ):
        """The whole defect in one assertion, using only names that already existed.

        Deliberately written without importing anything added by this change, so that its red
        state on the unfixed tree is a behavioural difference rather than a missing symbol. It
        composes the two functions exactly as ``run_cdk_nag_against_cfn_template`` does -- read
        the report, then map each finding's compliance and level onto SARIF -- and checks what a
        consumer of that SARIF sees.

        On the unfixed tree this returns ``(Level.error, Kind.fail)``, which ASH's severity
        ladder reads as CRITICAL. The pair is asserted rather than each field separately,
        because section 3.27.10 makes them dependent: ``level`` is only meaningful once ``kind``
        is known.
        """
        from automated_security_helper.schemas.sarif_schema_model import Kind, Level
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _level_and_kind,
            _violations_from_validation_report,
        )

        per_pack, _ = _violations_from_validation_report(
            _write_report(tmp_path, UNEVALUATED_REPORT)
        )
        rendered = {
            finding.rule_id: _level_and_kind(
                compliance=finding.compliance,
                rule_level=finding.rule_level,
                exception_reason=finding.exception_reason,
            )
            for finding in per_pack["AwsSolutions"]
        }

        assert rendered["AwsSolutions-EC26"] == (Level.none, Kind.notApplicable), (
            "a rule cdk-nag could not evaluate rendered as an evaluated result; "
            f"got {rendered['AwsSolutions-EC26']}"
        )
        # The rule that really did fire, from the same report, must be untouched.
        assert rendered["AwsSolutions-S1"] == (Level.error, Kind.fail)

    def test_the_unevaluated_rule_is_marked_as_its_own_compliance_state(
        self, tmp_path: Path
    ):
        """ "Not-Evaluated" is a third state alongside Non-Compliant and Suppressed.

        Asserted on the record rather than only on the rendered level, because the scanner reads
        ``compliance`` back out of the property bag -- that is how the run-level notification
        finds its rules -- and a reader of the raw report needs the same distinction the SARIF
        carries.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            NOT_EVALUATED,
            _violations_from_validation_report,
        )

        per_pack, failure = _violations_from_validation_report(
            _write_report(tmp_path, UNEVALUATED_REPORT)
        )

        assert failure is None
        by_rule = {f.rule_id: f for f in per_pack["AwsSolutions"]}

        assert by_rule["AwsSolutions-EC26"].compliance == NOT_EVALUATED
        assert by_rule["AwsSolutions-S1"].compliance == "Non-Compliant"

    def test_the_message_says_the_rule_was_not_evaluated(self, tmp_path: Path):
        """``kind`` is the machine-readable half; the message is the half people read.

        Plenty of report surfaces render only the message, so a reader looking at one of those
        would still see a rule that did not run described as a problem that was found. The
        wording follows the example section 3.27.9 gives for ``notApplicable``.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _result_message_text,
            _violations_from_validation_report,
        )

        per_pack, _ = _violations_from_validation_report(
            _write_report(tmp_path, UNEVALUATED_REPORT)
        )
        by_rule = {f.rule_id: f for f in per_pack["AwsSolutions"]}

        unevaluated = _result_message_text(by_rule["AwsSolutions-EC26"], "tpl.yaml")
        assert "'tpl.yaml' was NOT evaluated for rule AwsSolutions-EC26" in unevaluated

        # A real finding's message is unchanged, including the historical Exception Reason line.
        violation = _result_message_text(by_rule["AwsSolutions-S1"], "tpl.yaml")
        assert violation == (
            "The S3 Bucket has server access logs disabled.\n\nException Reason: N/A"
        )

    def test_an_unevaluated_rule_renders_as_notapplicable_with_no_severity(self):
        """The mapping in isolation, so a failure points at the mapping and not the reader."""
        from automated_security_helper.schemas.sarif_schema_model import Kind, Level
        from automated_security_helper.utils.cdk_nag_wrapper import (
            NOT_EVALUATED,
            _level_and_kind,
        )

        level, kind = _level_and_kind(
            compliance=NOT_EVALUATED, rule_level="Error", exception_reason="N/A"
        )

        assert kind == Kind.notApplicable
        assert level == Level.none

    def test_a_real_violation_still_renders_as_a_failure(self):
        """The control that stops the fix from demoting every finding.

        ``Error``/``Non-Compliant`` has to stay ``level=error, kind=fail``. Without this, a
        one-line change returning ``notApplicable`` unconditionally would pass every other test
        in this class while silencing the scanner completely.
        """
        from automated_security_helper.schemas.sarif_schema_model import Kind, Level
        from automated_security_helper.utils.cdk_nag_wrapper import _level_and_kind

        level, kind = _level_and_kind(
            compliance="Non-Compliant", rule_level="Error", exception_reason="N/A"
        )

        assert kind == Kind.fail
        assert level == Level.error

    @pytest.mark.parametrize(
        "description",
        [
            "Rule threw an error during validation. Something specific went wrong.",
            # verbose=False is not what ASH passes today, but _build_nag_pack is the only thing
            # making that true and the prefix is identical either way.
            (
                "Rule threw an error during validation. This is generally caused by a "
                "parameter referencing an intrinsic function."
            ),
        ],
    )
    def test_the_marker_is_recognized_in_both_of_cdk_nags_message_forms(
        self, tmp_path: Path, description: str
    ):
        """cdk-nag builds the description differently under verbose and non-verbose.

        Only the prefix is shared, which is why detection keys on the prefix. Pinning the whole
        string would work today and silently stop working the moment ``verbose`` changes -- and
        the failure mode is the defect coming back, not a red test.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            NOT_EVALUATED,
            _violations_from_validation_report,
        )

        report = {
            "pluginReports": [
                {
                    "pluginName": "AwsSolutions",
                    "violations": [
                        {
                            "ruleName": "AwsSolutions-EC26",
                            "description": description,
                            "severity": "error",
                            "violatingConstructs": [{"constructPath": "s/t/R"}],
                        }
                    ],
                }
            ]
        }

        per_pack, _ = _violations_from_validation_report(
            _write_report(tmp_path, report)
        )

        assert per_pack["AwsSolutions"][0].compliance == NOT_EVALUATED

    def test_a_description_that_merely_mentions_an_error_is_still_a_violation(
        self, tmp_path: Path
    ):
        """The prefix is anchored at the start, not searched for anywhere in the text.

        A rule whose own explanation happens to contain the words "an error during validation"
        must not be demoted. Without this, a substring search would look identical to the
        anchored one on every fixture above while silently suppressing real findings.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _violations_from_validation_report,
        )

        report = {
            "pluginReports": [
                {
                    "pluginName": "AwsSolutions",
                    "violations": [
                        {
                            "ruleName": "AwsSolutions-APIG1",
                            "description": (
                                "The API does not log. Without logs you cannot tell whether "
                                "a Rule threw an error during validation."
                            ),
                            "severity": "error",
                            "violatingConstructs": [{"constructPath": "s/t/R"}],
                        }
                    ],
                }
            ]
        }

        per_pack, _ = _violations_from_validation_report(
            _write_report(tmp_path, report)
        )

        assert per_pack["AwsSolutions"][0].compliance == "Non-Compliant"
