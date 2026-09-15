# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rule that raised instead of reaching a verdict must not produce a clean exit.

THE DEFECT THESE TESTS HOLD
---------------------------
Reporting a rule that threw as ``notApplicable``/``none`` is correct SARIF and is
covered elsewhere. It also removed the only thing that used to make such a rule
visible to a caller. Before that change the row arrived at whatever severity the
rule declared -- ``error`` for a cdk-nag error-level rule -- which the ladder read
as CRITICAL and which ``_compute_exit_code`` counted, so the scan exited non-zero.
Afterwards the row carries ``level=none``, ASH's ladder reads that as INFO, and the
default threshold of MEDIUM does not count it.

Nothing else caught it. ``targets_failed`` rises only when the wrapper could not
read a validation report at all or when the scan raised; a rule that throws on a
template whose report still parses hits neither, so the target counters stay clean
and ``--fail-on-incomplete-scanners`` had nothing to see either. The remaining
signals were a log line and a run-level notification, and neither reached the exit
code. Net: a scan whose only defect was systematic rule-evaluation failure reported
a clean exit 0.

WHY THE GATE READS A NOTIFICATION RATHER THAN A FINDING COUNT
------------------------------------------------------------
Because SARIF will not allow the finding. Section 3.27.10 requires ``level`` to be
"none" whenever ``kind`` (3.27.9) is anything but "fail", and "fail" asserts the
rule was evaluated and the target did not satisfy it. Making the result gate on
severity therefore means claiming a verdict that was never reached, which is the
same class of untrue report in the other direction. SARIF's own channel for "a
runtime condition detected by the tool during the analysis" is
``invocation.toolExecutionNotifications``, the scanner already writes one per rule
that could not be evaluated, and this gate reads it there.

WHAT WOULD MAKE THESE TESTS VACUOUS
-----------------------------------
``_compute_exit_code``'s other inputs are a metrics list and a findings count, and
both are neutralized here on purpose: ``get_unified_scanner_metrics`` is patched to
return no scanners and every model carries no results. So a non-zero code cannot
come from findings or from a MISSING scanner, only from the notification. The
paired zero-expecting case in each class is what proves that, and
``test_a_run_with_no_conditions_exits_zero`` is the direct control -- it is the same
model with the notification removed.
"""

from __future__ import annotations

from unittest.mock import patch

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    unevaluated_rules,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Invocation,
    Kind,
    Kind1,
    Level,
    Message,
    Message1,
    Notification,
    PropertyBag,
    ReportingDescriptorReference,
    ReportingDescriptorReference3,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _notification(
    rule_id: str | None,
    level: Level = Level.error,
    text: str = "could not be evaluated",
) -> Notification:
    """One run-level condition, shaped the way the cdk-nag scanner emits it."""
    return Notification(
        level=level,
        message=Message(root=Message1(text=text)),
        associatedRule=(
            ReportingDescriptorReference(root=ReportingDescriptorReference3(id=rule_id))
            if rule_id is not None
            else None
        ),
    )


def _sarif(
    notifications: list[Notification] | None,
    results: list[Result] | None = None,
) -> SarifReport:
    """A real SarifReport, not a stand-in.

    Built from the schema models rather than a MagicMock because the level check is
    exactly the kind of thing a mock cannot exercise: ``Level`` is a str-mixin enum,
    so ``str(Level.error)`` renders ``"Level.error"`` and a comparison written that
    way matches nothing while a MagicMock would satisfy it anyway.
    """
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ash-cdk-nag-wrapper")),
                results=results or [],
                invocations=[
                    Invocation(
                        executionSuccessful=True,
                        toolExecutionNotifications=notifications,
                    )
                ],
            )
        ],
    )


def _model(sarif: SarifReport | None) -> AshAggregatedResults:
    """An aggregated-results model carrying a real config.

    ``ash_config`` is populated rather than left at None for two reasons, and the
    second one is not optional. It is what a real run always has, and
    ``_resolve_fail_on_incomplete_scanners`` reads it -- so a None here would test a
    shape production never produces.

    It also has to be imported at all. ``AshAggregatedResults`` declares
    ``ash_config`` as a forward reference to ``AshConfig``, and Pydantic cannot build
    the class until that name has been defined somewhere in the process: without the
    ``get_default_config`` import above, instantiating this model raises
    ``PydanticUserError: 'AshAggregatedResults' is not fully defined``. Which import
    happens to have run first is not something a test should depend on, so the
    dependency is stated here instead of inherited from import order.
    """
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif = sarif
    return model


def _exit_code(tmp_path, model, **opt_kwargs) -> int:
    """``_compute_exit_code`` over *model* with every other input neutralized.

    No scanners in the metrics list, so neither the MISSING/ERROR arm of
    ``incomplete_scanners`` nor the actionable-findings count can contribute. The
    only remaining route to a non-zero code is the notification.
    """
    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        **opt_kwargs,
    )
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[]):
        return _compute_exit_code(model, opts)


class TestAnUnevaluatedRuleReachesTheExitCode:
    """The defect in its smallest form: a rule threw, everything else is clean."""

    def test_an_unevaluated_rule_exits_nonzero_under_default_config(self, tmp_path):
        """This is the assertion the defect report asked for.

        Default config throughout -- no ``--fail-on-incomplete-scanners``, findings
        gating left at its default. Before the gate existed this returned 0.

        1 rather than 2 on purpose, and asserted exactly: 2 tells a reviewer that
        clearing the listed findings clears the scan, which is what is not true when
        a rule never produced its verdict.
        """
        model = _model(_sarif([_notification("AwsSolutions-EC26")]))
        assert _exit_code(tmp_path, model) == 1

    def test_a_run_with_no_conditions_exits_zero(self, tmp_path):
        """THE CONTROL for the test above -- the same model, notification removed.

        Without this, the test above would pass equally well against a gate that
        returned 1 unconditionally.
        """
        model = _model(_sarif([]))
        assert _exit_code(tmp_path, model) == 0

    def test_it_fires_even_with_findings_gating_turned_off(self, tmp_path):
        """Ordering, not a second copy of the assertion above.

        An operator who passes ``--no-fail-on-findings`` has said "do not fail me
        for what you find". They have not said "do not tell me part of the scan
        never ran". The gate therefore has to sit ahead of the findings early
        return, and this is the only test that distinguishes those two placements.
        """
        model = _model(_sarif([_notification("AwsSolutions-EC26")]))
        assert _exit_code(tmp_path, model, fail_on_findings=False) == 1

    def test_it_does_not_need_the_completeness_flag(self, tmp_path):
        """Opting in must not be what makes it fire, and must not break it either.

        The reported defect is specifically that this is silent *under default
        config*, so a gate that only fires under the flag would not fix it. Both
        states are asserted because a check placed inside the flag's block would
        pass the second and fail the first.
        """
        model = _model(_sarif([_notification("AwsSolutions-EC26")]))
        assert _exit_code(tmp_path, model) == 1
        assert _exit_code(tmp_path, model, fail_on_incomplete_scanners=True) == 1


class TestWhatMustStayNonActionable:
    """The negative controls. Each one is a state that must keep exiting 0."""

    def test_a_rule_that_genuinely_does_not_apply_stays_non_actionable(self, tmp_path):
        """A notApplicable RESULT on its own must not gate.

        This is the distinction the whole fix turns on. "Did not apply to this
        target" and "tried and failed" are both absent from the findings, and only
        the second is a defect. cdk-nag's validation report carries violations only,
        so a rule that genuinely does not apply produces no row at all and therefore
        no notification -- which is why the gate keys on the notification rather
        than on ``kind``.

        Asserted with the result present and the notification absent, because that
        is precisely the shape a ``kind``-based gate would get wrong: it would fail
        this scan for a rule that had nothing to say about the template.
        """
        not_applicable = Result(
            ruleId="AwsSolutions-IAM4",
            kind=Kind.notApplicable,
            level=Level.none,
            message=Message(root=Message1(text="rule does not apply to this target")),
            properties=PropertyBag(),
        )
        model = _model(_sarif([], results=[not_applicable]))
        assert _exit_code(tmp_path, model) == 0

    def test_a_scan_with_no_sarif_at_all_exits_zero(self, tmp_path):
        """A scanner set that produced no SARIF must not become a failure.

        This covers the no-CloudFormation case the cdk-nag scanner reports as
        SKIPPED: nothing was evaluated, no rule raised, and the exit code has to
        stay 0. The gate reads ``results.sarif`` and has to tolerate its absence
        rather than treating absence as a condition.
        """
        assert _exit_code(tmp_path, _model(None)) == 0

    def test_a_warning_level_condition_does_not_gate(self, tmp_path):
        """Only ``error``.

        ``warning`` is the field's default, so a tool that reports a benign runtime
        note lands there. Gating on it would fail scans for conditions that cost no
        coverage, and the cdk-nag scanner sets ``error`` deliberately for exactly
        this reason.
        """
        model = _model(_sarif([_notification("SomeRule", level=Level.warning)]))
        assert _exit_code(tmp_path, model) == 0

    def test_a_note_level_condition_does_not_gate(self, tmp_path):
        """The remaining level, so the check is a match on one value not a floor."""
        model = _model(_sarif([_notification("SomeRule", level=Level.note)]))
        assert _exit_code(tmp_path, model) == 0


class TestSuppressionIsTheEscapeHatch:
    """Suppressing the rule's not-evaluated results suppresses the gate.

    A notification carries no suppression of its own, so a gate reading only the
    notification would be unavoidable. That is not an abstract concern: this
    repository's ``.ash/.ash.yaml`` accepts fifteen rules that throw on its
    deliberately parameterized templates, each with a reviewed reason, and its own
    note calls naming them "the only way to keep the exit code honest". A gate that
    ignored those would fail ASH's own default scan with no way to say "reviewed,
    accepted".
    """

    def test_a_suppressed_unevaluated_rule_does_not_gate(self, tmp_path):
        suppressed = Result(
            ruleId="AwsSolutions-EC26",
            kind=Kind.notApplicable,
            level=Level.none,
            message=Message(root=Message1(text="was NOT evaluated")),
            properties=PropertyBag(),
            suppressions=[
                Suppression(kind=Kind1.external, justification="reviewed, accepted")
            ],
        )
        model = _model(
            _sarif([_notification("AwsSolutions-EC26")], results=[suppressed])
        )
        assert unevaluated_rules(model) == []
        assert _exit_code(tmp_path, model) == 0

    def test_an_unsuppressed_unevaluated_rule_still_gates(self, tmp_path):
        """THE CONTROL for the test above: same shape, suppression removed.

        Without this the test above would pass against a gate that had simply
        stopped working.
        """
        unsuppressed = Result(
            ruleId="AwsSolutions-EC26",
            kind=Kind.notApplicable,
            level=Level.none,
            message=Message(root=Message1(text="was NOT evaluated")),
            properties=PropertyBag(),
        )
        model = _model(
            _sarif([_notification("AwsSolutions-EC26")], results=[unsuppressed])
        )
        assert unevaluated_rules(model) == ["AwsSolutions-EC26"]
        assert _exit_code(tmp_path, model) == 1

    def test_one_suppressed_occurrence_does_not_cover_an_unsuppressed_one(
        self, tmp_path
    ):
        """A rule that throws twice, suppressed on one resource only, still gates.

        Suppressions are per finding, so accepting the failure on one resource says
        nothing about another. Reading "any suppression for this rule" as "this rule
        is accepted" would silently widen every entry in an operator's config.
        """
        results = [
            Result(
                ruleId="AwsSolutions-EC26",
                kind=Kind.notApplicable,
                level=Level.none,
                message=Message(root=Message1(text="VolumeA")),
                properties=PropertyBag(),
                suppressions=[
                    Suppression(kind=Kind1.external, justification="reviewed")
                ],
            ),
            Result(
                ruleId="AwsSolutions-EC26",
                kind=Kind.notApplicable,
                level=Level.none,
                message=Message(root=Message1(text="VolumeB")),
                properties=PropertyBag(),
            ),
        ]
        model = _model(_sarif([_notification("AwsSolutions-EC26")], results=results))
        assert unevaluated_rules(model) == ["AwsSolutions-EC26"]
        assert _exit_code(tmp_path, model) == 1

    def test_a_suppressed_ordinary_finding_does_not_cover_a_thrown_rule(self, tmp_path):
        """Only not-evaluated rows count as evidence, which is why ``kind`` filters.

        One rule can throw on one resource while reaching a verdict on another. If
        an ordinary ``fail`` row counted, a rule whose throw was suppressed would be
        reported anyway on the strength of an unrelated finding -- and the mirror
        case, an unsuppressed throw hidden by a suppressed finding, is the one that
        loses coverage. The suppressed ``fail`` row here is the shape that would
        break a gate keying on suppression alone.
        """
        results = [
            Result(
                ruleId="AwsSolutions-EC26",
                kind=Kind.notApplicable,
                level=Level.none,
                message=Message(root=Message1(text="was NOT evaluated")),
                properties=PropertyBag(),
                suppressions=[
                    Suppression(kind=Kind1.external, justification="reviewed")
                ],
            ),
            Result(
                ruleId="AwsSolutions-EC26",
                kind=Kind.fail,
                level=Level.error,
                message=Message(root=Message1(text="a real violation elsewhere")),
                properties=PropertyBag(),
            ),
        ]
        model = _model(_sarif([_notification("AwsSolutions-EC26")], results=results))
        assert unevaluated_rules(model) == []
        assert _exit_code(tmp_path, model) == 0

    def test_a_rule_with_no_matching_result_is_still_reported(self, tmp_path):
        """Absence of a result is not evidence of suppression.

        A notification whose rule has no not-evaluated row at all cannot be shown to
        be accepted, so it is reported. Defaulting to silence here would put the
        silent pass back through the one shape nothing else checks.
        """
        other = Result(
            ruleId="SomeOtherRule",
            kind=Kind.notApplicable,
            level=Level.none,
            message=Message(root=Message1(text="unrelated")),
            properties=PropertyBag(),
            suppressions=[Suppression(kind=Kind1.external, justification="reviewed")],
        )
        model = _model(_sarif([_notification("AwsSolutions-EC26")], results=[other]))
        assert unevaluated_rules(model) == ["AwsSolutions-EC26"]
        assert _exit_code(tmp_path, model) == 1


class TestUnevaluatedRulesHelper:
    """``unevaluated_rules`` on its own, for the shapes a live run is awkward to make."""

    def test_it_names_the_rules_that_could_not_be_evaluated(self):
        rules = unevaluated_rules(
            _model(
                _sarif(
                    [
                        _notification("AwsSolutions-EC26"),
                        _notification("AwsSolutions-EC27"),
                    ]
                )
            )
        )
        assert rules == ["AwsSolutions-EC26", "AwsSolutions-EC27"]

    def test_one_rule_reported_twice_is_named_once(self):
        """Deduplicated, and sorted so the logged message is stable between runs.

        One rule that cannot resolve a property raises for every construct sharing
        the shape, and the scanner already deduplicates its notifications by rule.
        Deduplicating here as well means the gate does not depend on it continuing
        to.
        """
        rules = unevaluated_rules(
            _model(
                _sarif(
                    [
                        _notification("AwsSolutions-EC27"),
                        _notification("AwsSolutions-EC26"),
                        _notification("AwsSolutions-EC26"),
                    ]
                )
            )
        )
        assert rules == ["AwsSolutions-EC26", "AwsSolutions-EC27"]

    def test_a_condition_naming_no_rule_is_still_reported(self):
        """``associatedRule`` is optional, and an unnamed condition still counts.

        Falling back to the message rather than skipping the entry: a tool that
        reports an error-level runtime condition without attributing it to a rule
        has still told us part of its analysis did not run, and dropping it for
        lacking an id would be the silent pass this gate exists to remove.
        """
        rules = unevaluated_rules(
            _model(_sarif([_notification(None, text="engine aborted mid-analysis")]))
        )
        assert rules == ["engine aborted mid-analysis"]

    def test_a_model_with_no_sarif_reports_nothing(self):
        assert unevaluated_rules(_model(None)) == []
        assert unevaluated_rules(None) == []

    def test_a_run_with_no_invocations_reports_nothing(self):
        """Invocations are optional in the schema, so absence must not raise."""
        report = SarifReport(
            version="2.1.0",
            runs=[Run(tool=Tool(driver=ToolComponent(name="probe")), results=[])],
        )
        assert unevaluated_rules(_model(report)) == []

    def test_a_json_round_tripped_model_still_reports(self):
        """The level arrives as a plain string once the model has been serialized.

        ``ash.sarif`` is written with ``model_dump_json`` and a consumer may rebuild
        the model from it, at which point ``level`` is ``"error"`` rather than
        ``Level.error``. Both shapes have to read the same, which is why the check
        takes ``.value`` when it is present instead of comparing the member.
        """
        original = _sarif([_notification("AwsSolutions-EC26")])
        rebuilt = SarifReport.model_validate_json(
            original.model_dump_json(exclude_none=True, exclude_unset=True)
        )
        assert unevaluated_rules(_model(rebuilt)) == ["AwsSolutions-EC26"]
