# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fail-on-incomplete-scanners`` has to see a scanner that lost only *some* of its input.

Why these tests exist
---------------------
The completeness gate selected on status alone::

    _INCOMPLETE_SCANNER_STATUSES = {ERROR, MISSING}

and ``ScanResultsContainer.determine_status`` returns ERROR only once
``targets_failed >= targets_attempted``. Those two facts compose into a hole: a
scanner that failed on *some* of its targets keeps whatever status the severity
gate gives it -- normally PASSED -- so the gate never saw it. An operator who
turned the gate on to be told when coverage was lost was told only about total
loss, which is the rarer case.

Measured on this repository before the change: cdk-nag attempts 10 targets and
fails 4, its per-target container reports PASSED, and
``--fail-on-incomplete-scanners`` exited 0. Two of those four are real
CloudFormation templates that went unscanned.

What is deliberately NOT changed
--------------------------------
* No new ``ScannerStatus`` member. Partial coverage is expressed in this gate's
  own output and not by promoting a status, so ``cli.merge._completed`` keeps
  answering the narrower did-it-run-at-all question that shard refusal depends on.
  ``test_partial_coverage_still_counts_as_having_run`` pins that, and pins it
  falsifiably: it measures that the counters DO reach the entry -- the model sets
  ``extra="allow"`` -- so ``_completed`` ignoring them is a behavior a mutation can
  break rather than a structural impossibility.
* No new config key. This is the existing opt-in flag learning about a case it
  was always meant to cover.
* The default path. ``TestDefaultPathIsUntouched`` asserts that a partial-coverage
  run without the flag exits exactly as it did before -- because this change does
  move existing opt-in users from 0 to 1, and the blast radius has to stay
  confined to people who asked for the gate.

What IS changed elsewhere, so this file is not read as a claim about the whole PR
--------------------------------------------------------------------------------
A sibling commit ORs ``any_target_errored`` into the ``error`` flag, so a target
tree that lost ALL its targets -- which ``determine_status`` does report as ERROR
-- now reaches the ROLLED-UP status. That is a status change with no opt-in, and
it is not what this file is about; ``tests/unit/core/
test_scanner_status_across_targets.py`` owns it. The distinction that makes both
true at once: partial loss on a tree never became a status, total loss on a tree
always was one and simply could not be seen. ``TestTheGateReadsTheRealRollup``
below is where the two meet, and it is the only class here that does not patch
``get_unified_scanner_metrics``.

The tri-state is the subtle part
--------------------------------
``targets_attempted`` is ``None`` for the nine scanners that do not track
per-target outcomes at all. ``None`` is "makes no claim", ``0`` is the claim
"tracked, attempted none". Collapsing ``None`` to ``0`` would make every
non-tracking scanner look like it evaluated nothing;
``TestTriStateSurvivesTheGate`` pins all three values, because the gate is the
consumer most likely to get this wrong -- it is the one that turns the number
into a nonzero exit code.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_scanners,
)

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _metric(
    scanner_name: str,
    status: str = ScannerStatus.PASSED.value,
    *,
    targets_attempted: int | None = None,
    targets_failed: int = 0,
    actionable: int = 0,
) -> ScannerMetrics:
    """A real ``ScannerMetrics``, not a MagicMock.

    The sibling module's ``_metric`` helper builds MagicMocks on purpose -- it
    pins status strings the calculator would never derive. That will not do here:
    every attribute of a MagicMock is present and truthy, so a MagicMock cannot
    express "this scanner reported no target counts", which is exactly the state
    these tests have to distinguish from "reported zero".
    """
    return ScannerMetrics(
        scanner_name=scanner_name,
        status=status,
        actionable=actionable,
        targets_attempted=targets_attempted,
        targets_failed=targets_failed,
    )


def _opts(tmp_path, **kwargs) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        **kwargs,
    )


def _exit_code(tmp_path, metrics, **opt_kwargs) -> int:
    """``_compute_exit_code`` over *metrics*, with findings-gating off.

    ``fail_on_findings=False`` so the returned code reflects coverage alone. That
    also exercises the ordering that matters: the completeness gate is checked
    before the findings early-return, so a run with findings-gating off still
    learns that its coverage was partial.
    """
    results = MagicMock()
    results.sarif = None
    opts = _opts(tmp_path, fail_on_findings=False, **opt_kwargs)
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=metrics):
        return _compute_exit_code(results, opts)


class TestPartialCoverageTripsTheGate:
    """The defect in its smallest form: some targets lost, status still PASSED."""

    def test_partial_target_loss_exits_one_under_the_flag(self, tmp_path):
        """4 of 10 targets unevaluated is not a clean scan.

        This is the case measured on this repository. Before the change the
        status was PASSED, PASSED is not in ``_INCOMPLETE_SCANNER_STATUSES``, and
        the gate returned 0.
        """
        code = _exit_code(
            tmp_path,
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=4,
                )
            ],
            fail_on_incomplete_scanners=True,
        )

        assert code == 1, (
            "a scanner that could not evaluate 4 of its 10 targets has not "
            "completed; exit 0 is indistinguishable from having scanned all 10"
        )

    def test_a_single_lost_target_is_enough(self, tmp_path):
        """No tolerance threshold. One unevaluated target is unevaluated input.

        A percentage floor was considered and rejected: it would need a number
        nobody can justify, and "1 of 200 templates went unscanned" is still a
        template nobody looked at.
        """
        code = _exit_code(
            tmp_path,
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=200,
                    targets_failed=1,
                )
            ],
            fail_on_incomplete_scanners=True,
        )

        assert code == 1

    def test_the_message_names_the_scanner_and_both_counts(self):
        """An operator has to be able to tell this from a missing tool.

        The pre-existing message for ERROR/MISSING reads "did not run", which is
        false here -- the scanner ran and reported PASSED. The status string in
        the pair therefore has to carry the counts, or the report tells the
        operator to install a tool that is already installed.

        No ``tmp_path``: this asserts on the pairs the gate returns, which is
        where the numbers are data. That the counts also survive into a real
        ``ash.flat.json`` is a different claim with a different failure mode --
        ``ReportContentEmitter.get_scanner_results()`` enumerates its keys by
        hand -- and it is pinned separately in
        ``tests/unit/core/test_partial_target_coverage_visibility.py``.
        """
        listed = _listed(
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=4,
                )
            ]
        )

        assert len(listed) == 1
        name, status = listed[0]
        assert name == "cdk-nag"
        assert "4" in status and "10" in status, (
            f"the operator needs both counts to judge severity; got {status!r}"
        )

    def test_full_coverage_stays_at_exit_zero(self, tmp_path):
        """The control. Ten of ten evaluated is a complete scan."""
        code = _exit_code(
            tmp_path,
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=0,
                )
            ],
            fail_on_incomplete_scanners=True,
        )

        assert code == 0


class TestDefaultPathIsUntouched:
    """This change moves existing opt-in users from 0 to 1. It must move nobody else."""

    def test_partial_coverage_without_the_flag_exits_zero(self, tmp_path):
        """Same input as the tripping case, flag absent, exit 0.

        The gate is opt-in and stays opt-in. A repository whose cdk-nag loses 4
        of 10 targets keeps exiting 0 unless it asked to be told.
        """
        code = _exit_code(
            tmp_path,
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=4,
                )
            ],
        )

        assert code == 0

    def test_flag_explicitly_false_exits_zero(self, tmp_path):
        """``--no-fail-on-incomplete-scanners`` is honoured, not merely the default."""
        code = _exit_code(
            tmp_path,
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=4,
                )
            ],
            fail_on_incomplete_scanners=False,
        )

        assert code == 0

    def test_partial_coverage_still_counts_as_having_run(self):
        """``cli.merge._completed`` asks a narrower question and must keep asking it.

        This replaces a test that could not fail. Its predecessor built a
        ``ScannerMetrics`` with ``status=PASSED`` handed in and then asserted the
        status was PASSED, which pins only that ``incomplete_scanners`` does not
        mutate its argument -- something nobody proposed and no production code
        does. It exercised none of the two behaviors it claimed to protect.

        The behavior worth protecting is the one below. Two checks both mean
        "incomplete" and answer different questions:

        * ``_completed`` asks whether a scanner ran **at all**, and
          ``_verify_shard_contributions`` refuses a merge outright where a shard
          completed none of the scanners it owned. A scanner that read 6 of 10
          targets ran.
        * ``incomplete_scanners`` asks whether everything the scanner was given was
          evaluated. It answers no, and that is what the opt-in exit-code gate acts
          on.

        Why this is falsifiable, which an earlier note in ``tests/unit/cli/
        test_merge.py`` denied. That note said ``ScannerTargetStatusInfo``
        "declares no target counters at all, so it cannot see coverage even if
        someone wired it to try", making the boundary structural. The model sets
        ``extra="allow"``: counters written into ``scanner_results`` land in
        ``model_extra``, and the assertion below measures that ``getattr`` finds
        them. So ``_completed`` CAN read coverage, it simply does not, and
        reimplementing it to consult these counters fails this test.

        The counters are asserted present before the verdict is. Without that, a
        model that silently dropped the extras would make the ``_completed``
        assertion pass for the wrong reason -- there would be no coverage to
        ignore.
        """
        from automated_security_helper.cli.merge import _completed
        from automated_security_helper.models.asharp_model import (
            ScannerTargetStatusInfo,
        )

        entry = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED,
            targets_attempted=10,
            targets_failed=4,
        )

        assert getattr(entry, "targets_failed", None) == 4, (
            "the counters must reach the entry, or _completed has nothing to "
            "ignore and this test cannot fail"
        )
        assert _completed(entry) is True, (
            "a scanner that evaluated 6 of its 10 targets ran; reading its "
            "coverage here would make _verify_shard_contributions refuse healthy "
            "shards, failing the merge far from the code that caused it"
        )

    def test_a_scanner_that_evaluated_nothing_still_does_not_count_as_having_run(self):
        """The negative control for the assertion above.

        Without it, ``_completed`` could be ``return True`` and the test above
        would pass. ERROR is the status a target reaches when it lost everything,
        and that one really does mean the scanner did not run.
        """
        from automated_security_helper.cli.merge import _completed
        from automated_security_helper.models.asharp_model import (
            ScannerTargetStatusInfo,
        )

        entry = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            targets_attempted=10,
            targets_failed=10,
        )

        assert _completed(entry) is False


class TestTriStateSurvivesTheGate:
    """``None`` / ``0`` / positive must stay three distinct answers here."""

    def test_none_attempted_is_not_a_shortfall(self):
        """The nine non-tracking scanners must not all become failures.

        bandit, checkov, semgrep, grype, syft, detect-secrets, opengrep, cfn-nag
        and npm-audit report no target counts at all. Reading ``None`` as
        "attempted 0, so everything was lost" would fail every scan on every
        repository the moment the flag was turned on.
        """
        assert _listed([_metric("bandit", targets_attempted=None)]) == []

    def test_none_attempted_with_a_nonzero_failure_count_is_not_a_shortfall(self):
        """A failure count without an attempt count is a producer bug, not a verdict.

        There is no honest denominator to report, so the gate declines to invent
        one rather than emitting "3 of None".
        """
        assert (
            _listed([_metric("bandit", targets_attempted=None, targets_failed=3)]) == []
        )

    def test_zero_attempted_and_zero_failed_is_not_a_shortfall(self):
        """ "Tracked, attempted none, lost none" -- nothing was lost.

        ``determine_status`` already routes attempted-zero to SKIPPED, which the
        gate deliberately tolerates; this asserts the coverage arm does not
        second-guess it.
        """
        assert (
            _listed([_metric("cdk-nag", targets_attempted=0, targets_failed=0)]) == []
        )

    def test_a_positive_failure_count_with_a_known_denominator_is_a_shortfall(self):
        """The one arrangement that is genuinely lost coverage."""
        listed = _listed([_metric("cdk-nag", targets_attempted=10, targets_failed=4)])

        assert len(listed) == 1
        assert listed[0][0] == "cdk-nag"

    def test_non_integer_counters_are_not_read_as_counts(self):
        """A MagicMock metric must not trip the gate.

        Not hypothetical: the sibling test module's ``_metric`` builds MagicMocks,
        whose every attribute is present and truthy. Without this guard,
        ``test_helper_lists_only_incomplete_scanners_with_statuses`` -- which
        asserts that a PASSED bandit is absent from the list -- would start
        seeing bandit as a partial-coverage failure. The same guard is what
        ``unified_metrics.target_counts`` already applies to the serialized
        counters, for the same reason.
        """
        mock_metric = MagicMock()
        mock_metric.scanner_name = "bandit"
        mock_metric.status = ScannerStatus.PASSED.value

        assert _listed([mock_metric]) == [], (
            "a metric whose counters are not integers makes no coverage claim"
        )

    def test_a_boolean_counter_is_not_read_as_one_or_zero(self):
        """``True`` is an ``int`` subclass. Reading it as 1 would invent a target.

        Deliberately NOT built through ``ScannerMetrics``. An earlier version of
        this test was, and it failed for the wrong reason: pydantic coerces
        ``True`` to a genuine ``int`` 1 on an ``int | None`` field, so a bool
        never survives the model boundary and the assertion was describing a
        state the model cannot hold.

        The guard is reachable, though, because ``incomplete_scanners`` reads its
        rows off whatever ``get_unified_scanner_metrics`` returns and reaches the
        counters by ``getattr``. A plain object exercises that path. This is the
        same hazard ``unified_metrics.target_counts`` guards against for real --
        it reads the counters out of ``additional_reports``, which is parsed JSON,
        where a ``true`` arrives as an actual ``bool``.
        """
        row = SimpleNamespace(
            scanner_name="cdk-nag",
            status=ScannerStatus.PASSED.value,
            targets_attempted=True,
            targets_failed=True,
        )

        assert isinstance(row.targets_attempted, bool), (
            "the point of this test is a real bool reaching the gate"
        )
        assert _listed([row]) == []

    @pytest.mark.parametrize("bad_failed", [None, "4", 4.0, True])
    def test_a_valid_attempt_count_with_an_unusable_failure_count(self, bad_failed):
        """Each counter is guarded independently, and this is the second guard.

        Added because it was missing: the branch that rejects an unusable
        ``targets_failed`` was the one uncovered line in the new code after the
        first full-suite run. Every other case in this class is rejected on the
        ATTEMPT count and returns before the failure count is ever examined, so
        the second guard was dead as far as the tests were concerned -- present,
        plausible, and never executed.

        The state is reachable rather than theoretical: a producer that writes an
        attempt count and then a malformed failure count -- null, a string, a
        float, a bool -- lands exactly here. ``4.0`` is included because a float
        is not an ``int`` and would otherwise flow into the comparison; ``True``
        because bool is an ``int`` subclass and must be rejected on this counter
        for the same reason it is on the other one.

        A shortfall needs both numbers to be trustworthy, so an unusable failure
        count yields no claim rather than a guess.
        """
        row = SimpleNamespace(
            scanner_name="cdk-nag",
            status=ScannerStatus.PASSED.value,
            targets_attempted=10,
            targets_failed=bad_failed,
        )

        assert _listed([row]) == [], (
            f"targets_failed={bad_failed!r} is not a usable count, so there is no "
            f"honest shortfall to report"
        )


class TestTotalLossKeepsItsOldReport:
    """ERROR and MISSING have to read exactly as they did, message included."""

    @pytest.mark.parametrize(
        "status", [ScannerStatus.ERROR.value, ScannerStatus.MISSING.value]
    )
    def test_status_based_incompleteness_reports_the_bare_status(self, status):
        """No counts appended. These scanners were already covered by the gate.

        Total loss also satisfies the coverage condition -- ``targets_failed >=
        targets_attempted`` implies ``targets_failed > 0`` -- so without an
        explicit precedence the ERROR row would gain a parenthetical and every
        existing assertion on the message would break.
        """
        listed = _listed(
            [_metric("cdk-nag", status, targets_attempted=10, targets_failed=10)]
        )

        assert listed == [("cdk-nag", status)]

    def test_a_scanner_is_never_listed_twice(self):
        """One scanner, one row, whichever arm selected it."""
        listed = _listed(
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.ERROR.value,
                    targets_attempted=10,
                    targets_failed=10,
                )
            ]
        )

        assert len(listed) == 1

    def test_skipped_with_no_counts_still_never_trips_the_gate(self):
        """SKIPPED is how sharding excludes another shard's scanners.

        Guarded in the sibling module for the status arm; repeated here because
        the coverage arm is a second, independent route to the same list, and a
        SKIPPED shard sibling reaching it would fail every shard of every
        sharded scan.
        """
        assert _listed([_metric("semgrep", ScannerStatus.SKIPPED.value)]) == []


class TestOrderingAndMixedRuns:
    """A real run has several scanners in several states."""

    def test_both_arms_appear_in_scanner_name_order(self):
        """The list order is asserted because operators read it as a list."""
        listed = _listed(
            [
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric(
                    "cdk-nag",
                    ScannerStatus.PASSED.value,
                    targets_attempted=10,
                    targets_failed=4,
                ),
                _metric("grype", ScannerStatus.MISSING.value),
                _metric("semgrep", ScannerStatus.SKIPPED.value),
            ]
        )

        assert [name for name, _ in listed] == ["cdk-nag", "grype"]

    def test_a_failed_scanner_with_partial_coverage_is_still_a_shortfall(self):
        """FAILED means "ran and found problems", which does not mean "saw everything".

        A scanner can report findings from the targets it managed to read and
        still have lost others. The findings gate would fail this run anyway, but
        not for this reason, and an operator clearing the listed findings would
        believe the scan then clean.
        """
        listed = _listed(
            [
                _metric(
                    "cdk-nag",
                    ScannerStatus.FAILED.value,
                    targets_attempted=10,
                    targets_failed=4,
                    actionable=3,
                )
            ]
        )

        assert len(listed) == 1
        assert listed[0][0] == "cdk-nag"

    def test_no_results_is_still_empty(self):
        assert incomplete_scanners(None) == []


def _listed(metrics):
    """``incomplete_scanners`` over *metrics*."""
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=metrics):
        return incomplete_scanners(MagicMock())


def _rollup_model(reports: dict):
    """A results stand-in carrying serialized per-target reports and nothing derived.

    Everything above this line injects ``ScannerMetrics`` rows by patching
    ``get_unified_scanner_metrics``, which is the right shape for pinning the gate's
    own logic and the wrong shape for pinning that the gate and the rollup agree. The
    class below uses this instead: only ``additional_reports`` is populated, and the
    counters and the status are both DERIVED by the production code under test.

    ``scanner_results`` is left empty and ``sarif.runs`` is empty so no severity count
    can decide the status -- otherwise a fixture that accidentally carried findings
    would return FAILED and an assertion about ERROR would be measuring the findings
    gate.
    """
    model = MagicMock()
    model.sarif = MagicMock()
    model.sarif.runs = []
    model.scanner_results = {}
    model.ash_config = MagicMock()
    model.ash_config.global_settings.severity_threshold = "MEDIUM"
    model.ash_config.get_plugin_config.return_value = None
    model.additional_reports = reports
    return model


def _target_report(status: str, attempted=None, failed=None, name="cdk-nag") -> dict:
    """One serialized ``ScanResultsContainer``, as ``ScanResultProcessor`` writes it.

    Dumped with ``exclude_unset=True`` in production, so a scanner that does not track
    targets has no counter keys at all rather than zeroes. Omitting them here rather
    than passing None is what makes the non-tracking control a real control.
    """
    report = {"scanner_name": name, "status": status, "duration": 1.0}
    if attempted is not None:
        report["targets_attempted"] = attempted
    if failed is not None:
        report["targets_failed"] = failed
    return report


class TestTheGateReadsTheRealRollup:
    """End to end from serialized per-target reports to the gate's verdict, unpatched.

    Every other test in this module patches ``get_unified_scanner_metrics`` and hands
    the gate rows it built itself. That leaves the seam where this change's two halves
    meet completely uncovered: one half writes ``targets_attempted``/``targets_failed``
    into ``ScannerMetrics`` from ``additional_reports``, the other reads them here, and
    nothing drove the first into the second. A rename of either serialized key, or a
    rollup that stopped summing across targets, would leave every injected-row test
    green.

    So these assert on ``incomplete_scanners`` with NO patch of the metrics getter.
    ``target_counts``, ``get_scanner_status_info``, ``any_target_errored`` and
    ``get_unified_scanner_metrics`` all run for real.
    """

    def test_partial_coverage_travels_from_the_serialized_reports_to_the_gate(self):
        """The measured shape, derived rather than injected.

        10 attempted and 4 failed on the source tree, which is what a real cdk-nag run
        on this repository writes. The status stays PASSED because
        ``determine_status`` only reports ERROR on total loss, so the counts are the
        only thing that can carry the fact -- and they now arrive through the rollup.
        """
        listed = dict(
            incomplete_scanners(
                _rollup_model(
                    {"cdk-nag": {"source": _target_report("PASSED", 10, 4)}}
                )
            )
        )

        assert "cdk-nag" in listed, (
            "the counters did not survive the trip from additional_reports through "
            "get_unified_scanner_metrics to the gate"
        )
        assert listed["cdk-nag"] == "PASSED (4 of 10 targets unevaluated)"

    def test_a_total_loss_on_one_tree_arrives_as_error_carrying_its_counts(self):
        """Both halves of this change, in one assertion, through the real rollup.

        Source 2 attempted 0 failed, converted 1 attempted 1 failed. Two things have
        to happen and neither is injected:

        * ``any_target_errored`` has to see the converted tree's ERROR and roll the
          scanner up to ERROR. Reading only ``"source"`` gives PASSED.
        * the routing has to report the SUMMED counts -- 1 of 3 -- rather than the bare
          status, because 1 of 3 is a partial shortfall. Selecting the bare-status arm
          on status alone printed ``cdk-nag: ERROR`` and dropped them, which is exactly
          the case the counts exist for: ERROR alone reads as "the tool is missing".
        """
        listed = dict(
            incomplete_scanners(
                _rollup_model(
                    {
                        "cdk-nag": {
                            "source": _target_report("PASSED", 2, 0),
                            "converted": _target_report("ERROR", 1, 1),
                        }
                    }
                )
            )
        )

        assert listed["cdk-nag"] == "ERROR (1 of 3 targets unevaluated)", (
            f"expected the rolled-up ERROR to carry the summed counts; got "
            f"{listed.get('cdk-nag')!r}"
        )

    def test_total_loss_on_every_tree_still_reports_the_bare_status(self):
        """The precedence control, so the arm above cannot be "always append counts".

        Everything attempted was lost, so the status already says nothing was
        evaluated and a parenthetical would only repeat it.
        """
        listed = dict(
            incomplete_scanners(
                _rollup_model({"cdk-nag": {"source": _target_report("ERROR", 4, 4)}})
            )
        )

        assert listed["cdk-nag"] == "ERROR"

    def test_a_non_tracking_scanner_is_absent_from_the_real_rollup(self):
        """The tri-state control at the seam, not just at the gate.

        The nine scanners that report no counters must derive ``targets_attempted`` as
        None through ``target_counts`` and be absent. Collapsing absence to 0 anywhere
        along the way fails here, which the injected-row version of this control cannot
        detect -- it never runs ``target_counts`` at all.
        """
        reports = {"bandit": {"source": _target_report("PASSED", name="bandit")}}

        assert incomplete_scanners(_rollup_model(reports)) == []

    def test_the_default_exit_code_is_unchanged_through_the_real_rollup(self, tmp_path):
        """The blast-radius guard, measured end to end rather than on injected rows.

        ``_compute_exit_code`` reaches ``incomplete_scanners`` only once
        ``_resolve_fail_on_incomplete_scanners`` returns true, so a partial-coverage run
        that did not ask for the gate exits exactly as it did before. Asserted with the
        real rollup so that a future change routing coverage into the default path is
        caught here and not in somebody's pipeline.
        """
        model = _rollup_model({"cdk-nag": {"source": _target_report("PASSED", 10, 4)}})

        assert dict(incomplete_scanners(model)), (
            "the fixture must be genuinely partial or this asserts nothing"
        )

        opts = _opts(tmp_path, fail_on_findings=False)
        assert _compute_exit_code(model, opts) == 0

        opted_in = _opts(
            tmp_path, fail_on_findings=False, fail_on_incomplete_scanners=True
        )
        assert _compute_exit_code(model, opted_in) == 1
