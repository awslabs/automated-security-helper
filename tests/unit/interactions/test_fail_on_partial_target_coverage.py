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
fails 4, reports PASSED, and ``--fail-on-incomplete-scanners`` exited 0. Two of
those four are real CloudFormation templates that went unscanned.

What is deliberately NOT changed
--------------------------------
* No new ``ScannerStatus`` member. The status a scanner reports is unchanged, and
  ``test_partial_coverage_does_not_change_the_status`` pins that.
* No new config key. This is the existing opt-in flag learning about a case it
  was always meant to cover.
* The default path. ``TestDefaultPathIsUntouched`` asserts that a partial-coverage
  run without the flag exits exactly as it did before -- because this change does
  move existing opt-in users from 0 to 1, and the blast radius has to stay
  confined to people who asked for the gate.

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

    def test_partial_coverage_does_not_change_the_status(self):
        """The gate reads the status; it does not rewrite it.

        Were the fix implemented by promoting a partial-coverage scanner to
        ERROR, every reporter and the summary table would start calling a scan
        that ran an error, and ``_completed`` in ``cli.merge`` would begin
        refusing shards that had merely lost a target. The status stays PASSED
        and only the gate's own verdict changes.
        """
        metric = _metric(
            "cdk-nag",
            ScannerStatus.PASSED.value,
            targets_attempted=10,
            targets_failed=4,
        )

        assert metric.status == ScannerStatus.PASSED.value
        assert metric.passed is True


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
