# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ERROR on any scanned target has to reach the rolled-up scanner status.

WHY THIS FILE EXISTS
--------------------
``ScanPhase`` hands each scanner one task carrying two targets -- the source tree and the
converted tree -- and ``ScanResultProcessor`` writes one serialized container per target under
``additional_reports[scanner][target_type]``. The rolled-up status a human reads comes from
``get_unified_scanner_metrics``, whose loudest branch is ``stats["error"]``, and that flag is
produced by ``get_scanner_status_info``.

``get_scanner_status_info`` never consulted a per-target ERROR at all. Its branches are, in
order: the scanner-level ``"None"`` report, else the ``scanner_results`` entry, else the
``"source"`` report. Once ``scanner_results`` carries the scanner -- the first rebuild has no row
for a scanner whose trees all ran clean, but the completeness check writes an ERROR row for one
with an ERROR tree, and every later rebuild reads the row the first one wrote -- that middle branch
wins and read only ``excluded`` and ``dependencies_satisfied``: ``error`` stayed False and the
``"source"`` fallback was unreachable. The cells below build their models by hand with an empty
``scanner_results``; ``test_partial_loss_status_through_scan_phase`` runs the rows a scan writes.
So a scanner that passed on the source tree and errored
on the converted tree rolled up to PASSED: the ERROR container was written, serialized, and read
by nothing. An ERROR means no rule was evaluated on that target, so this is the silent-pass shape
the surrounding code was written against, arriving through the target dimension instead of through
the severity counts.

THIS IS A STATUS CHANGE, AND IT IS NOT OPTED IN
-----------------------------------------------
Worth stating plainly here because sibling files say partial coverage does NOT move a status, and
both are true of different conditions. ``error`` is the FIRST branch in both
``get_scanner_status`` and ``get_unified_scanner_metrics``, so for an affected scanner the summary
table, every report format and ``ash.flat.json``'s ``passed`` all change, on every scan, with no
flag. The CHANGELOG carries it as a breaking change. Measured on this repository nothing changes,
because cdk-nag's only target report is the source tree and it carries PASSED -- a repository is
affected only where some tree lost every target it attempted.

WHAT WAS ALREADY HANDLED, AND WHY THAT WAS NOT ENOUGH
-----------------------------------------------------
Two adjacent guards already existed and neither one covers this:

* ``ScanResultsContainer.determine_status`` returns ERROR when a tracking scanner failed every
  target it attempted. It did its job here -- the converted container really does carry
  ``status="ERROR"``. The loss is downstream of it.
* ``scanner_evaluated_nothing`` reads across EVERY target report, and documents why: only one
  of the two targets may have been empty. It is the correct quantifier applied to the wrong
  fact, and the asymmetry between the two functions is exactly where the defect lived.

ASSERTIONS ARE ON THE PRESENCE OF ERROR, NOT ON THE ABSENCE OF PASSED
--------------------------------------------------------------------
"The status is no longer PASSED" would also be satisfied by FAILED, SKIPPED or MISSING, and by
a scanner disappearing from the metrics list altogether. Each test below names the status it
requires.

MISSING ON ANY TARGET IS READ THE SAME WAY
------------------------------------------
``dependencies_missing`` is read across every target too. A dependency checked before the
scanner runs is a fact about the whole run, and the scanner-level report states it. But the
executor records MISSING per target when ``scan()`` returns a falsy value, so a scanner can
find its dependencies unavailable on the converted tree after evaluating the source tree. No
rule ran against the converted files, and a row reading PASSED for that run claims coverage
it does not have (contract clause 3i). The MISSING report's ``status`` is what is read, not
``_status_info_from_report``, and the row's ``missing_reason`` names the tree that went
unevaluated when another tree was evaluated.

``excluded`` stays scanner-level. Widening it to "any target" would let one target with an
unrecognized status -- which ``_status_info_from_report`` maps to ``excluded=True`` for
backward compatibility -- mark the whole scanner as operator-excluded.
"""

from unittest.mock import MagicMock

import pytest


def _model_with_target_statuses(
    source_status: str,
    converted_status: str,
    *,
    source_fields: dict | None = None,
    converted_fields: dict | None = None,
):
    """An AshAggregatedResults stand-in carrying one serialized container per target.

    The report shape is the one ``ScanResultProcessor`` actually writes: it dumps the
    container with ``exclude_unset=True``, so only fields a scanner assigned are present.
    That is why ``excluded`` is absent here rather than set to False -- its absence is what
    makes ``_status_info_from_report`` trust the field.

    ``sarif.runs`` is empty so every severity count is zero. That keeps the ``actionable > 0``
    branch out of the way, which matters: it is checked before the did-not-run branches, and a
    fixture that accidentally carried findings would return FAILED and pass a test that is
    supposed to be about ERROR.

    ``source_fields`` and ``converted_fields`` add fields to one target's report, such as
    the ``missing_reason`` and ``dependencies_satisfied`` the executor writes on a MISSING
    container.
    """
    model = MagicMock()
    model.sarif = MagicMock()
    model.sarif.runs = []
    model.scanner_results = {}
    # Real values, not bare MagicMock attributes. ``ScannerMetrics.threshold`` is typed as a
    # str and ``get_scanner_threshold_info`` reads it straight off the config, so an
    # auto-created mock attribute reaches pydantic and raises a validation error before any
    # status is computed -- a failure that looks like the defect but is the fixture.
    model.ash_config = MagicMock()
    model.ash_config.global_settings.severity_threshold = "MEDIUM"
    model.ash_config.get_plugin_config.return_value = None
    model.additional_reports = {
        "cdk-nag": {
            "source": {
                "scanner_name": "cdk-nag",
                "status": source_status,
                "targets_attempted": 2,
                "targets_failed": 0,
                "duration": 1.5,
                **(source_fields or {}),
            },
            "converted": {
                "scanner_name": "cdk-nag",
                "status": converted_status,
                "targets_attempted": 1,
                "targets_failed": 1,
                "duration": 0.5,
                **(converted_fields or {}),
            },
        }
    }
    return model


class TestErrorOnAnyTargetReachesTheRollup:
    def test_status_info_reports_error_when_only_the_converted_target_errored(self):
        """The measured shape: source PASSED, converted ERROR.

        This is the narrowest statement of the defect. ``get_scanner_status_info`` returns the
        ``error`` flag that every rolled-up status ultimately keys on, so if it is False here
        nothing downstream can recover the fact.
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses("PASSED", "ERROR")

        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert error is True, (
            "an ERROR on the converted target did not set the error flag; the container was "
            "written and never read"
        )
        # Named explicitly so a future change that produces error=True by routing through the
        # excluded/missing branches instead fails here rather than passing quietly.
        assert excluded is False
        assert dependencies_missing is False

    def test_status_info_reports_error_when_only_the_source_target_errored(self):
        """The mirror case, so the fix cannot be a source-versus-converted swap.

        Reading only ``"converted"`` would satisfy the test above and break this one. Both
        directions are asserted because "any target" is the property being fixed, not "the
        other target".
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses("ERROR", "PASSED")

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "cdk-nag"
        )

        assert error is True, "an ERROR on the source target did not set the error flag"

    def test_get_scanner_status_returns_error_for_a_converted_target_error(self):
        """The string status, which is the other public route to the same fact.

        ``get_scanner_status`` and ``get_unified_scanner_metrics`` are two functions answering
        "what is this scanner's status", and the module's own comments require they not
        disagree. Asserting both means a fix applied to one of them cannot leave the other
        reporting PASSED.
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses("PASSED", "ERROR")

        assert (
            ScannerStatisticsCalculator.get_scanner_status(model, "cdk-nag") == "ERROR"
        )

    def test_unified_metrics_rolls_a_converted_target_error_up_to_error(self):
        """The status a human reads off the summary table, and the ``passed`` flag with it.

        ``ScannerMetrics.passed`` is True for PASSED, SKIPPED and MISSING, so a row that
        rolled up wrong renders green and is also serialized into ``ash.flat.json`` as
        ``passed: true``. Both are asserted: the status is what the table shows, and
        ``passed`` is what a machine consumer gates on.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_target_statuses("PASSED", "ERROR")

        metrics = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}

        assert "cdk-nag" in metrics, (
            "the scanner vanished from the metrics list entirely"
        )
        assert metrics["cdk-nag"].status == "ERROR"
        assert metrics["cdk-nag"].passed is False

    @pytest.mark.parametrize("converted_status", ["PASSED", "FAILED", "SKIPPED"])
    def test_a_non_error_converted_target_does_not_invent_an_error(
        self, converted_status: str
    ):
        """The negative control, without which the fix could be ``error = True``.

        A test suite that only checks ERROR-is-visible is satisfied by a function that always
        reports an error. FAILED and SKIPPED are included alongside PASSED because both are
        verdicts a target legitimately reaches, and neither means "nothing was evaluated".
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses("PASSED", converted_status)

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "cdk-nag"
        )

        assert error is False, (
            f"a converted target reporting {converted_status} was read as an error"
        )


#: What the executor writes on a target's container when ``scan()`` returns a falsy value:
#: the plugin's own reason, which names no tree, and the dependency flag set to False.
_GONE_ON_THIS_TREE = {
    "missing_reason": "the rule pack it needs could not be loaded",
    "dependencies_satisfied": False,
}


class TestMissingOnAnyTargetReachesTheRollup:
    def test_status_info_reports_missing_when_only_the_converted_target_was_missing(
        self,
    ):
        """The measured shape: source PASSED, converted MISSING, and the row read PASSED."""
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses(
            "PASSED", "MISSING", converted_fields=_GONE_ON_THIS_TREE
        )

        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is True, (
            "a MISSING converted target did not set dependencies_missing; the scanner "
            "reads as having evaluated both trees"
        )
        assert excluded is False
        assert error is False

    def test_status_info_reports_missing_when_only_the_source_target_was_missing(self):
        """The mirror case, so the fix cannot be a swap of which report is read."""
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses(
            "MISSING", "PASSED", source_fields=_GONE_ON_THIS_TREE
        )

        _, dependencies_missing, _ = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is True

    def test_a_row_claiming_satisfied_dependencies_does_not_hide_a_missing_target(
        self,
    ):
        """The ``scanner_results`` branch, which a results file read back takes.

        A row rebuilt before per-target MISSING was read carries
        ``dependencies_satisfied: true`` for this run. The target report still says
        MISSING, and that is what decides.
        """
        from automated_security_helper.core.enums import ScannerStatus
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )
        from automated_security_helper.models.asharp_model import (
            ScannerTargetStatusInfo,
        )

        model = _model_with_target_statuses(
            "PASSED", "MISSING", converted_fields=_GONE_ON_THIS_TREE
        )
        model.scanner_results = {
            "cdk-nag": ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, dependencies_satisfied=True
            )
        }

        _, dependencies_missing, _ = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is True

    def test_get_scanner_status_returns_missing_for_a_converted_target_missing(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses(
            "PASSED", "MISSING", converted_fields=_GONE_ON_THIS_TREE
        )

        assert (
            ScannerStatisticsCalculator.get_scanner_status(model, "cdk-nag")
            == "MISSING"
        )

    def test_unified_metrics_roll_a_converted_target_missing_up_to_missing(self):
        """The row a human and the completeness gate read, with the tree named.

        The plugin's reason says what was unavailable and not where, and the source
        tree was evaluated. Without the tree, the row tells the operator nothing was
        scanned.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_target_statuses(
            "PASSED", "MISSING", converted_fields=_GONE_ON_THIS_TREE
        )

        metrics = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}

        row = metrics["cdk-nag"]
        assert row.status == "MISSING", row
        assert row.dependencies_missing is True, row
        assert row.missing_reason == (
            "on the converted files: the rule pack it needs could not be loaded"
        ), row

    def test_a_scanner_missing_on_every_target_keeps_the_reason_as_recorded(self):
        """Control: no tree was evaluated, so naming one would add nothing."""
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_target_statuses(
            "MISSING",
            "MISSING",
            source_fields=_GONE_ON_THIS_TREE,
            converted_fields=_GONE_ON_THIS_TREE,
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "MISSING", row
        assert row.missing_reason == "the rule pack it needs could not be loaded", row

    @pytest.mark.parametrize("converted_status", ["PASSED", "FAILED", "SKIPPED"])
    def test_a_non_missing_converted_target_does_not_invent_a_missing_dependency(
        self, converted_status: str
    ):
        """The negative control, without which the fix could be ``dependencies_missing = True``."""
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses("PASSED", converted_status)

        _, dependencies_missing, _ = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is False, (
            f"a converted target reporting {converted_status} was read as MISSING"
        )


def _model_with_findings_on_the_source_tree(build, converted: dict):
    """tool-a FAILED on the source tree with one HIGH finding, and *converted* as its
    converted tree's report. *build* is the ``model_with_one_high_finding`` fixture: a
    real results model, because the finding has to reach the actionable count through
    the SARIF."""
    return build(
        {
            "tool-a": {
                "source": {
                    "scanner_name": "tool-a",
                    "status": "FAILED",
                    "exit_code": 1,
                },
                "converted": {"scanner_name": "tool-a", **converted},
            }
        },
        scanner="tool-a",
        uri="src/app.py",
    )


class TestFindingsOutrankAMissingTreeWithoutHidingIt:
    """FAILED on the source tree and MISSING on the converted one stays FAILED.

    Findings outrank the did-not-run statuses, so the row keeps FAILED. The converted
    tree still went unevaluated, and a tool-level cause recorded for the run is never
    dropped (contract clause 3i): the row carries its missing_reason, naming the
    tree, and the completeness gate lists the scanner.
    """

    def test_the_failed_row_carries_the_missing_trees_reason(
        self, model_with_one_high_finding
    ):
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_findings_on_the_source_tree(
            model_with_one_high_finding, {"status": "MISSING", **_GONE_ON_THIS_TREE}
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "FAILED", row
        assert row.dependencies_missing is True, row
        assert row.missing_reason == (
            "on the converted files: the rule pack it needs could not be loaded"
        ), row
        assert row.exit_code == 1, row

    def test_the_completeness_gate_lists_it_with_the_reason(
        self, model_with_one_high_finding
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = _model_with_findings_on_the_source_tree(
            model_with_one_high_finding, {"status": "MISSING", **_GONE_ON_THIS_TREE}
        )

        incomplete = scan_incompleteness(model, gate=True)

        assert ("tool-a", "FAILED (MISSING on some files)") in incomplete.scanners, (
            incomplete
        )
        assert dict(incomplete.missing_reasons).get("tool-a") == (
            "on the converted files: the rule pack it needs could not be loaded"
        ), incomplete

    def test_the_payload_row_has_the_raw_status_and_names_the_unevaluated_tree(
        self, model_with_one_high_finding
    ):
        """The MCP row for FAILED beside a MISSING tree, measured through ``to_payload``.

        ``status`` is the bare rolled-up token, FAILED, and the display string with the
        qualifier is in ``detail``. No target counts are recorded, so the row is not a
        partial-coverage claim by its counts; its ``reason`` is the token the writer
        gives a status the per-scanner pass accepts (PASSED, FAILED, SKIPPED).
        """
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = _model_with_findings_on_the_source_tree(
            model_with_one_high_finding, {"status": "MISSING", **_GONE_ON_THIS_TREE}
        )

        (row,) = scan_incompleteness(model, gate=True).to_payload()[
            "incomplete_scanners"
        ]

        assert row == {
            "scanner": "tool-a",
            "status": "FAILED",
            "reason": "partial_coverage",
            "detail": "FAILED (MISSING on some files)",
        }, row

    def test_a_failed_scanner_whose_trees_both_ran_is_not_listed(
        self, model_with_one_high_finding
    ):
        """Control: findings alone are not incompleteness."""
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = _model_with_findings_on_the_source_tree(
            model_with_one_high_finding, {"status": "PASSED"}
        )

        (row,) = get_unified_scanner_metrics(model)
        assert row.status == "FAILED", row
        assert row.missing_reason is None, row
        assert not scan_incompleteness(model, gate=True).scanners


#: A tree that lost 4 of its 10 targets and surfaced nothing: determine_status grades it
#: ERROR because its surviving findings, none, pass the severity gate.
_PARTIAL_LOSS_ERROR_TREE = {
    "scanner_name": "tool-a",
    "status": "ERROR",
    "targets_attempted": 10,
    "targets_failed": 4,
    "duration": 1.0,
}


def _lost_tree_beside_a_failed_tree(build, lost_tree: dict):
    """*lost_tree* as the source tree's report, and a converted tree that is FAILED on the
    one HIGH finding (3 targets attempted, none lost). The SARIF result is at a path under
    the converted work dir, so the fixture says which tree the finding is on."""
    return build(
        {
            "tool-a": {
                "source": lost_tree,
                "converted": {
                    "scanner_name": "tool-a",
                    "status": "FAILED",
                    "targets_attempted": 3,
                    "targets_failed": 0,
                },
            }
        },
        scanner="tool-a",
        uri="converted/app.py.json",
    )


class TestAPartialLossTreeDoesNotOutrankAFailedSibling:
    """Findings outrank lost coverage except total loss, at the scanner level as on one tree.

    ``determine_status`` grades a tree that lost SOME of its targets FAILED when its
    surviving findings fail the gate, and ERROR only when they pass it. The scanner-level
    rollup follows the same rule, so the status a gate sees does not depend on which tree
    the finding landed on: 13 attempted, 4 lost and one HIGH finding reads FAILED whether
    the loss and the finding sit on one tree or on two. That is also what the
    findings-outrank-MISSING cell above pins for a tree that evaluated nothing. A tree that
    lost EVERY target it attempted evaluated nothing and still outranks the findings. The
    partial loss stays visible through ``incomplete_scanners`` with its denominator, not
    through status precedence.
    """

    def test_partial_loss_tree_plus_failed_tree_rolls_up_failed_with_the_loss_listed(
        self, model_with_one_high_finding
    ):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = _lost_tree_beside_a_failed_tree(
            model_with_one_high_finding, _PARTIAL_LOSS_ERROR_TREE
        )

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "tool-a"
        )
        (row,) = get_unified_scanner_metrics(model)

        assert error is False, "a partial loss set the rolled-up error flag"
        assert row.status == "FAILED", row
        assert row.passed is False, row
        assert row.high == 1, row
        assert row.actionable == 1, row
        assert (row.targets_attempted, row.targets_failed) == (13, 4), row
        # Visibility is pinned with the precedence: the gate still lists the scanner,
        # with the denominator the FAILED status does not carry.
        incomplete = scan_incompleteness(model, gate=True)
        assert (
            "tool-a",
            "FAILED (4 of 13 targets unevaluated)",
        ) in incomplete.scanners, incomplete

    def test_the_same_counts_and_finding_on_one_tree_read_the_same(self):
        """The per-tree arm of the rule, so the two-tree cell has a same-tree twin."""
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        container = ScanResultsContainer()
        container.record_target_attempt(13)
        for index in range(4):
            container.record_target_failure(f"target-{index}", "not evaluated")
        container.severity_counts.high = 1

        assert container.determine_status("MEDIUM").value == "FAILED"

    def test_a_total_loss_tree_still_outranks_a_failed_sibling(
        self, model_with_one_high_finding
    ):
        """The boundary of the rule: a tree that evaluated nothing is still ERROR."""
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _lost_tree_beside_a_failed_tree(
            model_with_one_high_finding,
            {**_PARTIAL_LOSS_ERROR_TREE, "targets_failed": 10},
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "ERROR", row
        assert row.high == 1, row

    def test_a_partial_loss_tree_beside_a_clean_sibling_is_still_error(self):
        """Without findings anywhere, nothing outranks the loss."""
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_target_statuses("ERROR", "PASSED")
        model.additional_reports["cdk-nag"]["source"].update(
            targets_attempted=10, targets_failed=4
        )
        model.additional_reports["cdk-nag"]["converted"].update(
            targets_attempted=3, targets_failed=0
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "ERROR", row


class TestAReportWithUnsatisfiedDependenciesIsMissing:
    """A target report that says its dependencies were unsatisfied is a missing tree.

    A scanner whose scan() override records its tool absent and still returns a
    report leaves that target's report PASSED with ``dependencies_satisfied: false``.
    No rule ran for want of the tool, whatever status the report reached, so the
    aggregation reads it as MISSING, as it reads a MISSING status.
    """

    def test_status_info_reads_the_unsatisfied_report_as_missing(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses(
            "PASSED", "PASSED", converted_fields=_GONE_ON_THIS_TREE
        )

        _, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is True
        assert error is False

    def test_the_row_is_missing_and_names_the_tree(self):
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model_with_target_statuses(
            "PASSED", "PASSED", converted_fields=_GONE_ON_THIS_TREE
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "MISSING", row
        assert row.missing_reason == (
            "on the converted files: the rule pack it needs could not be loaded"
        ), row

    def test_a_report_with_satisfied_dependencies_is_not_missing(self):
        """Control: the field read, not its presence."""
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        model = _model_with_target_statuses(
            "PASSED", "PASSED", converted_fields={"dependencies_satisfied": True}
        )

        _, dependencies_missing, _ = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "cdk-nag")
        )

        assert dependencies_missing is False


class TestWhichErrorTreesCountAsAPartialLoss:
    """``target_report_is_partial_loss`` is true of the ERROR ``determine_status`` gives a
    partial loss, and of no other ERROR.

    Counters alone are not enough. The executor writes ERROR over other grades for causes
    of its own -- a killed tool, a ``scan()`` that returned nothing, a tool it could not
    stop -- and those trees keep partial counters. The ERROR a partial loss earns exists
    only when the tree's own findings pass the gate; a recorded ERROR whose own counts
    fail it was written by something else.
    """

    @staticmethod
    def _is_partial_loss(report: dict, threshold: str = "MEDIUM") -> bool:
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        return ScannerStatisticsCalculator.target_report_is_partial_loss(
            report, threshold
        )

    def test_the_partial_loss_error_determine_status_gives(self):
        assert self._is_partial_loss(_PARTIAL_LOSS_ERROR_TREE) is True

    def test_findings_that_pass_the_gate_do_not_change_it(self):
        report = {**_PARTIAL_LOSS_ERROR_TREE, "severity_counts": {"low": 2}}

        assert self._is_partial_loss(report) is True

    def test_an_error_whose_own_findings_fail_the_gate_is_not_one(self):
        """``determine_status`` would have graded this tree FAILED: the ERROR is a
        cause's, written over the grade."""
        report = {**_PARTIAL_LOSS_ERROR_TREE, "severity_counts": {"high": 1}}

        assert self._is_partial_loss(report) is False

    def test_the_gate_is_the_scanners_threshold(self):
        report = {**_PARTIAL_LOSS_ERROR_TREE, "severity_counts": {"medium": 1}}

        assert self._is_partial_loss(report, "MEDIUM") is False
        assert self._is_partial_loss(report, "HIGH") is True

    def test_a_scan_that_returned_nothing_is_not_one(self):
        report = {
            **_PARTIAL_LOSS_ERROR_TREE,
            "raw_results": {"status": "failed", "exception": "Scanner returned None"},
        }

        assert self._is_partial_loss(report) is False

    def test_a_tool_that_could_not_be_stopped_is_not_one(self):
        report = {**_PARTIAL_LOSS_ERROR_TREE, "could_not_stop": "pid 4242"}

        assert self._is_partial_loss(report) is False

    def test_a_total_loss_and_a_report_without_counters_are_not_one(self):
        total_loss = {**_PARTIAL_LOSS_ERROR_TREE, "targets_failed": 10}

        assert self._is_partial_loss(total_loss) is False
        assert (
            self._is_partial_loss({"scanner_name": "tool-a", "status": "ERROR"})
            is False
        )

    def test_a_killed_tree_with_its_finding_rolls_up_error(
        self, model_with_one_high_finding
    ):
        """The timed-out partial tree with a finding, on a model built by hand.

        The finding is on the killed tree itself, so the rollup must not read the loss
        as a graded partial audit and show FAILED for it.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = model_with_one_high_finding(
            {
                "tool-a": {
                    "source": {
                        **_PARTIAL_LOSS_ERROR_TREE,
                        "severity_counts": {"high": 1},
                        "errors": [
                            "tool-a timed out after 300s on source and was killed"
                        ],
                    }
                }
            },
            scanner="tool-a",
            uri="src/app.py",
        )

        (row,) = get_unified_scanner_metrics(model)

        assert row.status == "ERROR", row
        assert row.high == 1, row
