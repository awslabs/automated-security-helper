# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that audited some of its targets ran, in every reader of that fact.

Three readers answer "did this scanner reach a verdict" or "did it lose targets",
and they have to agree:

* ``no_scanner_ran`` (through ``scan_incompleteness``) decides the set-level
  "no scanner reached a verdict" arm. A single-scanner run that lost 4 of 10
  targets with clean survivors grades ERROR, and it evaluated 6 targets, so it
  must not read as a run in which nothing ran.
* ``ScanIncompleteness.partial_coverage`` lists the scanners whose counts show a
  partial audit. ``_partial_coverage`` rejects ``bool`` counters on purpose, and
  this list has to reject them as well.
* A workspace project reports the same facts as a single scan, derived from one
  ``scan_incompleteness`` read.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.interactions.run_ash_scan import scan_incompleteness
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import ProjectRunStatus
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
    _scanner,
)

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _metric(
    status: str,
    *,
    attempted=None,
    failed=0,
) -> ScannerMetrics:
    # model_construct: validation would coerce a bool counter to an int, and the
    # bool cell has to hand the readers exactly what a producer bug would.
    return ScannerMetrics.model_construct(
        scanner_name="cdk-nag",
        status=status,
        actionable=0,
        targets_attempted=attempted,
        targets_failed=failed,
    )


def _facts(metric: ScannerMetrics):
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[metric]):
        return scan_incompleteness(AshAggregatedResults(), gate=True)


class TestAPartialAuditIsARun:
    def test_an_error_scanner_that_lost_some_targets_ran(self):
        facts = _facts(_metric(ScannerStatus.ERROR.value, attempted=10, failed=4))

        assert facts.scanners == (("cdk-nag", "ERROR (4 of 10 targets unevaluated)"),)
        assert facts.no_scanner_ran is False, (
            "6 of 10 targets were evaluated; reporting that no scanner reached a "
            "verdict contradicts the 4 of 10 line printed beside it"
        )

    def test_an_error_scanner_with_no_counts_did_not_run(self):
        # Control: the same ERROR without counts is indistinguishable from a
        # scanner that never started, and stays a run in which nothing ran.
        facts = _facts(_metric(ScannerStatus.ERROR.value))

        assert facts.no_scanner_ran is True

    def test_an_error_scanner_that_lost_every_target_did_not_run(self):
        facts = _facts(_metric(ScannerStatus.ERROR.value, attempted=10, failed=10))

        assert facts.no_scanner_ran is True

    def test_a_missing_scanner_with_partial_counts_did_not_run(self):
        # Only an ERROR status can carry the partial-audit claim.
        facts = _facts(_metric(ScannerStatus.MISSING.value, attempted=10, failed=4))

        assert facts.no_scanner_ran is True


class TestPartialCoverageRejectsBoolCounters:
    def test_a_true_failure_count_is_not_a_partial_audit(self):
        facts = _facts(_metric(ScannerStatus.ERROR.value, attempted=10, failed=True))

        assert facts.partial_coverage == (), (
            "True is not a count of one failed target; _partial_coverage rejects "
            "it and the gate's own reader has to agree"
        )

    def test_a_true_attempt_count_is_not_a_partial_audit(self):
        facts = _facts(_metric(ScannerStatus.ERROR.value, attempted=True, failed=0))

        assert facts.partial_coverage == ()

    def test_integer_counts_are_a_partial_audit(self):
        # Control: the same row with integers is listed.
        facts = _facts(_metric(ScannerStatus.ERROR.value, attempted=10, failed=4))

        assert facts.partial_coverage == ("cdk-nag",)


class TestAWorkspaceProjectReportsOneRead:
    """The coverage fields a workspace project derives from one read.

    All three come from the same read, so they must agree with each other.

    Run through ``_run``, so a change to the wiring in ``_scan_one_project`` (the
    ``gate=`` the coverage read uses, a field dropped, ``no_scanner_ran`` no longer
    reaching ``scan_incomplete``) turns these red.
    """

    @pytest.fixture(autouse=True)
    def _reset(self):
        FakeOrchestrator.built = []
        FakeOrchestrator.behaviour = {}
        yield
        FakeOrchestrator.built = []
        FakeOrchestrator.behaviour = {}

    def test_a_partial_audit_fills_all_three_fields(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "cdk-nag": _scanner("ERROR"),
                "bandit": _scanner("PASSED"),
            },
            "additional_reports": {
                "cdk-nag": {
                    "source": {"targets_attempted": 10, "targets_failed": 4},
                },
            },
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.status == ProjectRunStatus.COMPLETED
        assert entry.incomplete_scanners == ["cdk-nag"]
        assert entry.incomplete_scanner_details == {
            "cdk-nag": "ERROR (4 of 10 targets unevaluated)"
        }
        assert entry.partial_coverage_scanners == ["cdk-nag"]

    @pytest.mark.parametrize(
        ("attempted", "failed", "expected_no_scanner_ran"),
        [
            # The scanner evaluated 6 of 10 targets, so it ran.
            (10, 4, False),
            # Control: it lost every target, so nothing ran.
            (10, 10, True),
        ],
    )
    def test_a_partial_audit_that_is_the_only_scanner_that_ran(
        self, tmp_path, attempted, failed, expected_no_scanner_ran
    ):
        """No PASSED scanner beside it to make the two rules agree by accident.

        ``--scanners cdk-nag`` records every other scanner SKIPPED, so the partial
        audit is the only row that can answer the set-level question. The project
        has to answer as ``ash --source-dir P`` does.

        ``scan_incomplete`` is True in both rows, but not because of
        ``no_scanner_ran``: the ``cdk-nag`` row in ``incomplete_scanners`` already
        sets it. That the set-level answer alone decides ``scan_incomplete`` is
        pinned by ``test_no_scanner_ran_alone_decides_scan_incomplete``.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "cdk-nag": _scanner("ERROR"),
                "bandit": _scanner("SKIPPED", excluded=True),
            },
            "additional_reports": {
                "cdk-nag": {
                    "source": {
                        "targets_attempted": attempted,
                        "targets_failed": failed,
                    },
                },
            },
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.no_scanner_ran is expected_no_scanner_ran
        assert entry.incomplete_scanners == ["cdk-nag"]
        assert entry.scan_incomplete is True

    def test_no_scanner_ran_alone_decides_scan_incomplete(self, tmp_path):
        """The all-SKIPPED project, where no per-scanner row exists to set it.

        Nothing is listed in ``incomplete_scanners`` and nothing is stale, so the
        workspace outcome's ``scan_incomplete`` can only come from the set-level
        answer reaching it. The control is the same project with the gate off: the
        fact stays, the verdict does not.
        """
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("SKIPPED", excluded=True)},
        }

        entry = _run(tmp_path, plan).payload.projects[0]
        gate_off = _run(
            tmp_path, plan, fail_on_incomplete_scanners=False
        ).payload.projects[0]

        assert entry.incomplete_scanners == []
        assert entry.stale_content_databases == []
        assert entry.no_scanner_ran is True
        assert entry.scan_incomplete is True
        assert gate_off.no_scanner_ran is True
        assert gate_off.scan_incomplete is False

    def test_a_missing_scanner_fills_the_first_two_only(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "cfn-nag": _scanner("MISSING", satisfied=False),
            },
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.incomplete_scanners == ["cfn-nag"]
        assert entry.incomplete_scanner_details == {"cfn-nag": "MISSING"}
        assert entry.partial_coverage_scanners == []

    def test_a_complete_project_fills_none(self, tmp_path):
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "sarif": _sarif(count=0),
            "scanner_results": {"bandit": _scanner("PASSED")},
        }

        entry = _run(tmp_path, plan).payload.projects[0]

        assert entry.incomplete_scanners == []
        assert entry.incomplete_scanner_details == {}
        assert entry.partial_coverage_scanners == []
