# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanPhase's validation-reporting path, exercised against the REAL manager.

Why this file exists
--------------------
``scan_phase.py`` calls ``validation_manager.report_execution_discrepancies``
and ``report_result_completeness``. Neither existed on
``ScannerValidationManager``: both were defined when the call sites were added
(``ba32f87``) and removed by the StateTracker/Checkpointer split that landed
squashed inside PR #412 (``1641742``), whose own message claimed "all external
callers (scan_phase.py, tests) continue to work unchanged".

No existing test caught it, and the reason is the point of this file. The
fixture in ``test_scan_phase.py`` substitutes a bare ``MagicMock`` for the
manager, and a bare Mock fabricates any attribute that is accessed -- it even
had ``mock_val_mgr.report_execution_discrepancies.return_value = {}``, a stub
written for a method that does not exist. A double that agrees with everything
verifies nothing.

So every test here drives a REAL ``ScannerValidationManager``.

What the defect actually costs, which is more than the missing report
--------------------------------------------------------------------
Both call sites sit inside a ``try`` whose handler is ``except Exception``. The
``AttributeError`` is therefore caught, logged at ERROR, and turned into an
ERROR event -- the scan does not crash. But the ``except`` abandons the rest of
the method, and the rest of the method is where
``aggregated_results.validation_checkpoints`` is appended and
``metadata.validation_summary`` is written. Those writes sit OUTSIDE the
``if missing_scanners or unexpected_scanners:`` block, so they are lost for
every scan that hits a discrepancy, not just the report itself.

That is why the assertions below check the checkpoint and the summary as well as
the report. Asserting only on the report would pass as soon as the method stops
raising, while still leaving the larger loss in place.

Reachability
------------
The branch fires only when the expected and completed scanner sets differ, which
a healthy single-project scan never produces -- which is why CI never hit it.
The tests construct the discrepancy directly by registering a scanner as
queued-for-execution and then reporting that nothing completed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


@pytest.fixture
def plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


@pytest.fixture
def phase(plugin_context):
    """A ScanPhase whose validation_manager is the REAL class, not a double."""
    scan_phase = ScanPhase(
        plugin_context=plugin_context,
        plugins=[],
        progress_display=MagicMock(),
    )
    scan_phase.validation_manager = ScannerValidationManager(plugin_context)
    return scan_phase


def _expect_a_scanner_that_never_completes(phase, name="bandit"):
    """Register *name* as queued, so validating completion finds it missing.

    This is the only shape that reaches the reporting call: a scanner the
    validator expected to complete, which did not.
    """
    manager = phase.validation_manager
    manager.update_scanner_state(name, registration_status="registered")
    manager.update_scanner_state(name, enablement_status="enabled")
    manager.update_scanner_state(name, queued_for_execution=True)
    # No _completed_scanners, so the phase reports nothing completed.
    phase._completed_scanners = []
    return name


# ---------------------------------------------------------------------------
# 1. Execution-completion reporting
# ---------------------------------------------------------------------------


def test_execution_discrepancy_report_reaches_the_results(phase):
    """The report the call site asks for must land on the results object."""
    missing = _expect_a_scanner_that_never_completes(phase)
    results = AshAggregatedResults()

    phase._validate_execution_completion(results)

    report = getattr(results.metadata, "execution_discrepancy_report", None)
    assert report, (
        "execution_discrepancy_report is empty; either the call to "
        "report_execution_discrepancies raised and the except Exception handler "
        "swallowed it, or the assignment was guarded by a hasattr() that cannot "
        "be false because ReportMetadata declares the field"
    )
    assert missing in report["missing_scanners"]
    assert report["missing_count"] == 1
    assert (
        report["total_discrepancies"]
        == report["missing_count"] + report["unexpected_count"]
    )
    # Deliberately NOT asserting has_discrepancies is True. It mirrors
    # checkpoint.has_issues(), which tracks *recorded* discrepancies and errors,
    # and a missing scanner does not set that -- see
    # test_missing_scanners_detected in test_validation_checkpointer.py, which
    # pins the same asymmetry on the checkpoint itself. The counts are the field
    # that carries the information here.
    assert "has_discrepancies" in report


def test_a_discrepancy_still_records_its_checkpoint_and_summary(phase):
    """The bigger loss: the writes AFTER the report call, outside the if.

    validation_checkpoints and validation_summary are populated below the
    reporting call but outside the discrepancy branch, so an exception at the
    report call discards them for every scan that has a discrepancy. Asserting
    only on the report would pass while this stayed broken.
    """
    _expect_a_scanner_that_never_completes(phase)
    results = AshAggregatedResults()

    phase._validate_execution_completion(results)

    names = [cp.get("checkpoint_name") for cp in results.validation_checkpoints]
    assert names, (
        "no validation checkpoint recorded; the method aborted into its "
        "except handler before reaching the checkpoint write"
    )
    summary = getattr(results.metadata, "validation_summary", None)
    assert summary and "execution_completion_validation" in summary


def test_no_discrepancy_leaves_the_report_empty(phase):
    """Control: the report is populated only for the discrepancy case.

    Without this, a change that populated the report unconditionally would
    satisfy the two tests above.

    Asserts emptiness rather than absence, and that is forced rather than
    chosen: ReportMetadata DECLARES execution_discrepancy_report with a default
    of {}, so the attribute always exists and "never written" is
    indistinguishable from "written as the default". Emptiness is the strongest
    assertion available, and it still fails a change that writes a populated
    report when nothing was wrong.
    """
    phase._completed_scanners = []
    results = AshAggregatedResults()

    phase._validate_execution_completion(results)

    assert not getattr(results.metadata, "execution_discrepancy_report", None)


# ---------------------------------------------------------------------------
# 2. Result-completeness reporting
# ---------------------------------------------------------------------------


def test_result_completeness_report_reaches_the_results(phase):
    """The second call site, which has the same defect and no stub at all.

    The test fixture in test_scan_phase.py did not even stub
    report_result_completeness -- it stubbed a differently-named phantom,
    validate_result_completeness, while the real facade method is
    ensure_complete_results.
    """
    _expect_a_scanner_that_never_completes(phase)
    results = AshAggregatedResults()

    phase._validate_result_completeness(results)

    report = getattr(results.metadata, "result_completeness_report", None)
    assert report is not None, (
        "result_completeness_report was never written; the call to "
        "report_result_completeness raised and was swallowed"
    )
    assert "has_adjustments" in report
    assert "missing_scanners" in report
    assert "unexpected_scanners" in report
