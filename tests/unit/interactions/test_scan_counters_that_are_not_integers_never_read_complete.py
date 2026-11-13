# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner counter that is not a genuine integer never reads as a complete scan.

``targets_attempted`` and ``targets_failed`` say how much of its input a scanner
evaluated. A value that is not a genuine int (a string, a float, a bool, or None
while the other counter is set) says nothing trustworthy about coverage, so a
result carrying one must be refused where it is built, or graded ERROR, or listed
by the incomplete-scan check and fail its gate. It must never read as a complete
scan.

Two layers are exercised through their public entry points:

* the container model, built from a dict the way a result read back from JSON is
  built, then graded by ``determine_status``;
* the serialized per-target report, which is a plain dict inside
  ``additional_reports``, read by ``scan_incompleteness`` and the exit-code gate.

Genuine-int partial and complete results are the controls.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    scan_incompleteness,
)
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit

_COMPLETE = (ScannerStatus.PASSED, ScannerStatus.SKIPPED)


def _cases(*values):
    return [pytest.param(v, id=repr(v)) for v in values]


# ---- the container model ---------------------------------------------------


def _graded(field: str, value) -> ScannerStatus | None:
    """Status of a container built from a dict, None when the model refuses it.

    The other counter is a genuine int that makes the result a partial loss
    (3 attempted, 1 failed), so a complete reading can only come from the value
    under test.
    """
    data = {"scanner_name": "probe", "targets_attempted": 3, "targets_failed": 1}
    data[field] = value
    try:
        container = ScanResultsContainer.model_validate(data)
    except ValidationError:
        return None
    return container.determine_status("MEDIUM")


def _assert_refused_or_incomplete(field: str, value) -> None:
    status = _graded(field, value)
    if status is None:
        return
    assert status not in _COMPLETE, (
        f"{field}={value!r} was accepted and graded {status.value}, a complete scan"
    )


class TestTheContainerModel:
    @pytest.mark.parametrize(
        "value",
        _cases("3", "1", 1.0, 0.5, True, False, None),
    )
    def test_an_attempted_count_that_is_not_an_int_is_refused_or_incomplete(
        self, value
    ):
        _assert_refused_or_incomplete("targets_attempted", value)

    @pytest.mark.parametrize(
        "value",
        _cases("3", "1", 1.0, 0.5, True, None, False),
    )
    def test_a_failed_count_that_is_not_an_int_is_refused_or_incomplete(self, value):
        _assert_refused_or_incomplete("targets_failed", value)

    def test_genuine_int_partial_loss_grades_error(self):
        assert _graded("targets_failed", 1) == ScannerStatus.ERROR

    def test_genuine_int_full_coverage_grades_passed(self):
        assert _graded("targets_failed", 0) == ScannerStatus.PASSED


# ---- the serialized report, the incomplete-scan check and its gate ----------


def _results(report_counters: dict):
    """A results stand-in whose one scanner wrote a PASSED report beside counters.

    PASSED beside counters is the shape an older writer produced and a merged
    shard still carries; only ``additional_reports`` is populated, so the counters
    and the verdict are both derived by the code under test.
    """
    report = {"scanner_name": "probe", "status": "PASSED", "duration": 1.0}
    report.update(report_counters)
    results = MagicMock()
    results.sarif = MagicMock()
    results.sarif.runs = []
    results.scanner_results = {}
    results.ash_config = MagicMock()
    results.ash_config.global_settings.severity_threshold = "MEDIUM"
    results.ash_config.get_plugin_config.return_value = None
    results.additional_reports = {"probe": {"source": report}}
    return results


def _counters(field: str, value) -> dict:
    counters = {"targets_attempted": 3, "targets_failed": 1}
    counters[field] = value
    return counters


def _listed(report_counters: dict) -> bool:
    incompleteness = scan_incompleteness(_results(report_counters), gate=True)
    return any(name == "probe" for name, _ in incompleteness.scanners)


def _exit_code(tmp_path, report_counters: dict) -> int:
    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_findings=False,
        fail_on_incomplete_scanners=True,
    )
    return _compute_exit_code(_results(report_counters), opts)


_NOT_INTS = ("3", "1", 1.0, 0.5, True, False, None)


class TestTheSerializedReport:
    @pytest.mark.parametrize("value", _cases(*_NOT_INTS))
    def test_an_attempted_count_that_is_not_an_int_is_listed_incomplete(self, value):
        assert _listed(_counters("targets_attempted", value))

    @pytest.mark.parametrize("value", _cases(*_NOT_INTS))
    def test_a_failed_count_that_is_not_an_int_is_listed_incomplete(self, value):
        assert _listed(_counters("targets_failed", value))

    @pytest.mark.parametrize("value", _cases(*_NOT_INTS))
    def test_an_attempted_count_that_is_not_an_int_fails_the_incomplete_gate(
        self, tmp_path, value
    ):
        assert _exit_code(tmp_path, _counters("targets_attempted", value)) == 1

    @pytest.mark.parametrize("value", _cases(*_NOT_INTS))
    def test_a_failed_count_that_is_not_an_int_fails_the_incomplete_gate(
        self, tmp_path, value
    ):
        assert _exit_code(tmp_path, _counters("targets_failed", value)) == 1

    def test_a_negative_failed_count_is_listed_incomplete(self):
        assert _listed(_counters("targets_failed", -1))

    def test_a_genuine_int_partial_loss_is_listed_incomplete(self):
        assert _listed(_counters("targets_failed", 1))

    def test_a_genuine_int_partial_loss_fails_the_incomplete_gate(self, tmp_path):
        assert _exit_code(tmp_path, _counters("targets_failed", 1)) == 1

    def test_a_negative_attempted_count_is_listed_incomplete(self):
        assert _listed(_counters("targets_attempted", -1))

    def test_genuine_int_full_coverage_is_not_listed(self):
        assert not _listed(_counters("targets_failed", 0))

    def test_genuine_int_full_coverage_passes_the_incomplete_gate(self, tmp_path):
        assert _exit_code(tmp_path, _counters("targets_failed", 0)) == 0

    def test_a_scanner_that_reports_no_counters_is_not_listed(self):
        assert not _listed({})

    def test_a_missing_failed_count_beside_attempts_is_listed_incomplete(self):
        """An attempt claim with no failure accounting fails closed.

        A report carrying ``targets_attempted > 0`` and no ``targets_failed``
        key has counted its attempts but says nothing about how many were
        evaluated. Reading the absence as "zero failed" would complete a scan
        on a claim the writer never made, so the scanner is listed incomplete
        instead. Both counters absent stays the no-claim state (the control
        above), and a zero-attempt claim without a failure count stays benign
        (the control below): zero attempts leaves nothing unaccounted for.
        """
        assert _listed({"targets_attempted": 3})

    def test_a_missing_failed_count_beside_attempts_fails_the_incomplete_gate(
        self, tmp_path
    ):
        assert _exit_code(tmp_path, {"targets_attempted": 3}) == 1

    def test_a_zero_attempt_claim_without_a_failed_count_is_not_listed(self):
        assert not _listed({"targets_attempted": 0})

    def test_a_failed_count_beside_no_attempt_claim_is_listed_incomplete(self):
        """A failure count with no attempt count is a producer bug, not a
        clean scan: there is no denominator that could complete it."""
        assert _listed({"targets_failed": 2})

    def test_a_zero_failed_count_beside_no_attempt_claim_is_not_listed(self):
        """The shape every non-tracking scanner's stored report can take when
        a writer emits the zero default: no attempt claim was made and no
        failure is asserted, so it stays the no-claim state."""
        assert not _listed({"targets_failed": 0})
