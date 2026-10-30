# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The statistics calculator reads a failure's marks and a scanner's counts one way.

- A report that carries an ``exception`` is a failure's wherever it is read: not a
  partial loss, so the same reports give the same status whether or not the
  scanner has a recorded row.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _model(additional_reports: dict | None = None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if additional_reports is not None:
        model.additional_reports = additional_reports
    return model


def _report(scanner_name: str, target: str = "source", **fields) -> dict:
    report = {"scanner_name": scanner_name, "target_type": target, "status": "PASSED"}
    report.update(fields)
    return report


def _partial_loss(scanner_name: str, **fields) -> dict:
    """One tree's ERROR report with the counters of a partial loss and no findings:
    the ERROR ``determine_status`` gives a partial loss whose findings pass the gate."""
    return _report(
        scanner_name,
        status="ERROR",
        targets_attempted=3,
        targets_failed=1,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        **fields,
    )


class TestAnExceptionIsAFailuresMarkEverywhere:
    """``target_report_is_partial_loss`` refused ``raw_results.status == "failed"`` and
    ``could_not_stop`` but not an ``exception``, while ``_status_info_from_report`` and
    ``recorded_error_is_partial_loss`` read an ``exception`` as a crash. A report with
    partial counters and an ``exception`` (a merged or hand-written file; the executor's
    own rows also carry ``raw_results.status``) was therefore a crash for a scanner with
    a recorded ERROR row and a partial loss for one without, and with a finding on the
    other tree the row-less scanner read FAILED where the recorded one read ERROR."""

    def test_an_exception_mark_is_not_a_partial_loss(self):
        report = _partial_loss("cdk-nag", exception="RuntimeError: the run raised")

        assert (
            ScannerStatisticsCalculator.target_report_is_partial_loss(report, "MEDIUM")
            is False
        )

    def test_the_counters_alone_still_are_one(self):
        """Control: the same report without the mark is the partial loss it reads as."""
        assert (
            ScannerStatisticsCalculator.target_report_is_partial_loss(
                _partial_loss("cdk-nag"), "MEDIUM"
            )
            is True
        )

    @staticmethod
    def _crashed_partial_tree_beside_a_finding(with_row: bool) -> AshAggregatedResults:
        model = _model(
            {
                "cdk-nag": {
                    "source": _partial_loss(
                        "cdk-nag", exception="RuntimeError: the run raised"
                    ),
                    "converted": _report(
                        "cdk-nag",
                        "converted",
                        status="FAILED",
                        raw_results={"findings": [{"rule": "AwsSolutions-S1"}]},
                        severity_counts={"high": 1},
                    ),
                }
            }
        )
        if with_row:
            model.scanner_results["cdk-nag"] = ScannerTargetStatusInfo(
                status=ScannerStatus.ERROR
            )
        return model

    def test_the_same_reports_read_error_with_and_without_a_recorded_row(self):
        without_row = self._crashed_partial_tree_beside_a_finding(with_row=False)
        with_row = self._crashed_partial_tree_beside_a_finding(with_row=True)

        _, _, error_without_row = ScannerStatisticsCalculator.get_scanner_status_info(
            without_row, "cdk-nag"
        )
        _, _, error_with_row = ScannerStatisticsCalculator.get_scanner_status_info(
            with_row, "cdk-nag"
        )

        # The recorded-row read was already ERROR (recorded_error_is_partial_loss
        # refuses the exception); the row-less read let the converted tree's
        # HIGH finding outrank what it took for a partial loss and read FAILED.
        assert error_with_row is True
        assert error_without_row is True

    def test_a_partial_loss_without_the_mark_still_yields_to_a_finding(self):
        """Control: the rule the cure keeps. No crash mark, so the source tree's
        partial loss yields to the converted tree's gate-failing finding (FAILED)."""
        model = _model(
            {
                "cdk-nag": {
                    "source": _partial_loss("cdk-nag"),
                    "converted": _report(
                        "cdk-nag",
                        "converted",
                        status="FAILED",
                        raw_results={"findings": [{"rule": "AwsSolutions-S1"}]},
                        severity_counts={"high": 1},
                    ),
                }
            }
        )

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "cdk-nag"
        )

        assert error is False
