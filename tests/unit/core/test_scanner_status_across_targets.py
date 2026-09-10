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

``get_scanner_status_info`` read the ``"source"`` report and only the ``"source"`` report. So a
scanner that passed on the source tree and errored on the converted tree rolled up to PASSED:
the ERROR container was written, serialized, and never consulted. An ERROR means no rule was
evaluated on that target, so this is the silent-pass shape the surrounding code was written
against, arriving through the target dimension instead of through the severity counts.

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

WHAT IS DELIBERATELY NOT CHANGED
--------------------------------
``excluded`` and ``dependencies_missing`` are still read off the single scanner-level report.
Both are facts about configuration rather than about a target: a scanner is switched off, or
its tool is absent, for the whole run. Widening those to "any target" would let one target with
an unrecognized status -- which ``_status_info_from_report`` maps to ``excluded=True`` for
backward compatibility -- mark the whole scanner as operator-excluded.
"""

from unittest.mock import MagicMock

import pytest


def _model_with_target_statuses(source_status: str, converted_status: str):
    """An AshAggregatedResults stand-in carrying one serialized container per target.

    The report shape is the one ``ScanResultProcessor`` actually writes: it dumps the
    container with ``exclude_unset=True``, so only fields a scanner assigned are present.
    That is why ``excluded`` is absent here rather than set to False -- its absence is what
    makes ``_status_info_from_report`` trust the field.

    ``sarif.runs`` is empty so every severity count is zero. That keeps the ``actionable > 0``
    branch out of the way, which matters: it is checked before the did-not-run branches, and a
    fixture that accidentally carried findings would return FAILED and pass a test that is
    supposed to be about ERROR.
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
            },
            "converted": {
                "scanner_name": "cdk-nag",
                "status": converted_status,
                "targets_attempted": 1,
                "targets_failed": 1,
                "duration": 0.5,
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
