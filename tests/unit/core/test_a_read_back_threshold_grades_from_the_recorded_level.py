# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file read back grades from the level its reports record.

The configuration record keeps a severity threshold the scan read from the
environment as the reference its file wrote, never the level. Read back, an
external plugin's section still holds the reference text, which the ladder
grades CRITICAL only, and a typed section's field is listed unreadable and read
as its default, so the summary graded against a level the scan never used. The
executor now records the level it graded each target against on the target
report (``scanner_severity_threshold``), and ``_threshold_resolution`` grades a
read-back file from that record, showing the reference, without reading the
reader's environment.

Red at the base: the external section graded its reference text with
``threshold_from_env`` False, and the unreadable typed field graded the default
with source ``global``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

EXTERNAL_REFERENCE = "${ASH_X25_EXT_LEVEL:LOW}"
BANDIT_REFERENCE = "${ASH_X25_BANDIT_LEVEL}"
GLOBAL_REFERENCE = "${ASH_X25_GLOBAL_LEVEL}"


def _report(scanner_name: str, target: str = "source", **fields) -> dict:
    report = {
        "scanner_name": scanner_name,
        "target_type": target,
        "status": "PASSED",
        "duration": 1.0,
    }
    report.update(fields)
    return report


def _model(additional_reports: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.additional_reports = additional_reports
    return model


def _resolution(model: AshAggregatedResults, scanner_name: str) -> tuple:
    return ScannerStatisticsCalculator._threshold_resolution(model, scanner_name)


class TestAnExternalSectionsReference:
    def test_the_recorded_level_is_graded_and_the_reference_shown(self):
        model = _model(
            {"ext": {"source": _report("ext", scanner_severity_threshold="LOW")}}
        )
        with patch.object(
            type(model.ash_config),
            "get_plugin_config",
            return_value={"options": {"severity_threshold": EXTERNAL_REFERENCE}},
        ):
            graded, shown, source, from_env = _resolution(model, "ext")

        assert graded == "LOW"
        assert shown == "${ASH_X25_EXT_LEVEL}"
        assert source == "config"
        assert from_env is True

    def test_without_a_recorded_level_the_reference_is_graded_as_before(self):
        """The control: a results file from an ASH that recorded no level."""
        model = _model({"ext": {"source": _report("ext")}})
        with patch.object(
            type(model.ash_config),
            "get_plugin_config",
            return_value={"options": {"severity_threshold": EXTERNAL_REFERENCE}},
        ):
            graded, shown, source, from_env = _resolution(model, "ext")

        assert graded == EXTERNAL_REFERENCE
        assert source == "config"
        assert from_env is False


class TestATypedSectionListedUnreadable:
    def test_the_recorded_level_is_graded_as_the_scanners_own(self):
        model = _model(
            {"bandit": {"source": _report("bandit", scanner_severity_threshold="HIGH")}}
        )
        model.ash_config._unreadable_references = [
            ("scanners.bandit.options.severity_threshold", BANDIT_REFERENCE)
        ]

        graded, shown, source, from_env = _resolution(model, "bandit")

        assert graded == "HIGH"
        assert shown == BANDIT_REFERENCE
        assert source == "config"
        assert from_env is True

    def test_the_scanners_section_is_matched_under_another_spelling(self):
        model = _model(
            {
                "cfn-guard": {
                    "source": _report("cfn-guard", scanner_severity_threshold="LOW")
                }
            }
        )
        model.ash_config._unreadable_references = [
            ("scanners.cfn_guard.options.severity_threshold", BANDIT_REFERENCE)
        ]

        graded, shown, source, from_env = _resolution(model, "cfn-guard")

        assert (graded, source, from_env) == ("LOW", "config", True)

    def test_an_unreadable_global_threshold_grades_the_recorded_level(self):
        model = _model(
            {
                "bandit": {
                    "source": _report("bandit", scanner_severity_threshold="CRITICAL")
                }
            }
        )
        model.ash_config._unreadable_references = [
            ("global_settings.severity_threshold", GLOBAL_REFERENCE)
        ]

        graded, shown, source, from_env = _resolution(model, "bandit")

        assert graded == "CRITICAL"
        assert shown == GLOBAL_REFERENCE
        assert source == "global"
        assert from_env is True

    def test_without_a_recorded_level_the_default_is_graded_as_before(self):
        """The control: nothing to grade from but the record's own read."""
        model = _model({"bandit": {"source": _report("bandit")}})
        model.ash_config._unreadable_references = [
            ("scanners.bandit.options.severity_threshold", BANDIT_REFERENCE)
        ]

        graded, shown, source, from_env = _resolution(model, "bandit")

        assert graded == model.ash_config.global_settings.severity_threshold
        assert source == "global"
        assert from_env is False


class TestTheRecordNeverOverridesAReadableThreshold:
    def test_a_literal_threshold_is_graded_whatever_the_reports_say(self):
        """The control: the record's own read stands when the record can hold it."""
        model = _model(
            {"bandit": {"source": _report("bandit", scanner_severity_threshold="LOW")}}
        )

        graded, shown, source, from_env = _resolution(model, "bandit")

        assert graded == model.ash_config.global_settings.severity_threshold
        assert shown == graded
        assert from_env is False

    def test_two_targets_graded_against_different_levels_record_no_level(self):
        model = _model(
            {
                "bandit": {
                    "source": _report("bandit", scanner_severity_threshold="LOW"),
                    "converted": _report(
                        "bandit", "converted", scanner_severity_threshold="HIGH"
                    ),
                }
            }
        )

        assert (
            ScannerStatisticsCalculator._recorded_graded_level(model, "bandit") is None
        )

    def test_a_level_the_report_cannot_carry_records_no_level(self):
        model = _model(
            {"bandit": {"source": _report("bandit", scanner_severity_threshold="5")}}
        )

        assert (
            ScannerStatisticsCalculator._recorded_graded_level(model, "bandit") is None
        )

    def test_two_targets_graded_alike_record_the_one_level(self):
        model = _model(
            {
                "bandit": {
                    "source": _report("bandit", scanner_severity_threshold="HIGH"),
                    "converted": _report(
                        "bandit", "converted", scanner_severity_threshold="HIGH"
                    ),
                    "other": _report(
                        "semgrep", "other", scanner_severity_threshold="LOW"
                    ),
                }
            }
        )

        assert (
            ScannerStatisticsCalculator._recorded_graded_level(model, "bandit")
            == "HIGH"
        )
