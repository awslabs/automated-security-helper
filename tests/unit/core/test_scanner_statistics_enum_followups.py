# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Follow-ups to the enum adoption in the scanner statistics pass.

* An unknown source word from the threshold resolver degrades the one row to the
  global source, with a warning, as the sibling conversions do; it does not abort
  the statistics pass after the scan ran.
* ``ThresholdSource`` prints as its wire word, as ``Transport`` does, because the
  public getters return members that callers format into text.
* The severity count row is zipped against ``SEVERITY_COUNT_FIELDS`` strictly, so
  a change to that tuple's length fails loudly rather than truncating the row.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core import scanner_statistics_calculator as calc
from automated_security_helper.core.enums import ScannerStatus, ThresholdSource
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.vocab import SEVERITY_COUNT_FIELDS

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )
    return model


class TestAnUnknownResolvedSourceDegradesToGlobal:
    def _resolve(self):
        with patch.object(
            calc,
            "resolve_scanner_threshold",
            return_value=("MEDIUM", "not-a-source"),
        ):
            return ScannerStatisticsCalculator._threshold_resolution(_model(), "bandit")

    def test_the_resolution_answers_the_global_source(self):
        grading, shown, source, from_env = self._resolve()

        assert source is ThresholdSource.GLOBAL
        assert grading == shown == "MEDIUM"
        assert from_env is False

    def test_the_statistics_pass_still_writes_the_row(self):
        with patch.object(
            calc,
            "resolve_scanner_threshold",
            return_value=("MEDIUM", "not-a-source"),
        ):
            stats = ScannerStatisticsCalculator.extract_scanner_statistics(_model())

        assert stats["bandit"]["threshold_source"] == "global"

    def test_a_warning_names_the_scanner_and_the_word(self):
        with patch.object(calc.ASH_LOGGER, "warning") as warning:
            self._resolve()

        text = " ".join(str(call.args[0]) for call in warning.call_args_list)
        assert "bandit" in text and "not-a-source" in text, text


class TestThresholdSourcePrintsAsItsWireWord:
    @pytest.mark.parametrize("member", list(ThresholdSource))
    def test_str_and_format_are_the_value(self, member: ThresholdSource):
        assert str(member) == member.value
        assert f"{member}" == member.value

    def test_the_config_source_in_an_f_string(self):
        assert f"{ThresholdSource.CONFIG}" == "config"


class TestTheSeverityCountRowIsZippedStrictly:
    def test_the_count_fields_are_pinned(self):
        assert SEVERITY_COUNT_FIELDS == (
            "suppressed",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )

    def test_a_shorter_field_tuple_fails_instead_of_truncating(self):
        # Shorter, not longer: other readers of the tuple take each field off a
        # count object, so an extra name would fail there before the row is zipped.
        shorter = SEVERITY_COUNT_FIELDS[:-1]
        with patch.object(calc, "SEVERITY_COUNT_FIELDS", shorter):
            with pytest.raises(ValueError):
                ScannerStatisticsCalculator.extract_scanner_statistics(_model())
