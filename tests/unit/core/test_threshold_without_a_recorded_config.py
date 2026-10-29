# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's threshold comes from the configuration the results record.

``ScannerStatisticsCalculator.get_scanner_threshold_info`` feeds the summary
table, the actionable counts and the reports. It reads the threshold from the
results' own configuration. When the results record none, or it cannot be read,
the threshold is ASH_DEFAULT_SEVERITY_LEVEL and its source is reported as
``unavailable``. The configuration of the process doing the reading -- ASH's
defaults, or the file ``ASH_CONFIG`` names -- is never consulted.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

# Not ASH_DEFAULT_SEVERITY_LEVEL, so a threshold taken from this file is visible.
READING_PROCESS_THRESHOLD = "LOW" if ASH_DEFAULT_SEVERITY_LEVEL != "LOW" else "HIGH"


@pytest.fixture(autouse=True)
def _ash_config_names_a_file_with_its_own_threshold(tmp_path, monkeypatch):
    path = tmp_path / "operator.yaml"
    path.write_text(
        "project_name: reading-process\n"
        f"global_settings:\n  severity_threshold: {READING_PROCESS_THRESHOLD}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(path))


class _UnreadableConfig:
    """Results whose recorded configuration raises when it is read."""

    @property
    def ash_config(self):
        raise RuntimeError("the recorded configuration cannot be read")


def _threshold(results) -> tuple:
    return ScannerStatisticsCalculator.get_scanner_threshold_info(results, "bandit")


def test_an_unreadable_recorded_config_is_reported_unavailable():
    assert _threshold(_UnreadableConfig()) == (
        ASH_DEFAULT_SEVERITY_LEVEL,
        "unavailable",
    )


def test_no_recorded_config_is_reported_unavailable():
    assert _threshold(AshAggregatedResults()) == (
        ASH_DEFAULT_SEVERITY_LEVEL,
        "unavailable",
    )


def test_control_the_recorded_threshold_is_used():
    results = AshAggregatedResults(
        ash_config=AshConfig.model_validate(
            {"global_settings": {"severity_threshold": "CRITICAL"}}
        )
    )

    assert _threshold(results) == ("CRITICAL", "global")


def test_control_a_recorded_scanner_threshold_is_used():
    results = AshAggregatedResults(
        ash_config=AshConfig.model_validate(
            {"scanners": {"bandit": {"options": {"severity_threshold": "HIGH"}}}}
        )
    )

    assert _threshold(results) == ("HIGH", "config")
