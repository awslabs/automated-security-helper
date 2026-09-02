# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the ScannerExecutor -> sarif_utils metrics seam.

ScannerExecutor._extract_metrics_from_sarif is consumed as a 2-tuple:

    severity_counts, finding_count = self._extract_metrics_from_sarif(raw_results)

but get_severity_metrics_from_sarif returns a single ScannerSeverityCount model.
Returning it unchanged did not fail at import or type-check time, because pydantic
models are iterable: the unpack tried to spread the model's six fields across two
names and raised "too many values to unpack (expected 2)" only at runtime, only
once a scanner produced a real SARIF report. Every scanner then reported status
ERROR with zero findings while the whole unit suite stayed green.

These tests pin the arity and the counting semantics so the seam cannot drift again.
"""

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)


def _executor(tmp_path: Path) -> ScannerExecutor:
    ctx = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(),
    )
    return ScannerExecutor(
        plugin_context=ctx,
        progress_display=None,
        scanner_tasks=[],
    )


def _sarif(levels) -> SarifReport:
    results = [
        Result(ruleId=f"R{i}", level=lvl, message=Message(text="x"))
        for i, lvl in enumerate(levels)
    ]
    return SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="bandit")), results=results)]
    )


class TestExtractMetricsArity:
    """The method must return exactly (ScannerSeverityCount, int)."""

    def test_returns_a_two_tuple(self, tmp_path):
        out = _executor(tmp_path)._extract_metrics_from_sarif(_sarif([]))
        assert isinstance(out, tuple), f"expected a tuple, got {type(out).__name__}"
        assert len(out) == 2, f"expected 2 elements, got {len(out)}"

    def test_unpacks_into_two_names(self, tmp_path):
        """The exact shape the caller in _execute_scanner relies on."""
        counts, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
            _sarif([])
        )
        assert isinstance(counts, ScannerSeverityCount)
        assert isinstance(finding_count, int)

    def test_does_not_return_the_bare_model(self, tmp_path):
        """A bare ScannerSeverityCount is iterable, so this is the trap to block."""
        out = _executor(tmp_path)._extract_metrics_from_sarif(_sarif([]))
        assert not isinstance(out, ScannerSeverityCount), (
            "returning the model directly makes the caller's two-name unpack raise "
            "'too many values to unpack (expected 2)' at runtime"
        )


class TestExtractMetricsCounting:
    """Counting must match ScanPhase._extract_metrics_from_sarif."""

    def test_counts_findings(self, tmp_path):
        counts, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
            _sarif(["error", "warning", "note"])
        )
        assert finding_count == counts.total + counts.suppressed
        assert finding_count > 0, "a SARIF with three results must not count as zero"

    def test_empty_report_is_zero(self, tmp_path):
        counts, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
            _sarif([])
        )
        assert finding_count == 0
        assert counts.total == 0

    @pytest.mark.parametrize("n", [1, 5])
    def test_finding_count_tracks_result_count(self, tmp_path, n):
        _, finding_count = _executor(tmp_path)._extract_metrics_from_sarif(
            _sarif(["error"] * n)
        )
        assert finding_count == n
