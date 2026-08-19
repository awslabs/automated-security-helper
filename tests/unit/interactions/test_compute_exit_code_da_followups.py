# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DA followup tests for _compute_exit_code — issues #42 and #46.

#42: When opts.fail_on_findings is None, must fall back to
     config_fail_on_findings (the value from orchestrator.config.fail_on_findings)
     rather than unconditionally defaulting to True.

#46: When results is None (scan crashed), must return 1 regardless of
     fail_on_findings, and log an error message.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_opts(tmp_path, fail_on_findings=None, min_severity="low"):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_findings=fail_on_findings,
        min_severity=min_severity,
    )


def _make_results_with_findings(count: int = 1):
    """Return a mock AshAggregatedResults with *count* actionable findings."""
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    mock_metric = MagicMock(spec=ScannerMetrics)
    mock_metric.actionable = count
    results = MagicMock()
    results.sarif = None

    with patch(
        "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
        return_value=[mock_metric],
    ):
        yield results


def _make_results_no_findings():
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    mock_metric = MagicMock(spec=ScannerMetrics)
    mock_metric.actionable = 0
    results = MagicMock()
    results.sarif = None

    with patch(
        "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
        return_value=[mock_metric],
    ):
        yield results


# ---------------------------------------------------------------------------
# Issue #42 — config.fail_on_findings fallback
# ---------------------------------------------------------------------------


class TestComputeExitCodeConfigFallback:
    def test_uses_config_fail_on_findings_false_when_cli_unset(self, tmp_path):
        """opts.fail_on_findings=None + config False → should return 0, not 2."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=None)

        mock_metric = MagicMock()
        mock_metric.actionable = 3

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            mock_results = MagicMock()
            mock_results.sarif = None
            code = _compute_exit_code(mock_results, opts, config_fail_on_findings=False)

        assert code == 0, (
            "config.fail_on_findings=False must be respected when CLI flag is unset"
        )

    def test_cli_true_overrides_config_false(self, tmp_path):
        """opts.fail_on_findings=True overrides config False → returns 2."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=True)

        mock_metric = MagicMock()
        mock_metric.actionable = 1

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            mock_results = MagicMock()
            mock_results.sarif = None
            code = _compute_exit_code(mock_results, opts, config_fail_on_findings=False)

        assert code == 2, "CLI fail_on_findings=True must override config False"

    def test_cli_false_overrides_config_true(self, tmp_path):
        """opts.fail_on_findings=False overrides config True → returns 0."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=False)

        mock_metric = MagicMock()
        mock_metric.actionable = 5

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            mock_results = MagicMock()
            mock_results.sarif = None
            code = _compute_exit_code(mock_results, opts, config_fail_on_findings=True)

        assert code == 0, "CLI fail_on_findings=False must override config True"

    def test_cli_none_config_none_defaults_true(self, tmp_path):
        """Both None → still defaults to True (existing behavior baseline)."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=None)

        mock_metric = MagicMock()
        mock_metric.actionable = 1

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            mock_results = MagicMock()
            mock_results.sarif = None
            code = _compute_exit_code(mock_results, opts, config_fail_on_findings=None)

        assert code == 2, "Both None should default to True (fail on findings)"

    def test_cli_none_config_true_returns_two(self, tmp_path):
        """opts.fail_on_findings=None + config True → returns 2."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=None)

        mock_metric = MagicMock()
        mock_metric.actionable = 1

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            mock_results = MagicMock()
            mock_results.sarif = None
            code = _compute_exit_code(mock_results, opts, config_fail_on_findings=True)

        assert code == 2


# ---------------------------------------------------------------------------
# Issue #46 — results=None must return 1 unconditionally
# ---------------------------------------------------------------------------


class TestComputeExitCodeResultsNone:
    def test_returns_1_when_results_none_fail_on_findings_false(self, tmp_path):
        """results=None → exit 1 regardless of fail_on_findings=False."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=False)
        code = _compute_exit_code(None, opts)

        assert code == 1

    def test_returns_1_when_results_none_fail_on_findings_true(self, tmp_path):
        """results=None → exit 1 regardless of fail_on_findings=True."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=True)
        code = _compute_exit_code(None, opts)

        assert code == 1

    def test_returns_1_when_results_none_config_false(self, tmp_path):
        """results=None → exit 1 even when config says fail_on_findings=False."""
        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=None)
        code = _compute_exit_code(None, opts, config_fail_on_findings=False)

        assert code == 1

    def test_logs_error_when_results_none(self, tmp_path, caplog):
        """results=None must log an error about scan failure."""
        import logging

        from automated_security_helper.interactions.run_ash_scan import _compute_exit_code

        opts = _make_opts(tmp_path, fail_on_findings=False)

        with caplog.at_level(logging.ERROR):
            _compute_exit_code(None, opts)

        assert any(
            "scan" in record.message.lower() or "result" in record.message.lower()
            for record in caplog.records
            if record.levelno >= logging.ERROR
        ), f"Expected an ERROR log about scan/result failure, got: {[r.message for r in caplog.records]}"
