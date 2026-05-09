# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for run_ash_scan decomposition (Track 1.1).

Covers:
- ScanOptions model normalisation and path coercion
- _compute_exit_code using in-memory AshAggregatedResults (no disk reads)
- _run_container_mode dispatch
- _run_local_mode does not call os.chdir
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# ScanOptions
# ---------------------------------------------------------------------------


class TestScanOptionsNormalisesNoneToEmptyList:
    def test_scanners_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(source_dir=Path("/src"), output_dir=Path("/out"), scanners=None)
        assert opts.scanners == []

    def test_excluded_scanners_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(
            source_dir=Path("/src"), output_dir=Path("/out"), excluded_scanners=None
        )
        assert opts.excluded_scanners == []

    def test_output_formats_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(
            source_dir=Path("/src"), output_dir=Path("/out"), output_formats=None
        )
        assert opts.output_formats == []

    def test_config_overrides_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(
            source_dir=Path("/src"), output_dir=Path("/out"), config_overrides=None
        )
        assert opts.config_overrides == []

    def test_custom_build_arg_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(
            source_dir=Path("/src"), output_dir=Path("/out"), custom_build_arg=None
        )
        assert opts.custom_build_arg == []

    def test_ash_plugin_modules_none_becomes_empty_list(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(
            source_dir=Path("/src"), output_dir=Path("/out"), ash_plugin_modules=None
        )
        assert opts.ash_plugin_modules == []


class TestScanOptionsPathCoercion:
    def test_str_source_dir_coerced_to_absolute_path(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(source_dir=str(tmp_path), output_dir=str(tmp_path / "out"))
        assert isinstance(opts.source_dir, Path)
        assert opts.source_dir.is_absolute()

    def test_str_output_dir_coerced_to_absolute_path(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(source_dir=str(tmp_path), output_dir=str(tmp_path / "out"))
        assert isinstance(opts.output_dir, Path)
        assert opts.output_dir.is_absolute()

    def test_relative_source_dir_becomes_absolute(self):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        opts = ScanOptions(source_dir=".", output_dir="./out")
        assert opts.source_dir.is_absolute()
        assert opts.output_dir.is_absolute()


# ---------------------------------------------------------------------------
# _compute_exit_code — pure in-memory, no disk reads
# ---------------------------------------------------------------------------


def _make_results_no_findings():
    """Return an AshAggregatedResults with zero SARIF results."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results = AshAggregatedResults.__new__(AshAggregatedResults)
    results.__dict__.update(
        {
            "sarif": None,
            "scanner_results": {},
            "summary_stats": None,
            "validation_checkpoints": [],
            "metadata": MagicMock(),
            "_flat_vuln_cache": None,
        }
    )
    return results


class TestComputeExitCode:
    def test_no_findings_returns_zero(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )
        mock_results = MagicMock()
        # get_unified_scanner_metrics returns a list of metrics each with actionable=0
        mock_metric = MagicMock()
        mock_metric.actionable = 0
        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            with patch(
                "automated_security_helper.interactions.run_ash_scan._severity_filters_finding",
                return_value=False,
            ):
                code = _compute_exit_code(mock_results, opts)
        assert code == 0

    def test_actionable_findings_with_fail_on_findings_returns_two(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )
        mock_results = MagicMock()
        # Make sarif.runs return empty so has_qualifying defaults to True via the None-branch
        mock_results.sarif = None
        mock_metric = MagicMock()
        mock_metric.actionable = 3
        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            code = _compute_exit_code(mock_results, opts)
        assert code == 2

    def test_fail_on_findings_false_returns_zero_even_with_findings(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=False,
        )
        mock_results = MagicMock()
        mock_metric = MagicMock()
        mock_metric.actionable = 5
        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            code = _compute_exit_code(mock_results, opts)
        assert code == 0

    def test_does_not_read_disk(self, tmp_path):
        """_compute_exit_code must not open any files."""
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )
        mock_results = MagicMock()
        mock_metric = MagicMock()
        mock_metric.actionable = 0

        with patch("builtins.open", side_effect=AssertionError("disk read in _compute_exit_code")):
            with patch(
                "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
                return_value=[mock_metric],
            ):
                with patch(
                    "automated_security_helper.interactions.run_ash_scan._severity_filters_finding",
                    return_value=False,
                ):
                    # Should not raise — no disk I/O
                    code = _compute_exit_code(mock_results, opts)
        assert code == 0


# ---------------------------------------------------------------------------
# _run_container_mode dispatch
# ---------------------------------------------------------------------------


class TestRunContainerMode:
    def test_dispatches_to_run_ash_container(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _run_container_mode,
        )

        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

        mock_container_result = MagicMock()
        mock_container_result.returncode = 0

        from automated_security_helper.models.asharp_model import AshAggregatedResults
        dummy = AshAggregatedResults.__new__(AshAggregatedResults)

        mock_logger = MagicMock()
        fake_content = "{}"

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            return_value=mock_container_result,
        ) as mock_rac:
            with patch(
                "automated_security_helper.interactions.run_ash_scan.AshAggregatedResults.model_validate_json",
                return_value=dummy,
            ):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("builtins.open", MagicMock(
                        return_value=MagicMock(
                            __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=fake_content))),
                            __exit__=MagicMock(return_value=False),
                        )
                    )):
                        result = _run_container_mode(opts, mock_logger)

        mock_rac.assert_called_once()
        assert result is dummy


# ---------------------------------------------------------------------------
# _run_local_mode — no os.chdir
# ---------------------------------------------------------------------------


class TestRunLocalModeNoChdir:
    def test_does_not_call_os_chdir(self, tmp_path):
        """_run_local_mode must not call os.chdir — orchestrator uses absolute paths."""
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _run_local_mode,
        )

        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        mock_logger = MagicMock()

        mock_orchestrator = MagicMock()
        mock_results = MagicMock()
        mock_orchestrator.execute_scan.return_value = mock_results
        mock_orchestrator.config = MagicMock()
        mock_orchestrator.config.fail_on_findings = True

        mock_orchestrator_class = MagicMock()
        mock_orchestrator_class.create.return_value = mock_orchestrator

        with patch("os.chdir", side_effect=AssertionError("os.chdir must not be called")):
            with patch(
                "automated_security_helper.core.orchestrator.ASHScanOrchestrator",
                mock_orchestrator_class,
            ):
                with patch(
                    "automated_security_helper.interactions.run_ash_scan._run_local_mode.__globals__",
                    {},
                ) if False else patch(
                    "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
                    return_value=mock_orchestrator,
                ):
                    # _run_local_mode writes results to disk — patch open
                    with patch("builtins.open", MagicMock()):
                        with patch("pathlib.Path.exists", return_value=False):
                            result, _cfg_fof = _run_local_mode(opts, mock_logger)

        assert result is mock_results
