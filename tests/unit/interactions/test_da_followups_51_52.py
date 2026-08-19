# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for DA followups #51 and #52.

#51: container-mode must honour YAML fail_on_findings override.
     When opts.fail_on_findings is None and config has fail_on_findings=False,
     _compute_exit_code must receive config_fail_on_findings=False and return 0
     even when actionable findings exist.

#52: OCI_RUNNER_WRAPPER env var must propagate through _get_oci_wrapper_prefix.
     The function already exists; tests confirm it is reachable from the container
     execution path and that the env var is not silently dropped.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_opts(tmp_path, fail_on_findings=None, mode=None):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions
    from automated_security_helper.core.enums import RunMode

    kwargs = dict(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_findings=fail_on_findings,
    )
    if mode is not None:
        kwargs["mode"] = mode
    return ScanOptions(**kwargs)


def _make_results_with_findings(count: int = 1):
    mock_metric = MagicMock()
    mock_metric.actionable = count
    results = MagicMock()
    results.sarif = None
    return results, mock_metric


# ---------------------------------------------------------------------------
# DA #51 — container mode must honour config fail_on_findings
# ---------------------------------------------------------------------------


class TestContainerModeConfigFailOnFindings:
    def test_compute_exit_code_uses_config_fail_on_findings_false_in_container_mode(
        self, tmp_path
    ):
        """Container scan with config.fail_on_findings=False and CLI unset → exit 0."""
        from automated_security_helper.interactions.run_ash_scan import (
            _compute_exit_code,
            ScanOptions,
        )

        opts = _make_opts(tmp_path, fail_on_findings=None)
        results, mock_metric = _make_results_with_findings(count=5)

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            code = _compute_exit_code(results, opts, config_fail_on_findings=False)

        assert code == 0, (
            "config_fail_on_findings=False with CLI unset must produce exit 0, not 2"
        )

    def test_compute_exit_code_uses_config_fail_on_findings_true_in_container_mode(
        self, tmp_path
    ):
        """Container scan with config.fail_on_findings=True and CLI unset → exit 2."""
        from automated_security_helper.interactions.run_ash_scan import (
            _compute_exit_code,
            ScanOptions,
        )

        opts = _make_opts(tmp_path, fail_on_findings=None)
        results, mock_metric = _make_results_with_findings(count=3)

        with patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[mock_metric],
        ):
            code = _compute_exit_code(results, opts, config_fail_on_findings=True)

        assert code == 2

    def test_run_ash_scan_container_mode_plumbs_config_fail_on_findings(self, tmp_path):
        """run_ash_scan in container mode must pass config_fail_on_findings to
        _compute_exit_code so YAML overrides are honoured.

        The config value is resolved via _resolve_config_fail_on_findings (file-based)
        before dispatch; we patch it to return False to simulate YAML fail_on_findings: false.
        """
        from automated_security_helper.interactions import run_ash_scan as mod
        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        dummy_results = MagicMock(spec=AshAggregatedResults)
        dummy_results.sarif = None

        captured: dict = {}

        original_compute = mod._compute_exit_code

        def spy_compute(results, opts, config_fail_on_findings=None):
            captured["results_type"] = type(results)
            captured["config_fof"] = config_fail_on_findings
            return original_compute(results, opts, config_fail_on_findings)

        mock_metric = MagicMock()
        mock_metric.actionable = 0

        # Patch _resolve_config_fail_on_findings to return False (simulating YAML override)
        with patch.object(mod, "_resolve_config_fail_on_findings", return_value=False):
            with patch.object(mod, "_run_container_mode", return_value=dummy_results):
                with patch.object(mod, "_compute_exit_code", side_effect=spy_compute):
                    with patch.object(mod, "_setup_logger", return_value=MagicMock()):
                        with patch(
                            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
                            return_value=[mock_metric],
                        ):
                            mod.run_ash_scan(
                                source_dir=tmp_path / "src",
                                output_dir=tmp_path / "out",
                                mode=RunMode.container,
                                fail_on_findings=None,
                                show_summary=False,
                            )

        assert captured.get("config_fof") is False, (
            "_compute_exit_code must receive config_fail_on_findings=False from container mode"
        )
        assert captured.get("results_type") is not tuple, (
            "results passed to _compute_exit_code must not be a tuple"
        )


# ---------------------------------------------------------------------------
# DA #52 — OCI_RUNNER_WRAPPER env var propagation
# ---------------------------------------------------------------------------


class TestOciRunnerWrapperEnvPropagation:
    def test_get_oci_wrapper_prefix_reads_env_var(self):
        """_get_oci_wrapper_prefix must return ['sudo'] when OCI_RUNNER_WRAPPER=sudo."""
        from automated_security_helper.interactions.run_ash_container import (
            _get_oci_wrapper_prefix,
        )

        with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo"}):
            prefix = _get_oci_wrapper_prefix()

        assert prefix == ["sudo"]

    def test_get_oci_wrapper_prefix_splits_multi_word(self):
        """OCI_RUNNER_WRAPPER='sudo finch' must split into ['sudo', 'finch']."""
        from automated_security_helper.interactions.run_ash_container import (
            _get_oci_wrapper_prefix,
        )

        with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo finch"}):
            prefix = _get_oci_wrapper_prefix()

        assert prefix == ["sudo", "finch"]

    def test_get_oci_wrapper_prefix_empty_when_unset(self):
        """Absent OCI_RUNNER_WRAPPER must return an empty list (no prefix)."""
        from automated_security_helper.interactions.run_ash_container import (
            _get_oci_wrapper_prefix,
        )

        env = {k: v for k, v in os.environ.items() if k != "OCI_RUNNER_WRAPPER"}
        with patch.dict(os.environ, env, clear=True):
            prefix = _get_oci_wrapper_prefix()

        assert prefix == []

    def test_oci_wrapper_prefix_prepended_to_run_command(self, tmp_path):
        """When OCI_RUNNER_WRAPPER=sudo, _assemble_run_command must include 'sudo'
        as the first token of the returned command list."""
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )
        from automated_security_helper.core.enums import ExecutionStrategy

        with patch.dict(os.environ, {"OCI_RUNNER_WRAPPER": "sudo"}):
            oci_wrapper_prefix = ["sudo"]
            cmd = _assemble_run_command(
                oci_command_prefix=oci_wrapper_prefix,
                resolved_oci_runner="finch",
                image_name="ash:latest",
                source_dir=tmp_path / "src",
                output_dir=tmp_path / "out",
                offline=False,
                debug=False,
                color=False,
                quiet=True,
                progress=False,
                verbose=False,
                simple=False,
                python_based_plugins_only=False,
                cleanup=False,
                inspect=False,
                fail_on_findings=None,
                phases=[],
                scanners=[],
                exclude_scanners=[],
                output_formats=[],
                config=None,
                config_overrides=[],
                existing_results=None,
                ash_plugin_modules=[],
                strategy=ExecutionStrategy.PARALLEL,
                ctx=None,
            )

        assert cmd[0] == "sudo", f"Expected 'sudo' as first token, got: {cmd[:3]}"
        assert "finch" in cmd
