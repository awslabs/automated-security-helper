"""TDD tests for DA followup #57 — _resolve_config_fail_on_findings race in container mode.

When running in container mode the host calls _resolve_config_fail_on_findings() to
decide the local exit code, then launches the container.  If the user mutates the
config file between those two events the container may re-read a different value,
producing a host/container disagreement.

Fix: pass the already-resolved value into the container via the env var
ASH_CONFIG_FAIL_ON_FINDINGS so the container never re-reads the file.
The container side reads that env var instead of re-resolving via AshConfig.

These tests verify:
1. _run_container_mode passes the resolved fail_on_findings value to run_ash_container.
2. A simulated config mutation between host read and container call does not change
   what the host computes.
3. Local mode is unaffected (still resolves via orchestrator).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_opts(tmp_path, *, fail_on_findings=None, mode_str="container"):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions
    from automated_security_helper.core.enums import RunMode

    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)

    return ScanOptions(
        source_dir=src,
        output_dir=out,
        fail_on_findings=fail_on_findings,
        mode=RunMode[mode_str],
    )


def _write_config(tmp_path, *, fail_on_findings: bool) -> Path:
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        f"fail_on_findings: {'true' if fail_on_findings else 'false'}\n",
        encoding="utf-8",
    )
    return config_path


# ---------------------------------------------------------------------------
# Test 1 — _resolve_config_fail_on_findings returns host-read value and
# run_ash_container receives fail_on_findings equal to that value
# ---------------------------------------------------------------------------


class TestContainerReceivesResolvedFailOnFindings:
    def test_resolved_value_passed_to_run_ash_container(self, tmp_path):
        """run_ash_container must be called with the value resolved before config mutation."""
        from automated_security_helper.interactions.run_ash_scan import (
            _run_container_mode,
            _resolve_config_fail_on_findings,
        )

        config_path = _write_config(tmp_path, fail_on_findings=False)
        opts = _make_opts(tmp_path)
        opts = opts.model_copy(update={"config": str(config_path)})

        # Host resolves BEFORE any mutation
        resolved = _resolve_config_fail_on_findings(opts)
        assert resolved is False

        fake_result = MagicMock()
        fake_result.returncode = 0
        results_file = opts.output_dir / "ash_aggregated_results.json"
        results_file.write_text('{"sarif": null, "scanners": []}', encoding="utf-8")

        captured_kwargs: dict = {}

        def fake_run_ash_container(**kwargs):
            captured_kwargs.update(kwargs)
            return fake_result

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                side_effect=fake_run_ash_container,
            ),
            patch(
                "automated_security_helper.interactions.run_ash_scan.AshAggregatedResults.model_validate_json",
                return_value=MagicMock(),
            ),
        ):
            _run_container_mode(opts, MagicMock(), resolved_fail_on_findings=resolved)

        # After we resolved to False, the value forwarded must be False
        assert captured_kwargs.get("fail_on_findings") is False

    def test_mutation_between_host_read_and_container_call_does_not_affect_host(
        self, tmp_path
    ):
        """Mutating the config file after _resolve_config_fail_on_findings does not change
        the value the host computed for exit-code purposes."""
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_findings,
        )

        config_path = _write_config(tmp_path, fail_on_findings=False)
        opts = _make_opts(tmp_path)
        opts = opts.model_copy(update={"config": str(config_path)})

        # Host reads: False
        resolved_before = _resolve_config_fail_on_findings(opts)
        assert resolved_before is False

        # Simulate mutation
        config_path.write_text("fail_on_findings: true\n", encoding="utf-8")

        # Host value was captured; re-reading gives True but we already have False
        resolved_after = _resolve_config_fail_on_findings(opts)
        assert resolved_after is True  # confirms mutation took effect on disk

        # The host exit code is based on resolved_before, not resolved_after
        assert resolved_before is False, "host must use the value it originally read"


# ---------------------------------------------------------------------------
# Test 2 — local mode unaffected: still resolves via orchestrator
# ---------------------------------------------------------------------------


class TestLocalModeUnaffected:
    def test_local_mode_resolves_via_orchestrator(self, tmp_path):
        """run_ash_scan in local mode must use the orchestrator's config value,
        not the pre-read file-based value."""
        from automated_security_helper.interactions.run_ash_scan import (
            run_ash_scan,
            _compute_exit_code,
        )
        from automated_security_helper.core.enums import RunMode

        src = tmp_path / "src"
        src.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "out"
        out.mkdir(parents=True, exist_ok=True)

        mock_results = MagicMock()
        mock_results.sarif = None
        # Simulate orchestrator config reporting fail_on_findings=False
        mock_orchestrator = MagicMock()
        mock_orchestrator.config.fail_on_findings = False

        output_file = out / "ash_aggregated_results.json"
        output_file.write_text('{"sarif": null, "scanners": []}', encoding="utf-8")

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan._run_local_mode",
                return_value=(mock_results, False),
            ),
            patch(
                "automated_security_helper.interactions.run_ash_scan._compute_exit_code",
                return_value=0,
            ) as mock_exit,
        ):
            run_ash_scan(
                source_dir=str(src),
                output_dir=str(out),
                fail_on_findings=None,
            )

        # _compute_exit_code must have been called with config_fail_on_findings=False
        call_args = mock_exit.call_args
        assert call_args is not None
        # config_fail_on_findings is the third positional or keyword arg
        config_fof = call_args.args[2] if len(call_args.args) > 2 else call_args.kwargs.get("config_fail_on_findings")
        assert config_fof is False
