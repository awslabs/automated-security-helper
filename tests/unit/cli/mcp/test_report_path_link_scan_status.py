# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP scan refused for a link at a report path says which link.

``run_ash_scan`` exits 1 for the refusal, as for any error, and the MCP runner used
to record every exit 1 as "ASH exited with code 1". The client cannot read the
console the reason went to, so the refusal carries it (``ReportPathRefusedExit``)
and the runner adds it to the scan's error message.

The real runner, ``run_ash_scan``, ``_run_local_mode`` and ``ReportPhase`` run. Only
the orchestrator is replaced, by one whose scan is the report phase alone over a
reports directory holding a link: a fresh scan would clear that directory first.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _ReportOnlyOrchestrator:
    config = None

    def __init__(self, **kwargs: Any) -> None:
        self.output_dir = Path(kwargs["output_dir"])
        self.source_dir = Path(kwargs["source_dir"])

    @classmethod
    def create(cls, **kwargs: Any) -> "_ReportOnlyOrchestrator":
        return cls(**kwargs)

    def add_metadata(self, **values: Any) -> None:
        """run_ash_scan records changed_files_only and scan_source before the scan
        (ASHScanOrchestrator.add_metadata); this report-only stand-in keeps none."""

    def execute_scan(self, phases=None):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.phases.report_phase import ReportPhase
        from automated_security_helper.core.progress import LiveProgressDisplay
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        model = AshAggregatedResults()
        return ReportPhase(
            plugins=[SarifReporter],
            plugin_context=PluginContext(
                source_dir=self.source_dir,
                output_dir=self.output_dir,
                config=AshConfig(),
            ),
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=model,
        ).execute(
            report_dir=self.output_dir / "reports",
            aggregated_results=model,
            cli_output_formats=None,
            python_based_plugins_only=False,
        )


def test_the_scan_is_failed_with_the_link_named(tmp_path):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core import orchestrator
    from automated_security_helper.interactions import run_ash_scan as ras

    source = tmp_path / "proj"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    (output / "reports").mkdir(parents=True)
    outside = tmp_path / "outside.sarif"
    outside.write_text("unchanged", encoding="utf-8")
    link = output / "reports" / "ash.sarif"
    link.symlink_to(outside)

    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "ASHScanOrchestrator", _ReportOnlyOrchestrator),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold="MEDIUM",
            )
        )

    progress = registry.check_scan_progress(scan_id)
    assert progress["status"] == "failed"
    assert progress["error_message"].startswith("ASH exited with code 1: ")
    assert f"{link.as_posix()} is a symlink" in progress["error_message"]
    assert outside.read_text(encoding="utf-8") == "unchanged"
