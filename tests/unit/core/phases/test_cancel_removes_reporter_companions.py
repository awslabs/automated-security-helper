# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan puts back the previous scan's reports, a reporter's own files included.

Why this exists
---------------
cancel_scan's promise is that a scan stopped during the report phase leaves no
report of its own: the report phase removes the reports it wrote, and where the
previous scan's results were set aside they are put back in their place. The
unused-suppressions reporter writes a second file of its own,
``ash.unused-suppressions.md``, beside the JSON the phase writes for it. Here the
cancel lands once that reporter has run, with a previous scan's results set
aside: its markdown and the other reports have to come back byte for byte, in
place of what the cancelled scan wrote.

The scan goes through the real MCP tool, runner, run_ash_scan and orchestrator,
as in tests/unit/core/test_previous_results_are_kept.py; only the engine is
reduced to the real report phase, with the unused-suppressions reporter and one
other selected.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests.utils.tasks import drain

MARKDOWN = "ash.unused-suppressions.md"

#: The previous scan's reports, in bytes, so the restore is checked byte for byte:
#: a CRLF line ending and a non-ASCII character survive only an exact copy.
PREVIOUS = {
    "reports/ash.sarif": b'{"previous": "sarif"}',
    "reports/ash.unused-suppressions.json": b'{"previous": "unused"}',
    f"reports/{MARKDOWN}": "# Previous unused suppressions\r\n— none\n".encode("utf-8"),
    "ash_aggregated_results.json": b'{"previous": "results"}',
}


def _project(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    for rel, data in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return source, output


def _report_phase_only(self, phases=None, **kwargs):
    """execute_phases, running only the real report phase with two real reporters."""
    from automated_security_helper.core.phases.report_phase import ReportPhase

    phase = ReportPhase(
        plugins=self.plugins["reporter"],
        plugin_context=self._context,
        progress_display=self.progress_display,
        asharp_model=self._asharp_model,
    )
    return phase.execute(
        report_dir=self._context.output_dir.joinpath("reports"),
        cli_output_formats=["unused-suppressions", "sarif"],
        aggregated_results=self._asharp_model,
        python_based_plugins_only=False,
    )


@pytest.mark.asyncio
async def test_a_cancel_after_the_unused_suppressions_reporter_puts_the_previous_reports_back(
    tmp_path, monkeypatch
):
    """cancel_scan lands once the unused-suppressions reporter has built its report.

    By then the reporter has written its markdown itself. The phase sees the
    cancel before it writes the JSON the reporter returned, and stops; the
    previous scan's reports, that markdown included, come back byte for byte.
    """
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        unused_suppressions_reporter,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    source, output = _project(tmp_path)

    reporter = unused_suppressions_reporter.UnusedSuppressionsReporter
    real_report = reporter.report
    wrote_markdown = []

    def report_then_cancel(self, model):
        result = real_report(self, model)
        written = output / "reports" / MARKDOWN
        wrote_markdown.append(
            written.exists() and written.read_bytes() != PREVIOUS[f"reports/{MARKDOWN}"]
        )
        registry = get_scan_registry()
        for scan in registry.list_scans():
            registry.cancel_scan(scan["scan_id"])
        return result

    monkeypatch.setattr(reporter, "report", report_then_cancel)
    monkeypatch.setattr(ScanExecutionEngine, "execute_phases", _report_phase_only)
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
    assert begun["success"] is True, begun
    await drain(timeout=60)

    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress
    # The reporter ran and wrote its own markdown, or the test proves nothing.
    assert wrote_markdown == [True], wrote_markdown
    assert (output / "reports" / MARKDOWN).read_bytes() == PREVIOUS[
        f"reports/{MARKDOWN}"
    ]
    assert (output / "reports" / "ash.sarif").read_bytes() == PREVIOUS[
        "reports/ash.sarif"
    ]
