# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for cli/mcp/progress_monitor.py."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# conftest.py in this directory stubs out mcp.server.fastmcp before collection.
from automated_security_helper.cli.mcp.progress_monitor import monitor_scan_progress


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


class TestMonitorScanProgress:
    @pytest.mark.asyncio
    async def test_exits_early_when_initial_progress_fails(self, mock_ctx):
        with patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=AsyncMock(return_value={"success": False, "error": "not found"}),
        ):
            await monitor_scan_progress(mock_ctx, "scan-xyz")
        mock_ctx.error.assert_awaited()

    @pytest.mark.asyncio
    async def test_exits_early_when_directory_path_missing(self, mock_ctx):
        with patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=AsyncMock(return_value={"success": True, "directory_path": ""}),
        ):
            await monitor_scan_progress(mock_ctx, "scan-xyz")
        mock_ctx.error.assert_awaited()

    @pytest.mark.asyncio
    async def test_completes_when_aggregated_results_file_appears(self, mock_ctx, tmp_path):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        aggregated = output_dir / "ash_aggregated_results.json"
        aggregated.write_text("{}")

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            return {"success": True, "status": "running", "directory_path": str(tmp_path)}

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=fake_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=AsyncMock(
                    return_value={"success": True, "findings_count": 0, "severity_counts": {}}
                ),
            ),
        ):
            await monitor_scan_progress(mock_ctx, "scan-abc")

        mock_ctx.report_progress.assert_awaited()

    @pytest.mark.asyncio
    async def test_exits_when_scan_status_is_failed(self, mock_ctx, tmp_path):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            return {
                "success": True,
                "status": "failed",
                "error_message": "Scanner crashed",
                "directory_path": str(tmp_path),
            }

        with patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=fake_progress,
        ):
            await monitor_scan_progress(mock_ctx, "scan-fail")

        mock_ctx.error.assert_awaited()

    @pytest.mark.asyncio
    async def test_exits_when_scan_status_is_cancelled(self, mock_ctx, tmp_path):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            return {
                "success": True,
                "status": "cancelled",
                "directory_path": str(tmp_path),
            }

        with patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=fake_progress,
        ):
            await monitor_scan_progress(mock_ctx, "scan-cancelled")

        mock_ctx.info.assert_awaited()

    @pytest.mark.asyncio
    async def test_handles_cancellation_gracefully(self, mock_ctx, tmp_path):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            raise asyncio.CancelledError()

        with patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=fake_progress,
        ):
            # Should NOT propagate — monitor swallows CancelledError
            await monitor_scan_progress(mock_ctx, "scan-cancel")

    @pytest.mark.asyncio
    async def test_reports_scanner_progress_from_result_files(self, mock_ctx, tmp_path):
        output_dir = tmp_path / ".ash" / "ash_output"
        scanners_dir = output_dir / "scanners" / "bandit" / "source"
        scanners_dir.mkdir(parents=True)
        result_file = scanners_dir / "ASH.ScanResults.json"
        result_file.write_text(json.dumps({"severity_counts": {"high": 2, "medium": 1}}))

        aggregated = output_dir / "ash_aggregated_results.json"

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            if call_count >= 3:
                aggregated.write_text("{}")
            return {"success": True, "status": "running", "directory_path": str(tmp_path)}

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=fake_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=AsyncMock(
                    return_value={
                        "success": True,
                        "findings_count": 3,
                        "severity_counts": {"high": 2, "medium": 1},
                    }
                ),
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await monitor_scan_progress(mock_ctx, "scan-progress")

        assert mock_ctx.report_progress.await_count >= 1
