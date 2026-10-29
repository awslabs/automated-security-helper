# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for cli/mcp/progress_monitor.py."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# conftest.py in this directory stubs out mcp.server.mcpserver before collection.
from automated_security_helper.cli.mcp.progress_monitor import monitor_scan_progress

pytestmark = pytest.mark.unit


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
    async def test_completes_when_aggregated_results_file_appears(
        self, mock_ctx, tmp_path
    ):
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
            return {
                "success": True,
                "status": "running",
                "directory_path": str(tmp_path),
            }

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
                        "summary_stats": {"severity_counts": {}, "total": 0},
                    }
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
            raise asyncio.CancelledError

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
        result_file.write_text(
            json.dumps({"severity_counts": {"high": 2, "medium": 1}})
        )

        aggregated = output_dir / "ash_aggregated_results.json"

        call_count = 0

        async def fake_progress(scan_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": True, "directory_path": str(tmp_path)}
            if call_count >= 3:
                aggregated.write_text("{}")
            return {
                "success": True,
                "status": "running",
                "directory_path": str(tmp_path),
            }

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
                        "summary_stats": {
                            "severity_counts": {"high": 2, "medium": 1},
                            "total": 3,
                        },
                    }
                ),
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await monitor_scan_progress(mock_ctx, "scan-progress")

        assert mock_ctx.report_progress.await_count >= 1


def _results_reply(**summary_stats) -> dict:
    """What ``mcp_get_scan_results`` answers for a completed scan.

    The producer returns the aggregated results' ``summary_stats``
    (``severity_counts`` and ``total``) and never a top-level ``findings_count``
    or ``severity_counts``; the stubs here carry its shape so a monitor that
    reads the wrong keys is caught.
    """
    return {"success": True, "summary_stats": summary_stats}


async def _completed_scan(mock_ctx, tmp_path, results_reply, **monitor_kwargs):
    """Run the monitor over a scan whose aggregated results already exist."""
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    (output_dir / "ash_aggregated_results.json").write_text("{}")
    get_results = AsyncMock(return_value=results_reply)

    with (
        patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
            new=AsyncMock(
                return_value={"success": True, "directory_path": str(tmp_path)}
            ),
        ),
        patch(
            "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
            new=get_results,
        ),
    ):
        await monitor_scan_progress(mock_ctx, "scan-done", **monitor_kwargs)
    return get_results


class TestCompletionSummaryReadsTheResultsReply:
    """The completion summary is built from what the results call returns.

    The monitor read ``findings_count`` and ``severity_counts`` from the reply,
    which carries neither (they are inside ``summary_stats``), so every
    completed scan was announced as "Scan completed with no findings." whatever
    it found. Red at the base: the summary sent names no findings.
    """

    @pytest.mark.asyncio
    async def test_a_scan_with_findings_is_announced_with_its_counts(
        self, mock_ctx, tmp_path
    ):
        await _completed_scan(
            mock_ctx,
            tmp_path,
            _results_reply(
                severity_counts={
                    "suppressed": 1,
                    "critical": 0,
                    "high": 2,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
                total=3,
            ),
        )

        summaries = [
            call.args[0]
            for call in mock_ctx.info.await_args_list
            if str(call.args[0]).startswith("Scan completed")
        ]
        assert summaries == [
            "Scan completed with 3 findings: 1 suppressed, 2 high, 1 medium"
        ]

    @pytest.mark.asyncio
    async def test_a_total_the_reply_omits_is_summed_from_the_severities(
        self, mock_ctx, tmp_path
    ):
        """A reply whose stats carry the counts but no total still counts them.

        Suppressed findings are left out of the count, as the model's own
        ``total`` leaves them out.
        """
        await _completed_scan(
            mock_ctx,
            tmp_path,
            _results_reply(severity_counts={"suppressed": 4, "high": 1, "low": 2}),
        )

        summaries = [
            call.args[0]
            for call in mock_ctx.info.await_args_list
            if str(call.args[0]).startswith("Scan completed")
        ]
        assert summaries == [
            "Scan completed with 3 findings: 4 suppressed, 1 high, 2 low"
        ]

    @pytest.mark.asyncio
    async def test_a_clean_scan_is_announced_as_clean(self, mock_ctx, tmp_path):
        """Control: a reply with every count at zero still reads as no findings."""
        await _completed_scan(
            mock_ctx,
            tmp_path,
            _results_reply(severity_counts={"high": 0, "suppressed": 0}, total=0),
        )

        mock_ctx.info.assert_any_await("Scan completed with no findings.")

    @pytest.mark.asyncio
    async def test_the_results_are_read_as_the_scans_session(self, mock_ctx, tmp_path):
        """The results call is made as the session that started the scan.

        A delivered tree's output sits in that session's sandbox, which no
        operator grant names, so a read with no session is refused and the
        completion summary was never sent for a delivered tree. Red at the base:
        the call carried no session.
        """
        get_results = await _completed_scan(
            mock_ctx,
            tmp_path,
            _results_reply(severity_counts={}, total=0),
            session_id="session-a",
        )

        assert get_results.await_count == 1
        assert get_results.await_args.kwargs.get("session_id") == "session-a"

    @pytest.mark.asyncio
    async def test_the_default_session_passes_no_session(self, mock_ctx, tmp_path):
        """Control: with no session the results call names none, as before."""
        get_results = await _completed_scan(
            mock_ctx, tmp_path, _results_reply(severity_counts={}, total=0)
        )

        assert "session_id" not in get_results.await_args.kwargs
