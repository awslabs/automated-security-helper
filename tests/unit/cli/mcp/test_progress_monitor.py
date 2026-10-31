# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for cli/mcp/progress_monitor.py."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# conftest.py in this directory stubs out mcp.server.mcpserver before collection.
from automated_security_helper.cli.mcp import progress_monitor
from automated_security_helper.cli.mcp.progress_monitor import monitor_scan_progress

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _bounded_monitor_wait(monkeypatch):
    """Cap the monitor's wait so a stub that never ends the scan fails, not hangs.

    The loop polls until the registry reports a terminal status or
    ``_MAX_WAIT_SECONDS`` (1800) pass, sleeping between polls. A stub that
    answers no status, through a mistake in a test, made one test here run
    the whole half hour under a real ``asyncio.sleep`` and the unit job's
    600 s budget cut it. Sixty seconds is far above any test here (a real poll
    sleep is 5 s) and far below any budget.
    """
    monkeypatch.setattr(progress_monitor, "_MAX_WAIT_SECONDS", 60)


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
    async def test_completes_when_the_registry_says_completed(self, mock_ctx, tmp_path):
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
                "status": "completed",
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
                "status": "completed" if call_count >= 3 else "running",
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
                return_value={
                    "success": True,
                    "status": "completed",
                    "directory_path": str(tmp_path),
                }
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


def _progress_sequence(tmp_path, *statuses):
    """A progress stub answering the scan-info lookup, then ``statuses`` in turn.

    ``monitor_scan_progress`` calls the progress tool once for the scan's
    directory (``_fetch_initial_scan_info``) before its poll loop starts, so
    the first call gets the directory and no status; each poll then takes the
    next status, and the last one repeats once the sequence is spent. An
    earlier shape of this stub spent a status on the lookup, so a one-status
    sequence left every poll without one and the monitor waited out its whole
    budget: the unit job hung at that test.
    """
    answers = iter(statuses)
    state = {"looked_up": False, "last": None}

    async def fake_progress(scan_id, **kwargs):
        reply = {"success": True, "directory_path": str(tmp_path)}
        if not state["looked_up"]:
            state["looked_up"] = True
            return reply
        status = next(answers, state["last"])
        state["last"] = status
        if status is not None:
            reply["status"] = status
        return reply

    return fake_progress


class TestCompletionFollowsTheRegistryStatus:
    """The scan is over when the registry says so, not when a results file exists.

    The loop tested for ``ash_aggregated_results.json`` before it read the
    registry's status. The file is there before the scan ends when the previous
    scan's results were not set aside, it is put back when a scan fails or is
    cancelled without results, and the SCAN phase writes it before the REPORT
    phase has run; each of those was announced as "Scan completed" with the
    file's findings. Red at the base: the running and failed scans below were
    announced as completed on their first poll.
    """

    @pytest.mark.asyncio
    async def test_a_previous_results_file_does_not_complete_a_running_scan(
        self, mock_ctx, tmp_path
    ):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        (output_dir / "ash_aggregated_results.json").write_text("{}")
        get_results = AsyncMock(return_value=_results_reply(total=0))

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=_progress_sequence(tmp_path, "running", "running", "completed"),
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=get_results,
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await monitor_scan_progress(mock_ctx, "scan-prev")

        # Read once, after the registry said completed, never on the first poll.
        assert get_results.await_count == 1
        completed = [
            call.args[0]
            for call in mock_ctx.info.await_args_list
            if str(call.args[0]).startswith("Scan completed")
        ]
        assert completed == ["Scan completed with no findings."]

    @pytest.mark.asyncio
    async def test_a_failed_scan_with_results_put_back_is_reported_failed(
        self, mock_ctx, tmp_path
    ):
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        (output_dir / "ash_aggregated_results.json").write_text("{}")
        get_results = AsyncMock(return_value=_results_reply(total=0))

        async def fake_progress(scan_id, **kwargs):
            if "directory_path" not in getattr(fake_progress, "seen", {}):
                fake_progress.seen = {"directory_path": True}
                return {"success": True, "directory_path": str(tmp_path)}
            return {
                "success": True,
                "status": "failed",
                "error_message": "scanner crashed",
                "directory_path": str(tmp_path),
            }

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=fake_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=get_results,
            ),
        ):
            await monitor_scan_progress(mock_ctx, "scan-failed")

        assert get_results.await_count == 0
        mock_ctx.error.assert_any_await("Scan failed: scanner crashed")
        completed = [
            call.args[0]
            for call in mock_ctx.info.await_args_list
            if str(call.args[0]).startswith("Scan completed")
        ]
        assert completed == []

    @pytest.mark.asyncio
    async def test_a_completed_status_without_a_results_file_still_completes(
        self, mock_ctx, tmp_path
    ):
        """Control: the status alone ends the loop; the results call answers."""
        (tmp_path / ".ash" / "ash_output").mkdir(parents=True)
        get_results = AsyncMock(
            return_value={"success": False, "error": "no results file"}
        )

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=_progress_sequence(tmp_path, "completed"),
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=get_results,
            ),
        ):
            await monitor_scan_progress(mock_ctx, "scan-status-only")

        assert get_results.await_count == 1


class TestScannerResultsAreReadWithoutFollowingLinks:
    """A scanner's results file is read only when it is a regular file at its name.

    The directory a scanner writes is one a sandboxed scanner controls. The
    monitor opened each ``ASH.ScanResults.json`` with a plain ``open()``, which
    followed a link at the name to any file the server can read and blocked the
    event loop on a FIFO. Red at the base: the linked file's counts were reported
    as the scanner's.
    """

    @pytest.mark.asyncio
    async def test_a_linked_results_file_is_not_read(self, mock_ctx, tmp_path):
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text(json.dumps({"severity_counts": {"critical": 9}}))
        output_dir = tmp_path / "proj" / ".ash" / "ash_output"
        scanner_dir = output_dir / "scanners" / "bandit" / "source"
        scanner_dir.mkdir(parents=True)
        (scanner_dir / "ASH.ScanResults.json").symlink_to(elsewhere)

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=_progress_sequence(tmp_path / "proj", "running", "completed"),
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=AsyncMock(return_value=_results_reply(total=0)),
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await monitor_scan_progress(mock_ctx, "scan-link")

        messages = [
            str(call.kwargs.get("message", ""))
            for call in mock_ctx.report_progress.await_args_list
        ]
        assert not any("9 critical" in m for m in messages), messages
        mock_ctx.warning.assert_awaited()

    @pytest.mark.asyncio
    async def test_a_regular_results_file_is_read(self, mock_ctx, tmp_path):
        """Control: the scanner's own file is reported as before."""
        output_dir = tmp_path / ".ash" / "ash_output"
        scanner_dir = output_dir / "scanners" / "bandit" / "source"
        scanner_dir.mkdir(parents=True)
        (scanner_dir / "ASH.ScanResults.json").write_text(
            json.dumps({"severity_counts": {"high": 2}})
        )

        with (
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_progress",
                new=_progress_sequence(tmp_path, "running", "completed"),
            ),
            patch(
                "automated_security_helper.cli.mcp.progress_monitor.mcp_get_scan_results",
                new=AsyncMock(return_value=_results_reply(total=2)),
            ),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await monitor_scan_progress(mock_ctx, "scan-regular")

        messages = [
            str(call.kwargs.get("message", ""))
            for call in mock_ctx.report_progress.await_args_list
        ]
        assert any("bandit completed source scan: 2 high" in m for m in messages)


class TestWorkspaceProgressCountsOnlyNewResults:
    """A project is complete when its results file changed, not when one exists.

    With ``clean_output`` off the previous scan's file is in place from the
    start, and a failed project's restore puts its previous file back; both
    were counted as complete. Red at the base: the pre-existing file below was
    reported complete on the first sweep.
    """

    @pytest.mark.asyncio
    async def test_a_pre_existing_results_file_is_not_a_completed_project(
        self, tmp_path
    ):
        from automated_security_helper.cli.mcp.progress_monitor import (
            monitor_workspace_progress,
        )

        out = tmp_path / "projects" / "a"
        out.mkdir(parents=True)
        (out / "ash_aggregated_results.json").write_text("{}")
        report = AsyncMock()

        task = asyncio.ensure_future(
            monitor_workspace_progress(report, {"a": out}, poll_interval=0.01)
        )
        await asyncio.sleep(0.1)
        try:
            messages = [
                str(call.kwargs.get("message", "")) for call in report.await_args_list
            ]
            assert not any("a complete" in m for m in messages), messages
            assert not task.done()
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_a_previous_file_put_back_after_the_set_aside_is_not_complete(
        self, tmp_path
    ):
        """Red at the base: the monitor took its own baseline as it started, which
        is after the workspace scan had set the previous results aside, so it read
        the file as absent and counted a failed project's restore of it as that
        project's completion. The caller's snapshot from before the set-aside is
        the baseline now."""
        from automated_security_helper.cli.mcp.progress_monitor import (
            monitor_workspace_progress,
            results_files_before,
        )

        out = tmp_path / "projects" / "a"
        out.mkdir(parents=True)
        results = out / "ash_aggregated_results.json"
        results.write_text("{}")
        before = results_files_before({"a": out})
        set_aside = tmp_path / "set-aside.json"
        results.rename(set_aside)
        report = AsyncMock()

        task = asyncio.ensure_future(
            monitor_workspace_progress(
                report, {"a": out}, poll_interval=0.01, before=before
            )
        )
        await asyncio.sleep(0.05)
        set_aside.rename(results)
        await asyncio.sleep(0.1)
        try:
            messages = [
                str(call.kwargs.get("message", "")) for call in report.await_args_list
            ]
            assert not any("a complete" in m for m in messages), messages
            assert not task.done()
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_a_rewritten_results_file_completes_the_project(self, tmp_path):
        """Control: the scan writing its own results is counted."""
        from automated_security_helper.cli.mcp.progress_monitor import (
            monitor_workspace_progress,
        )

        out = tmp_path / "projects" / "a"
        out.mkdir(parents=True)
        results = out / "ash_aggregated_results.json"
        results.write_text("{}")
        report = AsyncMock()

        task = asyncio.ensure_future(
            monitor_workspace_progress(report, {"a": out}, poll_interval=0.01)
        )
        await asyncio.sleep(0.05)
        results.write_text('{"metadata": {}}')
        await asyncio.wait_for(task, timeout=5)

        messages = [
            str(call.kwargs.get("message", "")) for call in report.await_args_list
        ]
        assert any("a complete (1/1 projects)" in m for m in messages), messages
