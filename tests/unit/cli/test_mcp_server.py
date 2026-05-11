#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for MCP server implementation.

Tests cover server initialization, tool registration, request handling,
error responses, and helper functions in the mcp_server module.
"""

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    """Create a mock MCP Context with async logging methods."""
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.fixture
def mock_scan_registry_entry():
    """Create a mock ScanRegistryEntry."""
    entry = MagicMock()
    entry.output_directory = "/tmp/test-project/.ash/ash_output"  # nosec B108
    entry.scan_id = "test-scan-123"
    entry.directory_path = "/tmp/test-project"  # nosec B108
    entry.status = "running"
    return entry


@pytest.fixture
def sample_full_results():
    """Return a sample full results dict mirroring real scan output."""
    return {
        "success": True,
        "scan_id": "scan-abc",
        "status": "completed",
        "is_complete": True,
        "completion_time": "2025-01-01T00:00:00Z",
        "summary_stats": {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "low": 3,
            "info": 1,
            "suppressed": 4,
            "total": 25,
            "actionable": 21,
            "passed": 3,
            "failed": 2,
            "missing": 0,
            "skipped": 1,
        },
        "scanner_reports": {
            "bandit": {"findings": 7},
            "semgrep": {"findings": 5},
        },
        "raw_results": {
            "metadata": {
                "generated_at": "2025-01-01T00:00:00Z",
                "tool_version": "2.0.0",
                "summary_stats": {"duration": 42.5},
            },
            "scanner_results": {
                "bandit": {
                    "status": "FAILED",
                    "finding_count": 7,
                    "actionable_finding_count": 5,
                    "suppressed_finding_count": 2,
                    "duration": 3.1,
                    "severity_counts": {
                        "critical": 1,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                        "info": 0,
                        "suppressed": 2,
                    },
                },
                "semgrep": {
                    "status": "PASSED",
                    "finding_count": 5,
                    "actionable_finding_count": 5,
                    "suppressed_finding_count": 0,
                    "duration": 8.2,
                    "severity_counts": {
                        "critical": 1,
                        "high": 2,
                        "medium": 2,
                        "low": 0,
                        "info": 0,
                        "suppressed": 0,
                    },
                },
            },
            "additional_reports": {
                "bandit": {"extra": "data"},
                "semgrep": {"extra": "data2"},
            },
            "sarif": {
                "runs": [
                    {
                        "results": [
                            {"ruleId": "B101", "suppressions": []},
                            {
                                "ruleId": "B102",
                                "suppressions": [{"kind": "inSource"}],
                            },
                            {"ruleId": "B103"},
                        ]
                    }
                ]
            },
        },
    }


# ---------------------------------------------------------------------------
# Server initialization and module-level tests
# ---------------------------------------------------------------------------


class TestServerInitialization:
    """Tests for MCP server module initialization."""

    def test_mcp_server_module_imports(self):
        """Module imports without error and exposes the FastMCP instance."""
        from automated_security_helper.cli.mcp_server import mcp

        assert mcp is not None
        assert mcp.name == "ASH Security Scanner"

    def test_run_mcp_server_keyboard_interrupt(self):
        """run_mcp_server handles KeyboardInterrupt gracefully."""
        from automated_security_helper.cli.mcp_server import run_mcp_server

        with patch(
            "automated_security_helper.cli.mcp_server.mcp"
        ) as mock_mcp:
            mock_mcp.run.side_effect = KeyboardInterrupt()
            # Should not raise
            run_mcp_server()

    def test_run_mcp_server_closed_resource_error(self):
        """run_mcp_server logs warning for ClosedResourceError."""
        from automated_security_helper.cli.mcp_server import run_mcp_server

        with patch(
            "automated_security_helper.cli.mcp_server.mcp"
        ) as mock_mcp:
            mock_mcp.run.side_effect = RuntimeError("ClosedResourceError in TaskGroup")
            # Should not raise
            run_mcp_server()

    def test_run_mcp_server_generic_exception(self):
        """run_mcp_server logs exception for unexpected errors."""
        from automated_security_helper.cli.mcp_server import run_mcp_server

        with patch(
            "automated_security_helper.cli.mcp_server.mcp"
        ) as mock_mcp:
            mock_mcp.run.side_effect = ValueError("Something unexpected")
            # Should not raise
            run_mcp_server()


# ---------------------------------------------------------------------------
# run_ash_scan tool
# ---------------------------------------------------------------------------


class TestRunAshScan:
    """Tests for the run_ash_scan tool function."""

    @pytest.mark.asyncio
    async def test_scan_success(self, mock_ctx):
        """Successful scan start returns scan_id and running status."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        mock_result = {
            "success": True,
            "scan_id": "scan-001",
        }

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
            patch("automated_security_helper.cli.mcp_server.asyncio.create_task") as mock_task,
            patch("pathlib.Path.cwd", return_value=Path("/tmp/project")),  # nosec B108
        ):
            mock_task.return_value = MagicMock()
            mock_task.return_value.add_done_callback = MagicMock()

            result = await run_ash_scan(
                ctx=mock_ctx,
                source_dir="/tmp/project",  # nosec B108
                severity_threshold="HIGH",
            )

        assert result["success"] is True
        assert result["scan_id"] == "scan-001"
        assert result["status"] == "running"
        assert "important" in result
        mock_ctx.info.assert_called()

    @pytest.mark.asyncio
    async def test_scan_uses_cwd_when_source_dir_is_none(self, mock_ctx):
        """When source_dir is None, defaults to cwd."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        mock_result = {"success": True, "scan_id": "scan-002"}

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value=mock_result,
            ) as mock_scan,
            patch("automated_security_helper.cli.mcp_server.asyncio.create_task") as mock_task,
            patch("pathlib.Path.cwd", return_value=Path("/home/user/myrepo")),
        ):
            mock_task.return_value = MagicMock()
            mock_task.return_value.add_done_callback = MagicMock()

            result = await run_ash_scan(ctx=mock_ctx, source_dir=None)

        assert result["success"] is True
        # The scan should have been called with the cwd path
        call_kwargs = mock_scan.call_args[1]
        assert str(Path("/home/user/myrepo")) in call_kwargs["directory_path"]

    @pytest.mark.asyncio
    async def test_scan_resolves_relative_path(self, mock_ctx):
        """Relative source_dir gets resolved to absolute path."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        mock_result = {"success": True, "scan_id": "scan-003"}

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value=mock_result,
            ) as mock_scan,
            patch("automated_security_helper.cli.mcp_server.asyncio.create_task") as mock_task,
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            mock_task.return_value = MagicMock()
            mock_task.return_value.add_done_callback = MagicMock()

            result = await run_ash_scan(ctx=mock_ctx, source_dir="subdir")

        assert result["success"] is True
        call_kwargs = mock_scan.call_args[1]
        assert Path(call_kwargs["directory_path"]) == Path("/workspace/subdir")

    @pytest.mark.asyncio
    async def test_scan_start_failure(self, mock_ctx):
        """When mcp_scan_directory returns failure, error result is returned."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        mock_result = {"success": False, "error": "Permission denied"}

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/tmp")),  # nosec B108
        ):
            result = await run_ash_scan(ctx=mock_ctx, source_dir="/tmp")  # nosec B108

        assert result["success"] is False
        assert "Permission denied" in result["error"]
        assert result["error_type"] == "scan_start_failure"
        mock_ctx.error.assert_called()

    @pytest.mark.asyncio
    async def test_scan_exception_handling(self, mock_ctx):
        """Exceptions raised during scan start produce error result."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                side_effect=RuntimeError("Connection refused"),
            ),
            patch("pathlib.Path.cwd", return_value=Path("/tmp")),  # nosec B108
        ):
            result = await run_ash_scan(ctx=mock_ctx, source_dir="/tmp")  # nosec B108

        assert result["success"] is False
        assert "Connection refused" in result["error"]
        assert result["error_type"] == "RuntimeError"

    @pytest.mark.asyncio
    async def test_scan_cleans_existing_results(self, mock_ctx, tmp_path):
        """When clean_output=True and results file exists, it gets removed."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        # Create a fake results file
        output_dir = tmp_path / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        results_file = output_dir / "ash_aggregated_results.json"
        results_file.write_text("{}")

        mock_result = {"success": True, "scan_id": "scan-clean"}

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_scan_directory",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
            patch("automated_security_helper.cli.mcp_server.asyncio.create_task") as mock_task,
            patch("pathlib.Path.cwd", return_value=tmp_path),
        ):
            mock_task.return_value = MagicMock()
            mock_task.return_value.add_done_callback = MagicMock()

            result = await run_ash_scan(
                ctx=mock_ctx,
                source_dir=str(tmp_path),
                clean_output=True,
            )

        assert result["success"] is True
        assert not results_file.exists()


# ---------------------------------------------------------------------------
# get_scan_progress tool
# ---------------------------------------------------------------------------


class TestGetScanProgress:
    """Tests for the get_scan_progress tool function."""

    @pytest.mark.asyncio
    async def test_progress_success(self, mock_ctx, mock_scan_registry_entry, tmp_path):
        """Returns progress info with scanner results when scan is running."""
        from automated_security_helper.cli.mcp_server import get_scan_progress

        mock_progress = {
            "success": True,
            "status": "running",
            "progress_percentage": 50,
        }

        mock_registry = MagicMock()
        mock_scan_registry_entry.output_directory = str(tmp_path)
        mock_registry.get_scan.return_value = mock_scan_registry_entry

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_progress",
                new_callable=AsyncMock,
                return_value=mock_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp_server.get_scan_registry",
                return_value=mock_registry,
            ),
        ):
            result = await get_scan_progress(ctx=mock_ctx, scan_id="test-scan-123")

        assert result["success"] is True
        assert result["status"] == "running"
        assert "scanners" in result
        assert "severity_counts" in result

    @pytest.mark.asyncio
    async def test_progress_scan_not_found(self, mock_ctx):
        """Returns error when scan_id is not in registry."""
        from automated_security_helper.cli.mcp_server import get_scan_progress

        mock_progress = {"success": True, "status": "running"}

        mock_registry = MagicMock()
        mock_registry.get_scan.return_value = None

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_progress",
                new_callable=AsyncMock,
                return_value=mock_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp_server.get_scan_registry",
                return_value=mock_registry,
            ),
        ):
            result = await get_scan_progress(ctx=mock_ctx, scan_id="nonexistent")

        assert result["success"] is False
        assert "not found" in result["error"]
        assert result["error_type"] == "scan_not_found"

    @pytest.mark.asyncio
    async def test_progress_upstream_failure(self, mock_ctx):
        """When mcp_get_scan_progress fails, propagates the error result."""
        from automated_security_helper.cli.mcp_server import get_scan_progress

        mock_progress = {"success": False, "error": "Registry unavailable"}

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_get_scan_progress",
            new_callable=AsyncMock,
            return_value=mock_progress,
        ):
            result = await get_scan_progress(ctx=mock_ctx, scan_id="any-id")

        assert result["success"] is False
        assert "Registry unavailable" in result["error"]

    @pytest.mark.asyncio
    async def test_progress_reads_scanner_results(
        self, mock_ctx, mock_scan_registry_entry, tmp_path
    ):
        """Reads scanner result files and aggregates severity counts."""
        from automated_security_helper.cli.mcp_server import get_scan_progress

        # Set up scanner result files
        scanner_dir = tmp_path / "scanners" / "bandit" / "source"
        scanner_dir.mkdir(parents=True)
        result_file = scanner_dir / "ASH.ScanResults.json"
        result_file.write_text(
            json.dumps({"severity_counts": {"critical": 2, "high": 3}})
        )

        mock_progress = {"success": True, "status": "running"}
        mock_registry = MagicMock()
        mock_scan_registry_entry.output_directory = str(tmp_path)
        mock_registry.get_scan.return_value = mock_scan_registry_entry

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_progress",
                new_callable=AsyncMock,
                return_value=mock_progress,
            ),
            patch(
                "automated_security_helper.cli.mcp_server.get_scan_registry",
                return_value=mock_registry,
            ),
        ):
            result = await get_scan_progress(ctx=mock_ctx, scan_id="test-scan-123")

        assert result["severity_counts"]["critical"] == 2
        assert result["severity_counts"]["high"] == 3
        assert "bandit" in result["scanners"]

    @pytest.mark.asyncio
    async def test_progress_exception_handling(self, mock_ctx):
        """Exceptions produce a structured error response."""
        from automated_security_helper.cli.mcp_server import get_scan_progress

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_get_scan_progress",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Boom"),
        ):
            result = await get_scan_progress(ctx=mock_ctx, scan_id="x")

        assert result["success"] is False
        assert "Boom" in result["error"]
        assert result["error_type"] == "RuntimeError"


# ---------------------------------------------------------------------------
# get_scan_results tool
# ---------------------------------------------------------------------------


class TestGetScanResults:
    """Tests for the get_scan_results tool function."""

    @pytest.mark.asyncio
    async def test_results_full_filter(self, mock_ctx, sample_full_results):
        """filter_level=full returns unmodified results."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                filter_level="full",
            )

        assert result["success"] is True
        assert "raw_results" in result
        assert result["scan_id"] == "scan-abc"

    @pytest.mark.asyncio
    async def test_results_summary_filter(self, mock_ctx, sample_full_results):
        """filter_level=summary returns only summary data."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                filter_level="summary",
            )

        assert result["success"] is True
        assert result["_filter"] == "summary"
        assert "findings_summary" in result
        assert "scanner_summary" in result
        # Full data should not be present
        assert "raw_results" not in result

    @pytest.mark.asyncio
    async def test_results_minimal_filter(self, mock_ctx, sample_full_results):
        """filter_level=minimal returns only status info."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                filter_level="minimal",
            )

        assert result["success"] is True
        assert result["_filter"] == "minimal"
        assert result["scan_id"] == "scan-abc"
        assert result["is_complete"] is True
        assert "raw_results" not in result
        assert "scanner_reports" not in result

    @pytest.mark.asyncio
    async def test_results_unknown_filter_level(self, mock_ctx, sample_full_results):
        """Unknown filter_level logs warning and returns full results."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                filter_level="bogus",
            )

        assert result["success"] is True
        assert "raw_results" in result
        mock_ctx.warning.assert_called()

    @pytest.mark.asyncio
    async def test_results_actionable_only(self, mock_ctx, sample_full_results):
        """actionable_only=True filters out suppressed findings."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                actionable_only=True,
            )

        assert result["success"] is True
        assert result["_content_filters"]["actionable_only"] is True
        # Suppressed count should be zeroed
        assert result["summary_stats"]["suppressed"] == 0
        # SARIF results with suppressions should be removed
        sarif_results = result["raw_results"]["sarif"]["runs"][0]["results"]
        for r in sarif_results:
            suppressions = r.get("suppressions", [])
            assert len(suppressions) == 0

    @pytest.mark.asyncio
    async def test_results_scanner_filter(self, mock_ctx, sample_full_results):
        """scanners parameter filters to specific scanners."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx,
                output_dir="/workspace/.ash/ash_output",
                scanners="bandit",
            )

        assert "bandit" in result["raw_results"]["scanner_results"]
        assert "semgrep" not in result["raw_results"]["scanner_results"]

    @pytest.mark.asyncio
    async def test_results_error_from_upstream(self, mock_ctx):
        """When mcp_get_scan_results returns error, it is propagated."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        error_result = {"success": False, "error": "File not found"}

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=error_result,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx, output_dir="/workspace/.ash/ash_output"
            )

        assert result["success"] is False
        assert "File not found" in result["error"]

    @pytest.mark.asyncio
    async def test_results_exception_handling(self, mock_ctx):
        """Exceptions produce structured error response."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                side_effect=OSError("Disk full"),
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_results(
                ctx=mock_ctx, output_dir="/workspace/.ash/ash_output"
            )

        assert result["success"] is False
        assert "Disk full" in result["error"]
        assert result["error_type"] == "OSError"

    @pytest.mark.asyncio
    async def test_results_relative_path_resolution(self, mock_ctx, sample_full_results):
        """Relative output_dir is resolved against cwd."""
        from automated_security_helper.cli.mcp_server import get_scan_results

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ) as mock_get,
            patch("pathlib.Path.cwd", return_value=Path.cwd()),
        ):
            await get_scan_results(ctx=mock_ctx, output_dir=".ash/ash_output")

        # The output_dir passed to the inner function should be absolute
        call_kwargs = mock_get.call_args[1]
        assert Path(call_kwargs["output_dir"]).is_absolute()


# ---------------------------------------------------------------------------
# get_scan_summary tool
# ---------------------------------------------------------------------------


class TestGetScanSummary:
    """Tests for the get_scan_summary tool function."""

    @pytest.mark.asyncio
    async def test_summary_returns_lightweight_data(self, mock_ctx, sample_full_results):
        """Summary returns metadata, findings, and scanner info but not raw data."""
        from automated_security_helper.cli.mcp_server import get_scan_summary

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value=sample_full_results,
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_summary(
                ctx=mock_ctx, output_dir="/workspace/.ash/ash_output"
            )

        assert result["success"] is True
        assert result["_filter"] == "summary"
        assert "findings_summary" in result
        assert "scanner_summary" in result
        assert "metadata" in result
        # Should not contain raw_results
        assert "raw_results" not in result

    @pytest.mark.asyncio
    async def test_summary_error_propagation(self, mock_ctx):
        """Upstream errors are passed through."""
        from automated_security_helper.cli.mcp_server import get_scan_summary

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                return_value={"success": False, "error": "Not found"},
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_summary(
                ctx=mock_ctx, output_dir="/workspace/.ash/ash_output"
            )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_summary_exception_handling(self, mock_ctx):
        """Exceptions produce structured error response."""
        from automated_security_helper.cli.mcp_server import get_scan_summary

        with (
            patch(
                "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
                new_callable=AsyncMock,
                side_effect=ValueError("Bad data"),
            ),
            patch("pathlib.Path.cwd", return_value=Path("/workspace")),
        ):
            result = await get_scan_summary(
                ctx=mock_ctx, output_dir="/workspace/.ash/ash_output"
            )

        assert result["success"] is False
        assert "Bad data" in result["error"]
        assert result["error_type"] == "ValueError"


# ---------------------------------------------------------------------------
# list_active_scans tool
# ---------------------------------------------------------------------------


class TestListActiveScans:
    """Tests for the list_active_scans tool function."""

    @pytest.mark.asyncio
    async def test_list_scans_success(self, mock_ctx):
        """Successful call delegates to mcp_list_active_scans."""
        from automated_security_helper.cli.mcp_server import list_active_scans

        mock_scans = {
            "success": True,
            "scans": [{"scan_id": "s1", "status": "running"}],
        }

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_list_active_scans",
            new_callable=AsyncMock,
            return_value=mock_scans,
        ):
            result = await list_active_scans(ctx=mock_ctx)

        assert result["success"] is True
        assert len(result["scans"]) == 1

    @pytest.mark.asyncio
    async def test_list_scans_exception(self, mock_ctx):
        """Exception in mcp_list_active_scans is caught and returned."""
        from automated_security_helper.cli.mcp_server import list_active_scans

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_list_active_scans",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Network error"),
        ):
            result = await list_active_scans(ctx=mock_ctx)

        assert result["success"] is False
        assert "Network error" in result["error"]


# ---------------------------------------------------------------------------
# cancel_scan tool
# ---------------------------------------------------------------------------


class TestCancelScan:
    """Tests for the cancel_scan tool function."""

    @pytest.mark.asyncio
    async def test_cancel_success(self, mock_ctx):
        """Successful cancel delegates to mcp_cancel_scan."""
        from automated_security_helper.cli.mcp_server import cancel_scan

        mock_response = {"success": True, "message": "Scan cancelled"}

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_cancel_scan",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await cancel_scan(ctx=mock_ctx, scan_id="scan-to-cancel")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_cancel_exception(self, mock_ctx):
        """Exception during cancel is caught and returned."""
        from automated_security_helper.cli.mcp_server import cancel_scan

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_cancel_scan",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Process not found"),
        ):
            result = await cancel_scan(ctx=mock_ctx, scan_id="bad-id")

        assert result["success"] is False
        assert "Process not found" in result["error"]


# ---------------------------------------------------------------------------
# check_installation tool
# ---------------------------------------------------------------------------


class TestCheckInstallation:
    """Tests for the check_installation tool function."""

    @pytest.mark.asyncio
    async def test_installation_check_success(self, mock_ctx):
        """Successful check delegates to mcp_check_installation."""
        from automated_security_helper.cli.mcp_server import check_installation

        mock_response = {"success": True, "version": "2.0.0", "scanners": ["bandit"]}

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_check_installation",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await check_installation(ctx=mock_ctx)

        assert result["success"] is True
        assert result["version"] == "2.0.0"

    @pytest.mark.asyncio
    async def test_installation_check_exception(self, mock_ctx):
        """Exception during check is caught and returned."""
        from automated_security_helper.cli.mcp_server import check_installation

        with patch(
            "automated_security_helper.cli.mcp_server.mcp_check_installation",
            new_callable=AsyncMock,
            side_effect=ImportError("Module missing"),
        ):
            result = await check_installation(ctx=mock_ctx)

        assert result["success"] is False
        assert "Module missing" in result["error"]


# ---------------------------------------------------------------------------
# get_scan_result_paths tool
# ---------------------------------------------------------------------------


class TestGetScanResultPaths:
    """Tests for the get_scan_result_paths tool function."""

    @pytest.mark.asyncio
    async def test_paths_success(self, mock_ctx, tmp_path):
        """Returns file paths and existence status for all report types."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        # Create reports directory with a couple of files
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        (reports_dir / "ash.sarif").write_text("{}")
        (reports_dir / "ash.html").write_text("<html></html>")

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(tmp_path))

        assert result["success"] is True
        assert result["files"]["sarif"]["exists"] is True
        assert result["files"]["sarif"]["size_bytes"] > 0
        assert result["files"]["html"]["exists"] is True
        assert result["files"]["flat_json"]["exists"] is False

    @pytest.mark.asyncio
    async def test_paths_nonexistent_output_dir(self, mock_ctx):
        """Returns error when output directory does not exist."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        result = await get_scan_result_paths(
            ctx=mock_ctx, output_dir="/nonexistent/path"
        )

        assert result["success"] is False
        assert result["error_type"] == "DirectoryNotFound"

    @pytest.mark.asyncio
    async def test_paths_no_reports_dir(self, mock_ctx, tmp_path):
        """Returns error when reports subdirectory does not exist."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(tmp_path))

        assert result["success"] is False
        assert "Reports directory" in result["error"]

    @pytest.mark.asyncio
    async def test_paths_includes_scanner_results(self, mock_ctx, tmp_path):
        """Scanner-specific result files are discovered and reported."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        # Create reports and scanner dirs
        (tmp_path / "reports").mkdir()
        scanner_dir = tmp_path / "scanners" / "bandit" / "source"
        scanner_dir.mkdir(parents=True)
        (scanner_dir / "ASH.ScanResults.json").write_text("{}")

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(tmp_path))

        assert result["success"] is True
        assert "scanner_results" in result
        assert "bandit" in result["scanner_results"]
        assert result["scanner_results"]["bandit"]["source"]["exists"] is True

    @pytest.mark.asyncio
    async def test_paths_exception_handling(self, mock_ctx):
        """Exceptions produce structured error response."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        with patch("pathlib.Path.exists", side_effect=PermissionError("No access")):
            result = await get_scan_result_paths(
                ctx=mock_ctx, output_dir="/some/path"
            )

        assert result["success"] is False
        assert result["error_type"] == "PermissionError"


# ---------------------------------------------------------------------------
# Resource functions
# ---------------------------------------------------------------------------


class TestResources:
    """Tests for MCP resource functions."""

    def test_get_ash_status_success(self):
        """Status resource returns READY when version is available."""
        from automated_security_helper.cli.mcp_server import get_ash_status

        with patch(
            "automated_security_helper.utils.get_ash_version.get_ash_version",
            return_value="2.1.0",
        ):
            result = get_ash_status()

        assert "READY" in result
        assert "2.1.0" in result

    def test_get_ash_status_error(self):
        """Status resource returns ERROR when version lookup fails."""
        from automated_security_helper.cli.mcp_server import get_ash_status

        with patch(
            "automated_security_helper.utils.get_ash_version.get_ash_version",
            side_effect=RuntimeError("Missing config"),
        ):
            result = get_ash_status()

        assert "ERROR" in result
        assert "Missing config" in result

    def test_get_ash_help(self):
        """Help resource returns usage guide text."""
        from automated_security_helper.cli.mcp_server import get_ash_help

        result = get_ash_help()
        assert "ASH" in result
        assert "Bandit" in result
        assert "Semgrep" in result


# ---------------------------------------------------------------------------
# Prompt functions
# ---------------------------------------------------------------------------


class TestPrompts:
    """Tests for MCP prompt functions."""

    def test_run_ash_security_scan_prompt_with_dir(self):
        """Prompt includes the specified source directory."""
        from automated_security_helper.cli.mcp_server import run_ash_security_scan

        result = run_ash_security_scan(source_dir="/my/project")
        assert "/my/project" in result
        assert "run_ash_scan" in result

    def test_run_ash_security_scan_prompt_default(self):
        """Prompt uses cwd when no source_dir is given."""
        from automated_security_helper.cli.mcp_server import run_ash_security_scan

        with patch("pathlib.Path.cwd", return_value=Path("/default/dir")):
            # The function calls Path.cwd().absolute() internally
            with patch.object(Path, "absolute", return_value=Path("/default/dir")):
                result = run_ash_security_scan(source_dir=None)

        assert "/default/dir" in result or str(Path("/default/dir")) in result

    def test_analyze_security_findings_prompt(self):
        """Prompt includes directory and analysis instructions."""
        from automated_security_helper.cli.mcp_server import analyze_security_findings

        result = analyze_security_findings(source_dir="/src")
        assert "/src" in result
        assert "Summary" in result
        assert "Recommendations" in result


# ---------------------------------------------------------------------------
# Helper / filter functions (pure, sync)
# ---------------------------------------------------------------------------


class TestFilterHelpers:
    """Tests for internal filtering helper functions."""

    def test_filter_summary_extracts_metadata(self, sample_full_results):
        """_filter_summary extracts metadata from raw_results."""
        from automated_security_helper.cli.mcp_server import _filter_summary

        result = _filter_summary(sample_full_results)

        assert result["_filter"] == "summary"
        assert result["metadata"]["ash_version"] == "2.0.0"
        assert result["metadata"]["scan_duration_seconds"] == 42.5

    def test_filter_summary_scanner_counts(self, sample_full_results):
        """_filter_summary counts completed scanners correctly."""
        from automated_security_helper.cli.mcp_server import _filter_summary

        result = _filter_summary(sample_full_results)

        # bandit=FAILED, semgrep=PASSED -- both are "completed"
        assert result["scanner_summary"]["completed_scanners"] == 2
        assert result["scanner_summary"]["total_scanners"] == 2

    def test_filter_minimal(self, sample_full_results):
        """_filter_minimal returns only status fields."""
        from automated_security_helper.cli.mcp_server import _filter_minimal

        result = _filter_minimal(sample_full_results)

        assert result["_filter"] == "minimal"
        assert result["scan_id"] == "scan-abc"
        assert result["is_complete"] is True
        assert "raw_results" not in result
        assert "scanner_reports" not in result

    def test_filter_actionable_only_removes_suppressed(self, sample_full_results):
        """_filter_actionable_only removes SARIF results with suppressions."""
        from automated_security_helper.cli.mcp_server import _filter_actionable_only

        result = _filter_actionable_only(sample_full_results)

        sarif_results = result["raw_results"]["sarif"]["runs"][0]["results"]
        # Original had 3 results, one with suppressions should be removed
        assert len(sarif_results) == 2
        for r in sarif_results:
            assert not (r.get("suppressions") and len(r["suppressions"]) > 0)

    def test_filter_actionable_only_zeros_suppressed_counts(self, sample_full_results):
        """_filter_actionable_only zeros suppressed counts in stats."""
        from automated_security_helper.cli.mcp_server import _filter_actionable_only

        result = _filter_actionable_only(sample_full_results)

        assert result["summary_stats"]["suppressed"] == 0
        for scanner_data in result["raw_results"]["scanner_results"].values():
            assert scanner_data["suppressed_finding_count"] == 0
            assert scanner_data["severity_counts"]["suppressed"] == 0

    def test_filter_actionable_only_does_not_modify_original(
        self, sample_full_results
    ):
        """_filter_actionable_only does not mutate the input."""
        from automated_security_helper.cli.mcp_server import _filter_actionable_only

        original = copy.deepcopy(sample_full_results)
        _filter_actionable_only(sample_full_results)

        assert sample_full_results == original

    def test_apply_content_filters_scanner_only(self, sample_full_results):
        """_apply_content_filters with scanners keeps only specified scanners."""
        from automated_security_helper.cli.mcp_server import _apply_content_filters

        result = _apply_content_filters(sample_full_results, scanners="semgrep")

        assert "semgrep" in result["scanner_reports"]
        assert "bandit" not in result["scanner_reports"]
        assert "semgrep" in result["raw_results"]["scanner_results"]
        assert "bandit" not in result["raw_results"]["scanner_results"]

    def test_apply_content_filters_severity_only(self, sample_full_results):
        """_apply_content_filters with severities zeros out excluded levels."""
        from automated_security_helper.cli.mcp_server import _apply_content_filters

        result = _apply_content_filters(sample_full_results, severities="critical,high")

        assert result["summary_stats"]["critical"] == 2
        assert result["summary_stats"]["high"] == 5
        assert result["summary_stats"]["medium"] == 0
        assert result["summary_stats"]["low"] == 0

    def test_apply_content_filters_does_not_modify_original(self, sample_full_results):
        """_apply_content_filters does not mutate the input."""
        from automated_security_helper.cli.mcp_server import _apply_content_filters

        original = copy.deepcopy(sample_full_results)
        _apply_content_filters(sample_full_results, scanners="bandit", severities="high")

        assert sample_full_results == original


# ---------------------------------------------------------------------------
# _monitor_scan_progress background task
# ---------------------------------------------------------------------------
# Tests for the relocated `monitor_scan_progress` coroutine now live in
# tests/unit/cli/mcp/test_progress_monitor.py — that file targets the new
# import path (automated_security_helper.cli.mcp.progress_monitor) directly.
