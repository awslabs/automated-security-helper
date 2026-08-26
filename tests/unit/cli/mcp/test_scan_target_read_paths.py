#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The result-reading tools honour the same roots as the scan tools.

``get_scan_results`` and ``get_scan_result_paths`` take a caller-supplied
output directory and read from it. Legitimate output directories live at
``<source_dir>/.ash/ash_output`` -- beneath the scan target -- so one root set
covers the write door and the read door without a second policy.

The progress path is deliberately *not* covered by these tests, because it is
not caller-path-driven: ``get_scan_progress`` takes a scan_id and the output
directory comes back from the scan registry. The last test here pins that,
since adding a root check to the per-poll validation would break polling for
everyone.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    return ctx


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _completed_output_dir(project: Path) -> Path:
    """Build a plausible finished-scan output tree under ``project``."""
    output_dir = project / ".ash" / "ash_output"
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True)
    (output_dir / "ash_aggregated_results.json").write_text(json.dumps({}))
    (reports_dir / "ash.sarif").write_text("{}")
    return output_dir


class TestGetScanResultsConfinement:
    """``mcp_get_scan_results`` refuses an output dir outside the roots."""

    @pytest.mark.asyncio
    async def test_output_dir_outside_the_roots_is_refused(self, tmp_path, monkeypatch):
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_results

        output_dir = _completed_output_dir(tmp_path / "project")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        result = await mcp_get_scan_results(str(output_dir))

        assert result["success"] is False
        assert result["error_category"] == "invalid_path"

    @pytest.mark.asyncio
    async def test_output_dir_under_an_allowed_root_is_read(
        self, tmp_path, monkeypatch
    ):
        """Positive control, and the reason one root set suffices.

        The allowlist names the *project*; the output directory is two levels
        below it at ``.ash/ash_output``. Nothing extra has to be configured for
        results of a permitted scan to be readable.
        """
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_results

        project = tmp_path / "project"
        output_dir = _completed_output_dir(project)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(project))

        with patch(
            "automated_security_helper.cli.mcp_tools.get_scan_results_with_error_handling",
            return_value={"status": "completed", "is_complete": True},
        ) as mock_read:
            result = await mcp_get_scan_results(str(output_dir))

        assert result["status"] == "completed"
        mock_read.assert_called_once()

    @pytest.mark.asyncio
    async def test_refused_output_dir_is_never_read(self, tmp_path, monkeypatch):
        """The refusal happens before anything opens a file under the path."""
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_results

        output_dir = _completed_output_dir(tmp_path / "project")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        with patch(
            "automated_security_helper.cli.mcp_tools.get_scan_results_with_error_handling"
        ) as mock_read:
            result = await mcp_get_scan_results(str(output_dir))

        assert result["success"] is False
        mock_read.assert_not_called()


class TestGetScanResultPathsConfinement:
    """``get_scan_result_paths`` builds its own answer and needs its own check."""

    @pytest.mark.asyncio
    async def test_output_dir_outside_the_roots_is_refused(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        output_dir = _completed_output_dir(tmp_path / "project")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(output_dir))

        assert result["success"] is False
        assert result["error_type"] == "scan_target_not_permitted"

    @pytest.mark.asyncio
    async def test_output_dir_under_an_allowed_root_returns_paths(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        """Positive control: an allowed output dir still yields its report paths."""
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        project = tmp_path / "project"
        output_dir = _completed_output_dir(project)
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(project))

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(output_dir))

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_refusal_is_reported_as_a_refusal_not_a_missing_directory(
        self, tmp_path, monkeypatch, mock_ctx
    ):
        """Order again: the policy answers before the existence branch does.

        ``get_scan_result_paths`` returns ``DirectoryNotFound`` for a path that
        is not there. A refused-and-absent path must not be reported that way,
        or the operator never learns a root policy is in force.
        """
        from automated_security_helper.cli.mcp_server import get_scan_result_paths

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        absent = tmp_path / "project" / ".ash" / "ash_output"
        assert not absent.exists()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(allowed))

        result = await get_scan_result_paths(ctx=mock_ctx, output_dir=str(absent))

        assert result["success"] is False
        assert result["error_type"] == "scan_target_not_permitted"


class TestProgressPollingIsUnaffected:
    """Polling must keep working, with and without an allowlist."""

    def test_per_poll_validation_takes_no_root_policy(self, tmp_path, monkeypatch):
        """``validate_output_directory`` runs on every poll and stays permissive.

        This function is called from the progress path, where the output
        directory comes from the scan registry rather than from the caller. A
        root check here would reject in-progress polls for any deployment whose
        allowlist did not happen to name the same directory, so its absence is
        the behaviour being pinned -- not an oversight.
        """
        from automated_security_helper.core.resource_management.scan_tracking import (
            validate_output_directory,
        )

        output_dir = _completed_output_dir(tmp_path / "project")
        elsewhere = tmp_path / "unrelated"
        elsewhere.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(elsewhere))

        is_valid, error = validate_output_directory(output_dir)

        assert is_valid is True, error

    @pytest.mark.asyncio
    async def test_in_progress_poll_succeeds_under_an_allowlist(
        self, tmp_path, monkeypatch
    ):
        """An end-to-end poll for a running scan, with an unrelated allowlist set.

        The registry holds the real output directory; the allowlist names
        somewhere else entirely. The poll still has to answer.
        """
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress
        from automated_security_helper.core.resource_management.scan_registry import (
            get_scan_registry,
        )

        project = tmp_path / "project"
        output_dir = project / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)

        registry = get_scan_registry()
        scan_id = registry.register_scan(
            directory_path=str(project),
            output_directory=str(output_dir),
            severity_threshold="MEDIUM",
        )

        elsewhere = tmp_path / "unrelated"
        elsewhere.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(elsewhere))

        result = await mcp_get_scan_progress(scan_id=scan_id)

        assert result.get("scan_id") == scan_id
        assert "error_category" not in result
