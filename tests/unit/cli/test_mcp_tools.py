#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for MCP tools.

This module provides unit tests for the MCP tools for ASH security scanning
with file-based tracking of scan progress and completion.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from automated_security_helper.cli.mcp_tools import (
    mcp_get_scan_results,
    mcp_check_installation,
)


@pytest.mark.asyncio
async def test_mcp_get_scan_results():
    """Test the mcp_get_scan_results function."""
    # Mock the output directory
    output_dir = "/test/output"

    # Mock the get_scan_results_with_error_handling function
    mock_results = {
        "status": "completed",
        "is_complete": True,
        "findings_count": 10,
        "severity_counts": {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 3,
            "LOW": 4,
            "INFO": 0,
            "UNKNOWN": 0,
        },
    }

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_scan_results_with_error_handling",
            return_value=mock_results,
        ),
        patch(
            "automated_security_helper.core.resource_management.error_handling.validate_directory_path",
            return_value=None,  # No error
        ),
        patch(
            "pathlib.Path.is_absolute",
            return_value=True,  # Simulate absolute path
        ),
    ):
        # Call the function with output_dir parameter
        result = await mcp_get_scan_results(output_dir)

        # Check the result
        assert result["status"] == "completed"
        assert result["is_complete"] is True
        assert result["findings_count"] == 10
        assert result["severity_counts"]["CRITICAL"] == 1
        assert result["severity_counts"]["HIGH"] == 2
        assert result["severity_counts"]["MEDIUM"] == 3
        assert result["severity_counts"]["LOW"] == 4
        assert result["severity_counts"]["INFO"] == 0
        assert result["severity_counts"]["UNKNOWN"] == 0
        assert "timestamp" in result
        assert "operation" in result


@pytest.mark.asyncio
async def test_mcp_check_installation():
    """Test the mcp_check_installation function."""
    # Mock the get_ash_version function
    mock_version = "3.0.0"

    # Mock the Path.exists and Path.is_dir methods
    mock_path = MagicMock()
    mock_path.exists.return_value = True
    mock_path.is_dir.return_value = True

    # Mock the asyncio.create_subprocess_exec function
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = AsyncMock(return_value=(b"ASH version 3.0.0", b""))

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_ash_version",
            return_value=mock_version,
        ),
        patch("pathlib.Path.home", return_value=mock_path),
        patch("pathlib.Path.__truediv__", return_value=mock_path),
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)),
    ):
        # Call the function
        result = await mcp_check_installation()

        # Check the result
        assert result["success"] is True
        assert result["installed"] is True
        assert result["version"] == "3.0.0"
        assert result["ash_command_available"] is True
        assert "ash_command_output" in result
        assert "timestamp" in result
