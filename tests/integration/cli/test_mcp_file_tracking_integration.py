#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for MCP file-based tracking.

This module provides integration tests for the MCP tools for ASH security scanning
with file-based tracking of scan progress and completion.
"""

import json
import pytest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

from automated_security_helper.cli.mcp_tools import (
    mcp_scan_directory,
    mcp_get_scan_progress,
    mcp_get_scan_results,
    mcp_list_active_scans,
    mcp_cancel_scan,
)
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
    ScanStatus,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    check_scan_completion,
)


@pytest.fixture
def test_directory():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_scan_process():
    """Mock the scan process to simulate a running scan."""
    # Create a mock process that will be returned by asyncio.create_subprocess_exec
    mock_process = AsyncMock()
    mock_process.pid = 12345
    mock_process.returncode = 0
    mock_process.communicate = AsyncMock(return_value=(b"", b""))

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)):
        yield mock_process


@pytest.mark.asyncio
async def test_file_based_tracking_workflow(test_directory, mock_scan_process):
    """Test the complete file-based tracking workflow."""
    # Create test directory structure
    source_dir = test_directory / "source"
    source_dir.mkdir()

    # Create a simple file to scan
    test_file = source_dir / "test.py"
    test_file.write_text('password = "hardcoded_password"')

    # Start a scan
    with patch(
        "automated_security_helper.cli.mcp_tools._run_scan_async", AsyncMock()
    ) as mock_run_scan:
        result = await mcp_scan_directory(
            directory_path=str(source_dir),
            severity_threshold="MEDIUM",
        )

        # Check that the scan was started
        assert result["success"] is True
        assert "scan_id" in result
        scan_id = result["scan_id"]

        # Check that _run_scan_async was called
        mock_run_scan.assert_called_once()

    # Get the scan registry entry
    registry = get_scan_registry()
    entry = registry.get_scan(scan_id)
    assert entry is not None

    # Create output directory structure to simulate scan progress
    output_dir = Path(entry.output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    scanners_dir = output_dir / "scanners"
    scanners_dir.mkdir(exist_ok=True)

    # Create scanner directories and result files
    scanner_names = ["bandit", "detect-secrets"]
    for scanner_name in scanner_names:
        scanner_dir = scanners_dir / scanner_name
        scanner_dir.mkdir(exist_ok=True)

        source_dir = scanner_dir / "source"
        source_dir.mkdir(exist_ok=True)

        # Create a result file for the scanner
        result_file = source_dir / "ASH.ScanResults.json"
        result_data = {
            "findings": [
                {
                    "id": f"{scanner_name}-finding-1",
                    "severity": "HIGH",
                    "scanner": scanner_name,
                }
            ]
        }
        result_file.write_text(json.dumps(result_data))

    # Check scan progress
    progress_result = await mcp_get_scan_progress(scan_id)
    assert progress_result["scan_id"] == scan_id
    assert progress_result["is_complete"] is False
    assert progress_result["completed_scanners"] == 2
    assert progress_result["total_scanners"] == 2

    # Create aggregated results file to simulate scan completion
    aggregated_results = {
        "metadata": {
            "generated_at": "2023-01-01T00:00:00",
            "summary_stats": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
        },
        "scanner_results": {
            "bandit": {
                "finding_count": 1,
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 1,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                },
            },
            "detect-secrets": {
                "finding_count": 1,
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 0,
                    "INFO": 0,
                },
            },
        },
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"}
                    },
                    "results": [
                        {
                            "ruleId": "hardcoded-password",
                            "level": "error",
                            "message": {"text": "Hardcoded password found"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "root": {
                                            "artifactLocation": {"uri": "test.py"},
                                            "region": {"startLine": 1, "endLine": 1},
                                        }
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    }

    aggregated_results_file = output_dir / "ash_aggregated_results.json"
    aggregated_results_file.write_text(json.dumps(aggregated_results))

    # Update scan status in registry
    registry.update_scan_status(scan_id, ScanStatus.COMPLETED)

    # Check scan completion
    assert check_scan_completion(output_dir) is True

    # Get scan progress again
    progress_result = await mcp_get_scan_progress(scan_id)
    assert progress_result["scan_id"] == scan_id
    assert progress_result["is_complete"] is True
    assert progress_result["status"] == "completed"

    # Get scan results
    results = await mcp_get_scan_results(scan_id)
    assert results["scan_id"] == scan_id
    assert results["status"] == "completed"
    assert results["is_complete"] is True
    assert results["findings_count"] == 1
    assert results["severity_counts"]["HIGH"] == 1

    # List active scans
    active_scans = await mcp_list_active_scans()
    assert active_scans["success"] is True
    assert (
        len(active_scans["active_scans"]) == 0
    )  # No active scans since our scan is completed

    # Cancel the scan (should return False since it's already completed)
    cancel_result = await mcp_cancel_scan(scan_id)
    assert cancel_result["success"] is False  # Already completed
