#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the scan tracking module.

This module tests the file-based scan tracking utilities for ASH MCP server.
"""

import json
from datetime import datetime

import pytest

from automated_security_helper.core.resource_management.scan_tracking import (
    ScannerStatus,
    ScannerProgress,
    ScanProgress,
)


class TestScannerProgress:
    """Tests for the ScannerProgress class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        progress = ScannerProgress("test_scanner", "source")

        assert progress.scanner_name == "test_scanner"
        assert progress.target_type == "source"
        assert progress.status == ScannerStatus.PENDING
        assert progress.duration is None
        assert progress.finding_count == 0
        assert progress.severity_counts == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }
        assert progress.start_time is None
        assert progress.end_time is None

    def test_mark_running(self):
        """Test marking a scanner as running."""
        progress = ScannerProgress("test_scanner", "source")
        progress.mark_running()

        assert progress.status == ScannerStatus.RUNNING
        assert progress.start_time is not None
        assert isinstance(progress.start_time, datetime)

    def test_mark_completed(self):
        """Test marking a scanner as completed."""
        progress = ScannerProgress("test_scanner", "source")
        progress.mark_running()
        progress.mark_completed()

        assert progress.status == ScannerStatus.COMPLETED
        assert progress.end_time is not None
        assert isinstance(progress.end_time, datetime)
        assert progress.duration is not None
        assert progress.duration > 0

    def test_mark_failed(self):
        """Test marking a scanner as failed."""
        progress = ScannerProgress("test_scanner", "source")
        progress.mark_running()
        progress.mark_failed()

        assert progress.status == ScannerStatus.FAILED
        assert progress.end_time is not None
        assert isinstance(progress.end_time, datetime)
        assert progress.duration is not None
        assert progress.duration > 0

    def test_mark_skipped(self):
        """Test marking a scanner as skipped."""
        progress = ScannerProgress("test_scanner", "source")
        progress.mark_skipped()

        assert progress.status == ScannerStatus.SKIPPED

    def test_to_dict(self):
        """Test converting to dictionary."""
        progress = ScannerProgress("test_scanner", "source")
        progress.mark_running()
        progress.mark_completed()

        result = progress.to_dict()

        assert result["scanner_name"] == "test_scanner"
        assert result["target_type"] == "source"
        assert result["status"] == "completed"
        assert result["duration"] is not None
        assert result["finding_count"] == 0
        assert "severity_counts" in result
        assert "start_time" in result
        assert "end_time" in result


class TestScanProgress:
    """Tests for the ScanProgress class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        progress = ScanProgress("test_scan_id")

        assert progress.scan_id == "test_scan_id"
        assert progress.status == "in_progress"
        assert progress.scanners == {}
        assert progress.start_time is not None
        assert isinstance(progress.start_time, datetime)
        assert progress.end_time is None
        assert progress.duration is None
        assert progress.total_findings == 0
        assert progress.severity_counts == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }

    def test_add_scanner_progress(self):
        """Test adding scanner progress."""
        scan_progress = ScanProgress("test_scan_id")
        scanner_progress = ScannerProgress("test_scanner", "source")
        scanner_progress.finding_count = 5
        scanner_progress.severity_counts = {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 1,
            "suppressed": 0,
        }

        scan_progress.add_scanner_progress(scanner_progress)

        assert "test_scanner" in scan_progress.scanners
        assert "source" in scan_progress.scanners["test_scanner"]
        assert scan_progress.scanners["test_scanner"]["source"] == scanner_progress
        assert scan_progress.total_findings == 5
        assert scan_progress.severity_counts == {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 1,
            "suppressed": 0,
        }

    def test_update_totals(self):
        """Test updating totals."""
        scan_progress = ScanProgress("test_scan_id")

        # Add first scanner
        scanner1 = ScannerProgress("scanner1", "source")
        scanner1.finding_count = 3
        scanner1.severity_counts = {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }
        scan_progress.add_scanner_progress(scanner1)

        # Add second scanner
        scanner2 = ScannerProgress("scanner2", "source")
        scanner2.finding_count = 2
        scanner2.severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 1,
            "info": 1,
            "suppressed": 0,
        }
        scan_progress.add_scanner_progress(scanner2)

        # Verify totals
        assert scan_progress.total_findings == 5
        assert scan_progress.severity_counts == {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 1,
            "suppressed": 0,
        }

    def test_mark_completed(self):
        """Test marking a scan as completed."""
        scan_progress = ScanProgress("test_scan_id")
        scan_progress.mark_completed()

        assert scan_progress.status == "completed"
        assert scan_progress.end_time is not None
        assert isinstance(scan_progress.end_time, datetime)
        assert scan_progress.duration is not None
        assert scan_progress.duration > 0

    def test_mark_failed(self):
        """Test marking a scan as failed."""
        scan_progress = ScanProgress("test_scan_id")
        scan_progress.mark_failed()

        assert scan_progress.status == "failed"
        assert scan_progress.end_time is not None
        assert isinstance(scan_progress.end_time, datetime)
        assert scan_progress.duration is not None
        assert scan_progress.duration > 0

    def test_completed_scanners(self):
        """Test getting completed scanners count."""
        scan_progress = ScanProgress("test_scan_id")

        # Add pending scanner
        scanner1 = ScannerProgress("scanner1", "source")
        scan_progress.add_scanner_progress(scanner1)

        # Add completed scanner
        scanner2 = ScannerProgress("scanner2", "source")
        scanner2.status = ScannerStatus.COMPLETED
        scan_progress.add_scanner_progress(scanner2)

        # Add failed scanner
        scanner3 = ScannerProgress("scanner3", "source")
        scanner3.status = ScannerStatus.FAILED
        scan_progress.add_scanner_progress(scanner3)

        assert scan_progress.completed_scanners == 1
        assert scan_progress.total_scanners == 3

    def test_is_complete(self):
        """Test checking if a scan is complete."""
        scan_progress = ScanProgress("test_scan_id")
        assert not scan_progress.is_complete

        scan_progress.status = "completed"
        assert scan_progress.is_complete

        scan_progress.status = "failed"
        assert scan_progress.is_complete

        scan_progress.status = "in_progress"
        assert not scan_progress.is_complete

    def test_to_dict(self):
        """Test converting to dictionary."""
        scan_progress = ScanProgress("test_scan_id")
        scanner_progress = ScannerProgress("test_scanner", "source")
        scanner_progress.mark_completed()
        scan_progress.add_scanner_progress(scanner_progress)
        scan_progress.mark_completed()

        result = scan_progress.to_dict()

        assert result["scan_id"] == "test_scan_id"
        assert result["status"] == "completed"
        assert result["is_complete"] is True
        assert "start_time" in result
        assert "end_time" in result
        assert result["duration"] is not None
        assert result["completed_scanners"] == 1
        assert result["total_scanners"] == 1
        assert result["total_findings"] == 0
        assert "severity_counts" in result
        assert "scanners" in result
        assert "test_scanner" in result["scanners"]
        assert "source" in result["scanners"]["test_scanner"]


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary output directory with the expected structure."""
    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()

    # Create scanners directory
    scanners_dir = output_dir / "scanners"
    scanners_dir.mkdir()

    return output_dir


@pytest.fixture
def mock_scanner_results(temp_output_dir):
    """Create mock scanner result files."""
    scanners_dir = temp_output_dir / "scanners"

    # Create scanner1 results
    scanner1_dir = scanners_dir / "scanner1"
    scanner1_dir.mkdir()
    source_dir = scanner1_dir / "source"
    source_dir.mkdir()

    # Create scanner1 source results
    result_file = source_dir / "ASH.ScanResults.json"
    result_data = {
        "findings": [
            {"id": "1", "severity": "CRITICAL", "scanner": "scanner1"},
            {"id": "2", "severity": "HIGH", "scanner": "scanner1"},
        ]
    }
    with open(result_file, "w") as f:
        json.dump(result_data, f)

    # Create scanner2 results
    scanner2_dir = scanners_dir / "scanner2"
    scanner2_dir.mkdir()
    source_dir = scanner2_dir / "source"
    source_dir.mkdir()
    converted_dir = scanner2_dir / "converted"
    converted_dir.mkdir()

    # Create scanner2 source results
    result_file = source_dir / "ASH.ScanResults.json"
    result_data = {
        "findings": [
            {"id": "3", "severity": "MEDIUM", "scanner": "scanner2"},
        ]
    }
    with open(result_file, "w") as f:
        json.dump(result_data, f)

    # Create scanner2 converted results
    result_file = converted_dir / "ASH.ScanResults.json"
    result_data = {
        "findings": [
            {"id": "4", "severity": "LOW", "scanner": "scanner2"},
            {"id": "5", "severity": "INFO", "scanner": "scanner2"},
        ]
    }
    with open(result_file, "w") as f:
        json.dump(result_data, f)

    return temp_output_dir


@pytest.fixture
def mock_aggregated_results(temp_output_dir):
    """Create mock aggregated results file."""
    result_file = temp_output_dir / "ash_aggregated_results.json"
    result_data = {
        "findings": [
            {"id": "1", "severity": "critical", "scanner": "scanner1"},
            {"id": "2", "severity": "high", "scanner": "scanner1"},
            {"id": "3", "severity": "medium", "scanner": "scanner2"},
            {"id": "4", "severity": "low", "scanner": "scanner2"},
            {"id": "5", "severity": "info", "scanner": "scanner2"},
        ],
        "scanners_completed": ["scanner1", "scanner2"],
        "completion_time": datetime.now().isoformat(),
    }
    with open(result_file, "w") as f:
        json.dump(result_data, f)

    return temp_output_dir
