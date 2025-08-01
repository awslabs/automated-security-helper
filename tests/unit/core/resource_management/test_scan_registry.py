#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the scan registry module.

This module tests the scan registry and management components for ASH MCP server.
"""

import signal
from datetime import datetime
from unittest import mock

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanStatus,
    ScanRegistryEntry,
    ScanRegistry,
    get_scan_registry,
)


class TestScanRegistryEntry:
    """Tests for the ScanRegistryEntry class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        assert entry.scan_id == "test_scan_id"
        assert entry.directory_path == "/test/dir"
        assert entry.output_directory == "/test/output"
        assert entry.start_time is not None
        assert isinstance(entry.start_time, datetime)
        assert entry.end_time is None
        assert entry.status == ScanStatus.PENDING
        assert entry.severity_threshold == "MEDIUM"
        assert entry.config_path is None
        assert entry.process_id is None
        assert entry.error_message is None
        assert entry.warnings == []

    def test_init_with_custom_values(self):
        """Test initialization with custom values."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
            severity_threshold="HIGH",
            config_path="/test/config.yaml",
        )

        assert entry.scan_id == "test_scan_id"
        assert entry.directory_path == "/test/dir"
        assert entry.output_directory == "/test/output"
        assert entry.severity_threshold == "HIGH"
        assert entry.config_path == "/test/config.yaml"

    def test_to_dict(self):
        """Test converting to dictionary."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        result = entry.to_dict()

        assert result["scan_id"] == "test_scan_id"
        assert result["directory_path"] == "/test/dir"
        assert result["output_directory"] == "/test/output"
        assert "start_time" in result
        assert result["end_time"] is None
        assert result["status"] == "pending"
        assert result["severity_threshold"] == "MEDIUM"
        assert result["config_path"] is None
        assert result["process_id"] is None
        assert result["error_message"] is None
        assert result["warnings"] == []

    def test_mark_running(self):
        """Test marking a scan as running."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.mark_running(process_id=12345)

        assert entry.status == ScanStatus.RUNNING
        assert entry.process_id == 12345

    def test_mark_completed(self):
        """Test marking a scan as completed."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.mark_completed()

        assert entry.status == ScanStatus.COMPLETED
        assert entry.end_time is not None
        assert isinstance(entry.end_time, datetime)

    def test_mark_failed(self):
        """Test marking a scan as failed."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.mark_failed("Test error message")

        assert entry.status == ScanStatus.FAILED
        assert entry.end_time is not None
        assert isinstance(entry.end_time, datetime)
        assert entry.error_message == "Test error message"

    def test_mark_cancelled(self):
        """Test marking a scan as cancelled."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.mark_cancelled()

        assert entry.status == ScanStatus.CANCELLED
        assert entry.end_time is not None
        assert isinstance(entry.end_time, datetime)

    def test_add_warning(self):
        """Test adding a warning message."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.add_warning("Test warning")

        assert len(entry.warnings) == 1
        assert entry.warnings[0] == "Test warning"

    def test_is_active(self):
        """Test checking if a scan is active."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Initially pending
        assert entry.is_active() is True

        # Mark as running
        entry.mark_running()
        assert entry.is_active() is True

        # Mark as completed
        entry.mark_completed()
        assert entry.is_active() is False

        # Create a new entry and mark as failed
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )
        entry.mark_failed("Test error")
        assert entry.is_active() is False

        # Create a new entry and mark as cancelled
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )
        entry.mark_cancelled()
        assert entry.is_active() is False


@pytest.fixture
def mock_validate_directory_path():
    """Mock the validate_directory_path function to always return None (no error)."""
    with mock.patch(
        "automated_security_helper.core.resource_management.error_handling.validate_directory_path",
        return_value=None,
    ):
        yield


@pytest.fixture
def mock_validate_severity_threshold():
    """Mock the validate_severity_threshold function to always return None (no error)."""
    with mock.patch(
        "automated_security_helper.core.resource_management.error_handling.validate_severity_threshold",
        return_value=None,
    ):
        yield


@pytest.fixture
def mock_validate_config_path():
    """Mock the validate_config_path function to always return None (no error)."""
    with mock.patch(
        "automated_security_helper.core.resource_management.error_handling.validate_config_path",
        return_value=None,
    ):
        yield


class TestScanRegistry:
    """Tests for the ScanRegistry class."""

    def test_init(self):
        """Test initialization."""
        registry = ScanRegistry()
        assert registry._registry == {}

    def test_register_scan(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test registering a scan."""
        registry = ScanRegistry()

        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
            severity_threshold="HIGH",
            config_path="/test/config.yaml",
        )

        assert scan_id is not None
        assert scan_id in registry._registry

        entry = registry._registry[scan_id]
        assert entry.directory_path == "/test/dir"
        assert entry.output_directory == "/test/output"
        assert entry.severity_threshold == "HIGH"
        assert entry.config_path == "/test/config.yaml"
        assert entry.status == ScanStatus.PENDING

    def test_register_scan_with_custom_id(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test registering a scan with a custom ID."""
        registry = ScanRegistry()

        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
            scan_id="custom_id",
        )

        assert scan_id == "custom_id"
        assert scan_id in registry._registry

    def test_register_scan_duplicate_id(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test registering a scan with a duplicate ID."""
        registry = ScanRegistry()

        # Register first scan
        registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
            scan_id="duplicate_id",
        )

        # Try to register second scan with same ID
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path="/test/dir2",
                output_directory="/test/output2",
                scan_id="duplicate_id",
            )

        assert "already exists" in str(excinfo.value)

    def test_register_scan_active_directory(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test registering a scan for a directory that already has an active scan."""
        registry = ScanRegistry()

        # Register first scan
        registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output1",
        )

        # Try to register second scan for same directory
        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path="/test/dir",
                output_directory="/test/output2",
            )

        assert "already has an active scan" in str(excinfo.value)

    def test_register_scan_invalid_id(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test registering a scan with an invalid ID."""
        registry = ScanRegistry()

        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path="/test/dir",
                output_directory="/test/output",
                scan_id="",
            )

        assert "Invalid scan ID" in str(excinfo.value)

    def test_get_scan(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting a scan by ID."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Get the scan
        entry = registry.get_scan(scan_id)

        assert entry is not None
        assert entry.scan_id == scan_id
        assert entry.directory_path == "/test/dir"
        assert entry.output_directory == "/test/output"

    def test_get_scan_not_found(self):
        """Test getting a scan that doesn't exist."""
        registry = ScanRegistry()

        entry = registry.get_scan("non_existent_id")

        assert entry is None

    def test_get_scan_by_directory(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting a scan by directory path."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Get the scan by directory
        entry = registry.get_scan_by_directory("/test/dir")

        assert entry is not None
        assert entry.scan_id == scan_id
        assert entry.directory_path == "/test/dir"

    def test_get_scan_by_directory_not_found(self):
        """Test getting a scan by directory path when it doesn't exist."""
        registry = ScanRegistry()

        entry = registry.get_scan_by_directory("/non/existent/dir")

        assert entry is None

    def test_get_scan_by_directory_not_active(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting a scan by directory path when it's not active."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Mark the scan as completed
        registry._registry[scan_id].mark_completed()

        # Try to get the scan by directory
        entry = registry.get_scan_by_directory("/test/dir")

        assert entry is None

    def test_update_scan_status(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test updating scan status."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Update status to running
        result = registry.update_scan_status(scan_id, ScanStatus.RUNNING)
        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.RUNNING

        # Update status to completed
        result = registry.update_scan_status(scan_id, ScanStatus.COMPLETED)
        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.COMPLETED

        # Update status to failed with error message
        result = registry.update_scan_status(scan_id, ScanStatus.FAILED, "Test error")
        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.FAILED
        assert registry._registry[scan_id].error_message == "Test error"

        # Update status to cancelled
        result = registry.update_scan_status(scan_id, ScanStatus.CANCELLED)
        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.CANCELLED

    def test_update_scan_status_not_found(self):
        """Test updating scan status when scan doesn't exist."""
        registry = ScanRegistry()

        result = registry.update_scan_status("non_existent_id", ScanStatus.RUNNING)

        assert result is False

    def test_list_scans(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test listing scans."""
        registry = ScanRegistry()

        # Register scans
        scan_id1 = registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        scan_id2 = registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )

        # Mark one scan as completed
        registry._registry[scan_id2].mark_completed()

        # List all scans
        scans = registry.list_scans()

        assert len(scans) == 2
        assert any(s["scan_id"] == scan_id1 for s in scans)
        assert any(s["scan_id"] == scan_id2 for s in scans)

    def test_list_scans_active_only(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test listing only active scans."""
        registry = ScanRegistry()

        # Register scans
        scan_id1 = registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        scan_id2 = registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )

        # Mark one scan as completed
        registry._registry[scan_id2].mark_completed()

        # List active scans
        scans = registry.list_scans(active_only=True)

        assert len(scans) == 1
        assert scans[0]["scan_id"] == scan_id1

    def test_list_scans_by_directory(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test listing scans filtered by directory."""
        registry = ScanRegistry()

        # Register scans
        scan_id1 = registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )

        # List scans for directory 1
        scans = registry.list_scans(directory_path="/test/dir1")

        assert len(scans) == 1
        assert scans[0]["scan_id"] == scan_id1

    @mock.patch("os.kill")
    def test_cancel_scan(
        self,
        mock_kill,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cancelling a scan."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Mark as running with process ID
        registry._registry[scan_id].mark_running(process_id=12345)

        # Cancel the scan
        result = registry.cancel_scan(scan_id)

        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.CANCELLED
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)

    def test_cancel_scan_not_found(self):
        """Test cancelling a scan that doesn't exist."""
        registry = ScanRegistry()

        result = registry.cancel_scan("non_existent_id")

        assert result is False

    def test_cancel_scan_not_active(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cancelling a scan that is not active."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Mark as completed
        registry._registry[scan_id].mark_completed()

        # Try to cancel the scan
        result = registry.cancel_scan(scan_id)

        assert result is False

    @mock.patch("os.kill")
    def test_cancel_scan_process_not_found(
        self,
        mock_kill,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cancelling a scan when the process is not found."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Mark as running with process ID
        registry._registry[scan_id].mark_running(process_id=12345)

        # Mock os.kill to raise ProcessLookupError
        mock_kill.side_effect = ProcessLookupError()

        # Cancel the scan
        result = registry.cancel_scan(scan_id)

        assert result is True
        assert registry._registry[scan_id].status == ScanStatus.CANCELLED

    @mock.patch("os.kill")
    def test_cancel_scan_permission_error(
        self,
        mock_kill,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cancelling a scan when there's a permission error."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Mark as running with process ID
        registry._registry[scan_id].mark_running(process_id=12345)

        # Mock os.kill to raise PermissionError
        mock_kill.side_effect = PermissionError()

        # Cancel the scan
        with pytest.raises(MCPResourceError) as excinfo:
            registry.cancel_scan(scan_id)

        assert "Permission denied" in str(excinfo.value)

    def test_cleanup_scan(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cleaning up a scan."""
        registry = ScanRegistry()

        # Register a scan
        scan_id = registry.register_scan(
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        # Clean up the scan
        result = registry.cleanup_scan(scan_id)

        assert result is True
        assert scan_id not in registry._registry

    def test_cleanup_scan_not_found(self):
        """Test cleaning up a scan that doesn't exist."""
        registry = ScanRegistry()

        result = registry.cleanup_scan("non_existent_id")

        assert result is False

    def test_cleanup_completed_scans(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test cleaning up completed scans."""
        registry = ScanRegistry()

        # Register scans
        scan_id1 = registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        scan_id2 = registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )
        scan_id3 = registry.register_scan(
            directory_path="/test/dir3",
            output_directory="/test/output3",
        )

        # Mark scans as completed or failed
        registry._registry[scan_id1].mark_completed()
        registry._registry[scan_id2].mark_failed("Test error")

        # Set end_time to a very old time to ensure they get cleaned up
        old_time = datetime(2000, 1, 1)
        registry._registry[scan_id1].end_time = old_time
        registry._registry[scan_id2].end_time = old_time

        # Clean up completed scans
        count = registry.cleanup_completed_scans(max_age_hours=1)

        assert count == 2
        assert scan_id1 not in registry._registry
        assert scan_id2 not in registry._registry
        assert scan_id3 in registry._registry

    def test_get_active_scan_count(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting active scan count."""
        registry = ScanRegistry()

        # Register scans
        registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        scan_id2 = registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )

        # Mark one scan as completed
        registry._registry[scan_id2].mark_completed()

        # Get active scan count
        count = registry.get_active_scan_count()

        assert count == 1

    def test_get_scan_count(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting total scan count."""
        registry = ScanRegistry()

        # Register scans
        registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )

        # Get scan count
        count = registry.get_scan_count()

        assert count == 2

    def test_get_scan_status_counts(
        self,
        mock_validate_directory_path,
        mock_validate_severity_threshold,
        mock_validate_config_path,
    ):
        """Test getting scan status counts."""
        registry = ScanRegistry()

        # Register scans
        scan_id1 = registry.register_scan(
            directory_path="/test/dir1",
            output_directory="/test/output1",
        )
        scan_id2 = registry.register_scan(
            directory_path="/test/dir2",
            output_directory="/test/output2",
        )
        scan_id3 = registry.register_scan(
            directory_path="/test/dir3",
            output_directory="/test/output3",
        )
        scan_id4 = registry.register_scan(
            directory_path="/test/dir4",
            output_directory="/test/output4",
        )

        # Set different statuses
        registry._registry[scan_id1].mark_running()
        registry._registry[scan_id2].mark_completed()
        registry._registry[scan_id3].mark_failed("Test error")
        registry._registry[scan_id4].mark_cancelled()

        # Get status counts
        counts = registry.get_scan_status_counts()

        assert counts["pending"] == 0
        assert counts["running"] == 1
        assert counts["completed"] == 1
        assert counts["failed"] == 1
        assert counts["cancelled"] == 1

    def test_check_scan_progress_not_found(self):
        """Test checking scan progress when scan doesn't exist."""
        registry = ScanRegistry()

        with pytest.raises(MCPResourceError) as excinfo:
            registry.check_scan_progress("non_existent_id")

        assert "not found" in str(excinfo.value)


def test_get_scan_registry():
    """Test getting the global scan registry instance."""
    registry1 = get_scan_registry()
    registry2 = get_scan_registry()

    assert registry1 is registry2
    assert isinstance(registry1, ScanRegistry)
