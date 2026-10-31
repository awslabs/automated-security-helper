#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the scan registry module.

This module tests the scan registry and management components for ASH MCP server.
"""

import json
import os
import signal
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistryEntry,
    ScanRegistry,
    get_scan_registry,
)

pytestmark = pytest.mark.unit


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
        assert entry.status == MCScanStatus.PENDING
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

        assert entry.status == MCScanStatus.RUNNING
        assert entry.process_id == 12345

    def test_mark_completed(self):
        """Test marking a scan as completed."""
        entry = ScanRegistryEntry(
            scan_id="test_scan_id",
            directory_path="/test/dir",
            output_directory="/test/output",
        )

        entry.mark_completed()

        assert entry.status == MCScanStatus.COMPLETED
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

        assert entry.status == MCScanStatus.FAILED
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

        assert entry.status == MCScanStatus.CANCELLED
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
    """Mock the directory checks to always return None (no error).

    register_scan checks the source directory with source_directory_error and the
    output directory with validate_directory_path; these tests name directories
    that do not exist.
    """
    with (
        mock.patch(
            "automated_security_helper.core.resource_management.error_handling.validate_directory_path",
            return_value=None,
        ),
        mock.patch(
            "automated_security_helper.core.resource_management.error_handling.source_directory_error",
            return_value=None,
        ),
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
        assert entry.status == MCScanStatus.PENDING

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
        result = registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        assert result is True
        assert registry._registry[scan_id].status == MCScanStatus.RUNNING

        # Update status to completed
        result = registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
        assert result is True
        assert registry._registry[scan_id].status == MCScanStatus.COMPLETED

        # Update status to failed with error message
        result = registry.update_scan_status(scan_id, MCScanStatus.FAILED, "Test error")
        assert result is True
        assert registry._registry[scan_id].status == MCScanStatus.FAILED
        assert registry._registry[scan_id].error_message == "Test error"

        # Update status to cancelled
        result = registry.update_scan_status(scan_id, MCScanStatus.CANCELLED)
        assert result is True
        assert registry._registry[scan_id].status == MCScanStatus.CANCELLED

    def test_update_scan_status_not_found(self):
        """Test updating scan status when scan doesn't exist."""
        registry = ScanRegistry()

        result = registry.update_scan_status("non_existent_id", MCScanStatus.RUNNING)

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
        assert registry._registry[scan_id].status == MCScanStatus.CANCELLED
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
        assert registry._registry[scan_id].status == MCScanStatus.CANCELLED

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


class TestDirectoryComparisonIsCanonical:
    """One directory answers to one entry, however the caller spelled the path.

    Why this exists
    ---------------
    Every directory-keyed decision in the registry compared the raw string it was
    handed. ``/proj`` and ``/proj/`` were therefore two directories, as were
    ``/proj/../proj`` and ``/proj``, so ``register_scan`` admitted a second active
    scan on a tree that already had one. Both scans then wrote into
    ``<proj>/.ash/ash_output``: one source examined twice, its findings attributed
    twice, and two writers racing on one output tree.

    ``str(Path)`` never ends in a separator, so the trailing-separator spelling can
    only arrive from a caller -- which is the untrusted case. The single-project
    MCP flow reaches this code with one hand-typed path, which made it survivable;
    a workspace scan derives N of them from a file an operator wrote.

    Real directories, not mocked validators
    ---------------------------------------
    These use ``tmp_path`` rather than the ``mock_validate_directory_path``
    fixture the tests above share. The comparison under test resolves the path,
    and ``Path.resolve()`` on a directory that does not exist collapses ``..``
    lexically without consulting the filesystem -- so a mocked-away existence
    check would leave the traversal case measuring something weaker than the
    production path does.
    """

    @staticmethod
    def _register(registry: ScanRegistry, directory: Path, output: Path) -> str:
        return registry.register_scan(
            directory_path=str(directory), output_directory=str(output)
        )

    @staticmethod
    def _project_and_output(tmp_path: Path) -> tuple[Path, Path]:
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        return project, output

    def test_a_trailing_separator_does_not_admit_a_second_active_scan(self, tmp_path):
        project, output = self._project_and_output(tmp_path)
        registry = ScanRegistry()
        first = self._register(registry, project, output)

        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(project) + os.sep, output_directory=str(output)
            )

        assert "already has an active scan" in str(excinfo.value)
        assert excinfo.value.context["scan_id"] == first
        assert registry.get_scan_count() == 1

    def test_a_traversal_does_not_admit_a_second_active_scan(self, tmp_path):
        """``proj/../proj`` is ``proj`` and is not the same string.

        Joined as strings rather than with ``/`` on a ``Path``: pathlib collapses
        nothing at construction for ``..``, but it does drop a single ``.``, so
        string joining is the only way to be sure the un-canonical form survives
        to the call.
        """
        project, output = self._project_and_output(tmp_path)
        registry = ScanRegistry()
        first = self._register(registry, project, output)
        traversal = os.path.join(str(project), os.pardir, "proj")
        assert traversal != str(project)

        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=traversal, output_directory=str(output)
            )

        assert excinfo.value.context["scan_id"] == first
        assert registry.get_scan_count() == 1

    def test_a_sibling_sharing_a_prefix_still_registers(self, tmp_path):
        """Positive control: canonicalising must not collapse distinct paths.

        The cheapest wrong way to do this is a ``startswith`` or a prefix strip,
        and ``proj`` against ``proj-backup`` is where that shows.

        Each directory has an output directory of its own: two directories
        naming one output directory are refused by design (see
        ``test_two_directories_cannot_share_an_output_directory`` in
        ``test_scan_registry_lookups_and_claims.py``), which is a different
        rule from the one measured here.
        """
        project, output = self._project_and_output(tmp_path)
        sibling = tmp_path / "proj-backup"
        sibling.mkdir()
        sibling_output = tmp_path / "out-backup"
        sibling_output.mkdir()
        registry = ScanRegistry()

        first = self._register(registry, project, output)
        second = self._register(registry, sibling, sibling_output)

        assert first != second
        assert registry.get_scan_count() == 2

    def test_a_completed_scan_does_not_block_a_rescan(self, tmp_path):
        """The rule is about *active* scans, and canonicalising must not widen it.

        Applied without keeping the ``is_active()`` half of the condition, the
        first scan of a directory would permanently block every later one --
        which nothing else here would notice, because nothing else registers one
        directory twice.
        """
        project, output = self._project_and_output(tmp_path)
        registry = ScanRegistry()
        first = self._register(registry, project, output)
        registry.update_scan_status(first, MCScanStatus.COMPLETED)

        second = registry.register_scan(
            directory_path=str(project) + os.sep, output_directory=str(output)
        )

        assert second != first
        assert registry.get_scan_count() == 2

    def test_get_scan_by_directory_finds_the_entry_the_refusal_named(self, tmp_path):
        """The refusal and the lookup have to agree on what one directory is.

        ``register_scan`` reports the id of the scan already holding the
        directory. A caller handed that id, asking the registry for the same
        directory by the same string, must reach the same entry -- otherwise the
        refusal names a scan the caller cannot then inspect.
        """
        project, output = self._project_and_output(tmp_path)
        registry = ScanRegistry()
        first = self._register(registry, project, output)

        entry = registry.get_scan_by_directory(str(project) + os.sep)

        assert entry is not None
        assert entry.scan_id == first

    def test_list_scans_filters_by_the_same_directory_however_spelled(self, tmp_path):
        """The ``directory_path`` filter keys off the same notion of sameness.

        Left comparing raw strings, ``list_scans`` would report zero scans for a
        directory ``register_scan`` had just refused as occupied.

        The second scan has its own output directory: sharing one with the
        first is refused at registration, and this test is about the filter.
        """
        project, output = self._project_and_output(tmp_path)
        sibling = tmp_path / "other"
        sibling.mkdir()
        sibling_output = tmp_path / "out-other"
        sibling_output.mkdir()
        registry = ScanRegistry()
        first = self._register(registry, project, output)
        self._register(registry, sibling, sibling_output)

        matched = registry.list_scans(directory_path=str(project) + os.sep)

        assert [entry["scan_id"] for entry in matched] == [first]


class TestTheOutputDirectoryNeedNotExistYet:
    """A scan creates its output directory once registered, so it may be missing.

    register_scan refused an output directory that did not exist, which made
    both MCP scans create theirs before asking for a slot: a scan refused at
    max_concurrent_scans left an empty output tree behind.
    """

    def test_a_missing_output_directory_is_registered_and_not_created(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "proj" / ".ash" / "ash_output"
        registry = ScanRegistry()

        scan_id = registry.register_scan(
            directory_path=str(project), output_directory=str(output)
        )

        assert registry.get_scan(scan_id).output_directory == str(output)
        assert not (project / ".ash").exists()

    def test_an_output_path_that_is_a_file_is_refused(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.write_text("not a directory\n", encoding="utf-8")
        registry = ScanRegistry()

        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(project), output_directory=str(output)
            )

        assert str(excinfo.value) == f"Output directory is not a directory: {output}"
        assert registry.list_scans() == []


class TestAResultsFileThatDoesNotLoadClosesAPendingScanFailed:
    """A pending scan no runner owns is closed from its results file.

    The progress view can read a file as a finished scan's while the results
    model cannot be built from it, and then there is no coverage to assess. The
    poll used to close such a scan as completed, so a scan that was never shown
    to have covered anything read as a clean one. It closes as failed, with the
    file named, the way an unreadable file does.
    """

    _LOADER = (
        "automated_security_helper.core.resource_management.scan_registry."
        "load_aggregated_results_model"
    )

    @staticmethod
    def _pending_scan_with_a_results_file(tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(
                {
                    "metadata": {
                        "generated_at": "2024-01-01T00:00:00",
                        "summary_stats": {},
                    },
                    "scanner_results": {
                        "bandit": {"status": "PASSED", "finding_count": 0}
                    },
                }
            ),
            encoding="utf-8",
        )
        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(project), output_directory=str(output)
        )
        return registry, scan_id, output

    def test_a_loader_that_returns_none_fails_the_scan_and_names_the_file(
        self, tmp_path
    ):
        registry, scan_id, output = self._pending_scan_with_a_results_file(tmp_path)

        with mock.patch(self._LOADER, return_value=None):
            progress = registry.check_scan_progress(scan_id)

        entry = registry.get_scan(scan_id)
        assert entry.status is MCScanStatus.FAILED, entry.status
        assert entry.error_message is not None
        assert str(output / "ash_aggregated_results.json") in entry.error_message
        assert "could not be loaded" in entry.error_message
        assert entry.end_time is not None
        assert entry.closed_from_file is True
        assert progress["status"] == "failed"
        assert progress["is_complete"] is True
        assert progress["results_available"] is False
        assert progress["error_message"] == entry.error_message

    def test_a_results_file_that_loads_still_closes_the_scan_from_the_file(
        self, tmp_path
    ):
        """The same file through the real loader: nothing else changes."""
        from automated_security_helper.core.resource_management.scan_tracking import (
            load_aggregated_results_model,
        )

        registry, scan_id, output = self._pending_scan_with_a_results_file(tmp_path)
        assert load_aggregated_results_model(output) is not None

        progress = registry.check_scan_progress(scan_id)

        entry = registry.get_scan(scan_id)
        assert entry.status in (MCScanStatus.COMPLETED, MCScanStatus.INCOMPLETE)
        assert entry.error_message is None
        assert entry.closed_from_file is True
        assert progress["status"] == entry.status.value
        assert progress["results_available"] is True


def test_a_failed_scans_message_hides_a_value_split_by_an_escape_code(tmp_path):
    """The status sink redacts the message with the entry's registered values;
    an escape code a tool printed inside a value must not split the match."""
    head, tail = "ASH_CANARY_Zq7Kx9LmHead", "ASH_CANARY_Pw4Nv2RtTail"
    project = tmp_path / "proj"
    project.mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(tmp_path / "out"),
        environment_values=(f"{head}{tail}",),
    )

    registry.update_scan_status(
        scan_id, MCScanStatus.FAILED, f"tool failed at {head}\x1b[K{tail} here"
    )

    message = registry.get_scan(scan_id).error_message
    assert "tool failed" in message, repr(message)
    assert head not in message and tail not in message, repr(message)
