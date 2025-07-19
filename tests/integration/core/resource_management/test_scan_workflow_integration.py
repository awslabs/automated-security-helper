#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for the scan workflow.

This module tests the complete scan workflow, including file-based tracking,
scan registry, and scan management.
"""

import json
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanStatus,
    get_scan_registry,
)
from automated_security_helper.core.resource_management.scan_management import (
    list_active_scans,
    cancel_scan,
    cleanup_scan_resources,
    check_scan_progress,
    get_scan_statistics,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    get_scan_progress_info,
    get_scan_results,
)


@pytest.fixture
def test_directory(tmp_path):
    """Create a test directory with sample code files."""
    # Create a test directory with some sample files
    test_dir = tmp_path / "test_project"
    test_dir.mkdir()

    # Create some sample files
    (test_dir / "app.py").write_text("print('Hello, world!')")
    (test_dir / "requirements.txt").write_text("requests==2.28.1\npandas==1.5.0")

    # Create a subdirectory with more files
    src_dir = test_dir / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("import os\nimport sys\n\ndef main():\n    pass")
    (src_dir / "utils.py").write_text("def helper():\n    return 'helper'")

    return test_dir


@pytest.fixture
def output_directory(tmp_path):
    """Create an output directory for scan results."""
    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def mock_scan_process():
    """Mock function to simulate a scan process."""

    def create_mock_scan_results(
        output_dir, duration=1, scanner_count=2, with_errors=False
    ):
        """Create mock scan results in the output directory."""
        # Create scanners directory
        scanners_dir = output_dir / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        # Create scanner result files
        for i in range(scanner_count):
            scanner_name = f"scanner{i + 1}"
            scanner_dir = scanners_dir / scanner_name
            scanner_dir.mkdir(exist_ok=True)

            # Create source directory
            source_dir = scanner_dir / "source"
            source_dir.mkdir(exist_ok=True)

            # Create result file
            result_file = source_dir / "ASH.ScanResults.json"
            findings = []

            # Add some findings
            severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for j in range(i + 1):  # Each scanner has a different number of findings
                findings.append(
                    {
                        "id": f"{scanner_name}-{j + 1}",
                        "severity": severity_levels[j % len(severity_levels)],
                        "scanner": scanner_name,
                        "message": f"Test finding {j + 1}",
                        "file": "app.py",
                        "line": j + 1,
                    }
                )

            # Write result file
            result_data = {"findings": findings}
            with open(result_file, "w") as f:
                json.dump(result_data, f)

            # Simulate scan duration
            time.sleep(duration)

        # Create aggregated results file
        all_findings = []
        scanners_completed = []

        for i in range(scanner_count):
            scanner_name = f"scanner{i + 1}"
            scanners_completed.append(scanner_name)

            # Read scanner findings
            scanner_result_file = (
                scanners_dir / scanner_name / "source" / "ASH.ScanResults.json"
            )
            with open(scanner_result_file, "r") as f:
                scanner_data = json.load(f)
                all_findings.extend(scanner_data["findings"])

        # Add an error if requested
        if with_errors:
            all_findings.append(
                {
                    "id": "error-1",
                    "severity": "HIGH",
                    "scanner": "error_scanner",
                    "message": "Test error finding",
                    "file": "app.py",
                    "line": 10,
                    "error": True,
                }
            )
            scanners_completed.append("error_scanner")

        # Write aggregated results file
        aggregated_data = {
            "findings": all_findings,
            "scanners_completed": scanners_completed,
            "completion_time": datetime.now().isoformat(),
        }

        with open(output_dir / "ash_aggregated_results.json", "w") as f:
            json.dump(aggregated_data, f)

    return create_mock_scan_results


class TestScanWorkflowIntegration:
    """Integration tests for the scan workflow."""

    @pytest.mark.asyncio
    async def test_complete_scan_workflow(
        self, test_directory, output_directory, mock_scan_process
    ):
        """Test the complete scan workflow from start to finish."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Verify the scan was registered
        assert scan_id is not None
        assert registry.get_scan(scan_id) is not None
        assert registry.get_scan(scan_id).status == ScanStatus.PENDING

        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Verify the scan is running
        assert registry.get_scan(scan_id).status == ScanStatus.RUNNING

        # Start a background task to create mock scan results
        with ThreadPoolExecutor() as executor:
            # Run the mock scan process in a separate thread
            future = executor.submit(mock_scan_process, output_directory, 0.5, 3, False)

            # Check scan progress while it's running
            for _ in range(3):
                progress = await check_scan_progress(scan_id)
                assert progress["scan_id"] == scan_id
                assert "scanners" in progress

                # Wait a bit for more results
                await asyncio.sleep(0.2)

            # Wait for the mock scan to complete
            future.result()

        # Check scan progress after completion
        progress = await check_scan_progress(scan_id)
        assert progress["scan_id"] == scan_id
        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["completed_scanners"] == 3
        assert progress["total_scanners"] == 3
        assert progress["total_findings"] == 6  # 1 + 2 + 3 findings

        # Get scan results
        results = get_scan_results(scan_id, output_directory)
        assert results["scan_id"] == scan_id
        assert results["status"] == "completed"
        assert results["is_complete"] is True
        assert results["findings_count"] == 6
        assert len(results["findings"]) == 6
        assert "severity_counts" in results
        assert "scanners_completed" in results
        assert len(results["scanners_completed"]) == 3

        # Clean up the scan
        cleanup_result = await cleanup_scan_resources(scan_id, remove_output=False)
        assert cleanup_result["success"] is True
        assert cleanup_result["scan_id"] == scan_id
        assert cleanup_result["removed_from_registry"] is True

        # Verify the scan was removed from the registry
        assert registry.get_scan(scan_id) is None

    @pytest.mark.asyncio
    async def test_scan_cancellation(
        self, test_directory, output_directory, mock_scan_process
    ):
        """Test cancelling a scan in progress."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running with a fake process ID
        registry.get_scan(scan_id).mark_running(process_id=None)

        # Start a background task to create mock scan results
        with ThreadPoolExecutor() as executor:
            # Run the mock scan process in a separate thread with a longer duration
            future = executor.submit(mock_scan_process, output_directory, 1, 5, False)

            # Wait a bit for the scan to start creating results
            await asyncio.sleep(0.5)

            # Cancel the scan
            cancel_result = await cancel_scan(scan_id)
            assert cancel_result["success"] is True
            assert cancel_result["scan_id"] == scan_id
            assert cancel_result["status"] == "cancelled"

            # Wait for the mock scan to complete (it will continue despite cancellation in our test)
            future.result()

        # Check scan status after cancellation
        entry = registry.get_scan(scan_id)
        assert entry is not None
        assert entry.status == ScanStatus.CANCELLED

        # Clean up the scan
        await cleanup_scan_resources(scan_id, remove_output=True)

    @pytest.mark.asyncio
    async def test_error_handling_scan_not_found(self):
        """Test error handling when scan is not found."""
        # Try to check progress of a non-existent scan
        with pytest.raises(MCPResourceError) as excinfo:
            await check_scan_progress("non_existent_scan")

        assert "not found" in str(excinfo.value)

        # Try to cancel a non-existent scan
        cancel_result = await cancel_scan("non_existent_scan")
        assert cancel_result["success"] is False
        assert "not found" in cancel_result["error"]

        # Try to clean up a non-existent scan
        cleanup_result = await cleanup_scan_resources("non_existent_scan")
        assert cleanup_result["success"] is False
        assert "not found" in cleanup_result["error"]

    @pytest.mark.asyncio
    async def test_error_handling_invalid_output_directory(
        self, test_directory, tmp_path
    ):
        """Test error handling with invalid output directory."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan with a non-existent output directory
        output_dir = tmp_path / "non_existent"
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_dir),
            severity_threshold="MEDIUM",
        )

        # Try to check progress
        with pytest.raises(MCPResourceError) as excinfo:
            await check_scan_progress(scan_id)

        assert "not found" in str(excinfo.value) or "does not exist" in str(
            excinfo.value
        )

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_error_handling_incomplete_scan(
        self, test_directory, output_directory
    ):
        """Test error handling when trying to get results of an incomplete scan."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Create scanners directory but no aggregated results
        scanners_dir = output_directory / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        # Try to get scan results
        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(scan_id, output_directory)

        assert "not complete" in str(excinfo.value)

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_concurrent_scans(self, tmp_path, mock_scan_process):
        """Test running multiple scans concurrently."""
        # Get the scan registry
        registry = get_scan_registry()

        # Create multiple test directories
        test_dirs = []
        output_dirs = []
        scan_ids = []

        for i in range(3):
            # Create test directory
            test_dir = tmp_path / f"test_project_{i}"
            test_dir.mkdir()
            (test_dir / "app.py").write_text(f"print('Hello from project {i}!')")
            test_dirs.append(test_dir)

            # Create output directory
            output_dir = tmp_path / f"ash_output_{i}"
            output_dir.mkdir()
            output_dirs.append(output_dir)

            # Register scan
            scan_id = registry.register_scan(
                directory_path=str(test_dir),
                output_directory=str(output_dir),
                severity_threshold="MEDIUM",
            )
            scan_ids.append(scan_id)

            # Mark as running
            registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Start background tasks to create mock scan results
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Run the mock scan processes in separate threads
            futures = [
                executor.submit(mock_scan_process, output_dirs[0], 0.5, 2, False),
                executor.submit(mock_scan_process, output_dirs[1], 0.7, 3, False),
                executor.submit(mock_scan_process, output_dirs[2], 0.3, 1, True),
            ]

            # Check active scans while they're running
            active_scans = await list_active_scans()
            assert len(active_scans) == 3

            # Wait for all mock scans to complete
            for future in futures:
                future.result()

        # Check scan statistics
        stats = await get_scan_statistics()
        assert stats["total_scans"] == 3

        # Check each scan's progress
        for i, scan_id in enumerate(scan_ids):
            progress = await check_scan_progress(scan_id)
            assert progress["scan_id"] == scan_id
            assert progress["status"] == "completed"
            assert progress["is_complete"] is True

            # Get scan results
            results = get_scan_results(scan_id, output_dirs[i])
            assert results["scan_id"] == scan_id
            assert results["status"] == "completed"
            assert results["is_complete"] is True

            # Clean up the scan
            await cleanup_scan_resources(scan_id, remove_output=True)

        # Verify all scans were cleaned up
        active_scans = await list_active_scans()
        assert len(active_scans) == 0

    @pytest.mark.asyncio
    async def test_scan_with_errors(
        self, test_directory, output_directory, mock_scan_process
    ):
        """Test a scan that includes error findings."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Create mock scan results with errors
        mock_scan_process(output_directory, 0.2, 2, True)

        # Check scan progress
        progress = await check_scan_progress(scan_id)
        assert progress["scan_id"] == scan_id
        assert progress["status"] == "completed"
        assert progress["is_complete"] is True

        # Get scan results
        results = get_scan_results(scan_id, output_directory)
        assert results["scan_id"] == scan_id
        assert results["status"] == "completed"
        assert results["is_complete"] is True

        # Verify error findings are included
        error_findings = [f for f in results["findings"] if f.get("error", False)]
        assert len(error_findings) > 0

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_scan_file_based_progress_tracking(
        self, test_directory, output_directory, mock_scan_process
    ):
        """Test file-based progress tracking during a scan."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Create scanners directory
        scanners_dir = output_directory / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        # Check initial progress
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert progress_info["scanners_completed"] == []

        # Create results for first scanner
        scanner1_dir = scanners_dir / "scanner1"
        scanner1_dir.mkdir()
        source_dir = scanner1_dir / "source"
        source_dir.mkdir()

        result_file = source_dir / "ASH.ScanResults.json"
        result_data = {
            "findings": [
                {"id": "1", "severity": "CRITICAL", "scanner": "scanner1"},
                {"id": "2", "severity": "HIGH", "scanner": "scanner1"},
            ]
        }
        with open(result_file, "w") as f:
            json.dump(result_data, f)

        # Check progress after first scanner
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert "scanner1" in progress_info["scanners_completed"]
        assert progress_info["findings_count"] == 2

        # Create results for second scanner
        scanner2_dir = scanners_dir / "scanner2"
        scanner2_dir.mkdir()
        source_dir = scanner2_dir / "source"
        source_dir.mkdir()

        result_file = source_dir / "ASH.ScanResults.json"
        result_data = {
            "findings": [{"id": "3", "severity": "MEDIUM", "scanner": "scanner2"}]
        }
        with open(result_file, "w") as f:
            json.dump(result_data, f)

        # Check progress after second scanner
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert set(progress_info["scanners_completed"]) == {"scanner1", "scanner2"}
        assert progress_info["findings_count"] == 3

        # Create aggregated results file
        aggregated_data = {
            "findings": [
                {"id": "1", "severity": "CRITICAL", "scanner": "scanner1"},
                {"id": "2", "severity": "HIGH", "scanner": "scanner1"},
                {"id": "3", "severity": "MEDIUM", "scanner": "scanner2"},
            ],
            "scanners_completed": ["scanner1", "scanner2"],
            "completion_time": datetime.now().isoformat(),
        }

        with open(output_directory / "ash_aggregated_results.json", "w") as f:
            json.dump(aggregated_data, f)

        # Check progress after completion
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "completed"
        assert progress_info["is_complete"] is True
        assert set(progress_info["scanners_completed"]) == {"scanner1", "scanner2"}
        assert progress_info["findings_count"] == 3

        # Clean up the scan
        await cleanup_scan_resources(scan_id)
