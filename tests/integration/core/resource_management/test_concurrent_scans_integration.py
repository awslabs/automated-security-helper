#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for concurrent scan execution.

This module tests the behavior of the scan workflow when multiple scans
are running concurrently, ensuring proper isolation and resource management.
"""

import json
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest

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
    get_scan_results,
)


@pytest.fixture
def test_directories(tmp_path):
    """Create multiple test directories with sample code files."""
    directories = []

    for i in range(5):
        test_dir = tmp_path / f"test_project_{i}"
        test_dir.mkdir()

        # Create some sample files
        (test_dir / "app.py").write_text(f"print('Hello from project {i}!')")
        (test_dir / "requirements.txt").write_text(f"requests==2.28.1\npandas==1.5.{i}")

        # Create a subdirectory with more files
        src_dir = test_dir / "src"
        src_dir.mkdir()
        (src_dir / "main.py").write_text(
            f"import os\nimport sys\n\ndef main_{i}():\n    pass"
        )

        directories.append(test_dir)

    return directories


@pytest.fixture
def output_directories(tmp_path):
    """Create multiple output directories for scan results."""
    directories = []

    for i in range(5):
        output_dir = tmp_path / f"ash_output_{i}"
        output_dir.mkdir()
        directories.append(output_dir)

    return directories


@pytest.fixture
def mock_scan_process():
    """Mock function to simulate a scan process with variable duration and findings."""

    def create_mock_scan_results(
        output_dir, duration=1, scanner_count=2, finding_count=3, with_errors=False
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
            for j in range(
                min(finding_count, (i + 1) * 2)
            ):  # Each scanner has a different number of findings
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

            # Simulate scan duration with some variability
            time.sleep(duration * (0.8 + (i * 0.1)))

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


class TestConcurrentScansIntegration:
    """Integration tests for concurrent scan execution."""

    @pytest.mark.asyncio
    async def test_multiple_concurrent_scans(
        self, test_directories, output_directories, mock_scan_process
    ):
        """Test running multiple scans concurrently."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register multiple scans
        scan_ids = []
        for i in range(5):
            scan_id = registry.register_scan(
                directory_path=str(test_directories[i]),
                output_directory=str(output_directories[i]),
                severity_threshold="MEDIUM",
            )
            scan_ids.append(scan_id)

            # Mark as running
            registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Start background tasks to create mock scan results with different parameters
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Run the mock scan processes in separate threads with different parameters
            futures = [
                executor.submit(
                    mock_scan_process, output_directories[0], 0.3, 2, 3, False
                ),
                executor.submit(
                    mock_scan_process, output_directories[1], 0.5, 3, 2, False
                ),
                executor.submit(
                    mock_scan_process, output_directories[2], 0.2, 1, 5, True
                ),
                executor.submit(
                    mock_scan_process, output_directories[3], 0.4, 4, 1, False
                ),
                executor.submit(
                    mock_scan_process, output_directories[4], 0.6, 2, 4, True
                ),
            ]

            # Check active scans while they're running
            active_scans = await list_active_scans()
            assert len(active_scans) == 5

            # Check scan statistics
            stats = await get_scan_statistics()
            assert stats["total_scans"] == 5
            assert stats["active_scans"] == 5

            # Check progress of each scan while they're running
            for scan_id in scan_ids:
                progress = await check_scan_progress(scan_id)
                assert progress["scan_id"] == scan_id
                assert "scanners" in progress

            # Wait for all mock scans to complete
            for future in futures:
                future.result()

        # Check each scan's progress after completion
        for i, scan_id in enumerate(scan_ids):
            progress = await check_scan_progress(scan_id)
            assert progress["scan_id"] == scan_id
            assert progress["status"] == "completed"
            assert progress["is_complete"] is True

            # Get scan results
            results = get_scan_results(scan_id, output_directories[i])
            assert results["scan_id"] == scan_id
            assert results["status"] == "completed"
            assert results["is_complete"] is True

            # Verify results are isolated between scans
            if i == 2 or i == 4:  # Scans with errors
                error_findings = [
                    f for f in results["findings"] if f.get("error", False)
                ]
                assert len(error_findings) > 0
            else:
                error_findings = [
                    f for f in results["findings"] if f.get("error", False)
                ]
                assert len(error_findings) == 0

        # Clean up all scans
        for scan_id in scan_ids:
            await cleanup_scan_resources(scan_id, remove_output=True)

        # Verify all scans were cleaned up
        active_scans = await list_active_scans()
        assert len(active_scans) == 0

    @pytest.mark.asyncio
    async def test_concurrent_scan_cancellation(
        self, test_directories, output_directories, mock_scan_process
    ):
        """Test cancelling some scans while others continue running."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register multiple scans
        scan_ids = []
        for i in range(3):
            scan_id = registry.register_scan(
                directory_path=str(test_directories[i]),
                output_directory=str(output_directories[i]),
                severity_threshold="MEDIUM",
            )
            scan_ids.append(scan_id)

            # Mark as running
            registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Start background tasks to create mock scan results
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Run the mock scan processes in separate threads with longer durations
            futures = [
                executor.submit(
                    mock_scan_process, output_directories[0], 1.0, 3, 2, False
                ),
                executor.submit(
                    mock_scan_process, output_directories[1], 1.2, 2, 3, False
                ),
                executor.submit(
                    mock_scan_process, output_directories[2], 1.5, 4, 1, False
                ),
            ]

            # Wait a bit for the scans to start
            await asyncio.sleep(0.5)

            # Cancel the second scan
            cancel_result = await cancel_scan(scan_ids[1])
            assert cancel_result["success"] is True
            assert cancel_result["scan_id"] == scan_ids[1]
            assert cancel_result["status"] == "cancelled"

            # Wait for the remaining scans to complete
            for future in futures:
                future.result()

        # Check status of each scan
        # First scan should be completed
        progress0 = await check_scan_progress(scan_ids[0])
        assert progress0["status"] == "completed"
        assert progress0["is_complete"] is True

        # Second scan should be cancelled
        entry1 = registry.get_scan(scan_ids[1])
        assert entry1.status == ScanStatus.CANCELLED

        # Third scan should be completed
        progress2 = await check_scan_progress(scan_ids[2])
        assert progress2["status"] == "completed"
        assert progress2["is_complete"] is True

        # Clean up all scans
        for scan_id in scan_ids:
            await cleanup_scan_resources(scan_id, remove_output=True)

    @pytest.mark.asyncio
    async def test_concurrent_scan_resource_isolation(
        self, test_directories, output_directories
    ):
        """Test that concurrent scans maintain proper resource isolation."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register two scans
        scan_id1 = registry.register_scan(
            directory_path=str(test_directories[0]),
            output_directory=str(output_directories[0]),
            severity_threshold="MEDIUM",
        )

        scan_id2 = registry.register_scan(
            directory_path=str(test_directories[1]),
            output_directory=str(output_directories[1]),
            severity_threshold="HIGH",
        )

        # Mark both as running
        registry.update_scan_status(scan_id1, ScanStatus.RUNNING)
        registry.update_scan_status(scan_id2, ScanStatus.RUNNING)

        # Create results for first scan
        scanners_dir1 = output_directories[0] / "scanners"
        scanners_dir1.mkdir(exist_ok=True)

        scanner_dir1 = scanners_dir1 / "scanner1"
        scanner_dir1.mkdir()
        source_dir1 = scanner_dir1 / "source"
        source_dir1.mkdir()

        result_data1 = {
            "findings": [
                {
                    "id": "1",
                    "severity": "CRITICAL",
                    "scanner": "scanner1",
                    "message": "Critical in scan 1",
                }
            ]
        }
        with open(source_dir1 / "ASH.ScanResults.json", "w") as f:
            json.dump(result_data1, f)

        # Create results for second scan
        scanners_dir2 = output_directories[1] / "scanners"
        scanners_dir2.mkdir(exist_ok=True)

        scanner_dir2 = scanners_dir2 / "scanner1"
        scanner_dir2.mkdir()
        source_dir2 = scanner_dir2 / "source"
        source_dir2.mkdir()

        result_data2 = {
            "findings": [
                {
                    "id": "1",
                    "severity": "HIGH",
                    "scanner": "scanner1",
                    "message": "High in scan 2",
                }
            ]
        }
        with open(source_dir2 / "ASH.ScanResults.json", "w") as f:
            json.dump(result_data2, f)

        # Create aggregated results for both scans
        aggregated_data1 = {
            "findings": result_data1["findings"],
            "scanners_completed": ["scanner1"],
            "completion_time": datetime.now().isoformat(),
        }
        with open(output_directories[0] / "ash_aggregated_results.json", "w") as f:
            json.dump(aggregated_data1, f)

        aggregated_data2 = {
            "findings": result_data2["findings"],
            "scanners_completed": ["scanner1"],
            "completion_time": datetime.now().isoformat(),
        }
        with open(output_directories[1] / "ash_aggregated_results.json", "w") as f:
            json.dump(aggregated_data2, f)

        # Check progress of both scans
        progress1 = await check_scan_progress(scan_id1)
        progress2 = await check_scan_progress(scan_id2)

        # Verify isolation of results
        assert progress1["total_findings"] == 1
        assert progress2["total_findings"] == 1
        assert progress1["severity_counts"]["CRITICAL"] == 1
        assert progress1["severity_counts"]["HIGH"] == 0
        assert progress2["severity_counts"]["CRITICAL"] == 0
        assert progress2["severity_counts"]["HIGH"] == 1

        # Get results for both scans
        results1 = get_scan_results(scan_id1, output_directories[0])
        results2 = get_scan_results(scan_id2, output_directories[1])

        # Verify isolation of findings
        assert len(results1["findings"]) == 1
        assert len(results2["findings"]) == 1
        assert results1["findings"][0]["message"] == "Critical in scan 1"
        assert results2["findings"][0]["message"] == "High in scan 2"

        # Clean up
        await cleanup_scan_resources(scan_id1, remove_output=True)
        await cleanup_scan_resources(scan_id2, remove_output=True)

    @pytest.mark.asyncio
    async def test_concurrent_scan_registry_thread_safety(
        self, test_directories, output_directories
    ):
        """Test thread safety of the scan registry during concurrent operations."""
        # Get the scan registry
        registry = get_scan_registry()

        # Define a function to register and update scans
        async def register_and_update(index):
            scan_id = registry.register_scan(
                directory_path=str(test_directories[index]),
                output_directory=str(output_directories[index]),
                severity_threshold="MEDIUM",
            )
            registry.update_scan_status(scan_id, ScanStatus.RUNNING)
            await asyncio.sleep(
                0.1
            )  # Small delay to increase chance of race conditions
            registry.update_scan_status(scan_id, ScanStatus.COMPLETED)
            return scan_id

        # Run multiple concurrent registry operations
        tasks = [register_and_update(i) for i in range(3)]
        scan_ids = await asyncio.gather(*tasks)

        # Verify all scans were registered correctly
        for i, scan_id in enumerate(scan_ids):
            entry = registry.get_scan(scan_id)
            assert entry is not None
            assert entry.directory_path == str(test_directories[i])
            assert entry.output_directory == str(output_directories[i])
            assert entry.status == ScanStatus.COMPLETED

        # Clean up
        for scan_id in scan_ids:
            await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_concurrent_scan_cleanup(
        self, test_directories, output_directories, mock_scan_process
    ):
        """Test cleaning up multiple scans concurrently."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register multiple scans
        scan_ids = []
        for i in range(3):
            scan_id = registry.register_scan(
                directory_path=str(test_directories[i]),
                output_directory=str(output_directories[i]),
                severity_threshold="MEDIUM",
            )
            scan_ids.append(scan_id)

            # Mark as running
            registry.update_scan_status(scan_id, ScanStatus.RUNNING)

            # Create mock results
            mock_scan_process(output_directories[i], 0.1, 1, 1, False)

        # Define a function to clean up scans
        async def cleanup_scan(scan_id):
            return await cleanup_scan_resources(scan_id, remove_output=True)

        # Run multiple concurrent cleanup operations
        tasks = [cleanup_scan(scan_id) for scan_id in scan_ids]
        results = await asyncio.gather(*tasks)

        # Verify all cleanups were successful
        for result in results:
            assert result["success"] is True
            assert result["removed_from_registry"] is True
            assert result["removed_output"] is True

        # Verify all scans were removed from registry
        for scan_id in scan_ids:
            assert registry.get_scan(scan_id) is None
