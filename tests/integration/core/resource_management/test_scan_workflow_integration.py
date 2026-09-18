#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for the scan workflow with file-based tracking.

This module tests the complete scan workflow, including file-based tracking,
scan registry, scan management, and concurrent scan execution.

These tests were excluded from collection by a keyword filter from the v3
release until 2026-09, so nothing forced them to agree with the code. Three
things they assumed were never true:

* ``get_scan_results`` was called as ``get_scan_results(scan_id, output_dir)``.
  It has taken only ``output_dir`` since it was introduced, so it does not know
  the registry's scan ID and mints its own ``scan-<timestamp>``.
* The aggregated results file was written as ``{"findings": [...],
  "scanners_completed": [...], "completion_time": ...}``. ``AshAggregatedResults``
  has none of those fields and is configured ``extra="ignore"``, so every key was
  dropped on load and the tests asserted against an all-default model.
  The real shape is ``scanner_results`` keyed by scanner name, plus
  ``metadata.summary_stats``.
* ``check_scan_progress`` raised ``MCPResourceError``. It returns an error
  response dict; only the registry method underneath it raises.

The fixture below writes the schema ASH actually produces, so these tests fail
if that schema moves. ``severity_counts`` deliberately mirrors
``extract_findings_summary``'s lowercase buckets rather than inventing its own.
"""

import json
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from unittest import mock

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
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

# The buckets extract_findings_summary counts into. Anything else is dropped,
# which is why these are lowercase here.
SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info", "suppressed")

# Keys the tests used to assert on. get_scan_results has never returned them;
# asserting their absence keeps this file from drifting back.
LEGACY_RESULT_KEYS = (
    "findings",
    "findings_count",
    "severity_counts",
    "scanners_completed",
)


def severity_counts(findings):
    """Bucket findings by severity the way extract_findings_summary does."""
    counts = {bucket: 0 for bucket in SEVERITY_BUCKETS}
    for finding in findings:
        bucket = finding.get("severity", "").lower()
        if bucket in counts:
            counts[bucket] += 1
    return counts


def write_aggregated_results(output_dir, scanner_results, generated_at=None):
    """Write an ash_aggregated_results.json that AshAggregatedResults accepts.

    Only scanners whose status is PASSED or FAILED count as completed, so a
    scanner recorded as ERROR or MISSING here stays out of ``total_scanners``.
    """
    totals = {bucket: 0 for bucket in SEVERITY_BUCKETS}
    actionable = 0
    for info in scanner_results.values():
        actionable += info.get("finding_count", 0)
        for bucket, count in info.get("severity_counts", {}).items():
            if bucket in totals:
                totals[bucket] += count

    document = {
        "scanner_results": scanner_results,
        "metadata": {
            "summary_stats": {"actionable": actionable, **totals},
            "generated_at": generated_at or datetime.now().isoformat(),
        },
    }
    with open(output_dir / "ash_aggregated_results.json", "w") as handle:
        json.dump(document, handle)
    return document


def write_scanner_result(output_dir, scanner_name, target_type, findings):
    """Write scanners/<scanner>/<target>/ASH.ScanResults.json with findings."""
    target_dir = output_dir / "scanners" / scanner_name / target_type
    target_dir.mkdir(parents=True, exist_ok=True)
    with open(target_dir / "ASH.ScanResults.json", "w") as handle:
        json.dump({"findings": findings}, handle)
    return findings


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
        """Write per-scanner result files, then the aggregated results file.

        Writes the aggregated file last, the way a real scan does, so a caller
        polling check_scan_progress sees the incomplete branch first.
        """
        scanners_dir = output_dir / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        scanner_results = {}

        for i in range(scanner_count):
            scanner_name = f"scanner{i + 1}"

            # Each scanner has a different number of findings.
            findings = [
                {
                    "id": f"{scanner_name}-{j + 1}",
                    "severity": severity_levels[j % len(severity_levels)],
                    "scanner": scanner_name,
                    "message": f"Test finding {j + 1}",
                    "file": "app.py",
                    "line": j + 1,
                }
                for j in range(i + 1)
            ]

            write_scanner_result(output_dir, scanner_name, "source", findings)
            scanner_results[scanner_name] = {
                "status": "FAILED" if findings else "PASSED",
                "finding_count": len(findings),
                "severity_counts": severity_counts(findings),
            }

            # Simulate scan duration
            time.sleep(duration)

        if with_errors:
            # A scanner that ran and errored. It is not a completed scanner, so
            # it stays out of total_scanners while remaining visible in
            # scanner_results.
            scanner_results["error_scanner"] = {
                "status": "ERROR",
                "finding_count": 1,
                "severity_counts": severity_counts([{"severity": "HIGH"}]),
            }

        write_aggregated_results(output_dir, scanner_results)

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
        assert registry.get_scan(scan_id).status == MCScanStatus.PENDING

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Verify the scan is running
        assert registry.get_scan(scan_id).status == MCScanStatus.RUNNING

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
        assert progress["severity_counts"]["critical"] == 3

        # Get scan results
        results = get_scan_results(output_directory)
        assert results["status"] == "completed"
        assert results["is_complete"] is True
        assert results["total_scanners"] == 3
        assert results["actionable_findings"] == 6
        assert set(results["raw_results"]["scanner_results"]) == {
            "scanner1",
            "scanner2",
            "scanner3",
        }

        # get_scan_results reads a directory, not the registry, so it mints its
        # own ID rather than reporting the one the scan was registered under.
        assert results["scan_id"].startswith("scan-")
        assert results["scan_id"] != scan_id
        assert [key for key in LEGACY_RESULT_KEYS if key in results] == []

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
        assert entry.status == MCScanStatus.CANCELLED

        # Clean up the scan
        await cleanup_scan_resources(scan_id, remove_output=True)

    @pytest.mark.asyncio
    async def test_error_handling_scan_not_found(self):
        """Test error handling when scan is not found.

        None of these three raise. The registry method underneath raises, and
        each of these catches it and returns a create_error_response dict.
        """
        progress_result = await check_scan_progress("non_existent_scan")
        assert progress_result["success"] is False
        assert "not found" in progress_result["error"]
        assert progress_result["error_category"] == "scan_not_found"
        assert progress_result["operation"] == "check_scan_progress"

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
        """Test error handling when the output directory disappears mid-scan.

        register_scan validates the output directory up front, so the directory
        has to exist to register and is removed afterwards. Registering against a
        path that never existed only ever tested register_scan's own validation.
        """
        registry = get_scan_registry()

        output_dir = tmp_path / "vanishing_output"
        output_dir.mkdir()
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_dir),
            severity_threshold="MEDIUM",
        )

        output_dir.rmdir()

        result = await check_scan_progress(scan_id)
        assert result["success"] is False
        assert "Directory not found" in result["error"]
        assert result["error_category"] == "file_not_found"
        assert result["context"]["scan_id"] == scan_id

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

        # get_scan_results does raise, unlike the scan_management wrappers.
        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(output_directory)

        assert "Scan results not available" in str(excinfo.value)
        assert excinfo.value.context["error_category"] == "scan_incomplete"
        assert "Wait for the scan to complete" in excinfo.value.context["suggestions"]

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
            registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Scanner counts per scan, so the expectations below are not magic numbers.
        expected_scanners = [2, 3, 1]

        # Start background tasks to create mock scan results
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Run the mock scan processes in separate threads
            futures = [
                executor.submit(mock_scan_process, output_dirs[0], 0.5, 2, False),
                executor.submit(mock_scan_process, output_dirs[1], 0.7, 3, False),
                executor.submit(mock_scan_process, output_dirs[2], 0.3, 1, True),
            ]

            # Check active scans while they're running. The registry is a module
            # level singleton shared with every other test in this process, so
            # these assert on this test's own scan IDs rather than on a global
            # count that any sibling test can move.
            active_ids = {scan["scan_id"] for scan in await list_active_scans()}
            assert set(scan_ids) <= active_ids

            # Wait for all mock scans to complete
            for future in futures:
                future.result()

        # Check scan statistics
        stats = await get_scan_statistics()
        assert stats["total_scans"] >= 3

        # Check each scan's progress
        for i, scan_id in enumerate(scan_ids):
            progress = await check_scan_progress(scan_id)
            assert progress["scan_id"] == scan_id
            assert progress["status"] == "completed"
            assert progress["is_complete"] is True

            # Get scan results
            results = get_scan_results(output_dirs[i])
            assert results["status"] == "completed"
            assert results["is_complete"] is True
            # The third scan carries an ERROR scanner, which is reported but is
            # not a completed scanner.
            assert results["total_scanners"] == expected_scanners[i]
            if i == 2:
                assert "error_scanner" in results["raw_results"]["scanner_results"]

            # Clean up the scan
            await cleanup_scan_resources(scan_id, remove_output=True)

        # Verify all scans were cleaned up
        active_ids = {scan["scan_id"] for scan in await list_active_scans()}
        assert active_ids.isdisjoint(scan_ids)

    @pytest.mark.asyncio
    async def test_scan_with_errors(
        self, test_directory, output_directory, mock_scan_process
    ):
        """Test a scan where one scanner errored rather than reporting findings."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Create mock scan results with errors
        mock_scan_process(output_directory, 0.2, 2, True)

        # Check scan progress
        progress = await check_scan_progress(scan_id)
        assert progress["scan_id"] == scan_id
        assert progress["status"] == "completed"
        assert progress["is_complete"] is True

        # Get scan results
        results = get_scan_results(output_directory)
        assert results["status"] == "completed"
        assert results["is_complete"] is True

        # The errored scanner is visible, and is excluded from the completed
        # count: two scanners ran to a verdict, three are reported.
        scanner_results = results["raw_results"]["scanner_results"]
        assert scanner_results["error_scanner"]["status"] == "ERROR"
        assert len(scanner_results) == 3
        assert results["total_scanners"] == 2

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
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Create scanners directory
        scanners_dir = output_directory / "scanners"
        scanners_dir.mkdir(exist_ok=True)

        # Check initial progress
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert progress_info["scanners_completed"] == []

        # Create results for first scanner
        scanner1_findings = write_scanner_result(
            output_directory,
            "scanner1",
            "source",
            [
                {"id": "1", "severity": "CRITICAL", "scanner": "scanner1"},
                {"id": "2", "severity": "HIGH", "scanner": "scanner1"},
            ],
        )

        # Check progress after first scanner
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert "scanner1" in progress_info["scanners_completed"]
        assert progress_info["findings_count"] == 2

        # Create results for second scanner
        scanner2_findings = write_scanner_result(
            output_directory,
            "scanner2",
            "source",
            [{"id": "3", "severity": "MEDIUM", "scanner": "scanner2"}],
        )

        # Check progress after second scanner
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "in_progress"
        assert progress_info["is_complete"] is False
        assert set(progress_info["scanners_completed"]) == {"scanner1", "scanner2"}
        assert progress_info["findings_count"] == 3

        # Create aggregated results file. Once it exists, scanners_completed
        # comes from scanner_results rather than from the per-scanner tree.
        write_aggregated_results(
            output_directory,
            {
                "scanner1": {
                    "status": "FAILED",
                    "finding_count": len(scanner1_findings),
                    "severity_counts": severity_counts(scanner1_findings),
                },
                "scanner2": {
                    "status": "FAILED",
                    "finding_count": len(scanner2_findings),
                    "severity_counts": severity_counts(scanner2_findings),
                },
            },
        )

        # Check progress after completion
        progress_info = get_scan_progress_info(output_directory)
        assert progress_info["status"] == "completed"
        assert progress_info["is_complete"] is True
        assert set(progress_info["scanners_completed"]) == {"scanner1", "scanner2"}
        # findings_count on the completed branch counts SARIF results, and this
        # document carries no SARIF. The per-scanner counts are in
        # findings_summary, which is read verbatim from metadata.summary_stats.
        assert progress_info["findings_count"] == 0
        assert progress_info["findings_summary"]["actionable"] == 3
        assert progress_info["findings_summary"]["critical"] == 1

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_scan_progress_detection_with_partial_results(
        self, test_directory, output_directory
    ):
        """Test detection of scan progress with partial results."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # One scanner, two target types.
        write_scanner_result(
            output_directory,
            "scanner1",
            "source",
            [
                {
                    "id": "1",
                    "severity": "CRITICAL",
                    "scanner": "scanner1",
                    "file": "app.py",
                },
                {
                    "id": "2",
                    "severity": "HIGH",
                    "scanner": "scanner1",
                    "file": "app.py",
                },
            ],
        )
        write_scanner_result(
            output_directory,
            "scanner1",
            "converted",
            [
                {
                    "id": "3",
                    "severity": "MEDIUM",
                    "scanner": "scanner1",
                    "file": "app.py",
                }
            ],
        )

        # Check progress with multiple target types
        progress = await check_scan_progress(scan_id)
        assert progress["scan_id"] == scan_id
        assert progress["status"] == "running"
        assert progress["is_complete"] is False
        assert "scanners" in progress
        assert "scanner1" in progress["scanners"]
        assert "source" in progress["scanners"]["scanner1"]
        assert "converted" in progress["scanners"]["scanner1"]
        assert progress["total_findings"] == 3

        # With no aggregated file the counts come from extract_findings_summary
        # over the per-scanner findings, rather than being copied verbatim out of
        # the aggregated document. This is the only place that path is asserted.
        assert progress["severity_counts"]["critical"] == 1
        assert progress["severity_counts"]["high"] == 1
        assert progress["severity_counts"]["medium"] == 1
        assert progress["severity_counts"]["low"] == 0

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_scan_with_malformed_result_files(
        self, test_directory, output_directory
    ):
        """Test handling of malformed result files."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Create scanner with valid results
        write_scanner_result(
            output_directory,
            "scanner1",
            "source",
            [{"id": "1", "severity": "CRITICAL", "scanner": "scanner1"}],
        )

        # Create scanner with malformed results
        scanner2_source = output_directory / "scanners" / "scanner2" / "source"
        scanner2_source.mkdir(parents=True)
        with open(scanner2_source / "ASH.ScanResults.json", "w") as handle:
            handle.write("{invalid json")

        # Check progress with malformed file
        progress = await check_scan_progress(scan_id)
        assert progress["scan_id"] == scan_id
        assert progress["status"] == "running"
        assert progress["is_complete"] is False
        assert "scanners" in progress
        assert "scanner1" in progress["scanners"]

        # The malformed file should be handled gracefully
        assert (
            progress["total_findings"] == 1
        )  # Only the valid findings should be counted

        # The scanner whose file could not be read is still reported, with zero
        # findings, rather than dropping out of the progress view. Without this,
        # the test cannot tell a tolerated parse failure from one that propagates
        # and gets swallowed a layer up, since both leave total_findings at 1.
        assert "scanner2" in progress["scanners"]
        assert progress["scanners"]["scanner2"]["source"]["finding_count"] == 0

        # Clean up the scan
        await cleanup_scan_resources(scan_id)

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Live defect, not a stale assertion. extract_findings_summary "
            "defaults a missing severity to 'UNKNOWN' and then drops it, because "
            "its `if severity in summary` guard only admits the six lowercase "
            "buckets, so the 'UNKNOWN' default is dead code. ScanProgress drops "
            "it a second time: both __init__ and update_totals build the same "
            "six-key dict and aggregate under `if severity in "
            "self.severity_counts`. A fix has to touch both layers. Either way "
            "the finding counts toward total_findings and toward nothing in "
            "severity_counts, so the two disagree and a finding with no severity "
            "is invisible in the breakdown. Latent since the v3 release, and "
            "pinned from the SARIF side in "
            "tests/unit/core/resource_management/test_scan_tracking_results.py as "
            "'current behavior, not endorsed as correct'. Fixing it changes the "
            "severity_counts key set, so it needs to land with that unit test."
        ),
    )
    @pytest.mark.asyncio
    async def test_scan_with_missing_required_fields(
        self, test_directory, output_directory
    ):
        """A finding with no severity should be counted as UNKNOWN."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        write_scanner_result(
            output_directory,
            "scanner1",
            "source",
            [
                {"id": "1", "scanner": "scanner1"},  # Missing severity
                {"id": "2", "severity": "HIGH", "scanner": "scanner1"},  # Valid
            ],
        )

        # The registry is a process-wide singleton, so this has to be cleaned up
        # on the failing path too or the leaked entry perturbs sibling tests.
        try:
            # Check progress with invalid findings
            progress = await check_scan_progress(scan_id)
            assert progress["scan_id"] == scan_id
            assert progress["status"] == "running"
            assert progress["is_complete"] is False

            # The invalid finding should be handled gracefully
            assert progress["total_findings"] == 2  # Both findings should be counted
            assert (
                progress["severity_counts"]["UNKNOWN"] == 1
            )  # The missing severity should be counted as UNKNOWN
        finally:
            await cleanup_scan_resources(scan_id)

    @pytest.mark.asyncio
    async def test_scan_with_permission_errors(self, test_directory, output_directory):
        """Test handling of permission errors during scan cleanup."""
        # Get the scan registry
        registry = get_scan_registry()

        # Register a new scan
        scan_id = registry.register_scan(
            directory_path=str(test_directory),
            output_directory=str(output_directory),
            severity_threshold="MEDIUM",
        )

        # Mark the scan as running
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # Create mock scan results
        write_scanner_result(
            output_directory,
            "scanner1",
            "source",
            [{"id": "1", "severity": "CRITICAL", "scanner": "scanner1"}],
        )

        # Mock permission error during cleanup
        with mock.patch(
            "shutil.rmtree", side_effect=PermissionError("Permission denied")
        ):
            cleanup_result = await cleanup_scan_resources(scan_id, remove_output=True)

            # The cleanup should still succeed for the registry part
            assert cleanup_result["success"] is True
            assert cleanup_result["removed_from_registry"] is True
            assert cleanup_result["removed_output"] is False
            assert "output_dir_error" in cleanup_result
            assert "Permission denied" in cleanup_result["output_dir_error"]
