# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for StateManager class."""

import asyncio
import pytest
from datetime import datetime, timedelta

from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
    ScanProgressData,
)
from automated_security_helper.core.resource_management.exceptions import (
    StateManagementError,
)


class TestStateManager:
    """Test cases for StateManager class."""

    @pytest.fixture
    def state_manager(self):
        """Create a StateManager instance for testing."""
        return StateManager()

    @pytest.mark.asyncio
    async def test_create_scan_progress_success(self, state_manager):
        """Test successful scan progress creation."""
        success = await state_manager.create_scan_progress(
            scan_id="scan_123", directory_path="/test/path", task_id="task_456"
        )

        assert success

        # Verify scan was created
        progress = await state_manager.get_scan_progress("scan_123")
        assert progress is not None
        assert progress["scan_id"] == "scan_123"
        assert progress["directory_path"] == "/test/path"
        assert progress["task_id"] == "task_456"
        assert progress["status"] == "initializing"

    @pytest.mark.asyncio
    async def test_create_scan_progress_duplicate(self, state_manager):
        """Test creating duplicate scan progress."""
        # Create first scan
        success1 = await state_manager.create_scan_progress(
            scan_id="scan_123", directory_path="/test/path"
        )
        assert success1

        # Try to create duplicate
        success2 = await state_manager.create_scan_progress(
            scan_id="scan_123", directory_path="/test/path2"
        )
        assert not success2

    @pytest.mark.asyncio
    async def test_update_scan_progress_success(self, state_manager):
        """Test successful scan progress update."""
        # Create scan first
        await state_manager.create_scan_progress("scan_123", "/test/path")

        # Update progress
        updates = {"status": "running", "current_phase": "scanning", "progress": 0.5}
        success = await state_manager.update_scan_progress("scan_123", updates)
        assert success

        # Verify updates
        progress = await state_manager.get_scan_progress("scan_123")
        assert progress["status"] == "running"
        assert progress["current_phase"] == "scanning"
        assert progress["progress"] == 0.5

    @pytest.mark.asyncio
    async def test_update_scan_progress_nonexistent(self, state_manager):
        """Test updating non-existent scan progress."""
        success = await state_manager.update_scan_progress(
            "nonexistent_scan", {"status": "running"}
        )
        assert not success

    @pytest.mark.asyncio
    async def test_update_scan_progress_completion_sets_end_time(self, state_manager):
        """Test that completion status updates set end_time."""
        # Create scan
        await state_manager.create_scan_progress("scan_123", "/test/path")

        # Update to completed status
        await state_manager.update_scan_progress("scan_123", {"status": "completed"})

        # Verify end_time was set
        progress = await state_manager.get_scan_progress("scan_123")
        assert progress["end_time"] is not None

    @pytest.mark.asyncio
    async def test_register_directory_scan_success(self, state_manager):
        """Test successful directory scan registration."""
        success = await state_manager.register_directory_scan("/test/path", "scan_123")
        assert success

        # Verify registration
        scan_id = await state_manager.get_directory_scan("/test/path")
        assert scan_id == "scan_123"

    @pytest.mark.asyncio
    async def test_register_directory_scan_conflict_active(self, state_manager):
        """Test directory registration conflict with active scan."""
        # Create active scan
        await state_manager.create_scan_progress("scan_123", "/test/path")
        await state_manager.register_directory_scan("/test/path", "scan_123")

        # Try to register another scan for same directory
        success = await state_manager.register_directory_scan("/test/path", "scan_456")
        assert not success

    @pytest.mark.asyncio
    async def test_register_directory_scan_replaces_completed(self, state_manager):
        """Test directory registration replaces completed scan."""
        # Create completed scan
        await state_manager.create_scan_progress("scan_123", "/test/path")
        await state_manager.update_scan_progress("scan_123", {"status": "completed"})
        await state_manager.register_directory_scan("/test/path", "scan_123")

        # Register new scan for same directory
        success = await state_manager.register_directory_scan("/test/path", "scan_456")
        assert success

        # Verify new registration
        scan_id = await state_manager.get_directory_scan("/test/path")
        assert scan_id == "scan_456"

    @pytest.mark.asyncio
    async def test_unregister_directory_scan_success(self, state_manager):
        """Test successful directory scan unregistration."""
        # Register directory
        await state_manager.register_directory_scan("/test/path", "scan_123")

        # Unregister
        success = await state_manager.unregister_directory_scan(
            "/test/path", "scan_123"
        )
        assert success

        # Verify unregistration
        scan_id = await state_manager.get_directory_scan("/test/path")
        assert scan_id is None

    @pytest.mark.asyncio
    async def test_unregister_directory_scan_mismatch(self, state_manager):
        """Test directory unregistration with scan ID mismatch."""
        # Register directory
        await state_manager.register_directory_scan("/test/path", "scan_123")

        # Try to unregister with wrong scan ID
        success = await state_manager.unregister_directory_scan(
            "/test/path", "scan_456"
        )
        assert not success

        # Verify registration still exists
        scan_id = await state_manager.get_directory_scan("/test/path")
        assert scan_id == "scan_123"

    @pytest.mark.asyncio
    async def test_get_all_scan_progress(self, state_manager):
        """Test getting all scan progress data."""
        # Create multiple scans
        await state_manager.create_scan_progress("scan_1", "/path/1")
        await state_manager.create_scan_progress("scan_2", "/path/2")
        await state_manager.create_scan_progress("scan_3", "/path/3")

        all_progress = await state_manager.get_all_scan_progress()
        assert len(all_progress) == 3
        assert "scan_1" in all_progress
        assert "scan_2" in all_progress
        assert "scan_3" in all_progress

    @pytest.mark.asyncio
    async def test_remove_scan_progress(self, state_manager):
        """Test removing scan progress."""
        # Create scan
        await state_manager.create_scan_progress("scan_123", "/test/path")

        # Remove scan
        success = await state_manager.remove_scan_progress("scan_123")
        assert success

        # Verify removal
        progress = await state_manager.get_scan_progress("scan_123")
        assert progress is None

    @pytest.mark.asyncio
    async def test_remove_scan_progress_nonexistent(self, state_manager):
        """Test removing non-existent scan progress."""
        success = await state_manager.remove_scan_progress("nonexistent_scan")
        assert not success

    @pytest.mark.asyncio
    async def test_get_all_directory_scans(self, state_manager):
        """Test getting all directory scan registrations."""
        # Register multiple directories
        await state_manager.register_directory_scan("/path/1", "scan_1")
        await state_manager.register_directory_scan("/path/2", "scan_2")
        await state_manager.register_directory_scan("/path/3", "scan_3")

        all_directories = await state_manager.get_all_directory_scans()
        assert len(all_directories) == 3
        assert all_directories["/path/1"] == "scan_1"
        assert all_directories["/path/2"] == "scan_2"
        assert all_directories["/path/3"] == "scan_3"

    @pytest.mark.asyncio
    async def test_cleanup_completed_scans(self, state_manager):
        """Test cleanup of old completed scans."""
        # Create old completed scan
        await state_manager.create_scan_progress("old_scan", "/old/path")

        # Manually set old timestamps
        scan_data = state_manager._scan_progress_store["old_scan"]
        old_time = datetime.now() - timedelta(hours=25)  # 25 hours ago
        scan_data.start_time = old_time
        scan_data.end_time = old_time
        scan_data.status = "completed"

        # Create recent scan
        await state_manager.create_scan_progress("recent_scan", "/recent/path")
        await state_manager.update_scan_progress("recent_scan", {"status": "completed"})

        # Register directories
        await state_manager.register_directory_scan("/old/path", "old_scan")
        await state_manager.register_directory_scan("/recent/path", "recent_scan")

        # Cleanup with 24 hour threshold
        cleanup_count = await state_manager.cleanup_completed_scans(max_age_hours=24)
        assert cleanup_count == 1

        # Verify old scan was removed
        old_progress = await state_manager.get_scan_progress("old_scan")
        assert old_progress is None

        # Verify recent scan remains
        recent_progress = await state_manager.get_scan_progress("recent_scan")
        assert recent_progress is not None

        # Verify directory registrations were cleaned up
        old_dir_scan = await state_manager.get_directory_scan("/old/path")
        assert old_dir_scan is None

    @pytest.mark.asyncio
    async def test_get_state_statistics(self, state_manager):
        """Test getting state statistics."""
        # Create scans with different statuses
        await state_manager.create_scan_progress("scan_1", "/path/1")
        await state_manager.create_scan_progress("scan_2", "/path/2")
        await state_manager.update_scan_progress("scan_2", {"status": "running"})
        await state_manager.create_scan_progress("scan_3", "/path/3")
        await state_manager.update_scan_progress("scan_3", {"status": "completed"})

        # Register directories
        await state_manager.register_directory_scan("/path/1", "scan_1")
        await state_manager.register_directory_scan("/path/2", "scan_2")

        stats = state_manager.get_state_statistics()

        assert stats["total_scans"] == 3
        assert stats["active_directory_registrations"] == 2
        assert stats["scan_status_counts"]["initializing"] == 1
        assert stats["scan_status_counts"]["running"] == 1
        assert stats["scan_status_counts"]["completed"] == 1

    @pytest.mark.asyncio
    async def test_validate_state_consistency(self, state_manager):
        """Test state consistency validation."""
        # Create consistent state
        await state_manager.create_scan_progress("scan_1", "/path/1")
        await state_manager.register_directory_scan("/path/1", "scan_1")

        # Create inconsistent state - directory registration without scan data
        state_manager._active_scans_by_directory["/path/2"] = "nonexistent_scan"

        # Create inconsistent state - active scan without directory registration
        await state_manager.create_scan_progress("scan_3", "/path/3")
        await state_manager.update_scan_progress("scan_3", {"status": "running"})

        issues = await state_manager.validate_state_consistency()

        assert len(issues) == 2
        assert any("nonexistent_scan" in issue for issue in issues)
        assert any("scan_3" in issue for issue in issues)

    @pytest.mark.asyncio
    async def test_concurrent_access(self, state_manager):
        """Test concurrent access to state manager."""

        async def create_and_update_scan(scan_id, directory_path):
            await state_manager.create_scan_progress(scan_id, directory_path)
            await state_manager.register_directory_scan(directory_path, scan_id)
            await state_manager.update_scan_progress(scan_id, {"status": "running"})
            await state_manager.update_scan_progress(scan_id, {"progress": 0.5})
            await state_manager.update_scan_progress(scan_id, {"status": "completed"})

        # Run multiple concurrent operations
        tasks = []
        for i in range(5):
            task = create_and_update_scan(f"scan_{i}", f"/path/{i}")
            tasks.append(task)

        await asyncio.gather(*tasks)

        # Verify all scans were created and updated correctly
        all_progress = await state_manager.get_all_scan_progress()
        assert len(all_progress) == 5

        for i in range(5):
            progress = await state_manager.get_scan_progress(f"scan_{i}")
            assert progress is not None
            assert progress["status"] == "completed"
            assert progress["progress"] == 0.5

    @pytest.mark.asyncio
    async def test_scan_progress_data_to_dict(self):
        """Test ScanProgressData to_dict conversion."""
        start_time = datetime.now()
        end_time = datetime.now()

        scan_data = ScanProgressData(
            scan_id="test_scan",
            status="completed",
            directory_path="/test/path",
            start_time=start_time,
            end_time=end_time,
            current_phase="finished",
            progress=1.0,
            error=None,
            results={"findings": 5},
            task_id="task_123",
        )

        data_dict = scan_data.to_dict()

        assert data_dict["scan_id"] == "test_scan"
        assert data_dict["status"] == "completed"
        assert data_dict["directory_path"] == "/test/path"
        assert data_dict["start_time"] == start_time.isoformat()
        assert data_dict["end_time"] == end_time.isoformat()
        assert data_dict["current_phase"] == "finished"
        assert data_dict["progress"] == 1.0
        assert data_dict["error"] is None
        assert data_dict["results"] == {"findings": 5}
        assert data_dict["task_id"] == "task_123"

    @pytest.mark.asyncio
    async def test_concurrent_state_access_with_locks(self, state_manager):
        """Test concurrent access to shared state with proper locking."""
        # Create initial scan
        await state_manager.create_scan_progress("concurrent_scan", "/test/path")

        async def update_progress(update_id):
            """Update progress with unique values."""
            for i in range(10):
                await state_manager.update_scan_progress(
                    "concurrent_scan", {"progress": float(f"{update_id}.{i}")}
                )
                await asyncio.sleep(0.001)  # Small delay to encourage race conditions

        # Run multiple concurrent updates
        tasks = [update_progress(i) for i in range(5)]
        await asyncio.gather(*tasks)

        # Verify final state is consistent
        progress = await state_manager.get_scan_progress("concurrent_scan")
        assert progress is not None
        assert isinstance(progress["progress"], float)

    @pytest.mark.asyncio
    async def test_concurrent_directory_registration(self, state_manager):
        """Test concurrent directory registration operations."""
        directory_path = "/concurrent/test"

        async def register_scan(scan_id):
            """Try to register a scan for the same directory."""
            await state_manager.create_scan_progress(scan_id, directory_path)
            success = await state_manager.register_directory_scan(
                directory_path, scan_id
            )
            return success, scan_id

        # Try to register multiple scans for the same directory concurrently
        tasks = [register_scan(f"scan_{i}") for i in range(5)]
        results = await asyncio.gather(*tasks)

        # Only one should succeed
        successful_registrations = [result for result in results if result[0]]
        assert len(successful_registrations) == 1

        # Verify the directory is registered to the successful scan
        registered_scan_id = await state_manager.get_directory_scan(directory_path)
        assert registered_scan_id == successful_registrations[0][1]

    @pytest.mark.asyncio
    async def test_state_consistency_under_concurrent_operations(self, state_manager):
        """Test state consistency under high concurrent load."""

        async def scan_lifecycle(scan_id):
            """Complete scan lifecycle with state operations."""
            directory_path = f"/test/{scan_id}"

            # Create scan
            await state_manager.create_scan_progress(scan_id, directory_path)

            # Register directory
            await state_manager.register_directory_scan(directory_path, scan_id)

            # Update progress multiple times
            for progress in [0.2, 0.5, 0.8, 1.0]:
                await state_manager.update_scan_progress(
                    scan_id, {"progress": progress}
                )
                await asyncio.sleep(0.001)

            # Complete scan
            await state_manager.update_scan_progress(scan_id, {"status": "completed"})

            # Unregister directory
            await state_manager.unregister_directory_scan(directory_path, scan_id)

        # Run multiple scan lifecycles concurrently
        tasks = [scan_lifecycle(f"scan_{i}") for i in range(10)]
        await asyncio.gather(*tasks)

        # Verify final state consistency
        all_progress = await state_manager.get_all_scan_progress()
        assert len(all_progress) == 10

        # All scans should be completed
        for scan_id, progress in all_progress.items():
            assert progress["status"] == "completed"
            assert progress["progress"] == 1.0

        # No directory registrations should remain
        all_directories = await state_manager.get_all_directory_scans()
        assert len(all_directories) == 0

    @pytest.mark.asyncio
    async def test_error_handling_for_state_access_failures(self, state_manager):
        """Test error handling when state access operations fail."""
        # Test update with invalid field
        await state_manager.create_scan_progress("test_scan", "/test/path")

        # This should not raise an exception, just log a warning
        success = await state_manager.update_scan_progress(
            "test_scan", {"invalid_field": "value"}
        )
        assert success  # Should still succeed for valid fields

    @pytest.mark.asyncio
    async def test_cleanup_and_recovery_mechanisms(self, state_manager):
        """Test cleanup and recovery mechanisms."""
        # Create scans with various states
        await state_manager.create_scan_progress("active_scan", "/active/path")
        await state_manager.update_scan_progress("active_scan", {"status": "running"})

        await state_manager.create_scan_progress("completed_scan", "/completed/path")
        await state_manager.update_scan_progress(
            "completed_scan", {"status": "completed"}
        )

        await state_manager.create_scan_progress("failed_scan", "/failed/path")
        await state_manager.update_scan_progress("failed_scan", {"status": "failed"})

        # Register directories
        await state_manager.register_directory_scan("/active/path", "active_scan")
        await state_manager.register_directory_scan("/completed/path", "completed_scan")
        await state_manager.register_directory_scan("/failed/path", "failed_scan")

        # Manually create inconsistent state for testing recovery
        state_manager._active_scans_by_directory["/orphaned/path"] = "nonexistent_scan"

        # Test state validation and recovery
        issues = await state_manager.validate_state_consistency()
        assert len(issues) > 0

        # Verify active scan remains
        active_progress = await state_manager.get_scan_progress("active_scan")
        assert active_progress is not None

    @pytest.mark.asyncio
    async def test_state_manager_exception_handling(self, state_manager):
        """Test exception handling in state manager operations."""
        # Test creating scan with None values (should handle gracefully)
        with pytest.raises(StateManagementError):
            # Simulate an error by corrupting internal state
            original_store = state_manager._scan_progress_store
            state_manager._scan_progress_store = None
            try:
                await state_manager.create_scan_progress("test_scan", "/test/path")
            finally:
                state_manager._scan_progress_store = original_store

    @pytest.mark.asyncio
    async def test_concurrent_cleanup_operations(self, state_manager):
        """Test concurrent cleanup operations."""
        # Create multiple old scans
        for i in range(10):
            await state_manager.create_scan_progress(f"old_scan_{i}", f"/old/path/{i}")
            scan_data = state_manager._scan_progress_store[f"old_scan_{i}"]
            old_time = datetime.now() - timedelta(hours=25)
            scan_data.start_time = old_time
            scan_data.end_time = old_time
            scan_data.status = "completed"

        # Run concurrent cleanup operations
        cleanup_tasks = [
            state_manager.cleanup_completed_scans(max_age_hours=24) for _ in range(3)
        ]

        cleanup_results = await asyncio.gather(*cleanup_tasks)

        # Total cleanup count should be consistent
        total_cleaned = sum(cleanup_results)
        assert total_cleaned <= 10  # Should not double-count

        # Verify scans were actually cleaned up
        remaining_scans = await state_manager.get_all_scan_progress()
        assert len(remaining_scans) == 0

    @pytest.mark.asyncio
    async def test_get_health_status_comprehensive(self, state_manager):
        """Test comprehensive health status reporting."""
        # Test healthy state
        health = await state_manager.get_health_status()
        assert health["status"] == "healthy"
        assert health["is_healthy"] is True
        assert health["total_scans"] == 0

        # Create some scans with proper directory registration
        await state_manager.create_scan_progress("scan_1", "/path/1")
        await state_manager.register_directory_scan("/path/1", "scan_1")
        await state_manager.update_scan_progress("scan_1", {"status": "running"})

        await state_manager.create_scan_progress("scan_2", "/path/2")
        await state_manager.update_scan_progress("scan_2", {"status": "completed"})

        health = await state_manager.get_health_status()
        assert health["status"] == "healthy"
        assert health["total_scans"] == 2
        assert health["scan_status_counts"]["running"] == 1
        assert health["scan_status_counts"]["completed"] == 1

        # Create inconsistent state to trigger critical status
        state_manager._active_scans_by_directory["/orphaned"] = "nonexistent"

        health = await state_manager.get_health_status()
        assert health["status"] == "critical"
        assert health["is_healthy"] is False
        assert len(health["consistency_details"]) > 0

    @pytest.mark.asyncio
    async def test_get_resource_usage_comprehensive(self, state_manager):
        """Test comprehensive resource usage reporting."""
        # Test empty state
        usage = await state_manager.get_resource_usage()
        assert usage["scan_data_count"] == 0
        assert usage["directory_registrations"] == 0
        assert usage["memory_usage_mb"] == 0

        # Create scans with different durations
        await state_manager.create_scan_progress("active_scan", "/active/path")
        await state_manager.update_scan_progress("active_scan", {"status": "running"})

        await state_manager.create_scan_progress("completed_scan", "/completed/path")
        # Update to completed status first
        await state_manager.update_scan_progress(
            "completed_scan", {"status": "completed"}
        )
        # Then manually set completion time for duration calculation
        scan_data = state_manager._scan_progress_store["completed_scan"]
        scan_data.end_time = scan_data.start_time + timedelta(seconds=30)

        await state_manager.register_directory_scan("/active/path", "active_scan")

        usage = await state_manager.get_resource_usage()
        assert usage["scan_data_count"] == 2
        assert usage["directory_registrations"] == 1
        assert usage["memory_usage_mb"] > 0
        assert usage["active_scan_durations"]["count"] == 1
        assert usage["completed_scan_durations"]["count"] == 1
        assert usage["completed_scan_durations"]["average_seconds"] == 30.0

    @pytest.mark.asyncio
    async def test_race_condition_prevention(self, state_manager):
        """Test prevention of race conditions in critical sections."""

        async def rapid_updates(scan_id):
            """Perform rapid updates to test race conditions."""
            for i in range(50):
                await state_manager.update_scan_progress(
                    scan_id, {"progress": i / 50.0}
                )

        # Create scan
        await state_manager.create_scan_progress("race_test", "/race/path")

        # Run rapid concurrent updates
        tasks = [rapid_updates("race_test") for _ in range(5)]
        await asyncio.gather(*tasks)

        # Verify final state is consistent
        progress = await state_manager.get_scan_progress("race_test")
        assert progress is not None
        assert 0.0 <= progress["progress"] <= 1.0

    @pytest.mark.asyncio
    async def test_memory_cleanup_effectiveness(self, state_manager):
        """Test effectiveness of memory cleanup operations."""
        # Create many scans to test memory management
        scan_count = 50

        for i in range(scan_count):
            await state_manager.create_scan_progress(
                f"memory_test_{i}", f"/memory/path/{i}"
            )
            await state_manager.update_scan_progress(
                f"memory_test_{i}", {"status": "completed"}
            )

            # Set old timestamps for half of them
            if i < scan_count // 2:
                scan_data = state_manager._scan_progress_store[f"memory_test_{i}"]
                old_time = datetime.now() - timedelta(hours=25)
                scan_data.start_time = old_time
                scan_data.end_time = old_time

        # Get initial resource usage
        initial_usage = await state_manager.get_resource_usage()
        assert initial_usage["scan_data_count"] == scan_count

        # Perform cleanup
        cleanup_count = await state_manager.cleanup_completed_scans(max_age_hours=24)
        assert cleanup_count == scan_count // 2

        # Verify memory usage decreased
        final_usage = await state_manager.get_resource_usage()
        assert final_usage["scan_data_count"] == scan_count // 2
        assert final_usage["memory_usage_mb"] < initial_usage["memory_usage_mb"]

    @pytest.mark.asyncio
    async def test_edge_cases_and_boundary_conditions(self, state_manager):
        """Test edge cases and boundary conditions."""
        # Test with empty strings
        success = await state_manager.create_scan_progress("", "")
        assert success  # Should handle empty strings gracefully

        # Test with very long strings
        long_string = "x" * 1000
        success = await state_manager.create_scan_progress(long_string, long_string)
        assert success

        # Test with special characters
        special_scan_id = "scan-with_special.chars@123"
        special_path = "/path/with spaces/and-special_chars.txt"
        success = await state_manager.create_scan_progress(
            special_scan_id, special_path
        )
        assert success

        # Verify retrieval works with special characters
        progress = await state_manager.get_scan_progress(special_scan_id)
        assert progress is not None
        assert progress["directory_path"] == special_path

    @pytest.mark.asyncio
    async def test_state_recovery_after_corruption(self, state_manager):
        """Test state recovery mechanisms after data corruption."""
        # Create normal state
        await state_manager.create_scan_progress("normal_scan", "/normal/path")
        await state_manager.register_directory_scan("/normal/path", "normal_scan")

        # Simulate data corruption
        state_manager._active_scans_by_directory["/corrupted/path"] = "missing_scan"

        # Create scan without directory registration (inconsistent state)
        await state_manager.create_scan_progress("orphaned_scan", "/orphaned/path")
        await state_manager.update_scan_progress("orphaned_scan", {"status": "running"})

        # Validate and identify issues
        issues = await state_manager.validate_state_consistency()
        assert len(issues) >= 2

        # Test that normal operations still work despite corruption
        success = await state_manager.update_scan_progress(
            "normal_scan", {"status": "completed"}
        )
        assert success

        # Test cleanup can handle corrupted state
        cleanup_count = await state_manager.cleanup_completed_scans(max_age_hours=0)
        assert cleanup_count >= 0  # Should not crash
