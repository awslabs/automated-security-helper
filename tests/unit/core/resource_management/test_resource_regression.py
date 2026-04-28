"""Regression tests for resource_manager and task_manager bug fixes (batch 2).

Covers bugs: #68, #69, #74
"""

import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bug #68 -- resource_manager deprecated asyncio.get_event_loop()
# ---------------------------------------------------------------------------
class TestBug68DeprecatedGetEventLoop:
    """ResourceManager.shutdown_executor must use get_running_loop()."""

    def test_shutdown_uses_get_running_loop(self):
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        source = inspect.getsource(ResourceManager.shutdown_executor)
        assert "get_running_loop" in source, (
            "shutdown_executor should use asyncio.get_running_loop(), "
            "not the deprecated asyncio.get_event_loop()"
        )
        assert "get_event_loop" not in source, (
            "shutdown_executor still references deprecated get_event_loop()"
        )


# ---------------------------------------------------------------------------
# Bug #69 -- resource_manager get_executor false exhaustion
# ---------------------------------------------------------------------------
class TestBug69FalseExhaustion:
    """get_executor should not raise ResourceExhaustionError for monitoring callers."""

    @pytest.mark.asyncio
    async def test_get_executor_without_exhaustion_for_read(self):
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        rm = ResourceManager(max_workers=2, max_concurrent_scans=1)
        # Simulate one active operation
        rm._active_operations = 1

        # get_executor should still work -- it just returns the pool,
        # it should NOT check operation slots
        executor = await rm.get_executor()
        assert executor is not None

        # Clean up
        executor.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_acquire_slot_still_enforces_limit(self):
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        rm = ResourceManager(max_workers=2, max_concurrent_scans=1)
        got = await rm.acquire_operation_slot()
        assert got is True

        got2 = await rm.acquire_operation_slot()
        assert got2 is False

        # Clean up
        await rm.release_operation_slot()


# ---------------------------------------------------------------------------
# Bug #74 -- task_manager iterates _active_tasks without lock
# ---------------------------------------------------------------------------
class TestBug74UnsafeIteration:
    """get_tasks_by_scan_id and get_all_tasks_info must copy under lock."""

    def test_get_tasks_by_scan_id_copies_dict(self):
        from automated_security_helper.core.resource_management.task_manager import (
            TaskManager,
        )

        source = inspect.getsource(TaskManager.get_tasks_by_scan_id)
        # The fix should copy the dict before iterating, or use list()
        # to snapshot the items. We check for any copying pattern.
        assert "list(" in source or ".copy()" in source or "dict(" in source, (
            "get_tasks_by_scan_id should copy _active_tasks before iterating"
        )

    def test_get_all_tasks_info_copies_dict(self):
        from automated_security_helper.core.resource_management.task_manager import (
            TaskManager,
        )

        source = inspect.getsource(TaskManager.get_all_tasks_info)
        assert "list(" in source or ".copy()" in source or "dict(" in source, (
            "get_all_tasks_info should copy _active_tasks before iterating"
        )
