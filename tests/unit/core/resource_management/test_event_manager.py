# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for EventSubscriptionManager class."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
    EventSubscription,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)


class TestEventSubscriptionManager:
    """Test cases for EventSubscriptionManager class."""

    @pytest.fixture
    def event_manager(self):
        """Create an EventSubscriptionManager instance for testing."""
        return EventSubscriptionManager()

    @pytest.mark.asyncio
    async def test_register_subscription_success(self, event_manager):
        """Test successful subscription registration."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        success = await event_manager.register_subscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
            scan_id="scan_456",
            metadata={"key": "value"},
        )

        assert success

        # Verify subscription was registered
        info = event_manager.get_subscription_info("sub_123")
        assert info is not None
        assert info["subscription_id"] == "sub_123"
        assert info["event_type"] == "scan_progress"
        assert info["scan_id"] == "scan_456"
        assert info["has_cleanup_func"] is True
        assert info["metadata"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_register_subscription_duplicate(self, event_manager):
        """Test registering duplicate subscription."""
        handler = MagicMock()

        # Register first subscription
        success1 = await event_manager.register_subscription(
            subscription_id="sub_123", event_type="scan_progress", handler=handler
        )
        assert success1

        # Try to register duplicate
        success2 = await event_manager.register_subscription(
            subscription_id="sub_123", event_type="scan_progress", handler=handler
        )
        assert not success2

    @pytest.mark.asyncio
    async def test_register_subscription_minimal(self, event_manager):
        """Test registering subscription with minimal parameters."""
        handler = MagicMock()

        success = await event_manager.register_subscription(
            subscription_id="sub_123", event_type="scan_progress", handler=handler
        )

        assert success

        info = event_manager.get_subscription_info("sub_123")
        assert info["scan_id"] is None
        assert info["has_cleanup_func"] is False
        assert info["metadata"] == {}

    @pytest.mark.asyncio
    async def test_unregister_subscription_success(self, event_manager):
        """Test successful subscription unregistration."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        # Register subscription
        await event_manager.register_subscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
        )

        # Unregister subscription
        success = await event_manager.unregister_subscription("sub_123")
        assert success

        # Verify cleanup function was called
        cleanup_func.assert_called_once()

        # Verify subscription was removed
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

    @pytest.mark.asyncio
    async def test_unregister_subscription_with_async_cleanup(self, event_manager):
        """Test unregistration with async cleanup function."""
        handler = MagicMock()
        cleanup_func = AsyncMock()

        # Register subscription
        await event_manager.register_subscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
        )

        # Unregister subscription
        success = await event_manager.unregister_subscription("sub_123")
        assert success

        # Verify async cleanup function was called
        cleanup_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_unregister_subscription_cleanup_failure(self, event_manager):
        """Test unregistration when cleanup function fails."""
        handler = MagicMock()
        cleanup_func = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Register subscription
        await event_manager.register_subscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
        )

        # Unregister subscription (should handle cleanup failure)
        success = await event_manager.unregister_subscription("sub_123")
        assert not success  # Should return False due to cleanup failure

        # Verify subscription was still removed despite cleanup failure
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

        # Verify error was recorded
        errors = event_manager.get_cleanup_errors()
        assert len(errors) == 1
        assert "Cleanup failed" in errors[0]["error"]

    @pytest.mark.asyncio
    async def test_unregister_nonexistent_subscription(self, event_manager):
        """Test unregistering non-existent subscription."""
        success = await event_manager.unregister_subscription("nonexistent")
        assert not success

    @pytest.mark.asyncio
    async def test_cleanup_subscriptions_by_scan(self, event_manager):
        """Test cleaning up subscriptions by scan ID."""
        handler = MagicMock()
        cleanup_func1 = MagicMock()
        cleanup_func2 = MagicMock()

        # Register subscriptions for same scan
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func1,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            cleanup_func=cleanup_func2,
            scan_id="scan_123",
        )

        # Register subscription for different scan
        await event_manager.register_subscription(
            subscription_id="sub_3",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_456",
        )

        # Clean up subscriptions for scan_123
        results = await event_manager.cleanup_subscriptions_by_scan("scan_123")

        assert results["scan_id"] == "scan_123"
        assert results["total_subscriptions"] == 2
        assert results["successful_cleanups"] == 2
        assert results["failed_cleanups"] == 0

        # Verify cleanup functions were called
        cleanup_func1.assert_called_once()
        cleanup_func2.assert_called_once()

        # Verify subscriptions were removed
        assert event_manager.get_subscription_info("sub_1") is None
        assert event_manager.get_subscription_info("sub_2") is None

        # Verify other scan's subscription remains
        assert event_manager.get_subscription_info("sub_3") is not None

    @pytest.mark.asyncio
    async def test_cleanup_subscriptions_by_type(self, event_manager):
        """Test cleaning up subscriptions by event type."""
        handler = MagicMock()
        cleanup_func1 = MagicMock()
        cleanup_func2 = MagicMock()

        # Register subscriptions for same event type
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func1,
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func2,
        )

        # Register subscription for different event type
        await event_manager.register_subscription(
            subscription_id="sub_3", event_type="scan_complete", handler=handler
        )

        # Clean up subscriptions for scan_progress
        results = await event_manager.cleanup_subscriptions_by_type("scan_progress")

        assert results["event_type"] == "scan_progress"
        assert results["total_subscriptions"] == 2
        assert results["successful_cleanups"] == 2
        assert results["failed_cleanups"] == 0

        # Verify cleanup functions were called
        cleanup_func1.assert_called_once()
        cleanup_func2.assert_called_once()

        # Verify subscriptions were removed
        assert event_manager.get_subscription_info("sub_1") is None
        assert event_manager.get_subscription_info("sub_2") is None

        # Verify other event type's subscription remains
        assert event_manager.get_subscription_info("sub_3") is not None

    @pytest.mark.asyncio
    async def test_cleanup_all_subscriptions(self, event_manager):
        """Test cleaning up all subscriptions."""
        handler = MagicMock()
        cleanup_func1 = MagicMock()
        cleanup_func2 = MagicMock()

        # Register multiple subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func1,
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            cleanup_func=cleanup_func2,
        )
        await event_manager.register_subscription(
            subscription_id="sub_3", event_type="scan_error", handler=handler
        )

        # Clean up all subscriptions
        results = await event_manager.cleanup_all_subscriptions()

        assert results["total_subscriptions"] == 3
        assert results["successful_cleanups"] == 3
        assert results["failed_cleanups"] == 0

        # Verify cleanup functions were called
        cleanup_func1.assert_called_once()
        cleanup_func2.assert_called_once()

        # Verify all subscriptions were removed
        assert len(event_manager.get_all_subscriptions()) == 0

    @pytest.mark.asyncio
    async def test_get_subscriptions_by_scan(self, event_manager):
        """Test getting subscriptions by scan ID."""
        handler = MagicMock()

        # Register subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_3",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_456",
        )

        # Get subscriptions for scan_123
        subscriptions = event_manager.get_subscriptions_by_scan("scan_123")

        assert len(subscriptions) == 2
        subscription_ids = [sub["subscription_id"] for sub in subscriptions]
        assert "sub_1" in subscription_ids
        assert "sub_2" in subscription_ids

    @pytest.mark.asyncio
    async def test_get_subscriptions_by_type(self, event_manager):
        """Test getting subscriptions by event type."""
        handler = MagicMock()

        # Register subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1", event_type="scan_progress", handler=handler
        )
        await event_manager.register_subscription(
            subscription_id="sub_2", event_type="scan_progress", handler=handler
        )
        await event_manager.register_subscription(
            subscription_id="sub_3", event_type="scan_complete", handler=handler
        )

        # Get subscriptions for scan_progress
        subscriptions = event_manager.get_subscriptions_by_type("scan_progress")

        assert len(subscriptions) == 2
        subscription_ids = [sub["subscription_id"] for sub in subscriptions]
        assert "sub_1" in subscription_ids
        assert "sub_2" in subscription_ids

    @pytest.mark.asyncio
    async def test_get_subscription_statistics(self, event_manager):
        """Test getting subscription statistics."""
        handler = MagicMock()

        # Register subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_3",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_456",
        )

        stats = event_manager.get_subscription_statistics()

        assert stats["total_subscriptions"] == 3
        assert stats["subscriptions_by_scan_count"] == 2
        assert stats["subscriptions_by_type_count"] == 2
        assert "scan_progress" in stats["event_types"]
        assert "scan_complete" in stats["event_types"]
        assert "scan_123" in stats["scan_ids"]
        assert "scan_456" in stats["scan_ids"]

    @pytest.mark.asyncio
    async def test_cleanup_errors_management(self, event_manager):
        """Test cleanup error tracking and management."""
        handler = MagicMock()
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup error"))

        # Register subscription with failing cleanup
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=failing_cleanup,
        )

        # Unregister to trigger cleanup failure
        await event_manager.unregister_subscription("sub_1")

        # Check cleanup errors
        errors = event_manager.get_cleanup_errors()
        assert len(errors) == 1
        assert errors[0]["subscription_id"] == "sub_1"
        assert "Cleanup error" in errors[0]["error"]

        # Test error limit - limit=0 should return empty list
        limited_errors = event_manager.get_cleanup_errors(limit=0)
        assert len(limited_errors) == 0

        # Clear errors
        cleared_count = event_manager.clear_cleanup_errors()
        assert cleared_count == 1
        assert len(event_manager.get_cleanup_errors()) == 0

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, event_manager):
        """Test concurrent subscription operations."""
        handler = MagicMock()

        async def register_subscription(sub_id):
            return await event_manager.register_subscription(
                subscription_id=f"sub_{sub_id}",
                event_type="scan_progress",
                handler=handler,
                scan_id=f"scan_{sub_id}",
            )

        async def unregister_subscription(sub_id):
            return await event_manager.unregister_subscription(f"sub_{sub_id}")

        # Register multiple subscriptions concurrently
        register_tasks = [register_subscription(i) for i in range(5)]
        results = await asyncio.gather(*register_tasks)

        # All registrations should succeed
        assert all(results)
        assert len(event_manager.get_all_subscriptions()) == 5

        # Unregister concurrently
        unregister_tasks = [unregister_subscription(i) for i in range(5)]
        results = await asyncio.gather(*unregister_tasks)

        # All unregistrations should succeed
        assert all(results)
        assert len(event_manager.get_all_subscriptions()) == 0

    def test_event_subscription_dataclass(self):
        """Test EventSubscription dataclass functionality."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        subscription = EventSubscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
            scan_id="scan_456",
            metadata={"key": "value"},
        )

        # Test basic attributes
        assert subscription.subscription_id == "sub_123"
        assert subscription.event_type == "scan_progress"
        assert subscription.handler is handler
        assert subscription.cleanup_func is cleanup_func
        assert subscription.scan_id == "scan_456"
        assert subscription.metadata == {"key": "value"}

        # Test hashability
        subscription_set = {subscription}
        assert len(subscription_set) == 1

        # Test that created_at is set
        assert subscription.created_at is not None

    @pytest.mark.asyncio
    async def test_subscription_context_manager_success(self, event_manager):
        """Test successful use of subscription context manager."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        async with event_manager.subscription_context(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
            scan_id="scan_456",
        ) as subscription_id:
            # Verify subscription was registered
            assert subscription_id == "sub_123"
            info = event_manager.get_subscription_info("sub_123")
            assert info is not None
            assert info["event_type"] == "scan_progress"

        # Verify cleanup was called after context exit
        cleanup_func.assert_called_once()

        # Verify subscription was removed
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

    @pytest.mark.asyncio
    async def test_subscription_context_manager_exception(self, event_manager):
        """Test context manager behavior when exception occurs."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        with pytest.raises(ValueError, match="Test exception"):
            async with event_manager.subscription_context(
                subscription_id="sub_123",
                event_type="scan_progress",
                handler=handler,
                cleanup_func=cleanup_func,
            ) as subscription_id:
                # Verify subscription was registered
                assert subscription_id == "sub_123"
                info = event_manager.get_subscription_info("sub_123")
                assert info is not None

                # Raise exception to test cleanup
                raise ValueError("Test exception")

        # Verify cleanup was still called despite exception
        cleanup_func.assert_called_once()

        # Verify subscription was removed
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

    @pytest.mark.asyncio
    async def test_subscription_context_manager_registration_failure(
        self, event_manager
    ):
        """Test context manager when subscription registration fails."""
        handler = MagicMock()

        # Register subscription first to cause duplicate registration failure
        await event_manager.register_subscription(
            subscription_id="sub_123", event_type="scan_progress", handler=handler
        )

        with pytest.raises(MCPResourceError, match="Failed to register subscription"):
            async with event_manager.subscription_context(
                subscription_id="sub_123", event_type="scan_progress", handler=handler
            ):
                pass  # Should not reach here

    @pytest.mark.asyncio
    async def test_event_subscription_context_manager_class(self, event_manager):
        """Test EventSubscriptionContextManager class."""
        from automated_security_helper.core.resource_management.event_manager import (
            EventSubscriptionContextManager,
        )

        context_manager = EventSubscriptionContextManager(event_manager)
        handler = MagicMock()
        cleanup_func = MagicMock()

        async with context_manager.managed_subscription(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=cleanup_func,
            scan_id="scan_456",
            metadata={"test": "data"},
        ) as subscription_info:
            # Verify subscription info
            assert subscription_info["subscription_id"] == "sub_123"
            assert subscription_info["event_type"] == "scan_progress"
            assert subscription_info["scan_id"] == "scan_456"
            assert subscription_info["registered"] is True
            assert subscription_info["cleanup_attempted"] is False

            # Test control methods
            info = subscription_info["get_info"]()
            assert info is not None
            assert info["subscription_id"] == "sub_123"

        # Verify cleanup was performed
        cleanup_func.assert_called_once()

        # Verify subscription was removed
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

    @pytest.mark.asyncio
    async def test_managed_subscription_with_exception(self, event_manager):
        """Test managed subscription with exception and auto-cleanup."""
        from automated_security_helper.core.resource_management.event_manager import (
            EventSubscriptionContextManager,
        )

        context_manager = EventSubscriptionContextManager(event_manager)
        handler = MagicMock()
        cleanup_func = MagicMock()

        with pytest.raises(RuntimeError, match="Test error"):
            async with context_manager.managed_subscription(
                subscription_id="sub_123",
                event_type="scan_progress",
                handler=handler,
                cleanup_func=cleanup_func,
                auto_cleanup_on_error=True,
            ) as subscription_info:
                assert subscription_info["registered"] is True
                raise RuntimeError("Test error")

        # Verify cleanup was performed due to auto-cleanup
        cleanup_func.assert_called_once()

        # Verify subscription was removed
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

    @pytest.mark.asyncio
    async def test_context_manager_cleanup_failure(self, event_manager):
        """Test context manager behavior when cleanup fails."""
        handler = MagicMock()
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Should not raise exception even if cleanup fails
        async with event_manager.subscription_context(
            subscription_id="sub_123",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=failing_cleanup,
        ) as subscription_id:
            assert subscription_id == "sub_123"

        # Verify cleanup was attempted
        failing_cleanup.assert_called_once()

        # Verify subscription was still removed despite cleanup failure
        info = event_manager.get_subscription_info("sub_123")
        assert info is None

        # Verify error was recorded
        errors = event_manager.get_cleanup_errors()
        assert len(errors) == 1

    @pytest.mark.asyncio
    async def test_health_status_healthy(self, event_manager):
        """Test health status when system is healthy."""
        handler = MagicMock()

        # Register a few subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            scan_id="scan_456",
        )

        health = await event_manager.get_health_status()

        assert health["status"] == "healthy"
        assert health["is_healthy"] is True
        assert health["total_subscriptions"] == 2
        assert health["cleanup_errors"] == 0
        assert "scan_progress" in health["subscriptions_by_type"]
        assert "scan_complete" in health["subscriptions_by_type"]
        assert "scan_123" in health["subscriptions_by_scan"]
        assert "scan_456" in health["subscriptions_by_scan"]

    @pytest.mark.asyncio
    async def test_health_status_warning_with_errors(self, event_manager):
        """Test health status with cleanup errors."""
        handler = MagicMock()
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Register and unregister subscription to create cleanup error
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=failing_cleanup,
        )
        await event_manager.unregister_subscription("sub_1")

        health = await event_manager.get_health_status()

        assert health["status"] == "warning"
        assert health["is_healthy"] is False
        assert health["cleanup_errors"] == 1

    @pytest.mark.asyncio
    async def test_health_status_critical_with_many_errors(self, event_manager):
        """Test health status with many cleanup errors."""
        handler = MagicMock()
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Create many cleanup errors
        for i in range(15):
            await event_manager.register_subscription(
                subscription_id=f"sub_{i}",
                event_type="scan_progress",
                handler=handler,
                cleanup_func=failing_cleanup,
            )
            await event_manager.unregister_subscription(f"sub_{i}")

        health = await event_manager.get_health_status()

        assert health["status"] == "critical"
        assert health["is_healthy"] is False
        assert health["cleanup_errors"] == 15

    @pytest.mark.asyncio
    async def test_health_status_warning_with_many_subscriptions(self, event_manager):
        """Test health status with too many subscriptions."""
        handler = MagicMock()

        # Register many subscriptions (over threshold)
        for i in range(105):
            await event_manager.register_subscription(
                subscription_id=f"sub_{i}", event_type="scan_progress", handler=handler
            )

        health = await event_manager.get_health_status()

        assert health["status"] == "warning"
        assert health["is_healthy"] is False
        assert health["total_subscriptions"] == 105

    @pytest.mark.asyncio
    async def test_resource_usage_calculation(self, event_manager):
        """Test resource usage calculation."""
        handler = MagicMock()

        # Register subscriptions
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_2",
            event_type="scan_complete",
            handler=handler,
            scan_id="scan_456",
        )

        # Create cleanup error
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))
        await event_manager.register_subscription(
            subscription_id="sub_3",
            event_type="scan_error",
            handler=handler,
            cleanup_func=failing_cleanup,
        )
        await event_manager.unregister_subscription("sub_3")

        usage = await event_manager.get_resource_usage()

        assert usage["subscription_count"] == 2
        assert usage["cleanup_errors_stored"] == 1
        assert usage["memory_usage_kb"] > 0
        assert usage["memory_usage_mb"] > 0
        assert usage["subscription_ages"]["count"] == 2
        assert usage["subscription_ages"]["average_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_resource_usage_empty_state(self, event_manager):
        """Test resource usage calculation with no subscriptions."""
        usage = await event_manager.get_resource_usage()

        assert usage["subscription_count"] == 0
        assert usage["cleanup_errors_stored"] == 0
        assert usage["memory_usage_kb"] >= 0
        assert usage["subscription_ages"]["count"] == 0
        assert usage["subscription_ages"]["average_seconds"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_subscriptions_by_scan_no_subscriptions(self, event_manager):
        """Test cleanup by scan ID when no subscriptions exist."""
        results = await event_manager.cleanup_subscriptions_by_scan("nonexistent_scan")

        assert results["scan_id"] == "nonexistent_scan"
        assert results["total_subscriptions"] == 0
        assert results["successful_cleanups"] == 0
        assert results["failed_cleanups"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_subscriptions_by_type_no_subscriptions(self, event_manager):
        """Test cleanup by event type when no subscriptions exist."""
        results = await event_manager.cleanup_subscriptions_by_type("nonexistent_type")

        assert results["event_type"] == "nonexistent_type"
        assert results["total_subscriptions"] == 0
        assert results["successful_cleanups"] == 0
        assert results["failed_cleanups"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_all_subscriptions_empty(self, event_manager):
        """Test cleanup all subscriptions when none exist."""
        results = await event_manager.cleanup_all_subscriptions()

        assert results["total_subscriptions"] == 0
        assert results["successful_cleanups"] == 0
        assert results["failed_cleanups"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_with_partial_failures(self, event_manager):
        """Test cleanup with some failures."""
        handler = MagicMock()
        good_cleanup = MagicMock()
        bad_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Register subscriptions with different cleanup behaviors
        await event_manager.register_subscription(
            subscription_id="sub_good",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=good_cleanup,
            scan_id="scan_123",
        )
        await event_manager.register_subscription(
            subscription_id="sub_bad",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=bad_cleanup,
            scan_id="scan_123",
        )

        results = await event_manager.cleanup_subscriptions_by_scan("scan_123")

        assert results["total_subscriptions"] == 2
        assert results["successful_cleanups"] == 1
        assert results["failed_cleanups"] == 1
        assert len(results["errors"]) == 0  # Errors are tracked separately

        # Verify good cleanup was called
        good_cleanup.assert_called_once()
        bad_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_subscriptions_empty_results(self, event_manager):
        """Test getting subscriptions when none match criteria."""
        handler = MagicMock()

        # Register subscription
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )

        # Query for non-existent scan
        subscriptions = event_manager.get_subscriptions_by_scan("nonexistent_scan")
        assert len(subscriptions) == 0

        # Query for non-existent type
        subscriptions = event_manager.get_subscriptions_by_type("nonexistent_type")
        assert len(subscriptions) == 0

    @pytest.mark.asyncio
    async def test_subscription_indexing_consistency(self, event_manager):
        """Test that subscription indexing remains consistent."""
        handler = MagicMock()

        # Register subscription
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            scan_id="scan_123",
        )

        # Verify indexing
        assert "scan_123" in event_manager._subscriptions_by_scan
        assert "scan_progress" in event_manager._subscriptions_by_type
        assert "sub_1" in event_manager._subscriptions_by_scan["scan_123"]
        assert "sub_1" in event_manager._subscriptions_by_type["scan_progress"]

        # Unregister subscription
        await event_manager.unregister_subscription("sub_1")

        # Verify indices are cleaned up
        assert "scan_123" not in event_manager._subscriptions_by_scan
        assert "scan_progress" not in event_manager._subscriptions_by_type

    @pytest.mark.asyncio
    async def test_subscription_without_scan_id(self, event_manager):
        """Test subscription registration without scan ID."""
        handler = MagicMock()

        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            # No scan_id provided
        )

        # Should not be indexed by scan
        assert len(event_manager._subscriptions_by_scan) == 0

        # Should still be indexed by type
        assert "scan_progress" in event_manager._subscriptions_by_type

        # Should be retrievable
        info = event_manager.get_subscription_info("sub_1")
        assert info is not None
        assert info["scan_id"] is None

    @pytest.mark.asyncio
    async def test_async_cleanup_function_failure(self, event_manager):
        """Test async cleanup function failure handling."""
        handler = MagicMock()
        async_failing_cleanup = AsyncMock(
            side_effect=RuntimeError("Async cleanup failed")
        )

        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=async_failing_cleanup,
        )

        success = await event_manager.unregister_subscription("sub_1")
        assert not success  # Should return False due to cleanup failure

        # Verify async cleanup was called
        async_failing_cleanup.assert_called_once()

        # Verify error was recorded
        errors = event_manager.get_cleanup_errors()
        assert len(errors) == 1
        assert "Async cleanup failed" in errors[0]["error"]

    @pytest.mark.asyncio
    async def test_registration_exception_handling(self, event_manager):
        """Test exception handling during registration."""
        handler = MagicMock()

        # Mock the EventSubscription constructor to raise an exception
        with patch(
            "automated_security_helper.core.resource_management.event_manager.EventSubscription"
        ) as mock_subscription:
            mock_subscription.side_effect = RuntimeError("Subscription creation failed")

            with pytest.raises(
                MCPResourceError, match="Failed to register event subscription"
            ):
                await event_manager.register_subscription(
                    subscription_id="sub_1", event_type="scan_progress", handler=handler
                )

    @pytest.mark.asyncio
    async def test_memory_leak_prevention_mechanisms(self, event_manager):
        """Test memory leak prevention mechanisms."""
        handler = MagicMock()

        # Register many subscriptions
        subscription_ids = []
        for i in range(50):
            sub_id = f"sub_{i}"
            subscription_ids.append(sub_id)
            await event_manager.register_subscription(
                subscription_id=sub_id,
                event_type=f"event_type_{i % 5}",  # 5 different event types
                handler=handler,
                scan_id=f"scan_{i % 10}",  # 10 different scans
            )

        # Verify all subscriptions are tracked
        assert len(event_manager.get_all_subscriptions()) == 50

        # Clean up by scan (should remove 5 subscriptions per scan)
        for scan_num in range(10):
            results = await event_manager.cleanup_subscriptions_by_scan(
                f"scan_{scan_num}"
            )
            assert results["successful_cleanups"] == 5

        # Verify all subscriptions were cleaned up
        assert len(event_manager.get_all_subscriptions()) == 0
        assert len(event_manager._subscriptions_by_scan) == 0
        assert len(event_manager._subscriptions_by_type) == 0

    @pytest.mark.asyncio
    async def test_context_manager_exception_handling_comprehensive(
        self, event_manager
    ):
        """Test comprehensive exception handling in context managers."""
        handler = MagicMock()
        cleanup_func = MagicMock()

        # Test exception during context execution
        with pytest.raises(ValueError):
            async with event_manager.subscription_context(
                subscription_id="sub_1",
                event_type="scan_progress",
                handler=handler,
                cleanup_func=cleanup_func,
            ):
                # Verify subscription exists during context
                info = event_manager.get_subscription_info("sub_1")
                assert info is not None
                raise ValueError("Test exception")

        # Verify cleanup was performed despite exception
        cleanup_func.assert_called_once()
        assert event_manager.get_subscription_info("sub_1") is None

    @pytest.mark.asyncio
    async def test_context_manager_cleanup_exception_handling(self, event_manager):
        """Test context manager handling of cleanup exceptions."""
        handler = MagicMock()
        failing_cleanup = MagicMock(side_effect=RuntimeError("Cleanup failed"))

        # Context manager should not raise exception even if cleanup fails
        async with event_manager.subscription_context(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            cleanup_func=failing_cleanup,
        ):
            pass

        # Verify cleanup was attempted
        failing_cleanup.assert_called_once()

        # Verify subscription was removed despite cleanup failure
        assert event_manager.get_subscription_info("sub_1") is None

    @pytest.mark.asyncio
    async def test_managed_subscription_no_auto_cleanup(self, event_manager):
        """Test managed subscription without auto-cleanup on error."""
        from automated_security_helper.core.resource_management.event_manager import (
            EventSubscriptionContextManager,
        )

        context_manager = EventSubscriptionContextManager(event_manager)
        handler = MagicMock()
        cleanup_func = MagicMock()

        with pytest.raises(RuntimeError):
            async with context_manager.managed_subscription(
                subscription_id="sub_1",
                event_type="scan_progress",
                handler=handler,
                cleanup_func=cleanup_func,
                auto_cleanup_on_error=False,
            ) as subscription_info:
                assert subscription_info["registered"] is True
                raise RuntimeError("Test error")

        # Cleanup should still be performed in finally block
        cleanup_func.assert_called_once()
        assert event_manager.get_subscription_info("sub_1") is None

    @pytest.mark.asyncio
    async def test_subscription_statistics_edge_cases(self, event_manager):
        """Test subscription statistics with edge cases."""
        # Test with no subscriptions
        stats = event_manager.get_subscription_statistics()
        assert stats["total_subscriptions"] == 0
        assert stats["subscriptions_by_scan_count"] == 0
        assert stats["subscriptions_by_type_count"] == 0
        assert len(stats["event_types"]) == 0
        assert len(stats["scan_ids"]) == 0

        # Test with subscriptions without scan_id
        handler = MagicMock()
        await event_manager.register_subscription(
            subscription_id="sub_1",
            event_type="scan_progress",
            handler=handler,
            # No scan_id
        )

        stats = event_manager.get_subscription_statistics()
        assert stats["total_subscriptions"] == 1
        assert stats["subscriptions_by_scan_count"] == 0  # No scan associations
        assert stats["subscriptions_by_type_count"] == 1
        assert "scan_progress" in stats["event_types"]
        assert len(stats["scan_ids"]) == 0

    @pytest.mark.asyncio
    async def test_health_status_edge_cases(self, event_manager):
        """Test health status edge cases."""
        # Test with no subscriptions
        health = await event_manager.get_health_status()
        assert health["status"] == "healthy"
        assert health["total_subscriptions"] == 0
        assert health["details"]["oldest_subscription"] is None
        assert health["details"]["newest_subscription"] is None

        # Test with exactly threshold number of subscriptions
        handler = MagicMock()
        for i in range(100):  # Exactly at threshold
            await event_manager.register_subscription(
                subscription_id=f"sub_{i}", event_type="scan_progress", handler=handler
            )

        health = await event_manager.get_health_status()
        assert health["status"] == "healthy"  # Should still be healthy at threshold
        assert health["total_subscriptions"] == 100

    def test_event_subscription_dataclass_defaults(self):
        """Test EventSubscription dataclass with default values."""
        handler = MagicMock()

        subscription = EventSubscription(
            subscription_id="sub_123", event_type="scan_progress", handler=handler
        )

        # Test default values
        assert subscription.cleanup_func is None
        assert subscription.scan_id is None
        assert subscription.metadata == {}
        assert subscription.created_at is not None

        # Test that different instances have different hashes
        subscription2 = EventSubscription(
            subscription_id="sub_456", event_type="scan_progress", handler=handler
        )

        assert hash(subscription) != hash(subscription2)
