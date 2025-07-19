# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for ShutdownManager class.

This module tests the graceful shutdown coordination functionality
including signal handling, timeout management, and cleanup sequencing.
"""

import asyncio
import signal
import unittest
import pytest
from unittest.mock import Mock, AsyncMock, patch

from automated_security_helper.core.resource_management.shutdown_manager import (
    ShutdownManager,
)
from automated_security_helper.core.resource_management.task_manager import TaskManager
from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
)
from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
)
from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
)


@pytest.fixture
def mock_task_manager():
    """Create a mock TaskManager."""
    manager = Mock(spec=TaskManager)
    manager.cancel_all_tasks = AsyncMock(return_value=["task1", "task2"])
    return manager


@pytest.fixture
def mock_state_manager():
    """Create a mock StateManager."""
    manager = Mock(spec=StateManager)
    manager.cleanup_completed_scans = AsyncMock(return_value=3)
    manager.validate_state_consistency = AsyncMock(return_value=[])
    manager.get_state_statistics = Mock(return_value={"total_scans": 5})
    return manager


@pytest.fixture
def mock_resource_manager():
    """Create a mock ResourceManager."""
    manager = Mock(spec=ResourceManager)
    manager.shutdown_executor = AsyncMock()
    manager.get_resource_stats = Mock(return_value=Mock(active_scans=0))
    return manager


@pytest.fixture
def mock_event_manager():
    """Create a mock EventSubscriptionManager."""
    manager = Mock(spec=EventSubscriptionManager)
    manager.cleanup_all = Mock(return_value=[])
    return manager


@pytest.fixture
def shutdown_manager(
    mock_task_manager, mock_state_manager, mock_resource_manager, mock_event_manager
):
    """Create a ShutdownManager instance with mocked dependencies."""
    return ShutdownManager(
        task_manager=mock_task_manager,
        state_manager=mock_state_manager,
        resource_manager=mock_resource_manager,
        event_manager=mock_event_manager,
        shutdown_timeout=10.0,
    )


class TestShutdownManagerInitialization:
    """Test ShutdownManager initialization."""

    def test_init_with_all_managers(
        self,
        mock_task_manager,
        mock_state_manager,
        mock_resource_manager,
        mock_event_manager,
    ):
        """Test initialization with all managers."""
        manager = ShutdownManager(
            task_manager=mock_task_manager,
            state_manager=mock_state_manager,
            resource_manager=mock_resource_manager,
            event_manager=mock_event_manager,
            shutdown_timeout=15.0,
        )

        assert manager._task_manager is mock_task_manager
        assert manager._state_manager is mock_state_manager
        assert manager._resource_manager is mock_resource_manager
        assert manager._event_manager is mock_event_manager
        assert manager._shutdown_timeout == 15.0
        assert not manager._shutdown_requested
        assert not manager._shutdown_in_progress
        assert not manager._shutdown_complete

    def test_init_without_event_manager(
        self, mock_task_manager, mock_state_manager, mock_resource_manager
    ):
        """Test initialization without event manager."""
        manager = ShutdownManager(
            task_manager=mock_task_manager,
            state_manager=mock_state_manager,
            resource_manager=mock_resource_manager,
            shutdown_timeout=20.0,
        )

        assert manager._event_manager is None
        assert manager._shutdown_timeout == 20.0

    def test_init_default_timeout(
        self, mock_task_manager, mock_state_manager, mock_resource_manager
    ):
        """Test initialization with default timeout."""
        manager = ShutdownManager(
            task_manager=mock_task_manager,
            state_manager=mock_state_manager,
            resource_manager=mock_resource_manager,
        )

        assert manager._shutdown_timeout == 30.0


class TestShutdownCallbacks:
    """Test shutdown callback functionality."""

    def test_add_shutdown_callback(self, shutdown_manager):
        """Test adding shutdown callbacks."""
        callback1 = Mock()
        callback2 = AsyncMock()

        shutdown_manager.add_shutdown_callback(callback1)
        shutdown_manager.add_shutdown_callback(callback2)

        assert len(shutdown_manager._shutdown_callbacks) == 2
        assert callback1 in shutdown_manager._shutdown_callbacks
        assert callback2 in shutdown_manager._shutdown_callbacks

    @pytest.mark.asyncio
    async def test_execute_shutdown_callbacks_sync(self, shutdown_manager):
        """Test executing synchronous shutdown callbacks."""
        callback1 = Mock()
        callback2 = Mock()

        shutdown_manager.add_shutdown_callback(callback1)
        shutdown_manager.add_shutdown_callback(callback2)

        await shutdown_manager._execute_shutdown_callbacks()

        callback1.assert_called_once()
        callback2.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_shutdown_callbacks_async(self, shutdown_manager):
        """Test executing asynchronous shutdown callbacks."""
        callback1 = AsyncMock()
        callback2 = AsyncMock()

        shutdown_manager.add_shutdown_callback(callback1)
        shutdown_manager.add_shutdown_callback(callback2)

        await shutdown_manager._execute_shutdown_callbacks()

        callback1.assert_called_once()
        callback2.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_shutdown_callbacks_with_exception(self, shutdown_manager):
        """Test executing callbacks when one raises an exception."""
        callback1 = Mock(side_effect=Exception("Test error"))
        callback2 = Mock()

        shutdown_manager.add_shutdown_callback(callback1)
        shutdown_manager.add_shutdown_callback(callback2)

        # Should not raise exception, should continue with other callbacks
        await shutdown_manager._execute_shutdown_callbacks()

        callback1.assert_called_once()
        callback2.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_shutdown_callbacks_timeout(self, shutdown_manager):
        """Test callback execution with timeout."""

        async def slow_callback():
            await asyncio.sleep(10)  # Longer than callback timeout

        callback1 = slow_callback
        callback2 = Mock()

        shutdown_manager.add_shutdown_callback(callback1)
        shutdown_manager.add_shutdown_callback(callback2)

        # Should handle timeout gracefully
        await shutdown_manager._execute_shutdown_callbacks()

        callback2.assert_called_once()


class TestSignalHandling:
    """Test signal handling functionality."""

    @patch("signal.signal")
    def test_setup_signal_handlers_unix(self, mock_signal):
        """Test setting up signal handlers on Unix systems."""
        with patch("sys.platform", "linux"):
            shutdown_manager = ShutdownManager(
                task_manager=Mock(), state_manager=Mock(), resource_manager=Mock()
            )

            mock_signal.return_value = Mock()  # Original handler

            shutdown_manager.setup_signal_handlers()

            # Should install handlers for SIGINT and SIGTERM
            assert mock_signal.call_count == 2
            calls = mock_signal.call_args_list
            signals_handled = [call[0][0] for call in calls]
            assert signal.SIGINT in signals_handled
            assert signal.SIGTERM in signals_handled

    @patch("signal.signal")
    def test_setup_signal_handlers_windows(self, mock_signal):
        """Test setting up signal handlers on Windows."""
        with patch("sys.platform", "win32"):
            shutdown_manager = ShutdownManager(
                task_manager=Mock(), state_manager=Mock(), resource_manager=Mock()
            )

            mock_signal.return_value = Mock()  # Original handler

            shutdown_manager.setup_signal_handlers()

            # Should only install handler for SIGINT on Windows
            assert mock_signal.call_count == 1
            mock_signal.assert_called_with(signal.SIGINT, unittest.mock.ANY)

    @patch("signal.signal")
    def test_restore_signal_handlers(self, mock_signal):
        """Test restoring original signal handlers."""
        shutdown_manager = ShutdownManager(
            task_manager=Mock(), state_manager=Mock(), resource_manager=Mock()
        )

        original_handler = Mock()
        mock_signal.return_value = original_handler

        # Setup handlers first
        shutdown_manager.setup_signal_handlers()

        # Reset mock to track restore calls
        mock_signal.reset_mock()

        # Restore handlers
        shutdown_manager.restore_signal_handlers()

        # Should restore original handlers
        assert mock_signal.call_count >= 1
        # Check that original handler was restored
        restore_calls = [
            call
            for call in mock_signal.call_args_list
            if call[0][1] == original_handler
        ]
        assert len(restore_calls) >= 1

    @patch("signal.signal")
    def test_signal_handler_exception(self, mock_signal):
        """Test signal handler setup with exception."""
        shutdown_manager = ShutdownManager(
            task_manager=Mock(), state_manager=Mock(), resource_manager=Mock()
        )

        mock_signal.side_effect = OSError("Cannot install handler")

        # Should not raise exception
        shutdown_manager.setup_signal_handlers()

        # Should have attempted to install handlers
        assert mock_signal.call_count >= 1


class TestGracefulShutdown:
    """Test graceful shutdown functionality."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_success(self, shutdown_manager):
        """Test successful graceful shutdown."""
        await shutdown_manager.graceful_shutdown()

        # Verify all managers were called
        shutdown_manager._task_manager.cancel_all_tasks.assert_called_once()
        shutdown_manager._state_manager.cleanup_completed_scans.assert_called_once()
        shutdown_manager._state_manager.validate_state_consistency.assert_called_once()
        shutdown_manager._resource_manager.shutdown_executor.assert_called_once()

        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_graceful_shutdown_without_event_manager(
        self, mock_task_manager, mock_state_manager, mock_resource_manager
    ):
        """Test graceful shutdown without event manager."""
        manager = ShutdownManager(
            task_manager=mock_task_manager,
            state_manager=mock_state_manager,
            resource_manager=mock_resource_manager,
        )

        await manager.graceful_shutdown()

        # Should complete successfully without event manager
        assert manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_graceful_shutdown_already_in_progress(self, shutdown_manager):
        """Test graceful shutdown when already in progress."""
        shutdown_manager._shutdown_in_progress = True

        await shutdown_manager.graceful_shutdown()

        # Should not call managers again
        shutdown_manager._task_manager.cancel_all_tasks.assert_not_called()

    @pytest.mark.asyncio
    async def test_graceful_shutdown_already_complete(self, shutdown_manager):
        """Test graceful shutdown when already complete."""
        shutdown_manager._shutdown_complete = True

        await shutdown_manager.graceful_shutdown()

        # Should not call managers
        shutdown_manager._task_manager.cancel_all_tasks.assert_not_called()

    @pytest.mark.asyncio
    async def test_graceful_shutdown_task_failure(self, shutdown_manager):
        """Test graceful shutdown when task cancellation fails."""
        shutdown_manager._task_manager.cancel_all_tasks.side_effect = Exception(
            "Task error"
        )

        # Should continue with other shutdown phases
        await shutdown_manager.graceful_shutdown()

        # Other managers should still be called
        shutdown_manager._resource_manager.shutdown_executor.assert_called_once()
        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_graceful_shutdown_resource_failure(self, shutdown_manager):
        """Test graceful shutdown when resource shutdown fails."""
        shutdown_manager._resource_manager.shutdown_executor.side_effect = Exception(
            "Resource error"
        )

        # Should continue and complete
        await shutdown_manager.graceful_shutdown()

        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_graceful_shutdown_timeout(self, shutdown_manager):
        """Test graceful shutdown with timeout."""

        # Make task cancellation take too long
        async def slow_cancel_tasks(timeout):
            await asyncio.sleep(timeout + 1)
            return []

        shutdown_manager._task_manager.cancel_all_tasks.side_effect = slow_cancel_tasks

        # Should handle timeout gracefully
        await shutdown_manager.graceful_shutdown()

        assert shutdown_manager._shutdown_complete


class TestShutdownPhases:
    """Test individual shutdown phases."""

    @pytest.mark.asyncio
    async def test_shutdown_tasks(self, shutdown_manager):
        """Test task shutdown phase."""
        await shutdown_manager._shutdown_tasks()

        shutdown_manager._task_manager.cancel_all_tasks.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_events_without_manager(
        self, mock_task_manager, mock_state_manager, mock_resource_manager
    ):
        """Test event shutdown phase without event manager."""
        manager = ShutdownManager(
            task_manager=mock_task_manager,
            state_manager=mock_state_manager,
            resource_manager=mock_resource_manager,
        )

        # Should not raise exception
        await manager._shutdown_events()

    @pytest.mark.asyncio
    async def test_shutdown_state(self, shutdown_manager):
        """Test state shutdown phase."""
        await shutdown_manager._shutdown_state()

        shutdown_manager._state_manager.cleanup_completed_scans.assert_called_once()
        shutdown_manager._state_manager.validate_state_consistency.assert_called_once()
        shutdown_manager._state_manager.get_state_statistics.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_resources(self, shutdown_manager):
        """Test resource shutdown phase."""
        await shutdown_manager._shutdown_resources()

        shutdown_manager._resource_manager.shutdown_executor.assert_called_once()

    @pytest.mark.asyncio
    async def test_final_cleanup(self, shutdown_manager):
        """Test final cleanup phase."""
        with patch.object(shutdown_manager, "restore_signal_handlers") as mock_restore:
            await shutdown_manager._final_cleanup()

            mock_restore.assert_called_once()


class TestShutdownStatus:
    """Test shutdown status methods."""

    def test_is_shutdown_requested(self, shutdown_manager):
        """Test shutdown requested status."""
        assert not shutdown_manager.is_shutdown_requested()

        shutdown_manager._shutdown_requested = True
        assert shutdown_manager.is_shutdown_requested()

    def test_is_shutdown_in_progress(self, shutdown_manager):
        """Test shutdown in progress status."""
        assert not shutdown_manager.is_shutdown_in_progress()

        shutdown_manager._shutdown_in_progress = True
        assert shutdown_manager.is_shutdown_in_progress()

    def test_is_shutdown_complete(self, shutdown_manager):
        """Test shutdown complete status."""
        assert not shutdown_manager.is_shutdown_complete()

        shutdown_manager._shutdown_complete = True
        assert shutdown_manager.is_shutdown_complete()

    def test_get_shutdown_status(self, shutdown_manager):
        """Test getting shutdown status information."""
        status = shutdown_manager.get_shutdown_status()

        assert isinstance(status, dict)
        assert "shutdown_requested" in status
        assert "shutdown_in_progress" in status
        assert "shutdown_complete" in status
        assert "shutdown_timeout" in status
        assert "callback_count" in status
        assert "signal_handlers_installed" in status

        assert status["shutdown_timeout"] == 10.0
        assert status["callback_count"] == 0

    @pytest.mark.asyncio
    async def test_request_shutdown(self, shutdown_manager):
        """Test programmatic shutdown request."""
        assert not shutdown_manager._shutdown_requested

        await shutdown_manager.request_shutdown()

        assert shutdown_manager._shutdown_requested
        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_request_shutdown_already_requested(self, shutdown_manager):
        """Test programmatic shutdown request when already requested."""
        shutdown_manager._shutdown_requested = True

        await shutdown_manager.request_shutdown()

        # Should not call managers since already requested
        shutdown_manager._task_manager.cancel_all_tasks.assert_not_called()


class TestForceShutdown:
    """Test force shutdown functionality."""

    @pytest.mark.asyncio
    async def test_force_shutdown(self, shutdown_manager):
        """Test force shutdown."""
        await shutdown_manager.force_shutdown()

        # Should cancel tasks and shutdown resources
        shutdown_manager._task_manager.cancel_all_tasks.assert_called_once()
        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_force_shutdown_with_exceptions(self, shutdown_manager):
        """Test force shutdown when operations fail."""
        shutdown_manager._task_manager.cancel_all_tasks.side_effect = Exception(
            "Task error"
        )
        shutdown_manager._resource_manager.shutdown_executor.side_effect = Exception(
            "Resource error"
        )

        # Should handle exceptions and complete
        await shutdown_manager.force_shutdown()

        assert shutdown_manager._shutdown_complete

    @pytest.mark.asyncio
    async def test_force_shutdown_timeout(self, shutdown_manager):
        """Test force shutdown with custom timeout."""
        await shutdown_manager.force_shutdown(timeout=2.0)

        # Should complete regardless of timeout
        assert shutdown_manager._shutdown_complete


class TestSignalHandlerIntegration:
    """Test signal handler integration."""

    @pytest.mark.asyncio
    async def test_handle_signal_shutdown(self, shutdown_manager):
        """Test handling shutdown initiated by signal."""
        with patch("sys.exit") as mock_exit:
            await shutdown_manager._handle_signal_shutdown("SIGINT")

            # Should complete graceful shutdown
            assert shutdown_manager._shutdown_complete
            # Should call sys.exit(0)
            mock_exit.assert_called_once_with(0)

    @pytest.mark.asyncio
    async def test_handle_signal_shutdown_with_exception(self, shutdown_manager):
        """Test handling signal shutdown when graceful shutdown fails."""
        shutdown_manager._task_manager.cancel_all_tasks.side_effect = Exception(
            "Test error"
        )

        with patch("sys.exit") as mock_exit:
            # Should handle exception gracefully
            await shutdown_manager._handle_signal_shutdown("SIGTERM")

            # Should still complete
            assert shutdown_manager._shutdown_complete
            # Should call sys.exit(0)
            mock_exit.assert_called_once_with(0)
