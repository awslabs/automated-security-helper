"""Tests for multiprocessing cleanup utilities."""

import multiprocessing
from unittest.mock import Mock, patch

from automated_security_helper.utils.multiprocessing_cleanup import (
    MultiprocessingCleanupManager,
    register_multiprocessing_queue,
    cleanup_multiprocessing_queue,
    _cleanup_manager,
)


class TestMultiprocessingCleanupManager:
    """Test the MultiprocessingCleanupManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.manager = MultiprocessingCleanupManager()

    def test_init(self):
        """Test manager initialization."""
        assert self.manager._queues == []
        assert self.manager._registered is False

    @patch("atexit.register")
    def test_register_queue_first_time(self, mock_atexit_register):
        """Test registering the first queue registers atexit handler."""
        mock_queue = Mock()

        self.manager.register_queue(mock_queue)

        assert mock_queue in self.manager._queues
        assert self.manager._registered is True
        mock_atexit_register.assert_called_once_with(self.manager.cleanup_all)

    @patch("atexit.register")
    def test_register_queue_subsequent_times(self, mock_atexit_register):
        """Test registering subsequent queues doesn't re-register atexit handler."""
        mock_queue1 = Mock()
        mock_queue2 = Mock()

        self.manager.register_queue(mock_queue1)
        self.manager.register_queue(mock_queue2)

        assert mock_queue1 in self.manager._queues
        assert mock_queue2 in self.manager._queues
        mock_atexit_register.assert_called_once_with(self.manager.cleanup_all)

    def test_register_queue_none(self):
        """Test registering None queue is ignored."""
        self.manager.register_queue(None)

        assert self.manager._queues == []
        assert self.manager._registered is False

    def test_cleanup_queue_none(self):
        """Test cleaning up None queue is handled gracefully."""
        self.manager.cleanup_queue(None)

    def test_cleanup_queue_success(self):
        """Test successful queue cleanup."""
        mock_queue = Mock()
        mock_queue.empty.return_value = True

        self.manager._queues.append(mock_queue)

        self.manager.cleanup_queue(mock_queue)

        mock_queue.close.assert_called_once()
        assert mock_queue not in self.manager._queues

    def test_cleanup_queue_with_items(self):
        """Test queue cleanup when queue has items."""
        mock_queue = Mock()
        mock_queue.empty.side_effect = [False, False, True]
        mock_queue.get_nowait.side_effect = ["item1", "item2"]

        self.manager._queues.append(mock_queue)

        self.manager.cleanup_queue(mock_queue)

        assert mock_queue.get_nowait.call_count == 2
        mock_queue.close.assert_called_once()
        assert mock_queue not in self.manager._queues

    def test_cleanup_queue_get_nowait_exception(self):
        """Test queue cleanup when get_nowait raises exception."""
        mock_queue = Mock()
        mock_queue.empty.side_effect = [False, True]
        mock_queue.get_nowait.side_effect = Exception("Queue error")

        self.manager._queues.append(mock_queue)

        self.manager.cleanup_queue(mock_queue)

        mock_queue.get_nowait.assert_called_once()
        mock_queue.close.assert_called_once()
        assert mock_queue not in self.manager._queues

    @patch("automated_security_helper.utils.multiprocessing_cleanup.ASH_LOGGER")
    def test_cleanup_queue_close_exception(self, mock_logger):
        """Test queue cleanup when close() raises exception."""
        mock_queue = Mock()
        mock_queue.empty.return_value = True
        mock_queue.close.side_effect = Exception("Close error")

        self.manager._queues.append(mock_queue)

        self.manager.cleanup_queue(mock_queue)

        mock_queue.close.assert_called_once()
        mock_logger.debug.assert_called_once()
        assert mock_queue not in self.manager._queues

    def test_cleanup_all_empty(self):
        """Test cleanup_all with no queues."""
        self.manager.cleanup_all()
        assert self.manager._queues == []

    def test_cleanup_all_with_queues(self):
        """Test cleanup_all with multiple queues."""
        mock_queue1 = Mock()
        mock_queue1.empty.return_value = True
        mock_queue2 = Mock()
        mock_queue2.empty.return_value = True

        self.manager._queues = [mock_queue1, mock_queue2]

        self.manager.cleanup_all()

        mock_queue1.close.assert_called_once()
        mock_queue2.close.assert_called_once()
        assert self.manager._queues == []

    def test_cleanup_all_with_exception(self):
        """Test cleanup_all continues even if one queue cleanup fails."""
        mock_queue1 = Mock()
        mock_queue1.empty.return_value = True
        mock_queue1.close.side_effect = Exception("Close error")

        mock_queue2 = Mock()
        mock_queue2.empty.return_value = True

        self.manager._queues = [mock_queue1, mock_queue2]

        self.manager.cleanup_all()

        mock_queue1.close.assert_called_once()
        mock_queue2.close.assert_called_once()
        assert self.manager._queues == []


class TestGlobalFunctions:
    """Test the global convenience functions."""

    def setup_method(self):
        """Set up test fixtures."""
        _cleanup_manager._queues.clear()
        _cleanup_manager._registered = False

    @patch(
        "automated_security_helper.utils.multiprocessing_cleanup._cleanup_manager.register_queue"
    )
    def test_register_multiprocessing_queue(self, mock_register):
        """Test the global register function."""
        mock_queue = Mock()

        register_multiprocessing_queue(mock_queue)

        mock_register.assert_called_once_with(mock_queue)

    @patch(
        "automated_security_helper.utils.multiprocessing_cleanup._cleanup_manager.cleanup_queue"
    )
    def test_cleanup_multiprocessing_queue(self, mock_cleanup):
        """Test the global cleanup function."""
        mock_queue = Mock()

        cleanup_multiprocessing_queue(mock_queue)

        mock_cleanup.assert_called_once_with(mock_queue)


class TestIntegrationWithRealQueue:
    """Integration tests with real multiprocessing queues."""

    def test_real_queue_cleanup(self):
        """Test cleanup with a real multiprocessing queue."""
        queue = multiprocessing.Queue()

        queue.put("item1")
        queue.put("item2")

        manager = MultiprocessingCleanupManager()
        manager.cleanup_queue(queue)

    def test_real_queue_register_and_cleanup(self):
        """Test the full workflow with a real queue."""
        queue = multiprocessing.Queue()

        queue.put("item1")
        queue.put("item2")

        register_multiprocessing_queue(queue)
        cleanup_multiprocessing_queue(queue)

    @patch("atexit.register")
    def test_atexit_registration_with_real_queue(self, mock_atexit_register):
        """Test that atexit handler is registered with real queue."""
        # Reset the global manager state to ensure clean test
        _cleanup_manager._registered = False

        queue = multiprocessing.Queue()

        register_multiprocessing_queue(queue)

        # Check that our cleanup function was registered (it might be called multiple times due to multiprocessing internals)
        assert mock_atexit_register.call_count >= 1
        # Verify that our cleanup_all method was registered
        calls = [
            call
            for call in mock_atexit_register.call_args_list
            if hasattr(call[0][0], "__self__")
            and isinstance(call[0][0].__self__, MultiprocessingCleanupManager)
        ]
        assert len(calls) >= 1

        cleanup_multiprocessing_queue(queue)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_cleanup_queue_not_in_tracking_list(self):
        """Test cleaning up a queue that's not in the tracking list."""
        manager = MultiprocessingCleanupManager()
        mock_queue = Mock()
        mock_queue.empty.return_value = True

        manager.cleanup_queue(mock_queue)

        mock_queue.close.assert_called_once()

    @patch("automated_security_helper.utils.multiprocessing_cleanup.ASH_LOGGER")
    def test_cleanup_with_complex_exception(self, mock_logger):
        """Test cleanup when multiple operations fail."""
        mock_queue = Mock()
        mock_queue.empty.side_effect = Exception("Empty check failed")

        manager = MultiprocessingCleanupManager()
        manager._queues.append(mock_queue)

        manager.cleanup_queue(mock_queue)

        mock_logger.debug.assert_called_once()
        assert mock_queue not in manager._queues

    def test_cleanup_all_modifies_list_during_iteration(self):
        """Test that cleanup_all handles list modification during iteration."""
        manager = MultiprocessingCleanupManager()

        mock_queue1 = Mock()
        mock_queue1.empty.return_value = True
        mock_queue2 = Mock()
        mock_queue2.empty.return_value = True

        manager._queues = [mock_queue1, mock_queue2]

        manager.cleanup_all()

        assert manager._queues == []
        mock_queue1.close.assert_called_once()
        mock_queue2.close.assert_called_once()

    def test_all_imports_covered(self):
        """Test that all imports are used and covered."""
        from automated_security_helper.utils.multiprocessing_cleanup import (
            MultiprocessingCleanupManager,
            register_multiprocessing_queue,
            cleanup_multiprocessing_queue,
            _cleanup_manager,
        )

        assert isinstance(_cleanup_manager, MultiprocessingCleanupManager)
        assert callable(register_multiprocessing_queue)
        assert callable(cleanup_multiprocessing_queue)

    def test_manager_attributes_accessible(self):
        """Test that all manager attributes are accessible."""
        manager = MultiprocessingCleanupManager()

        assert isinstance(manager._queues, list)
        assert isinstance(manager._registered, bool)

        assert callable(manager.register_queue)
        assert callable(manager.cleanup_queue)
        assert callable(manager.cleanup_all)
