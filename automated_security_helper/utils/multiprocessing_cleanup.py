"""Utilities for cleaning up multiprocessing resources to prevent hangs."""

import atexit
from typing import List
from automated_security_helper.utils.log import ASH_LOGGER


class MultiprocessingCleanupManager:
    """Manager for cleaning up multiprocessing resources to prevent hangs."""

    def __init__(self):
        self._queues: List = []
        self._registered = False

    def register_queue(self, queue) -> None:
        """Register a multiprocessing queue for cleanup."""
        if queue is not None:
            self._queues.append(queue)
            if not self._registered:
                atexit.register(self.cleanup_all)
                self._registered = True

    def cleanup_queue(self, queue) -> None:
        """Clean up a specific queue."""
        if queue is None:
            return

        try:
            # Clear any remaining items
            while not queue.empty():
                try:
                    queue.get_nowait()
                except Exception as e:
                    ASH_LOGGER.debug(f"Queue is now empty: {e}")
                    break

            # Close the queue
            queue.close()

        except Exception as e:
            ASH_LOGGER.debug(f"Error cleaning up multiprocessing queue: {e}")
        finally:
            # Always remove from our tracking list, even if cleanup failed
            if queue in self._queues:
                self._queues.remove(queue)

    def cleanup_all(self) -> None:
        """Clean up all registered queues."""
        for queue in self._queues[:]:
            self.cleanup_queue(queue)
        self._queues.clear()


# Global instance
_cleanup_manager = MultiprocessingCleanupManager()


def register_multiprocessing_queue(queue) -> None:
    """Register a multiprocessing queue for automatic cleanup."""
    _cleanup_manager.register_queue(queue)


def cleanup_multiprocessing_queue(queue) -> None:
    """Clean up a specific multiprocessing queue."""
    _cleanup_manager.cleanup_queue(queue)
