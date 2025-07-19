# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shutdown management for MCP server graceful termination.

This module provides the ShutdownManager class for coordinating graceful
shutdown of all resource managers with proper cleanup sequencing and
timeout handling.
"""

import asyncio
import signal
import sys
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
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
from automated_security_helper.utils.log import ASH_LOGGER


class ShutdownManager:
    """Coordinates graceful shutdown of all resources.

    This class provides centralized coordination of graceful shutdown
    across all resource managers, ensuring proper cleanup sequencing
    and timeout handling for production-ready MCP server operation.
    """

    def __init__(
        self,
        task_manager: TaskManager,
        state_manager: StateManager,
        resource_manager: ResourceManager,
        event_manager: Optional[EventSubscriptionManager] = None,
        shutdown_timeout: float = 30.0,
    ):
        """Initialize the ShutdownManager.

        Args:
            task_manager: TaskManager instance to coordinate
            state_manager: StateManager instance to coordinate
            resource_manager: ResourceManager instance to coordinate
            event_manager: Optional EventSubscriptionManager instance
            shutdown_timeout: Total timeout for shutdown operations
        """
        self._task_manager = task_manager
        self._state_manager = state_manager
        self._resource_manager = resource_manager
        self._event_manager = event_manager
        self._shutdown_timeout = shutdown_timeout
        self._logger = ASH_LOGGER

        self._shutdown_requested = False
        self._shutdown_in_progress = False
        self._shutdown_complete = False
        self._shutdown_callbacks: List[Callable] = []
        self._original_signal_handlers: Dict[int, Any] = {}

    def add_shutdown_callback(self, callback: Callable) -> None:
        """Add a callback to be executed during shutdown.

        Args:
            callback: Function to call during shutdown (can be async)
        """
        self._shutdown_callbacks.append(callback)

    def is_shutdown_complete(self) -> bool:
        """Check if shutdown has completed.

        Returns:
            True if shutdown is complete, False otherwise
        """
        return self._shutdown_complete

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested.

        Returns:
            True if shutdown was requested, False otherwise
        """
        return self._shutdown_requested

    async def force_shutdown(self, timeout: float = 5.0) -> None:
        """Force immediate shutdown with minimal cleanup.

        Args:
            timeout: Maximum time to spend on cleanup before forcing exit
        """
        if self._shutdown_complete:
            return

        self._logger.warning(f"Force shutdown requested with {timeout}s timeout")
        start_time = datetime.now()

        try:
            # Try to do minimal cleanup within the timeout
            await asyncio.wait_for(self._minimal_cleanup(), timeout=timeout)
        except asyncio.TimeoutError:
            self._logger.warning("Force shutdown cleanup timed out")
        except Exception as e:
            self._logger.error(f"Error during force shutdown: {str(e)}")
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            self._logger.info(f"Force shutdown completed in {duration:.2f}s")
            self._shutdown_complete = True

    async def _minimal_cleanup(self) -> None:
        """Perform minimal cleanup for force shutdown."""
        # Cancel active tasks quickly
        if self._task_manager:
            try:
                await asyncio.wait_for(
                    self._task_manager.cancel_all_tasks(timeout=2.0), timeout=2.0
                )
            except asyncio.TimeoutError:
                self._logger.warning(
                    "Task cancellation timed out during force shutdown"
                )

        # Clean up event subscriptions quickly
        if self._event_manager:
            try:
                await asyncio.wait_for(
                    self._event_manager.cleanup_all_subscriptions(), timeout=1.0
                )
            except asyncio.TimeoutError:
                self._logger.warning("Event cleanup timed out during force shutdown")

    def setup_signal_handlers(self) -> None:
        """Setup enhanced signal handlers for graceful shutdown.

        This method replaces existing signal handlers with enhanced versions
        that coordinate graceful shutdown across all resource managers.
        """

        def signal_handler(signum: int, frame) -> None:
            """Handle shutdown signals."""
            signal_name = signal.Signals(signum).name
            self._logger.info(
                f"Received {signal_name} signal, initiating graceful shutdown"
            )

            # Set shutdown flag
            self._shutdown_requested = True

            # For MCP server, we need to be more aggressive about shutdown
            # since the FastMCP server.run() blocks and may not respond to async tasks
            try:
                # Try to schedule graceful shutdown first
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create a task for graceful shutdown
                    asyncio.create_task(self._handle_signal_shutdown(signal_name))

                    # Give it a short time to complete, then force exit
                    def force_exit():
                        if not self._shutdown_complete:
                            self._logger.warning(
                                "Graceful shutdown timed out, forcing exit"
                            )
                            sys.exit(0)

                    # Schedule force exit after a short delay
                    loop.call_later(2.0, force_exit)
                else:
                    # If no event loop is running, force immediate shutdown
                    self._logger.warning(
                        "No event loop running, forcing immediate shutdown"
                    )
                    sys.exit(0)
            except RuntimeError:
                # No event loop available, force immediate shutdown
                self._logger.warning(
                    "No event loop available, forcing immediate shutdown"
                )
                sys.exit(0)
            except Exception as e:
                # Any other error, force immediate shutdown
                self._logger.error(
                    f"Error in signal handler: {str(e)}, forcing immediate shutdown"
                )
                sys.exit(0)

        # Store original handlers for restoration
        signals_to_handle = [signal.SIGINT, signal.SIGTERM]

        # On Windows, SIGTERM might not be available
        if sys.platform == "win32":
            signals_to_handle = [signal.SIGINT]

        for sig in signals_to_handle:
            try:
                self._original_signal_handlers[sig] = signal.signal(sig, signal_handler)
                self._logger.debug(
                    f"Installed signal handler for {signal.Signals(sig).name}"
                )
            except (OSError, ValueError) as e:
                self._logger.warning(
                    f"Could not install handler for signal {sig}: {str(e)}"
                )

    def restore_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        for sig, handler in self._original_signal_handlers.items():
            try:
                signal.signal(sig, handler)
                self._logger.debug(f"Restored original handler for signal {sig}")
            except (OSError, ValueError) as e:
                self._logger.warning(
                    f"Could not restore handler for signal {sig}: {str(e)}"
                )

        self._original_signal_handlers.clear()

    async def _handle_signal_shutdown(self, signal_name: str) -> None:
        """Handle shutdown initiated by signal.

        Args:
            signal_name: Name of the signal that triggered shutdown
        """
        try:
            self._logger.info(f"Starting graceful shutdown due to {signal_name}")
            await self.graceful_shutdown()
            self._logger.info("Graceful shutdown completed successfully")
        except Exception as e:
            self._logger.error(f"Error during graceful shutdown: {str(e)}")
        finally:
            # Exit the process
            sys.exit(0)

    async def graceful_shutdown(self) -> None:
        """Perform graceful shutdown of all resources.

        This method coordinates shutdown across all resource managers
        with proper sequencing and timeout handling.

        Raises:
            MCPResourceError: If shutdown fails critically
        """
        if self._shutdown_in_progress:
            self._logger.warning("Shutdown already in progress")
            return

        if self._shutdown_complete:
            self._logger.debug("Shutdown already completed")
            return

        self._shutdown_in_progress = True
        start_time = datetime.now()

        try:
            self._logger.info("Starting graceful shutdown sequence")

            # Phase 1: Execute shutdown callbacks
            await self._execute_shutdown_callbacks()

            # Phase 2: Cancel all active tasks
            await self._shutdown_tasks()

            # Phase 3: Clean up event subscriptions
            await self._shutdown_events()

            # Phase 4: Clean up state and directory registrations
            await self._shutdown_state()

            # Phase 5: Shutdown shared resources (thread pools, etc.)
            await self._shutdown_resources()

            # Phase 6: Final cleanup
            await self._final_cleanup()

            self._shutdown_complete = True
            duration = (datetime.now() - start_time).total_seconds()
            self._logger.info(f"Graceful shutdown completed in {duration:.2f}s")

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            self._logger.error(
                f"Graceful shutdown failed after {duration:.2f}s: {str(e)}"
            )
            raise MCPResourceError(f"Graceful shutdown failed: {str(e)}")
        finally:
            self._shutdown_in_progress = False

    async def _execute_shutdown_callbacks(self) -> None:
        """Execute all registered shutdown callbacks."""
        if not self._shutdown_callbacks:
            return

        self._logger.debug(
            f"Executing {len(self._shutdown_callbacks)} shutdown callbacks"
        )
        callback_timeout = min(5.0, self._shutdown_timeout / 6)  # 1/6 of total timeout

        for i, callback in enumerate(self._shutdown_callbacks):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await asyncio.wait_for(callback(), timeout=callback_timeout)
                else:
                    # Run sync callback in thread pool
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, callback), timeout=callback_timeout
                    )
                self._logger.debug(
                    f"Executed shutdown callback {i + 1}/{len(self._shutdown_callbacks)}"
                )
            except asyncio.TimeoutError:
                self._logger.warning(
                    f"Shutdown callback {i + 1} timed out after {callback_timeout}s"
                )
            except Exception as e:
                self._logger.error(f"Shutdown callback {i + 1} failed: {str(e)}")

    async def _shutdown_tasks(self) -> None:
        """Shutdown task manager and cancel all active tasks."""
        self._logger.debug("Shutting down task manager")
        task_timeout = min(15.0, self._shutdown_timeout / 2)  # Half of total timeout

        try:
            cancelled_tasks = await asyncio.wait_for(
                self._task_manager.cancel_all_tasks(timeout=task_timeout),
                timeout=task_timeout + 5.0,
            )

            if cancelled_tasks:
                self._logger.info(f"Cancelled {len(cancelled_tasks)} active tasks")
            else:
                self._logger.debug("No active tasks to cancel")

        except asyncio.TimeoutError:
            self._logger.warning(f"Task cancellation timed out after {task_timeout}s")
        except Exception as e:
            self._logger.error(f"Error during task shutdown: {str(e)}")

    async def _shutdown_events(self) -> None:
        """Shutdown event subscription manager."""
        if self._event_manager is None:
            return

        self._logger.debug("Shutting down event subscription manager")

        try:
            # Clean up all event subscriptions
            cleanup_results = await self._event_manager.cleanup_all_subscriptions()
            if cleanup_results.get("errors"):
                self._logger.warning(
                    f"Event cleanup errors: {cleanup_results['errors']}"
                )
            else:
                self._logger.debug(
                    f"Event subscriptions cleaned up successfully: {cleanup_results['successful_cleanups']} cleaned"
                )
        except Exception as e:
            self._logger.error(f"Error during event shutdown: {str(e)}")

    async def _shutdown_state(self) -> None:
        """Shutdown state manager and clean up state."""
        self._logger.debug("Shutting down state manager")

        try:
            # Clean up old completed scans
            cleanup_count = await self._state_manager.cleanup_completed_scans(
                max_age_hours=0
            )
            if cleanup_count > 0:
                self._logger.debug(
                    f"Cleaned up {cleanup_count} scan records during shutdown"
                )

            # Validate state consistency
            issues = await self._state_manager.validate_state_consistency()
            if issues:
                self._logger.warning(
                    f"State consistency issues found during shutdown: {issues}"
                )

            # Get final statistics
            stats = self._state_manager.get_state_statistics()
            self._logger.debug(f"Final state statistics: {stats}")

        except Exception as e:
            self._logger.error(f"Error during state shutdown: {str(e)}")

    async def _shutdown_resources(self) -> None:
        """Shutdown resource manager and shared resources."""
        self._logger.debug("Shutting down resource manager")
        resource_timeout = min(10.0, self._shutdown_timeout / 3)  # 1/3 of total timeout

        try:
            await asyncio.wait_for(
                self._resource_manager.shutdown_executor(
                    wait=True, timeout=resource_timeout
                ),
                timeout=resource_timeout + 5.0,
            )
            self._logger.debug("Resource manager shutdown completed")
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Resource shutdown timed out after {resource_timeout}s"
            )
        except Exception as e:
            self._logger.error(f"Error during resource shutdown: {str(e)}")

    async def _final_cleanup(self) -> None:
        """Perform final cleanup operations."""
        self._logger.debug("Performing final cleanup")

        try:
            # Restore signal handlers
            self.restore_signal_handlers()

            # Log final resource statistics
            if hasattr(self._resource_manager, "get_resource_stats"):
                try:
                    final_stats = self._resource_manager.get_resource_stats()
                    self._logger.info(f"Final resource stats: {final_stats}")
                except Exception as e:
                    self._logger.debug(f"Could not get final resource stats: {str(e)}")

            self._logger.debug("Final cleanup completed")

        except Exception as e:
            self._logger.error(f"Error during final cleanup: {str(e)}")

    def is_shutdown_in_progress(self) -> bool:
        """Check if shutdown is currently in progress.

        Returns:
            True if shutdown is in progress, False otherwise
        """
        return self._shutdown_in_progress

    async def request_shutdown(self) -> None:
        """Request graceful shutdown programmatically.

        This method can be called to initiate shutdown without a signal.
        """
        if self._shutdown_requested:
            self._logger.debug("Shutdown already requested")
            return

        self._logger.info("Shutdown requested programmatically")
        self._shutdown_requested = True
        await self.graceful_shutdown()

    def get_shutdown_status(self) -> Dict[str, Any]:
        """Get current shutdown status information.

        Returns:
            Dictionary with shutdown status details
        """
        return {
            "shutdown_requested": self._shutdown_requested,
            "shutdown_in_progress": self._shutdown_in_progress,
            "shutdown_complete": self._shutdown_complete,
            "shutdown_timeout": self._shutdown_timeout,
            "callback_count": len(self._shutdown_callbacks),
            "signal_handlers_installed": len(self._original_signal_handlers) > 0,
        }
