# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event subscription management for MCP server resource management.

This module provides the EventSubscriptionManager class for tracking and managing
event subscriptions with automatic cleanup to prevent memory leaks.
"""

import asyncio
from typing import Dict, List, Set, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER


@dataclass
class EventSubscription:
    """Information about an event subscription."""

    subscription_id: str
    event_type: str
    handler: Callable
    cleanup_func: Optional[Callable] = None
    created_at: datetime = field(default_factory=datetime.now)
    scan_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        """Make EventSubscription hashable for use in sets."""
        return hash(self.subscription_id)


class EventSubscriptionManager:
    """Manages event subscriptions with automatic cleanup.

    This class provides centralized management of event subscriptions to prevent
    memory leaks caused by untracked event handlers in the MCP server.
    """

    def __init__(self):
        """Initialize the EventSubscriptionManager."""
        self._subscriptions: Dict[str, EventSubscription] = {}
        self._subscriptions_by_scan: Dict[str, Set[str]] = {}
        self._subscriptions_by_type: Dict[str, Set[str]] = {}
        self._subscription_lock = asyncio.Lock()
        self._logger = ASH_LOGGER
        self._cleanup_errors: List[Dict[str, Any]] = []

    async def register_subscription(
        self,
        subscription_id: str,
        event_type: str,
        handler: Callable,
        cleanup_func: Optional[Callable] = None,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Register a new event subscription.

        Args:
            subscription_id: Unique identifier for the subscription
            event_type: Type of event being subscribed to
            handler: Event handler function
            cleanup_func: Optional cleanup function to call when unsubscribing
            scan_id: Optional scan ID associated with the subscription
            metadata: Optional metadata for the subscription

        Returns:
            True if registration was successful, False if subscription already exists

        Raises:
            MCPResourceError: If registration fails
        """
        async with self._subscription_lock:
            try:
                if subscription_id in self._subscriptions:
                    self._logger.warning(
                        f"Subscription {subscription_id} already exists"
                    )
                    return False

                subscription = EventSubscription(
                    subscription_id=subscription_id,
                    event_type=event_type,
                    handler=handler,
                    cleanup_func=cleanup_func,
                    scan_id=scan_id,
                    metadata=metadata or {},
                )

                # Store subscription
                self._subscriptions[subscription_id] = subscription

                # Index by scan ID
                if scan_id:
                    if scan_id not in self._subscriptions_by_scan:
                        self._subscriptions_by_scan[scan_id] = set()
                    self._subscriptions_by_scan[scan_id].add(subscription_id)

                # Index by event type
                if event_type not in self._subscriptions_by_type:
                    self._subscriptions_by_type[event_type] = set()
                self._subscriptions_by_type[event_type].add(subscription_id)

                self._logger.debug(
                    f"Registered event subscription: {subscription_id} "
                    f"(type: {event_type}, scan_id: {scan_id})"
                )

                return True

            except Exception as e:
                self._logger.error(
                    f"Failed to register subscription {subscription_id}: {str(e)}"
                )
                raise MCPResourceError(
                    f"Failed to register event subscription: {str(e)}",
                    context={
                        "subscription_id": subscription_id,
                        "event_type": event_type,
                        "scan_id": scan_id,
                    },
                )

    async def unregister_subscription(self, subscription_id: str) -> bool:
        """Unregister an event subscription with cleanup.

        Args:
            subscription_id: The subscription ID to unregister

        Returns:
            True if unregistration was successful, False if subscription not found
        """
        async with self._subscription_lock:
            subscription = self._subscriptions.get(subscription_id)
            if subscription is None:
                self._logger.debug(
                    f"Subscription {subscription_id} not found for unregistration"
                )
                return False

            # Execute cleanup function if provided
            cleanup_success = True
            if subscription.cleanup_func:
                try:
                    if asyncio.iscoroutinefunction(subscription.cleanup_func):
                        await subscription.cleanup_func()
                    else:
                        subscription.cleanup_func()
                    self._logger.debug(
                        f"Executed cleanup for subscription {subscription_id}"
                    )
                except Exception as e:
                    cleanup_success = False
                    error_info = {
                        "subscription_id": subscription_id,
                        "event_type": subscription.event_type,
                        "scan_id": subscription.scan_id,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                    self._cleanup_errors.append(error_info)
                    self._logger.error(
                        f"Cleanup failed for subscription {subscription_id}: {str(e)}"
                    )

            # Remove from indices
            if (
                subscription.scan_id
                and subscription.scan_id in self._subscriptions_by_scan
            ):
                self._subscriptions_by_scan[subscription.scan_id].discard(
                    subscription_id
                )
                if not self._subscriptions_by_scan[subscription.scan_id]:
                    del self._subscriptions_by_scan[subscription.scan_id]

            if subscription.event_type in self._subscriptions_by_type:
                self._subscriptions_by_type[subscription.event_type].discard(
                    subscription_id
                )
                if not self._subscriptions_by_type[subscription.event_type]:
                    del self._subscriptions_by_type[subscription.event_type]

            # Remove subscription
            del self._subscriptions[subscription_id]

            self._logger.debug(f"Unregistered subscription {subscription_id}")
            return cleanup_success

    async def cleanup_subscriptions_by_scan(self, scan_id: str) -> Dict[str, Any]:
        """Clean up all subscriptions for a specific scan.

        Args:
            scan_id: The scan ID

        Returns:
            Dictionary with cleanup results
        """
        cleanup_results = {
            "scan_id": scan_id,
            "total_subscriptions": 0,
            "successful_cleanups": 0,
            "failed_cleanups": 0,
            "errors": [],
        }

        async with self._subscription_lock:
            subscription_ids = self._subscriptions_by_scan.get(scan_id, set()).copy()
            cleanup_results["total_subscriptions"] = len(subscription_ids)

        if not subscription_ids:
            self._logger.debug(f"No subscriptions found for scan {scan_id}")
            return cleanup_results

        # Clean up each subscription
        for subscription_id in subscription_ids:
            try:
                success = await self.unregister_subscription(subscription_id)
                if success:
                    cleanup_results["successful_cleanups"] += 1
                else:
                    cleanup_results["failed_cleanups"] += 1
            except Exception as e:
                cleanup_results["failed_cleanups"] += 1
                cleanup_results["errors"].append(
                    {"subscription_id": subscription_id, "error": str(e)}
                )
                self._logger.error(
                    f"Error cleaning up subscription {subscription_id} for scan {scan_id}: {str(e)}"
                )

        self._logger.info(
            f"Cleaned up {cleanup_results['successful_cleanups']}/{cleanup_results['total_subscriptions']} "
            f"subscriptions for scan {scan_id}"
        )

        return cleanup_results

    async def cleanup_subscriptions_by_type(self, event_type: str) -> Dict[str, Any]:
        """Clean up all subscriptions for a specific event type.

        Args:
            event_type: The event type

        Returns:
            Dictionary with cleanup results
        """
        cleanup_results = {
            "event_type": event_type,
            "total_subscriptions": 0,
            "successful_cleanups": 0,
            "failed_cleanups": 0,
            "errors": [],
        }

        async with self._subscription_lock:
            subscription_ids = self._subscriptions_by_type.get(event_type, set()).copy()
            cleanup_results["total_subscriptions"] = len(subscription_ids)

        if not subscription_ids:
            self._logger.debug(f"No subscriptions found for event type {event_type}")
            return cleanup_results

        # Clean up each subscription
        for subscription_id in subscription_ids:
            try:
                success = await self.unregister_subscription(subscription_id)
                if success:
                    cleanup_results["successful_cleanups"] += 1
                else:
                    cleanup_results["failed_cleanups"] += 1
            except Exception as e:
                cleanup_results["failed_cleanups"] += 1
                cleanup_results["errors"].append(
                    {"subscription_id": subscription_id, "error": str(e)}
                )
                self._logger.error(
                    f"Error cleaning up subscription {subscription_id} for event type {event_type}: {str(e)}"
                )

        self._logger.info(
            f"Cleaned up {cleanup_results['successful_cleanups']}/{cleanup_results['total_subscriptions']} "
            f"subscriptions for event type {event_type}"
        )

        return cleanup_results

    async def cleanup_all_subscriptions(self) -> Dict[str, Any]:
        """Clean up all registered subscriptions.

        Returns:
            Dictionary with cleanup results
        """
        cleanup_results = {
            "total_subscriptions": 0,
            "successful_cleanups": 0,
            "failed_cleanups": 0,
            "errors": [],
        }

        async with self._subscription_lock:
            subscription_ids = list(self._subscriptions.keys())
            cleanup_results["total_subscriptions"] = len(subscription_ids)

        if not subscription_ids:
            self._logger.debug("No subscriptions to clean up")
            return cleanup_results

        # Clean up each subscription
        for subscription_id in subscription_ids:
            try:
                success = await self.unregister_subscription(subscription_id)
                if success:
                    cleanup_results["successful_cleanups"] += 1
                else:
                    cleanup_results["failed_cleanups"] += 1
            except Exception as e:
                cleanup_results["failed_cleanups"] += 1
                cleanup_results["errors"].append(
                    {"subscription_id": subscription_id, "error": str(e)}
                )
                self._logger.error(
                    f"Error cleaning up subscription {subscription_id}: {str(e)}"
                )

        self._logger.info(
            f"Cleaned up {cleanup_results['successful_cleanups']}/{cleanup_results['total_subscriptions']} "
            f"total subscriptions"
        )

        return cleanup_results

    def get_subscription_info(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific subscription.

        Args:
            subscription_id: The subscription ID

        Returns:
            Subscription information dictionary or None if not found
        """
        subscription = self._subscriptions.get(subscription_id)
        if subscription is None:
            return None

        return {
            "subscription_id": subscription.subscription_id,
            "event_type": subscription.event_type,
            "created_at": subscription.created_at.isoformat(),
            "scan_id": subscription.scan_id,
            "has_cleanup_func": subscription.cleanup_func is not None,
            "metadata": subscription.metadata,
        }

    def get_subscriptions_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all subscriptions for a specific scan.

        Args:
            scan_id: The scan ID

        Returns:
            List of subscription information dictionaries
        """
        subscription_ids = self._subscriptions_by_scan.get(scan_id, set())
        return [
            self.get_subscription_info(sub_id)
            for sub_id in subscription_ids
            if self.get_subscription_info(sub_id) is not None
        ]

    def get_subscriptions_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        """Get all subscriptions for a specific event type.

        Args:
            event_type: The event type

        Returns:
            List of subscription information dictionaries
        """
        subscription_ids = self._subscriptions_by_type.get(event_type, set())
        return [
            self.get_subscription_info(sub_id)
            for sub_id in subscription_ids
            if self.get_subscription_info(sub_id) is not None
        ]

    def get_all_subscriptions(self) -> List[Dict[str, Any]]:
        """Get information about all subscriptions.

        Returns:
            List of subscription information dictionaries
        """
        return [
            self.get_subscription_info(sub_id) for sub_id in self._subscriptions.keys()
        ]

    def get_subscription_statistics(self) -> Dict[str, Any]:
        """Get subscription statistics.

        Returns:
            Dictionary with subscription statistics
        """
        return {
            "total_subscriptions": len(self._subscriptions),
            "subscriptions_by_scan_count": len(self._subscriptions_by_scan),
            "subscriptions_by_type_count": len(self._subscriptions_by_type),
            "event_types": list(self._subscriptions_by_type.keys()),
            "scan_ids": list(self._subscriptions_by_scan.keys()),
            "cleanup_errors_count": len(self._cleanup_errors),
        }

    def get_cleanup_errors(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get recent cleanup errors.

        Args:
            limit: Optional limit on number of errors to return

        Returns:
            List of cleanup error information
        """
        if limit is None:
            return self._cleanup_errors.copy()
        if limit == 0:
            return []
        return self._cleanup_errors[-limit:] if self._cleanup_errors else []

    def clear_cleanup_errors(self) -> int:
        """Clear stored cleanup errors.

        Returns:
            Number of errors that were cleared
        """
        error_count = len(self._cleanup_errors)
        self._cleanup_errors.clear()
        return error_count

    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of the event subscription manager.

        Returns:
            Dictionary with health status information
        """
        async with self._subscription_lock:
            total_subscriptions = len(self._subscriptions)
            cleanup_errors = len(self._cleanup_errors)

            # Calculate health status
            too_many_subscriptions = total_subscriptions > 100  # Threshold
            has_cleanup_errors = cleanup_errors > 0

            if has_cleanup_errors and cleanup_errors > 10:
                status = "critical"
            elif too_many_subscriptions or has_cleanup_errors:
                status = "warning"
            else:
                status = "healthy"

            is_healthy = status == "healthy"

            # Get subscription distribution
            subscriptions_by_type = {}
            subscriptions_by_scan = {}

            for subscription in self._subscriptions.values():
                # Count by event type
                event_type = subscription.event_type
                subscriptions_by_type[event_type] = (
                    subscriptions_by_type.get(event_type, 0) + 1
                )

                # Count by scan ID
                if subscription.scan_id:
                    scan_id = subscription.scan_id
                    subscriptions_by_scan[scan_id] = (
                        subscriptions_by_scan.get(scan_id, 0) + 1
                    )

            return {
                "status": status,
                "total_subscriptions": total_subscriptions,
                "cleanup_errors": cleanup_errors,
                "subscriptions_by_type": subscriptions_by_type,
                "subscriptions_by_scan": subscriptions_by_scan,
                "is_healthy": is_healthy,
                "details": {
                    "oldest_subscription": min(
                        (sub.created_at for sub in self._subscriptions.values()),
                        default=None,
                    ).isoformat()
                    if self._subscriptions
                    else None,
                    "newest_subscription": max(
                        (sub.created_at for sub in self._subscriptions.values()),
                        default=None,
                    ).isoformat()
                    if self._subscriptions
                    else None,
                    "recent_cleanup_errors": self._cleanup_errors[-5:]
                    if self._cleanup_errors
                    else [],
                },
            }

    async def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage statistics.

        Returns:
            Dictionary with resource usage information
        """
        async with self._subscription_lock:
            # Calculate memory usage estimate
            subscription_size = (
                len(self._subscriptions) * 1
            )  # ~1KB per subscription estimate
            index_size = (
                len(self._subscriptions_by_scan) + len(self._subscriptions_by_type)
            ) * 0.1  # ~0.1KB per index entry
            error_size = len(self._cleanup_errors) * 0.5  # ~0.5KB per error
            total_memory_kb = subscription_size + index_size + error_size

            # Get subscription age statistics
            now = datetime.now()
            subscription_ages = []

            for subscription in self._subscriptions.values():
                age_seconds = (now - subscription.created_at).total_seconds()
                subscription_ages.append(age_seconds)

            return {
                "memory_usage_kb": total_memory_kb,
                "memory_usage_mb": total_memory_kb / 1024,
                "subscription_count": len(self._subscriptions),
                "index_entries": len(self._subscriptions_by_scan)
                + len(self._subscriptions_by_type),
                "cleanup_errors_stored": len(self._cleanup_errors),
                "subscription_ages": {
                    "count": len(subscription_ages),
                    "average_seconds": sum(subscription_ages) / len(subscription_ages)
                    if subscription_ages
                    else 0,
                    "max_seconds": max(subscription_ages) if subscription_ages else 0,
                    "min_seconds": min(subscription_ages) if subscription_ages else 0,
                },
            }

    @asynccontextmanager
    async def subscription_context(
        self,
        subscription_id: str,
        event_type: str,
        handler: Callable,
        cleanup_func: Optional[Callable] = None,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Async context manager for safe event subscription handling.

        This context manager ensures that event subscriptions are properly
        cleaned up even if exceptions occur during event handling.

        Args:
            subscription_id: Unique identifier for the subscription
            event_type: Type of event being subscribed to
            handler: Event handler function
            cleanup_func: Optional cleanup function to call when unsubscribing
            scan_id: Optional scan ID associated with the subscription
            metadata: Optional metadata for the subscription

        Yields:
            The subscription ID if registration was successful

        Raises:
            MCPResourceError: If subscription registration fails
        """
        subscription_registered = False

        try:
            # Register the subscription
            success = await self.register_subscription(
                subscription_id=subscription_id,
                event_type=event_type,
                handler=handler,
                cleanup_func=cleanup_func,
                scan_id=scan_id,
                metadata=metadata,
            )

            if not success:
                raise MCPResourceError(
                    f"Failed to register subscription: {subscription_id}",
                    context={
                        "subscription_id": subscription_id,
                        "event_type": event_type,
                        "scan_id": scan_id,
                    },
                )

            subscription_registered = True
            self._logger.debug(
                f"Context manager registered subscription: {subscription_id}"
            )

            # Yield control to the caller
            yield subscription_id

        except Exception as e:
            self._logger.error(
                f"Exception in subscription context for {subscription_id}: {str(e)}"
            )
            raise

        finally:
            # Always attempt cleanup, even if an exception occurred
            if subscription_registered:
                try:
                    cleanup_success = await self.unregister_subscription(
                        subscription_id
                    )
                    if cleanup_success:
                        self._logger.debug(
                            f"Context manager successfully cleaned up subscription: {subscription_id}"
                        )
                    else:
                        self._logger.warning(
                            f"Context manager cleanup had issues for subscription: {subscription_id}"
                        )
                except Exception as cleanup_error:
                    self._logger.error(
                        f"Context manager cleanup failed for subscription {subscription_id}: {str(cleanup_error)}"
                    )
                    # Don't re-raise cleanup errors to avoid masking original exceptions


class EventSubscriptionContextManager:
    """Standalone context manager for event subscriptions.

    This provides an alternative context manager interface that can be used
    independently of the EventSubscriptionManager instance.
    """

    def __init__(self, event_manager: EventSubscriptionManager):
        """Initialize with an EventSubscriptionManager instance.

        Args:
            event_manager: The EventSubscriptionManager to use
        """
        self._event_manager = event_manager
        self._logger = ASH_LOGGER

    @asynccontextmanager
    async def managed_subscription(
        self,
        subscription_id: str,
        event_type: str,
        handler: Callable,
        cleanup_func: Optional[Callable] = None,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        auto_cleanup_on_error: bool = True,
    ):
        """Create a managed event subscription with automatic cleanup.

        Args:
            subscription_id: Unique identifier for the subscription
            event_type: Type of event being subscribed to
            handler: Event handler function
            cleanup_func: Optional cleanup function to call when unsubscribing
            scan_id: Optional scan ID associated with the subscription
            metadata: Optional metadata for the subscription
            auto_cleanup_on_error: Whether to automatically cleanup on errors

        Yields:
            Dictionary with subscription information and control methods

        Raises:
            MCPResourceError: If subscription management fails
        """
        subscription_info = {
            "subscription_id": subscription_id,
            "event_type": event_type,
            "scan_id": scan_id,
            "registered": False,
            "cleanup_attempted": False,
        }

        try:
            # Register subscription
            success = await self._event_manager.register_subscription(
                subscription_id=subscription_id,
                event_type=event_type,
                handler=handler,
                cleanup_func=cleanup_func,
                scan_id=scan_id,
                metadata=metadata,
            )

            if not success:
                raise MCPResourceError(
                    f"Failed to register managed subscription: {subscription_id}",
                    context=subscription_info,
                )

            subscription_info["registered"] = True

            # Add control methods to subscription info
            subscription_info["unregister"] = (
                lambda: self._event_manager.unregister_subscription(subscription_id)
            )
            subscription_info["get_info"] = (
                lambda: self._event_manager.get_subscription_info(subscription_id)
            )

            self._logger.debug(f"Managed subscription created: {subscription_id}")

            # Yield subscription info with control methods
            yield subscription_info

        except Exception as e:
            self._logger.error(
                f"Error in managed subscription {subscription_id}: {str(e)}"
            )
            if auto_cleanup_on_error and subscription_info["registered"]:
                try:
                    await self._event_manager.unregister_subscription(subscription_id)
                    subscription_info["cleanup_attempted"] = True
                    self._logger.debug(
                        f"Auto-cleanup performed for {subscription_id} due to error"
                    )
                except Exception as cleanup_error:
                    self._logger.error(
                        f"Auto-cleanup failed for {subscription_id}: {str(cleanup_error)}"
                    )
            raise

        finally:
            # Final cleanup if not already done
            if (
                subscription_info["registered"]
                and not subscription_info["cleanup_attempted"]
            ):
                try:
                    await self._event_manager.unregister_subscription(subscription_id)
                    subscription_info["cleanup_attempted"] = True
                    self._logger.debug(f"Final cleanup performed for {subscription_id}")
                except Exception as cleanup_error:
                    self._logger.error(
                        f"Final cleanup failed for {subscription_id}: {str(cleanup_error)}"
                    )
