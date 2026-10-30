# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event subscription management for MCP server resource management.

This module provides the EventSubscriptionManager class for tracking and managing
event subscriptions with automatic cleanup to prevent memory leaks.
"""

import asyncio
import inspect
from typing import Dict, List, Set, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER

#: How many cleanup errors the manager keeps, newest last. The list used to grow
#: without bound for the life of the process.
MAX_CLEANUP_ERRORS = 100

#: How long a cleanup error counts toward the health status. Errors older than
#: this are dropped from the store, so one historical failure does not keep the
#: status at "warning", and eleven at "critical", for the life of the process.
CLEANUP_ERROR_RETENTION_SECONDS = 3600.0


def _utc_now() -> datetime:
    """The current time, timezone-aware in UTC.

    Subscription ages and the cleanup-error timestamps are differences between
    two readings; taken from the naive local clock, a daylight-saving fall-back
    or a clock step between them made an age negative or an hour off.
    """
    return datetime.now(timezone.utc)


@dataclass
class EventSubscription:
    """Information about an event subscription."""

    subscription_id: str
    event_type: str
    handler: Callable
    cleanup_func: Optional[Callable] = None
    created_at: datetime = field(default_factory=_utc_now)
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

    def __init__(self) -> None:
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

        The metadata is copied: stored by reference, the registering caller's
        later edits to its own dict changed the registered subscription. A
        registration that fails partway (an unhashable scan_id or event_type
        raises while the indices are updated) leaves nothing behind: the stored
        entry used to stay, unindexed, while the caller was told it failed.
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
                    metadata=dict(metadata) if metadata else {},
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
                self._discard_partial_registration(subscription_id, scan_id, event_type)
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

    def _discard_partial_registration(
        self, subscription_id: str, scan_id: Any, event_type: Any
    ) -> None:
        """Undo whatever register_subscription stored before it raised."""
        self._subscriptions.pop(subscription_id, None)
        for index, key in (
            (self._subscriptions_by_scan, scan_id),
            (self._subscriptions_by_type, event_type),
        ):
            try:
                members = index.get(key)
            except TypeError:
                # An unhashable key was never indexed.
                continue
            if members is not None:
                members.discard(subscription_id)
                if not members:
                    del index[key]

    def get_registration(self, subscription_id: str) -> Optional[EventSubscription]:
        """The registered subscription object for ``subscription_id``, or None.

        For a caller that registers a subscription and later has to remove
        exactly that registration and not whatever is registered under the id by
        then: :meth:`unregister_registration` takes the object this returns.
        """
        return self._subscriptions.get(subscription_id)

    def _detach(self, subscription: EventSubscription) -> None:
        """Take ``subscription`` out of the registry and its indices. Caller holds the lock."""
        subscription_id = subscription.subscription_id
        if subscription.scan_id and subscription.scan_id in self._subscriptions_by_scan:
            self._subscriptions_by_scan[subscription.scan_id].discard(subscription_id)
            if not self._subscriptions_by_scan[subscription.scan_id]:
                del self._subscriptions_by_scan[subscription.scan_id]

        if subscription.event_type in self._subscriptions_by_type:
            self._subscriptions_by_type[subscription.event_type].discard(
                subscription_id
            )
            if not self._subscriptions_by_type[subscription.event_type]:
                del self._subscriptions_by_type[subscription.event_type]

        del self._subscriptions[subscription_id]

    async def _run_cleanup(self, subscription: EventSubscription) -> Optional[str]:
        """Run a detached subscription's cleanup, outside the lock.

        Returns None when it ran (or there was none), else the error's text,
        which is also recorded in the cleanup errors.
        """
        subscription_id = subscription.subscription_id
        if not subscription.cleanup_func:
            return None
        try:
            outcome = subscription.cleanup_func()
            if inspect.isawaitable(outcome):
                await outcome
            self._logger.debug(f"Executed cleanup for subscription {subscription_id}")
            return None
        except Exception as e:
            self._record_cleanup_error(
                {
                    "subscription_id": subscription_id,
                    "event_type": subscription.event_type,
                    "scan_id": subscription.scan_id,
                    "error": str(e),
                    "timestamp": _utc_now().isoformat(),
                }
            )
            self._logger.error(
                f"Cleanup failed for subscription {subscription_id}: {str(e)}"
            )
            return str(e)

    def _record_cleanup_error(self, error_info: Dict[str, Any]) -> None:
        """Keep ``error_info``, dropping the oldest past MAX_CLEANUP_ERRORS."""
        self._cleanup_errors.append(error_info)
        excess = len(self._cleanup_errors) - MAX_CLEANUP_ERRORS
        if excess > 0:
            del self._cleanup_errors[:excess]

    def _drop_expired_cleanup_errors(self) -> None:
        """Forget cleanup errors older than CLEANUP_ERROR_RETENTION_SECONDS."""
        if not self._cleanup_errors:
            return
        now = _utc_now()
        kept = []
        for error_info in self._cleanup_errors:
            recorded = error_info.get("timestamp")
            try:
                when = datetime.fromisoformat(recorded)
            except (TypeError, ValueError):
                kept.append(error_info)
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if (now - when).total_seconds() <= CLEANUP_ERROR_RETENTION_SECONDS:
                kept.append(error_info)
        self._cleanup_errors[:] = kept

    async def unregister_subscription(self, subscription_id: str) -> bool:
        """Unregister an event subscription with cleanup.

        Args:
            subscription_id: The subscription ID to unregister

        Returns:
            True if unregistration was successful, False if subscription not found
            or its cleanup raised.

        The subscription is taken out of the registry under the lock, and its
        cleanup runs after the lock is released. Run under it, a cleanup that
        called back into this manager deadlocked on the non-reentrant lock, and
        a slow one stalled every other caller for its duration. The cleanup is
        awaited whenever what it returns is awaitable: a plain callable that
        returns a coroutine used to be called and its coroutine dropped, so the
        cleanup never ran and was reported as a success.
        """
        async with self._subscription_lock:
            subscription = self._subscriptions.get(subscription_id)
            if subscription is None:
                self._logger.debug(
                    f"Subscription {subscription_id} not found for unregistration"
                )
                return False
            self._detach(subscription)

        # Execute cleanup function if provided, outside the lock.
        cleanup_error = await self._run_cleanup(subscription)
        self._logger.debug(f"Unregistered subscription {subscription_id}")
        return cleanup_error is None

    async def unregister_registration(self, subscription: EventSubscription) -> bool:
        """Unregister exactly ``subscription``, if it is still the one registered.

        For the context managers, which register a subscription and remove it on
        exit: removing by id alone removed, and ran the cleanup of, a different
        subscription registered under the same id during the block, after the
        block's own had been unregistered. Returns False, and touches nothing,
        when the registry no longer holds this object under its id; otherwise as
        :meth:`unregister_subscription`.
        """
        async with self._subscription_lock:
            if (
                self._subscriptions.get(subscription.subscription_id)
                is not subscription
            ):
                self._logger.debug(
                    f"Subscription {subscription.subscription_id} is no longer the "
                    "registered one; leaving the registry as it is"
                )
                return False
            self._detach(subscription)
        cleanup_error = await self._run_cleanup(subscription)
        return cleanup_error is None

    async def _cleanup_detached(
        self,
        detached: List[EventSubscription],
        cleanup_results: Dict[str, Any],
        what: str,
    ) -> Dict[str, Any]:
        """Run the cleanups of subscriptions already taken out of the registry.

        The bulk cleanups detach their whole set under one lock acquisition and
        run the cleanups afterwards. They used to snapshot ids, release the lock
        and unregister each id in turn: an id re-registered meanwhile under
        another scan or type was removed as if it were the old one, a
        subscription removed meanwhile was counted as a failed cleanup, and a
        cleanup that raised was counted as failed with nothing in ``errors``.
        """
        for subscription in detached:
            error = await self._run_cleanup(subscription)
            if error is None:
                cleanup_results["successful_cleanups"] += 1
            else:
                cleanup_results["failed_cleanups"] += 1
                cleanup_results["errors"].append(
                    {"subscription_id": subscription.subscription_id, "error": error}
                )

        self._logger.info(
            f"Cleaned up {cleanup_results['successful_cleanups']}/"
            f"{cleanup_results['total_subscriptions']} {what}"
        )
        return cleanup_results

    def _detach_all(self, subscription_ids: Set[str]) -> List[EventSubscription]:
        """Detach every registered subscription in ``subscription_ids``. Caller holds the lock."""
        detached = []
        for subscription_id in list(subscription_ids):
            subscription = self._subscriptions.get(subscription_id)
            if subscription is not None:
                self._detach(subscription)
                detached.append(subscription)
        return detached

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
            detached = self._detach_all(self._subscriptions_by_scan.get(scan_id, set()))
            cleanup_results["total_subscriptions"] = len(detached)

        if not detached:
            self._logger.debug(f"No subscriptions found for scan {scan_id}")
            return cleanup_results

        return await self._cleanup_detached(
            detached, cleanup_results, f"subscriptions for scan {scan_id}"
        )

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
            detached = self._detach_all(
                self._subscriptions_by_type.get(event_type, set())
            )
            cleanup_results["total_subscriptions"] = len(detached)

        if not detached:
            self._logger.debug(f"No subscriptions found for event type {event_type}")
            return cleanup_results

        return await self._cleanup_detached(
            detached, cleanup_results, f"subscriptions for event type {event_type}"
        )

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
            detached = self._detach_all(set(self._subscriptions.keys()))
            cleanup_results["total_subscriptions"] = len(detached)

        if not detached:
            self._logger.debug("No subscriptions to clean up")
            return cleanup_results

        return await self._cleanup_detached(
            detached, cleanup_results, "total subscriptions"
        )

    def get_subscription_info(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific subscription.

        Args:
            subscription_id: The subscription ID

        Returns:
            Subscription information dictionary or None if not found. The
            metadata is a copy: handed out by reference, a caller editing the
            returned info changed the registered subscription.
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
            "metadata": dict(subscription.metadata),
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
            limit: Optional limit on number of errors to return, the newest
                ones. Zero returns none; a negative limit is refused with
                ValueError (it used to slice away the oldest ``|limit|`` and
                return the rest).

        Returns:
            List of cleanup error information
        """
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be zero or positive, not {limit}")
        self._drop_expired_cleanup_errors()
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

        ``cleanup_errors`` counts the errors of the last
        CLEANUP_ERROR_RETENTION_SECONDS: counted for the life of the process,
        one old failure kept the status at "warning" and eleven at "critical"
        with nothing in-tree ever clearing them.
        """
        async with self._subscription_lock:
            self._drop_expired_cleanup_errors()
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
            now = _utc_now()
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

        On exit the block's own registration is removed, and only that one
        (:meth:`unregister_registration`): removing by id removed a different
        subscription registered under the same id during the block, after the
        block's had been unregistered.
        """
        registered: Optional[EventSubscription] = None

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

            registered = self.get_registration(subscription_id)
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
            if registered is not None:
                try:
                    cleanup_success = await self.unregister_registration(registered)
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
            auto_cleanup_on_error: Whether the subscription is unregistered when
                the block raises. With it False the subscription stays
                registered after an error, for the caller to deal with; it used
                to be unregistered by the final cleanup anyway, so the flag
                changed nothing.

        Yields:
            Dictionary with subscription information and control methods. Its
            ``unregister`` control removes the block's own registration and
            records that it did, so leaving the block does not unregister the
            id a second time (and with it a same-id subscription registered
            after the explicit call).

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
        registered: Optional[EventSubscription] = None
        block_raised = False

        async def _unregister() -> bool:
            subscription_info["cleanup_attempted"] = True
            if registered is None:
                return False
            return await self._event_manager.unregister_registration(registered)

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
            registered = self._event_manager.get_registration(subscription_id)

            # Add control methods to subscription info
            subscription_info["unregister"] = _unregister
            subscription_info["get_info"] = lambda: (
                self._event_manager.get_subscription_info(subscription_id)
            )

            self._logger.debug(f"Managed subscription created: {subscription_id}")

            # Yield subscription info with control methods
            yield subscription_info

        except Exception as e:
            block_raised = True
            self._logger.error(
                f"Error in managed subscription {subscription_id}: {str(e)}"
            )
            if auto_cleanup_on_error and registered is not None:
                try:
                    await self._event_manager.unregister_registration(registered)
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
            # Final cleanup if not already done, and not declined for an error
            if (
                registered is not None
                and not subscription_info["cleanup_attempted"]
                and not (block_raised and not auto_cleanup_on_error)
            ):
                try:
                    await self._event_manager.unregister_registration(registered)
                    subscription_info["cleanup_attempted"] = True
                    self._logger.debug(f"Final cleanup performed for {subscription_id}")
                except Exception as cleanup_error:
                    self._logger.error(
                        f"Final cleanup failed for {subscription_id}: {str(cleanup_error)}"
                    )
