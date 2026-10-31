# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Event subscription management for MCP server resource management.

This module provides the EventSubscriptionManager class for tracking and managing
event subscriptions with automatic cleanup to prevent memory leaks.
"""

import asyncio
import inspect
from typing import Dict, Iterable, List, Set, Any, Optional, Callable
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
    between them made an age an hour off. This is still the wall clock: a
    clock step (NTP, a manual set) between two readings still makes an age
    negative, or expires an error early. The snapshot tests pin this module's
    ``datetime`` to a fixed instant, which a monotonic clock would escape.
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
        # The ids whose cleanup_func is running right now (detached from the
        # registry, cleanup awaited outside the lock). register_subscription
        # refuses an id in here: with the cleanup moved outside the lock, a
        # same-id registration was admitted while the old cleanup was still
        # awaiting, and a cleanup that tears down resources keyed by the id
        # (a per-id queue, channel or file) destroyed what the new registration
        # had just set up. Mutated only on the event-loop thread between
        # awaits, so it needs no lock of its own.
        self._cleanups_running: Set[str] = set()

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
            True if registration was successful, False if subscription already
            exists, or if the cleanup of a previous subscription under this id
            is still running (retry once it has ended).

        Raises:
            MCPResourceError: If registration fails

        The metadata is copied: stored by reference, the registering caller's
        later edits to its own dict changed the registered subscription. A
        registration that fails partway (an unhashable scan_id or event_type
        raises while the indices are updated) leaves nothing behind: the stored
        entry used to stay, unindexed, while the caller was told it failed. An
        unhashable subscription_id is refused the same way, with
        MCPResourceError: it used to escape as a bare TypeError raised from
        inside the error handler.
        """
        return (
            await self._register(
                subscription_id,
                event_type,
                handler,
                cleanup_func=cleanup_func,
                scan_id=scan_id,
                metadata=metadata,
            )
            is not None
        )

    async def _register(
        self,
        subscription_id: str,
        event_type: str,
        handler: Callable,
        cleanup_func: Optional[Callable] = None,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[EventSubscription]:
        """Register a subscription and return the stored object, or None.

        :meth:`register_subscription` reports this as a bool. The context
        managers use the object itself, so that what they unregister on exit is
        the registration they made: recovered with a second lookup by id after
        the registration, a subclass or test double whose registration stores
        nothing left them with None and skipped the exit cleanup silently.
        """
        async with self._subscription_lock:
            try:
                if subscription_id in self._subscriptions:
                    self._logger.warning(
                        f"Subscription {subscription_id} already exists"
                    )
                    return None
                if subscription_id in self._cleanups_running:
                    self._logger.warning(
                        f"Subscription {subscription_id} is not registered: the "
                        "cleanup of the previous subscription under this id is "
                        "still running; retry once it has ended"
                    )
                    return None

                subscription = EventSubscription(
                    subscription_id=subscription_id,
                    event_type=event_type,
                    handler=handler,
                    cleanup_func=cleanup_func,
                    scan_id=scan_id,
                    metadata=dict(metadata) if metadata else {},
                )
                self._attach(subscription)

                self._logger.debug(
                    f"Registered event subscription: {subscription_id} "
                    f"(type: {event_type}, scan_id: {scan_id})"
                )

                return subscription

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

    def _attach(self, subscription: EventSubscription) -> None:
        """Store ``subscription`` and index it. Caller holds the lock.

        The inverse of :meth:`_detach`: ``_register`` stores a new subscription
        through it, and a bulk cleanup that is cancelled puts the subscriptions
        it never reached back through it.
        """
        subscription_id = subscription.subscription_id
        self._subscriptions[subscription_id] = subscription

        if subscription.scan_id:
            if subscription.scan_id not in self._subscriptions_by_scan:
                self._subscriptions_by_scan[subscription.scan_id] = set()
            self._subscriptions_by_scan[subscription.scan_id].add(subscription_id)

        if subscription.event_type not in self._subscriptions_by_type:
            self._subscriptions_by_type[subscription.event_type] = set()
        self._subscriptions_by_type[subscription.event_type].add(subscription_id)

    def _discard_partial_registration(
        self, subscription_id: Any, scan_id: Any, event_type: Any
    ) -> None:
        """Undo whatever register_subscription stored before it raised."""
        try:
            self._subscriptions.pop(subscription_id, None)
        except TypeError:
            # An unhashable id was never stored. Probing for it raised a second
            # TypeError from inside the error handler, which replaced the
            # MCPResourceError the caller is promised.
            return
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
        self._cleanups_running.add(subscription_id)
        try:
            outcome = subscription.cleanup_func()
            if inspect.isawaitable(outcome):
                await outcome
            self._logger.debug(f"Executed cleanup for subscription {subscription_id}")
            return None
        except Exception as e:
            self._record_cleanup_failure(subscription, str(e))
            self._logger.error(
                f"Cleanup failed for subscription {subscription_id}: {str(e)}"
            )
            return str(e)
        finally:
            self._cleanups_running.discard(subscription_id)

    async def _run_cleanup_of_one(self, subscription: EventSubscription) -> bool:
        """Run one detached subscription's cleanup for a single unregistration.

        True when the cleanup ran (or there was none), False when it raised.
        A cancellation that lands in the cleanup (a shutdown that gave the
        unregistration a deadline) goes on after recording the subscription as
        a cleanup that was interrupted: detached and cancelled partway, it was
        gone from the registry with nothing recording that its cleanup had not
        finished, as the bulk cleanups record theirs (``_restore_unreached``).
        """
        try:
            return await self._run_cleanup(subscription) is None
        except BaseException:
            self._record_cleanup_failure(
                subscription,
                "cleanup was interrupted before it finished: the unregistration "
                "was cancelled",
            )
            raise

    def _record_cleanup_failure(
        self, subscription: EventSubscription, error: str
    ) -> None:
        """Record that ``subscription``'s cleanup failed, or did not run, with ``error``."""
        self._record_cleanup_error(
            {
                "subscription_id": subscription.subscription_id,
                "event_type": subscription.event_type,
                "scan_id": subscription.scan_id,
                "error": error,
                "timestamp": _utc_now().isoformat(),
            }
        )

    def _record_cleanup_error(self, error_info: Dict[str, Any]) -> None:
        """Keep ``error_info``, dropping the expired and the oldest past MAX_CLEANUP_ERRORS.

        Expired errors are dropped here and in every reader
        (``_drop_expired_cleanup_errors``), so the counts agree: pruned by only
        two of the readers, ``get_health_status`` reported 0 errors while
        ``get_subscription_statistics`` reported 5 for the same state.
        """
        self._drop_expired_cleanup_errors()
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
            recorded: Any = error_info.get("timestamp")
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
        cleaned = await self._run_cleanup_of_one(subscription)
        self._logger.debug(f"Unregistered subscription {subscription_id}")
        return cleaned

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
        return await self._run_cleanup_of_one(subscription)

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

        A cancellation of the calling task (a shutdown that gives the bulk
        cleanup a deadline with ``asyncio.wait_for``) lands in the cleanup being
        awaited. The subscriptions after it are then put back into the registry
        (``_attach``), or recorded as cleanup errors when their id has been
        taken meanwhile, and the interrupted one is recorded too, before the
        cancellation goes on. Detached up front and never reached, they used to
        be gone from the registry, never cleaned up and nowhere recorded: a leak
        in the module that exists to prevent them, where the base code's
        per-id loop left them registered for a later cleanup to find.
        """
        reached = 0
        try:
            for reached, subscription in enumerate(detached):
                error = await self._run_cleanup(subscription)
                if error is None:
                    cleanup_results["successful_cleanups"] += 1
                else:
                    cleanup_results["failed_cleanups"] += 1
                    cleanup_results["errors"].append(
                        {
                            "subscription_id": subscription.subscription_id,
                            "error": error,
                        }
                    )
        except BaseException:
            await self._restore_unreached(detached[reached], detached[reached + 1 :])
            raise

        self._logger.info(
            f"Cleaned up {cleanup_results['successful_cleanups']}/"
            f"{cleanup_results['total_subscriptions']} {what}"
        )
        return cleanup_results

    async def _restore_unreached(
        self,
        interrupted: EventSubscription,
        unreached: List[EventSubscription],
    ) -> None:
        """Put back what a cancelled bulk cleanup never reached; see _cleanup_detached.

        ``interrupted`` is the subscription whose cleanup the cancellation
        landed in: its cleanup ran partway, so it is not put back, and a cleanup
        error names it. Each of ``unreached`` is re-attached under the lock when
        its id is free, else recorded as a cleanup that did not run.
        """
        self._record_cleanup_failure(
            interrupted,
            "cleanup was interrupted before it finished: the bulk cleanup was "
            "cancelled",
        )
        if not unreached:
            return
        async with self._subscription_lock:
            for subscription in unreached:
                if subscription.subscription_id in self._subscriptions:
                    self._record_cleanup_failure(
                        subscription,
                        "cleanup did not run: the bulk cleanup was cancelled before "
                        "it reached this subscription, and its id was registered "
                        "again meanwhile",
                    )
                    continue
                self._attach(subscription)
        self._logger.warning(
            f"Bulk cleanup cancelled: {len(unreached)} subscription(s) it never "
            "reached were put back into the registry or recorded as not cleaned up"
        )

    def _detach_all(self, subscription_ids: Iterable[str]) -> List[EventSubscription]:
        """Detach every registered subscription in ``subscription_ids``, in
        registration order. Caller holds the lock.

        The order is the registry's (insertion) order, whatever the order of
        ``subscription_ids``: the indices are sets, and ``cleanup_all`` used to
        pass a set of the keys too, so the cleanups ran in per-process hash
        order, which changes from run to run (PYTHONHASHSEED), and a teardown
        that needs an earlier-registered resource to still be up failed
        intermittently.
        """
        wanted = set(subscription_ids)
        detached = []
        for subscription_id in list(self._subscriptions):
            if subscription_id in wanted:
                subscription = self._subscriptions[subscription_id]
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
            detached = self._detach_all(self._subscriptions.keys())
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
            Dictionary with subscription statistics. ``cleanup_errors_count``
            counts the errors still in retention, as the health status does.
        """
        self._drop_expired_cleanup_errors()
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
            List of cleanup error information. The entries are copies: editing
            one does not change what the manager stored.
        """
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be zero or positive, not {limit}")
        self._drop_expired_cleanup_errors()
        if limit is None:
            return [dict(entry) for entry in self._cleanup_errors]
        if limit == 0:
            return []
        return [dict(entry) for entry in self._cleanup_errors[-limit:]]

    def clear_cleanup_errors(self) -> int:
        """Clear stored cleanup errors.

        Returns:
            Number of errors that were cleared: the ones still in retention,
            the same count every other reader gives.
        """
        self._drop_expired_cleanup_errors()
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
            self._drop_expired_cleanup_errors()
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
            # Register the subscription; what is unregistered on exit is the
            # object this stored, not a second lookup by id.
            registered = await self._register(
                subscription_id,
                event_type,
                handler,
                cleanup_func=cleanup_func,
                scan_id=scan_id,
                metadata=metadata,
            )

            if registered is None:
                raise MCPResourceError(
                    f"Failed to register subscription: {subscription_id}",
                    context={
                        "subscription_id": subscription_id,
                        "event_type": event_type,
                        "scan_id": scan_id,
                    },
                )

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
            # Register subscription; the stored object is what the controls and
            # the exit cleanup unregister, not a second lookup by id.
            registered = await self._event_manager._register(
                subscription_id,
                event_type,
                handler,
                cleanup_func=cleanup_func,
                scan_id=scan_id,
                metadata=metadata,
            )

            if registered is None:
                raise MCPResourceError(
                    f"Failed to register managed subscription: {subscription_id}",
                    context=subscription_info,
                )

            subscription_info["registered"] = True

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
