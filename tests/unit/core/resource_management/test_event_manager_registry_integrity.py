# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The event subscription manager keeps its registry consistent with what it reports.

Each test is pinned against the behavior it replaced:

* Metadata was stored and returned by reference, so a caller's later edits to
  its own dict, or to the returned info, changed the registered subscription.
* ``register_subscription`` stored the entry before indexing it and had no
  rollback, so an indexing error left a half-registered subscription while the
  caller was told registration failed.
* The bulk cleanups snapshotted ids under the lock, released it and unregistered
  each id in turn: a same-id subscription registered meanwhile under another
  scan was removed, one removed meanwhile counted as a failed cleanup, and a
  cleanup that raised was counted with an empty ``errors`` list.
* Cleanup errors grew without bound and counted toward the health status for
  the life of the process.
* ``get_cleanup_errors`` with a negative limit returned all but the oldest.
* The context managers unregistered by id on exit, removing a same-id
  subscription registered after their own was unregistered; the managed
  subscription's ``unregister`` control did not record that it ran; and
  ``auto_cleanup_on_error=False`` still unregistered on error.
* Ages and timestamps came from the naive local clock.
* The bulk cleanups ran in hash order (a set of the keys), detached their whole
  set before any cleanup ran so a cancellation lost every cleanup it had not
  reached, admitted a same-id registration while the old cleanup still ran,
  raised a bare TypeError for an unhashable id, pruned expired cleanup errors in
  only two of their readers, and the context managers recovered their own
  registration with a second lookup by id.
* A single unregistration cancelled while its cleanup ran left the subscription
  gone from the registry with no record that the cleanup had not finished.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from automated_security_helper.core.resource_management import event_manager
from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionContextManager,
    EventSubscriptionManager,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)

pytestmark = pytest.mark.unit


async def _register(manager, subscription_id, scan_id="scan", cleanup_func=None, **kw):
    return await manager.register_subscription(
        subscription_id=subscription_id,
        event_type=kw.pop("event_type", "scan_progress"),
        handler=lambda event: None,
        cleanup_func=cleanup_func,
        scan_id=scan_id,
        **kw,
    )


class TestMetadataIsNotAliased:
    @pytest.mark.asyncio
    async def test_the_callers_later_edits_do_not_reach_the_registry(self):
        manager = EventSubscriptionManager()
        metadata = {"owner": "a"}
        await _register(manager, "sub", metadata=metadata)

        metadata["owner"] = "b"

        assert manager.get_subscription_info("sub")["metadata"] == {"owner": "a"}

    @pytest.mark.asyncio
    async def test_editing_the_returned_info_does_not_reach_the_registry(self):
        manager = EventSubscriptionManager()
        await _register(manager, "sub", metadata={"owner": "a"})

        manager.get_subscription_info("sub")["metadata"]["owner"] = "b"

        assert manager.get_subscription_info("sub")["metadata"] == {"owner": "a"}


class TestAFailedRegistrationLeavesNothingBehind:
    @pytest.mark.asyncio
    async def test_an_unhashable_scan_id_registers_nothing(self):
        manager = EventSubscriptionManager()

        with pytest.raises(MCPResourceError):
            await _register(manager, "sub", scan_id=["not", "hashable"])

        assert manager.get_subscription_info("sub") is None
        assert manager.get_subscription_statistics()["total_subscriptions"] == 0
        assert manager.get_all_subscriptions() == []


class TestBulkCleanupDetachesThenCleans:
    @pytest.mark.asyncio
    async def test_a_same_id_subscription_registered_during_cleanup_survives(self):
        manager = EventSubscriptionManager()

        async def a_cleans_up():
            # A's cleanup removes B itself and re-registers the id under
            # another scan, as a handler reacting to the cleanup might.
            await manager.unregister_subscription("b")
            await _register(manager, "b", scan_id="other-scan")

        await _register(manager, "a", scan_id="scan", cleanup_func=a_cleans_up)
        await _register(manager, "b", scan_id="scan")

        results = await manager.cleanup_all_subscriptions()

        assert (results["successful_cleanups"], results["failed_cleanups"]) == (2, 0)
        survivor = manager.get_subscription_info("b")
        assert survivor is not None
        assert survivor["scan_id"] == "other-scan"

    @pytest.mark.asyncio
    async def test_a_subscription_removed_meanwhile_is_not_a_failed_cleanup(self):
        manager = EventSubscriptionManager()

        async def a_cleans_up():
            await manager.unregister_subscription("b")

        await _register(manager, "a", scan_id="scan", cleanup_func=a_cleans_up)
        await _register(manager, "b", scan_id="scan")

        # cleanup_all visits in registration order, so A's cleanup runs first
        # and removes B before the loop reaches it.
        results = await manager.cleanup_all_subscriptions()

        assert results["total_subscriptions"] == 2
        assert results["failed_cleanups"] == 0
        assert results["successful_cleanups"] == 2
        assert manager.get_subscriptions_by_scan("scan") == []

    @pytest.mark.asyncio
    async def test_a_cleanup_that_raises_is_named_in_the_errors(self):
        manager = EventSubscriptionManager()

        def broken():
            raise RuntimeError("socket already closed")

        await _register(manager, "a", scan_id="scan", cleanup_func=broken)

        results = await manager.cleanup_subscriptions_by_type("scan_progress")

        assert results["failed_cleanups"] == 1
        assert results["errors"] == [
            {"subscription_id": "a", "error": "socket already closed"}
        ]


class TestCleanupErrorsAreBoundedAndExpire:
    @pytest.mark.asyncio
    async def test_only_the_newest_errors_are_kept(self):
        manager = EventSubscriptionManager()

        def broken():
            raise RuntimeError("boom")

        for index in range(event_manager.MAX_CLEANUP_ERRORS + 50):
            await _register(manager, f"sub-{index}", cleanup_func=broken)
            await manager.unregister_subscription(f"sub-{index}")

        errors = manager.get_cleanup_errors()

        assert len(errors) == event_manager.MAX_CLEANUP_ERRORS
        assert (
            errors[-1]["subscription_id"]
            == f"sub-{event_manager.MAX_CLEANUP_ERRORS + 49}"
        )

    @pytest.mark.asyncio
    async def test_an_old_error_no_longer_drives_the_health_status(self):
        manager = EventSubscriptionManager()

        def broken():
            raise RuntimeError("boom")

        await _register(manager, "sub", cleanup_func=broken)
        await manager.unregister_subscription("sub")
        assert (await manager.get_health_status())["status"] == "warning"

        stale = datetime.now(timezone.utc) - timedelta(
            seconds=event_manager.CLEANUP_ERROR_RETENTION_SECONDS + 60
        )
        manager._cleanup_errors[0]["timestamp"] = stale.isoformat()

        health = await manager.get_health_status()

        assert health["status"] == "healthy"
        assert health["cleanup_errors"] == 0
        assert manager.get_cleanup_errors() == []

    def test_a_negative_limit_is_refused(self):
        manager = EventSubscriptionManager()

        with pytest.raises(ValueError):
            manager.get_cleanup_errors(limit=-1)


class TestContextManagersRemoveOnlyTheirOwnRegistration:
    @pytest.mark.asyncio
    async def test_subscription_context_leaves_a_same_id_successor_alone(self):
        manager = EventSubscriptionManager()

        async with manager.subscription_context(
            subscription_id="sub", event_type="scan_progress", handler=lambda e: None
        ):
            await manager.unregister_subscription("sub")
            await _register(manager, "sub", scan_id="successor")

        survivor = manager.get_subscription_info("sub")
        assert survivor is not None
        assert survivor["scan_id"] == "successor"

    @pytest.mark.asyncio
    async def test_the_explicit_unregister_control_is_not_repeated_on_exit(self):
        manager = EventSubscriptionManager()
        managed = EventSubscriptionContextManager(manager)

        async with managed.managed_subscription(
            subscription_id="sub", event_type="scan_progress", handler=lambda e: None
        ) as info:
            assert await info["unregister"]() is True
            assert info["cleanup_attempted"] is True
            await _register(manager, "sub", scan_id="successor")

        survivor = manager.get_subscription_info("sub")
        assert survivor is not None
        assert survivor["scan_id"] == "successor"

    @pytest.mark.asyncio
    async def test_auto_cleanup_off_keeps_the_subscription_after_an_error(self):
        manager = EventSubscriptionManager()
        managed = EventSubscriptionContextManager(manager)

        with pytest.raises(RuntimeError):
            async with managed.managed_subscription(
                subscription_id="sub",
                event_type="scan_progress",
                handler=lambda e: None,
                auto_cleanup_on_error=False,
            ):
                raise RuntimeError("handler blew up")

        assert manager.get_subscription_info("sub") is not None


class TestTimesAreTimezoneAware:
    @pytest.mark.asyncio
    async def test_created_at_and_error_timestamps_carry_a_zone(self):
        manager = EventSubscriptionManager()

        def broken():
            raise RuntimeError("boom")

        await _register(manager, "sub", cleanup_func=broken)
        created_at = datetime.fromisoformat(
            manager.get_subscription_info("sub")["created_at"]
        )
        # Read while the subscription is registered: the ages are taken from
        # its zone-aware created_at against the zone-aware clock, so a naive
        # created_at would raise here and a skewed one would be negative.
        usage = await manager.get_resource_usage()
        await manager.unregister_subscription("sub")
        recorded = datetime.fromisoformat(manager.get_cleanup_errors()[0]["timestamp"])

        assert created_at.tzinfo is not None
        assert recorded.tzinfo is not None
        ages = usage["subscription_ages"]
        assert ages["count"] == 1
        assert ages["min_seconds"] >= 0
        assert ages["max_seconds"] >= ages["min_seconds"]
        assert ages["max_seconds"] < 60


class TestBulkCleanupRunsInRegistrationOrder:
    """cleanup_all passed a set of the keys, and the two indices are sets, so the
    cleanups ran in per-process hash order (PYTHONHASHSEED): a teardown that
    needs an earlier-registered resource to still be up failed intermittently."""

    @staticmethod
    def _recording(ran, name):
        def cleanup():
            ran.append(name)

        return cleanup

    @pytest.mark.asyncio
    async def test_cleanup_all_visits_in_registration_order(self):
        manager = EventSubscriptionManager()
        ran = []
        names = [f"sub-{index}" for index in range(12)]
        for name in names:
            await _register(manager, name, cleanup_func=self._recording(ran, name))

        await manager.cleanup_all_subscriptions()

        assert ran == names

    @pytest.mark.asyncio
    async def test_the_scan_and_type_cleanups_visit_in_registration_order(self):
        manager = EventSubscriptionManager()
        ran = []
        names = [f"sub-{index}" for index in range(12)]
        for name in names:
            await _register(
                manager,
                name,
                scan_id="scan",
                event_type="findings",
                cleanup_func=self._recording(ran, name),
            )

        await manager.cleanup_subscriptions_by_scan("scan")
        by_scan = list(ran)
        ran.clear()
        for name in names:
            await _register(
                manager,
                name,
                scan_id="scan",
                event_type="findings",
                cleanup_func=self._recording(ran, name),
            )
        await manager.cleanup_subscriptions_by_type("findings")

        assert by_scan == names
        assert ran == names


class TestACancelledBulkCleanupKeepsWhatItNeverReached:
    """The bulk cleanups detach their whole set before any cleanup runs; a
    cancellation of the calling task (a shutdown with a deadline on
    cleanup_all) landed in the awaited cleanup, and every subscription after it
    was gone from the registry, never cleaned up and recorded nowhere."""

    @staticmethod
    async def _cancel_during_the_first_cleanup(manager, started):
        task = asyncio.create_task(manager.cleanup_all_subscriptions())
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_the_unreached_subscriptions_are_put_back(self):
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()
        ran = []

        async def blocks():
            started.set()
            await release.wait()

        await _register(manager, "a", cleanup_func=blocks)
        await _register(
            manager, "b", scan_id="scan", cleanup_func=lambda: ran.append("b")
        )
        await _register(
            manager, "c", scan_id="scan", cleanup_func=lambda: ran.append("c")
        )

        await self._cancel_during_the_first_cleanup(manager, started)

        # The interrupted one is gone and recorded; the rest are back as they were.
        assert manager.get_subscription_info("a") is None
        assert manager.get_subscription_info("b") is not None
        assert manager.get_subscription_info("c") is not None
        assert manager.get_subscriptions_by_scan("scan") != []
        assert ran == []
        errors = manager.get_cleanup_errors()
        assert [e["subscription_id"] for e in errors] == ["a"]
        assert "cancelled" in errors[0]["error"]

        # A later bulk cleanup finds them, in order.
        results = await manager.cleanup_all_subscriptions()
        assert results["total_subscriptions"] == 2
        assert ran == ["b", "c"]

    @pytest.mark.asyncio
    async def test_an_id_registered_again_meanwhile_is_recorded_not_overwritten(self):
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()

        async def blocks():
            # Before blocking, a handler re-registers c's id under another scan.
            await _register(manager, "c", scan_id="other")
            started.set()
            await release.wait()

        await _register(manager, "a", cleanup_func=blocks)
        await _register(manager, "b", scan_id="scan")
        await _register(manager, "c", scan_id="scan")

        await self._cancel_during_the_first_cleanup(manager, started)

        assert manager.get_subscription_info("b")["scan_id"] == "scan"
        assert manager.get_subscription_info("c")["scan_id"] == "other"
        recorded = {
            e["subscription_id"]: e["error"] for e in manager.get_cleanup_errors()
        }
        assert set(recorded) == {"a", "c"}
        assert "did not run" in recorded["c"]


class TestACancelledUnregistrationRecordsItsInterruptedCleanup:
    """A single unregistration detaches the subscription before its cleanup
    runs. A cancellation that landed in the cleanup left the subscription gone
    from the registry with nothing recording that its cleanup had not
    finished; the bulk cleanups record theirs."""

    @staticmethod
    async def _cancel_while_cleaning(unregister, started):
        task = asyncio.create_task(unregister())
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @staticmethod
    def _assert_recorded_once(manager):
        errors = manager.get_cleanup_errors()
        assert [e["subscription_id"] for e in errors] == ["a"]
        assert "interrupted" in errors[0]["error"]
        assert "cancelled" in errors[0]["error"]

    @pytest.mark.asyncio
    async def test_unregister_subscription(self):
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()

        async def blocks():
            started.set()
            await release.wait()

        await _register(manager, "a", cleanup_func=blocks)

        await self._cancel_while_cleaning(
            lambda: manager.unregister_subscription("a"), started
        )

        assert manager.get_subscription_info("a") is None
        self._assert_recorded_once(manager)

    @pytest.mark.asyncio
    async def test_unregister_registration(self):
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()

        async def blocks():
            started.set()
            await release.wait()

        await _register(manager, "a", cleanup_func=blocks)
        registered = manager.get_registration("a")

        await self._cancel_while_cleaning(
            lambda: manager.unregister_registration(registered), started
        )

        assert manager.get_subscription_info("a") is None
        self._assert_recorded_once(manager)

    @pytest.mark.asyncio
    async def test_a_cleanup_that_finishes_records_nothing(self):
        """The control: an uninterrupted unregistration adds no error."""
        manager = EventSubscriptionManager()
        await _register(manager, "a", cleanup_func=lambda: None)

        assert await manager.unregister_subscription("a") is True
        assert manager.get_cleanup_errors() == []


class TestAnUnhashableSubscriptionIdIsRefusedAsAResourceError:
    @pytest.mark.asyncio
    async def test_the_documented_error_is_raised_and_nothing_is_stored(self):
        """The membership test raised TypeError, and the rollback's pop raised
        it again from inside the handler, so the caller got a chained TypeError
        where the contract promises MCPResourceError."""
        manager = EventSubscriptionManager()

        with pytest.raises(MCPResourceError):
            await _register(manager, ["not", "hashable"])

        assert manager.get_subscription_statistics()["total_subscriptions"] == 0
        assert manager.get_all_subscriptions() == []


class TestAnIdIsNotReusedWhileItsCleanupRuns:
    @pytest.mark.asyncio
    async def test_a_registration_during_the_old_cleanup_is_refused_then_admitted(self):
        """With the cleanup moved outside the lock, a same-id registration was
        admitted while the old cleanup_func was still awaiting; a cleanup that
        tears down resources keyed by the id destroyed what the new registration
        had just set up."""
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()

        async def slow():
            started.set()
            await release.wait()

        await _register(manager, "sub", cleanup_func=slow)
        unregistering = asyncio.create_task(manager.unregister_subscription("sub"))
        try:
            await asyncio.wait_for(started.wait(), 5)

            assert await _register(manager, "sub") is False
            assert manager.get_subscription_info("sub") is None
        finally:
            release.set()
        assert await asyncio.wait_for(unregistering, 5) is True

        assert await _register(manager, "sub") is True

    @pytest.mark.asyncio
    async def test_another_id_is_admitted_during_a_cleanup(self):
        """The control: only the id whose cleanup runs is held."""
        manager = EventSubscriptionManager()
        started, release = asyncio.Event(), asyncio.Event()

        async def slow():
            started.set()
            await release.wait()

        await _register(manager, "sub", cleanup_func=slow)
        unregistering = asyncio.create_task(manager.unregister_subscription("sub"))
        try:
            await asyncio.wait_for(started.wait(), 5)
            assert await _register(manager, "other") is True
        finally:
            release.set()
        assert await asyncio.wait_for(unregistering, 5) is True


class TestEveryReaderOfCleanupErrorsAgreesOnTheCount:
    @pytest.mark.asyncio
    async def test_an_expired_error_is_counted_by_no_reader(self):
        """Pruned by get_cleanup_errors and get_health_status only, the health
        status reported 0 errors while the statistics and the resource usage
        reported 1 for the same state, and clear_cleanup_errors counted it."""
        manager = EventSubscriptionManager()

        def broken():
            raise RuntimeError("boom")

        await _register(manager, "sub", cleanup_func=broken)
        await manager.unregister_subscription("sub")
        assert manager.get_subscription_statistics()["cleanup_errors_count"] == 1
        stale = datetime.now(timezone.utc) - timedelta(
            seconds=event_manager.CLEANUP_ERROR_RETENTION_SECONDS + 60
        )
        manager._cleanup_errors[0]["timestamp"] = stale.isoformat()

        assert manager.get_subscription_statistics()["cleanup_errors_count"] == 0
        assert (await manager.get_resource_usage())["cleanup_errors_stored"] == 0
        assert (await manager.get_health_status())["cleanup_errors"] == 0
        assert manager.clear_cleanup_errors() == 0


class TestTheContextManagersUnregisterTheObjectTheyStored:
    """The context managers recovered their registration with a second lookup
    by id after registering; a manager whose registration stored nothing left
    them with None and they skipped the exit cleanup silently."""

    @pytest.mark.asyncio
    async def test_subscription_context_needs_no_second_lookup(self, monkeypatch):
        manager = EventSubscriptionManager()
        ran = []
        monkeypatch.setattr(manager, "get_registration", lambda subscription_id: None)

        async with manager.subscription_context(
            subscription_id="sub",
            event_type="scan_progress",
            handler=lambda e: None,
            cleanup_func=lambda: ran.append("ran"),
        ):
            assert manager.get_subscription_info("sub") is not None

        assert ran == ["ran"]
        assert manager.get_subscription_info("sub") is None

    @pytest.mark.asyncio
    async def test_managed_subscription_needs_no_second_lookup(self, monkeypatch):
        manager = EventSubscriptionManager()
        managed = EventSubscriptionContextManager(manager)
        ran = []
        monkeypatch.setattr(manager, "get_registration", lambda subscription_id: None)

        async with managed.managed_subscription(
            subscription_id="sub",
            event_type="scan_progress",
            handler=lambda e: None,
            cleanup_func=lambda: ran.append("ran"),
        ) as info:
            assert info["registered"] is True

        assert ran == ["ran"]
        assert manager.get_subscription_info("sub") is None
