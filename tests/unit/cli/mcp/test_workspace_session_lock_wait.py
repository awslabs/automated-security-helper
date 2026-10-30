#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The wait for a session's scan lock is bounded and a cancel ends it.

A workspace scan of a session runs under that session's scan lock, and the
scan's clock starts once the lock is held. The wait for the lock had no bound
and no way out: a scan queued behind another scan of its session kept its
RUNNING registry entries and its place in the concurrent-scan limit for the
whole wait, ``scan_timeout_seconds`` did not apply, and a cancel could not
interrupt the blocking acquire. The wait is now taken in slices: a set cancel
event ends it as a cancel, and the caller's scan timeout bounds it, after which
the scan is refused as busy rather than started late.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.cancellation import ScanCancelled

pytestmark = pytest.mark.unit


class TestTheWaitForTheSessionLock:
    def test_a_lock_another_scan_holds_past_the_bound_refuses_as_busy(self):
        """Red at the base: there was no bound and no such refusal."""
        lock = threading.Lock()
        assert lock.acquire(blocking=False)
        try:
            started = time.monotonic()
            with pytest.raises(workspace_module.WorkspaceSessionBusy, match="busy-s"):
                workspace_module._acquire_session_lock(
                    lock, "busy-s", stop=None, wait_seconds=0.3
                )
            assert time.monotonic() - started < 5
            # The holder still holds it: the refusal took nothing.
            assert lock.locked()
        finally:
            lock.release()

    def test_a_cancel_ends_the_wait(self):
        """Red at the base: the blocking acquire read no cancel event."""
        lock = threading.Lock()
        assert lock.acquire(blocking=False)
        stop = threading.Event()
        threading.Timer(0.1, stop.set).start()
        try:
            started = time.monotonic()
            with pytest.raises(ScanCancelled, match="cancel-s"):
                workspace_module._acquire_session_lock(
                    lock, "cancel-s", stop=stop, wait_seconds=None
                )
            assert time.monotonic() - started < 5
            assert lock.locked()
        finally:
            lock.release()

    def test_a_lock_that_frees_within_the_bound_is_taken(self):
        """Control: a holder that finishes in time hands the lock over."""
        lock = threading.Lock()
        assert lock.acquire(blocking=False)
        threading.Timer(0.1, lock.release).start()

        workspace_module._acquire_session_lock(
            lock, "free-s", stop=None, wait_seconds=5
        )

        assert lock.locked()
        lock.release()

    def test_the_run_releases_the_lock_it_took(self):
        """Control: ``_under_session_lock`` takes the lock around the run and
        gives it back, with the clock started once it is held."""
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry,
            reset_default_registry_for_tests,
        )

        reset_default_registry_for_tests()
        try:
            session = get_default_registry().session_for("release-s")
            order = []
            settings = MagicMock(offline=False)

            with patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda *a, **k: order.append("ran"),
            ):
                workspace_module._under_session_lock(
                    "release-s",
                    MagicMock(),
                    settings,
                    on_locked=lambda: order.append("clock started"),
                    stop=threading.Event(),
                    wait_seconds=5,
                )

            assert order == ["clock started", "ran"]
            assert session.lock.acquire(blocking=False)
            session.lock.release()
        finally:
            reset_default_registry_for_tests()

    def test_a_busy_refusal_is_answered_as_session_busy(self):
        response = workspace_module._error_response(
            workspace_module.WorkspaceSessionBusy("another scan holds the lock"),
            "scan_workspace",
        )

        assert response["success"] is False
        assert response["error_type"] == "session_busy"
        assert "another scan holds the lock" in response["error"]
