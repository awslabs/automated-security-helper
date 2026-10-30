#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the registry stops answering for ends the monitor.

The monitor's loop reads the scan's status from the registry on every poll.
Once the aggregated results file stopped counting as an ending, a lookup that
answers ``success: False`` (the entry was removed, or the session that owns it
ended) left ``status`` None, and the loop polled every few seconds for the rest
of its wait limit, half an hour, on a scan nobody tracked. A lookup the registry
refuses is now an ending of its own, reported to the client once.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import progress_monitor as pm

pytestmark = pytest.mark.unit


def _ctx() -> MagicMock:
    ctx = MagicMock()
    for name in ("debug", "info", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _lookup_answering(first: dict, then: dict):
    """A ``mcp_get_scan_progress`` that answers ``first`` once, then ``then``."""
    answers = iter([first])

    async def lookup(**kwargs):
        return next(answers, then)

    return lookup


class TestALostScanEndsTheMonitor:
    def test_a_refused_lookup_is_reported_once_and_the_loop_ends(self, tmp_path):
        """Red at the base: the loop polled on until the timeout warning."""
        ctx = _ctx()
        found = {"success": True, "directory_path": str(tmp_path)}
        lost = {"success": False, "error": "Scan not found: scan-1"}

        with (
            patch.object(pm, "mcp_get_scan_progress", _lookup_answering(found, lost)),
            patch.object(pm, "_MAX_WAIT_SECONDS", 2),
            patch.object(pm, "_sleep_interval_for", return_value=0),
        ):
            asyncio.run(pm.monitor_scan_progress(ctx, "scan-1"))

        assert ctx.error.await_count == 1, ctx.error.await_args_list
        assert "no longer tracked" in ctx.error.await_args.args[0]
        assert "Scan not found: scan-1" in ctx.error.await_args.args[0]
        assert ctx.warning.await_count == 0, ctx.warning.await_args_list

    def test_a_dead_connection_gets_no_lost_scan_report(self, tmp_path):
        """The report honors connection_alive like every other send of the loop."""
        ctx = _ctx()
        ctx.report_progress = AsyncMock(side_effect=RuntimeError("closed"))
        found = {"success": True, "directory_path": str(tmp_path)}
        lost = {"success": False, "error": "Scan not found: scan-1"}

        with (
            patch.object(pm, "mcp_get_scan_progress", _lookup_answering(found, lost)),
            patch.object(pm, "_MAX_WAIT_SECONDS", 2),
            patch.object(pm, "_sleep_interval_for", return_value=0),
        ):
            asyncio.run(pm.monitor_scan_progress(ctx, "scan-1"))

        assert ctx.error.await_count == 0, ctx.error.await_args_list
        assert ctx.warning.await_count == 0, ctx.warning.await_args_list

    def test_a_scan_that_ends_is_still_reported_by_its_status(self, tmp_path):
        """Control: a lookup that succeeds with a terminal status ends as before."""
        ctx = _ctx()
        found = {"success": True, "directory_path": str(tmp_path)}
        cancelled = {"success": True, "status": "cancelled"}

        with (
            patch.object(
                pm, "mcp_get_scan_progress", _lookup_answering(found, cancelled)
            ),
            patch.object(pm, "_sleep_interval_for", return_value=0),
        ):
            asyncio.run(pm.monitor_scan_progress(ctx, "scan-1"))

        ctx.info.assert_any_await("Scan was cancelled.")
        assert ctx.error.await_count == 0, ctx.error.await_args_list
