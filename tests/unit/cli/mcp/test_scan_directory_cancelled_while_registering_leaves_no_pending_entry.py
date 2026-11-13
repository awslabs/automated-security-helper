# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A directory scan cancelled while it registers leaves no pending entry.

The directory tool registers its scan in a worker thread
(``asyncio.to_thread(registry.register_scan, ...)``). A cancel of the awaiting
task cannot interrupt that thread, so the thread goes on and writes the PENDING
entry after the caller is gone. The tool's failure arm only gives back a scan
it knows it registered, so the entry stayed PENDING: it held its directory and
a ``max_concurrent_scans`` slot for the life of the server, and nothing swept
it, because only closed entries are ever cleaned up.

The tool now closes that entry as a scan that did not start as soon as the
worker thread returns.
"""

import asyncio
import threading
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_WAIT_SECONDS = 10.0


async def _until(condition):
    deadline = time.monotonic() + _WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


def test_a_start_cancelled_while_it_registers_leaves_no_pending_entry(
    tmp_path, monkeypatch
):
    """Red at the base: the entry the worker thread writes stays PENDING."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    real_register = registry.register_scan
    in_the_thread = threading.Event()
    let_it_register = threading.Event()
    seen: Dict[str, Any] = {}

    def a_registration_held_until_released(*args, **kwargs):
        in_the_thread.set()
        if not let_it_register.wait(_WAIT_SECONDS):
            raise RuntimeError("control: the registration was never released")
        return real_register(*args, **kwargs)

    registry.register_scan = a_registration_held_until_released

    async def cancel_the_start_while_the_thread_is_blocked():
        task = asyncio.ensure_future(mcp_tools.mcp_scan_directory(str(tmp_path)))
        try:
            if not await _until(in_the_thread.is_set):
                raise RuntimeError("control: the registration never started")
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # The caller is gone and the thread has registered nothing yet.
            seen["before"] = registry.get_scan_count()
        finally:
            let_it_register.set()
        # The thread now writes its entry; it is closed once the thread returns.
        seen["registered"] = await _until(lambda: registry.get_scan_count() == 1)
        seen["closed"] = await _until(lambda: registry.get_active_scan_count() == 0)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        asyncio.run(cancel_the_start_while_the_thread_is_blocked())

    # Controls: the cancel landed before the entry existed, and the thread did
    # write one afterwards, so the assertions below are about that entry.
    assert seen["before"] == 0, seen
    assert seen["registered"], "control: the worker thread never wrote its entry"
    counts = registry.get_scan_status_counts()
    assert counts[MCScanStatus.PENDING.value] == 0, counts
    assert seen["closed"], counts
    assert counts[MCScanStatus.FAILED.value] == 1, counts
    # The slot and the directory are free: a registration at a limit of one,
    # for the same directory, is admitted.
    assert real_register(
        directory_path=str(tmp_path),
        output_directory=str(tmp_path / ".ash" / "ash_output"),
        max_active=1,
    )
