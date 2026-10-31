# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The directory tool registers its scan off the event loop.

``ScanRegistry.register_scan`` waits for an output-tree removal still in
progress for the same directory (a previous scan's cleanup deletes the tree
behind a per-entry event). The directory tool called it synchronously inside
its coroutine, so that wait ran on the event loop's thread and froze every
other request of the server for as long as the delete took; a delete that
never ended froze them for good. The registration now runs in a worker thread,
as the tool's other registry work does, so the loop keeps serving while a
registration waits.
"""

import asyncio
import threading
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger
from tests.utils.scan_task_stubs import end_the_scans_scope_as_its_task_would

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"


def _a_start_that_never_runs(scan_id, runner, **_start_options):
    # The scan itself is not the subject: the task is closed unrun, and the
    # scope ends as the task's completion would end it.
    runner.close()
    end_the_scans_scope_as_its_task_would()


def test_the_registration_runs_in_a_worker_thread(tmp_path, monkeypatch):
    """Red at the base: register_scan ran on the thread that runs the loop."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    real_register = registry.register_scan
    seen = {}

    def a_registration_that_notes_its_thread(*args, **kwargs):
        seen["thread"] = threading.get_ident()
        return real_register(*args, **kwargs)

    registry.register_scan = a_registration_that_notes_its_thread

    async def start_and_note_the_loops_thread():
        seen["loop_thread"] = threading.get_ident()
        return await mcp_tools.mcp_scan_directory(str(tmp_path))

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_a_start_that_never_runs),
    ):
        started = asyncio.run(start_and_note_the_loops_thread())

    if started.get("success") is not True:
        raise RuntimeError(("control: the scan did not start", started))
    assert "thread" in seen, "control: the registration was never called"
    assert seen["thread"] != seen["loop_thread"], (
        "register_scan ran on the event loop's thread"
    )
