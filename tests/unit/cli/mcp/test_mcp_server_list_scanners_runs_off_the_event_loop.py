# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""list_scanners runs the scanner inventory on a worker thread.

The tool was a sync function that ran the whole inventory inline: each
scanner's dependency check in turn, then a wait on the process-wide inventory
lock, seconds during which every other session's calls stalled on the event
loop. check_installation already moved the same inventory to a thread; the
list tool now does the same.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli import mcp_server

pytestmark = pytest.mark.unit


def test_list_scanners_is_an_async_tool() -> None:
    tool = mcp_server.mcp._tool_manager.get_tool("list_scanners")
    assert tool is not None
    # Red before the fix: the tool was registered as sync.
    assert tool.is_async is True


def test_the_inventory_runs_on_a_worker_thread(monkeypatch) -> None:
    threads: List[threading.Thread] = []
    answer: List[Dict[str, Any]] = [{"name": "bandit", "enabled": True}]

    def inventory() -> list:
        threads.append(threading.current_thread())
        return answer

    monkeypatch.setattr(mcp_server, "mcp_list_scanners", inventory)

    # Red before the fix: the tool returned a list, which asyncio.run refuses.
    result = asyncio.run(mcp_server.list_scanners())

    assert result == answer
    assert threads and threads[0] is not threading.main_thread(), threads


def test_an_inventory_error_is_still_answered_as_the_error_list(monkeypatch) -> None:
    def inventory() -> list:
        raise RuntimeError("inventory broke")

    monkeypatch.setattr(mcp_server, "mcp_list_scanners", inventory)

    result = asyncio.run(mcp_server.list_scanners())

    assert result[0]["success"] is False, result
    assert "inventory broke" in result[0]["error"], result
    assert result[0]["error_type"] == "RuntimeError", result
