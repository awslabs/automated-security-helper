# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two MCP sessions' offline workspace scans overlap: the second stays offline.

``cli/mcp/workspace._execute`` set ``ASH_OFFLINE=YES`` for an offline scan and put back
what it saw. With two sessions' scans overlapping, the first to end put back "unset"
while the other was still scanning, and the last put back "YES", so the server stayed
offline. It now holds the variable (utils/process_env.hold_environ), as
``run_ash_scan``'s call sites do.
"""

from __future__ import annotations

import asyncio
import os
import threading
from types import SimpleNamespace

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module

WAIT = 30


class _Blockers:
    """One blocked ``execute_workspace`` call per plan, each released on its own."""

    def __init__(self):
        self.entered = {}
        self.release = {}

    def add(self, plan):
        self.entered[plan] = threading.Event()
        self.release[plan] = threading.Event()

    def __call__(self, plan, settings, **_kwargs):
        self.entered[plan].set()
        assert self.release[plan].wait(WAIT), "the test never released this scan"
        return None


def _session(plan):
    settings = SimpleNamespace(offline=True)

    def run():
        asyncio.run(workspace_module._execute(plan, settings, {}, None))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def blockers(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    stub = _Blockers()
    monkeypatch.setattr(workspace_module, "execute_workspace", stub)
    return stub


def test_the_second_session_stays_offline_after_the_first_ends(blockers):
    first_plan, second_plan = object(), object()
    blockers.add(first_plan)
    blockers.add(second_plan)

    first = _session(first_plan)
    assert blockers.entered[first_plan].wait(WAIT)
    second = _session(second_plan)
    assert blockers.entered[second_plan].wait(WAIT)

    blockers.release[first_plan].set()
    first.join(WAIT)

    assert os.environ.get("ASH_OFFLINE") == "YES", (
        "the first session's scan took offline mode away from the second's"
    )

    blockers.release[second_plan].set()
    second.join(WAIT)

    assert "ASH_OFFLINE" not in os.environ, "the server stayed offline afterwards"
