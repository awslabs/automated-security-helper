# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stopped scan's directory stays held while a tool its stop could not end runs.

A stopped scan's entry keeps its directory while its runner settles
(``occupies_its_directory``), and the runner's finish freed it. A scanner tool
the stop could not end runs on its own clock, past that finish, and writes into
the output directory: ``register_scan`` admitted a new scan of the same
directory the moment the runner was done, and ``cleanup_scan`` dropped the entry,
so the new scan's output could be overwritten by a tool the old scan's client
had only been warned about, and a client of another session was never warned
at all. The entry now keeps the ``(tool, pid)`` pairs the stop left behind,
holds the directory while any of those processes is still running, refuses a
rescan with a reason that names the tools, and is kept by cleanup until they
are gone.

The liveness probe is replaced by a table of pids, so no process is started or
signalled; one test asks the real probe about this process.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.core.resource_management import scan_registry
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit

BANDIT_PID = 4242


@pytest.fixture()
def alive(monkeypatch) -> Dict[int, bool]:
    """Which pids the probe reports running; a pid not listed is gone."""
    table: Dict[int, bool] = {}
    monkeypatch.setattr(
        scan_registry, "_tool_may_be_running", lambda pid: table.get(pid, False)
    )
    return table


def _a_stopped_scan_whose_tool_survived(
    tmp_path: Path, session_id: str = "owner"
) -> tuple[ScanRegistry, str, Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    output = project / ".ash" / "ash_output"
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(output),
        session_id=session_id,
    )
    entry = registry.get_scan(scan_id)
    entry.has_runner = True
    entry.mark_running()
    assert registry.cancel_scan(scan_id) is True
    # The thread that ran the scan records the tool, then lets the runner go.
    assert registry.record_cancel_outcome(scan_id, (("bandit", BANDIT_PID),)) is True
    entry.runner_done.set()
    return registry, scan_id, project, output


def test_the_directory_stays_held_while_the_tool_runs(tmp_path, alive):
    """Red at the base: runner_done freed the directory, so the rescan was
    admitted and cleanup dropped the entry while the tool still ran."""
    alive[BANDIT_PID] = True
    registry, scan_id, project, output = _a_stopped_scan_whose_tool_survived(tmp_path)
    entry = registry.get_scan(scan_id)

    assert entry.status == MCScanStatus.CANCELLED
    assert entry.occupies_its_directory() is True

    with pytest.raises(MCPResourceError) as refused:
        registry.register_scan(
            directory_path=str(project),
            output_directory=str(output),
            session_id="owner",
        )
    message = str(refused.value)
    assert "may still be running" in message, message
    assert "bandit" in message, message
    assert str(BANDIT_PID) not in message, message

    assert registry.cleanup_scan(scan_id) is False
    assert registry.get_scan(scan_id) is not None
    assert registry.cleanup_completed_scans(max_age_hours=0) == 0
    assert registry.get_scan(scan_id) is not None


def test_another_session_is_told_the_directory_is_busy_and_nothing_more(
    tmp_path, alive
):
    """The hold protects every session's scan of the directory; the other
    session learns it is busy, not what happened to a scan it cannot see."""
    alive[BANDIT_PID] = True
    registry, scan_id, project, output = _a_stopped_scan_whose_tool_survived(tmp_path)

    with pytest.raises(MCPResourceError) as refused:
        registry.register_scan(
            directory_path=str(project),
            output_directory=str(output),
            session_id="someone-else",
        )
    message = str(refused.value)
    assert "already has an active scan" in message, message
    assert "bandit" not in message, message
    assert scan_id not in message, message


def test_the_directory_frees_once_the_tool_is_gone(tmp_path, alive):
    registry, scan_id, project, output = _a_stopped_scan_whose_tool_survived(tmp_path)
    entry = registry.get_scan(scan_id)
    assert BANDIT_PID not in alive

    assert entry.occupies_its_directory() is False
    rescan = registry.register_scan(
        directory_path=str(project),
        output_directory=str(output),
        session_id="owner",
    )
    assert rescan != scan_id
    assert registry.cleanup_scan(scan_id) is True


def test_a_stopped_scan_with_no_surviving_tool_frees_as_before(tmp_path, alive):
    """Control: the hold is for a recorded tool only; a clean stop frees the
    directory the moment the runner is done, as it always did."""
    project = tmp_path / "project"
    project.mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(project / ".ash" / "ash_output"),
        session_id="owner",
    )
    entry = registry.get_scan(scan_id)
    entry.has_runner = True
    entry.mark_running()
    registry.cancel_scan(scan_id)
    assert entry.occupies_its_directory() is True
    entry.runner_done.set()

    assert entry.could_not_stop == ()
    assert entry.occupies_its_directory() is False
    assert registry.cleanup_scan(scan_id) is True


def test_the_probe_reads_this_process_as_running():
    assert scan_registry._tool_may_be_running(os.getpid()) is True


def test_the_probe_reads_no_process_for_a_pid_that_is_not_a_process():
    assert scan_registry._tool_may_be_running(0) is False
    assert scan_registry._tool_may_be_running(-1) is False


@pytest.mark.skipif(sys.platform != "linux", reason="the pid range read is Linux's")
def test_the_probe_reads_no_process_past_the_pid_range():
    # Above pid_max (at most 2**22 on Linux): no process can hold it.
    assert scan_registry._tool_may_be_running(2**31 - 1) is False
