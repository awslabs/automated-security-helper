# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stopped workspace scan tells every project which scanner tools would not end.

The workspace's projects run under their entries' cancel events, each chained
to the run's own `stop` event, and the subprocess layer records a tool a stop
could not end on the chain's root: `stop`. The timeout closes the project
entries FAILED and sets `stop`; the run's next check raises a ScanCancelled
carrying the records, and the tool's ``except ScanCancelled`` arm caught it
bare: the records went nowhere, and every project read back as a plain timeout
while a tool might still write into its output directory. The records are now
attached to each stopped project's entry, before the thread lets the
directories go and again once the task has closed the entries, whichever runs
first.

``execute_workspace`` is replaced by a stand-in that does what the real timeout
does around the run: it closes each project's entry FAILED with the timeout's
reason and sets its event, records one tool on the run's `stop` event, sets it,
and ends at the run's next check. No process starts; the projects are empty
directories under the test's tmp_path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Tuple

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.cancellation import (
    current_cancel_event,
    raise_if_cancelled,
)
from automated_security_helper.core.resource_management import (
    scan_registry as scan_registry_module,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    get_scan_registry,
)

pytestmark = pytest.mark.unit

_PROJECTS = ("api", "web")
TIMEOUT_REASON = "Workspace scan exceeded the server's limit and was cancelled"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """No confinement (not what these tests measure) and a registry of this
    test's own, so another test's entries cannot hold a directory here."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(scan_registry_module, "_scan_registry", ScanRegistry())


@pytest.fixture()
def workspace_file(tmp_path: Path) -> Path:
    for name in _PROJECTS:
        (tmp_path / name).mkdir()
    path = tmp_path / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name} for name in _PROJECTS]}),
        encoding="utf-8",
    )
    return path


def _a_run_the_timeout_stops(surviving: Tuple[Tuple[str, int], ...]):
    def run(plan: Any, settings: Any, **kwargs: Any) -> Any:
        registry = get_scan_registry()
        active = registry.list_scans(active_only=True)
        assert active, "control: the projects were not registered"
        for scan in active:
            # _stop_at_timeout: the entry closed FAILED with the reason, then
            # its event set.
            registry.finish_scan(scan["scan_id"], MCScanStatus.FAILED, TIMEOUT_REASON)
            registry.get_scan(scan["scan_id"]).cancel_event.set()
        stop = current_cancel_event()
        assert stop is not None, "control: the run has no cancel scope"
        for tool, pid in surviving:
            # The subprocess layer's record for a child that would not end.
            stop.note_could_not_stop(tool, pid)
        stop.set()
        raise_if_cancelled()
        raise AssertionError("control: the run was not stopped")

    return run


def _stopped_answer(workspace_file: Path) -> dict:
    answer = asyncio.run(
        workspace_module.mcp_scan_workspace(workspace_file=str(workspace_file))
    )
    assert answer.get("success") is False, answer
    assert set(answer.get("scan_ids", {})) == set(_PROJECTS), answer
    return answer


def test_every_stopped_project_names_the_tool_the_stop_could_not_end(
    workspace_file, monkeypatch
):
    """Red at the base: the arm caught the ScanCancelled bare, so each
    project's entry read FAILED with the timeout and no warning."""
    monkeypatch.setattr(
        workspace_module,
        "execute_workspace",
        _a_run_the_timeout_stops((("bandit", 4242),)),
    )

    answer = _stopped_answer(workspace_file)

    registry = get_scan_registry()
    for key, scan_id in answer["scan_ids"].items():
        entry = registry.get_scan(scan_id)
        assert entry.status == MCScanStatus.FAILED, (key, entry.status)
        assert entry.error_message == TIMEOUT_REASON, (key, entry.error_message)
        assert any("bandit" in w and "4242" in w for w in entry.warnings), (
            key,
            entry.warnings,
        )
        assert entry.could_not_stop == (("bandit", 4242),), key
        # One warning per stopped project, not one per place the record ran.
        assert sum("bandit" in w for w in entry.warnings) == 1, (key, entry.warnings)


def test_on_a_network_transport_the_warning_names_the_tool_not_its_pid(
    workspace_file, monkeypatch
):
    monkeypatch.setattr(
        workspace_module,
        "execute_workspace",
        _a_run_the_timeout_stops((("bandit", 4242),)),
    )
    # The pid is withheld from a remote caller, which the workspace module now
    # reads per session (caller_is_remote), not from the transport alone: a
    # stand-in that answers True for every session is the network transport.
    monkeypatch.setattr(workspace_module, "caller_is_remote", lambda session_id: True)

    answer = _stopped_answer(workspace_file)

    registry = get_scan_registry()
    for key, scan_id in answer["scan_ids"].items():
        entry = registry.get_scan(scan_id)
        named = [w for w in entry.warnings if "bandit" in w]
        assert named, (key, entry.warnings)
        assert all("4242" not in w for w in named), (key, named)
        assert entry.could_not_stop == (("bandit", 4242),), key


def test_a_stop_that_ended_every_tool_adds_no_warning(workspace_file, monkeypatch):
    """Control: a timeout with nothing left running stays a plain timeout."""
    monkeypatch.setattr(
        workspace_module, "execute_workspace", _a_run_the_timeout_stops(())
    )

    answer = _stopped_answer(workspace_file)

    registry = get_scan_registry()
    for key, scan_id in answer["scan_ids"].items():
        entry = registry.get_scan(scan_id)
        assert entry.status == MCScanStatus.FAILED, (key, entry.status)
        assert entry.warnings == [], (key, entry.warnings)
        assert entry.could_not_stop == (), key
