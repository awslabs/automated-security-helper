# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""remove_output_of_scan refuses the two cases that are about the entry itself.

WHY THIS EXISTS
---------------
The method asked only whether OTHER scans held the output tree. Its one caller,
``cleanup_scan_resources``, reads its entry before a cancel and a runner wait,
and both give up control, so by the time the removal ran the entry could be one
the registry no longer held: a concurrent cleanup of the same scan had removed
it. The removal mark then sat on an object ``register_scan`` could not see, so a
new scan of the same tree was admitted while this call was deleting it.

And a cancelled scan whose cancel could not end one of its scanner tools still
writes into the tree through that tool (``could_not_stop``), after its runner
has finished. ``cleanup_scan`` kept such an entry for exactly that reason while
the removal deleted the tree under the tool.

Both refusals are decided under the registry lock, where ``register_scan``
decides too, so the registry's answer and the delete cannot disagree.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.core.resource_management import scan_registry
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


class _Remover:
    """The delete the caller hands in; counts its calls so a refusal is provable."""

    def __init__(self, output: Path) -> None:
        self.output = output
        self.calls = 0

    def __call__(self) -> bool:
        self.calls += 1
        shutil.rmtree(self.output)
        return not self.output.exists()


def _registered(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    output = project / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project), output_directory=str(output)
    )
    return registry, scan_id, registry.get_scan(scan_id), output


def _stopped_with_a_surviving_tool(tmp_path: Path):
    registry, scan_id, entry, output = _registered(tmp_path)
    entry.has_runner = True
    entry.mark_running()
    assert registry.cancel_scan(scan_id) is True
    assert registry.record_cancel_outcome(scan_id, (("bandit", BANDIT_PID),)) is True
    entry.runner_done.set()
    return registry, scan_id, entry, output


def test_an_entry_the_registry_no_longer_holds_is_refused(tmp_path):
    registry, scan_id, entry, output = _registered(tmp_path)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
    assert registry.cleanup_scan(scan_id) is True
    remover = _Remover(output)

    reason, removed = registry.remove_output_of_scan(entry, remover)

    assert reason is not None
    assert "no longer in the registry" in reason
    assert removed is False
    assert remover.calls == 0
    assert output.exists()


def test_a_stopped_scan_whose_tool_still_runs_is_refused(tmp_path, alive):
    alive[BANDIT_PID] = True
    registry, _scan_id, entry, output = _stopped_with_a_surviving_tool(tmp_path)
    remover = _Remover(output)

    reason, removed = registry.remove_output_of_scan(entry, remover)

    assert reason is not None
    assert "could not end" in reason
    assert removed is False
    assert remover.calls == 0
    assert output.exists()


def test_the_removal_runs_once_the_tool_is_gone(tmp_path, alive):
    registry, _scan_id, entry, output = _stopped_with_a_surviving_tool(tmp_path)
    remover = _Remover(output)

    reason, removed = registry.remove_output_of_scan(entry, remover)

    assert reason is None
    assert removed is True
    assert remover.calls == 1
    assert not output.exists()


def test_a_running_scan_is_refused(tmp_path):
    registry, _scan_id, entry, output = _registered(tmp_path)
    entry.mark_running()
    remover = _Remover(output)

    reason, removed = registry.remove_output_of_scan(entry, remover)

    assert reason is not None
    assert "running or stopping" in reason
    assert removed is False
    assert remover.calls == 0
    assert output.exists()


def test_a_finished_scan_with_no_runner_is_removed_as_before(tmp_path):
    """Control: the refusals above are about occupancy, not about every entry."""
    registry, scan_id, entry, output = _registered(tmp_path)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
    remover = _Remover(output)

    reason, removed = registry.remove_output_of_scan(entry, remover)

    assert reason is None
    assert removed is True
    assert remover.calls == 1
    assert not output.exists()
