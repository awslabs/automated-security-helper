# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the server stopped can be told which scanner tools its stop could not end.

A stop closes the entry at once: ``cancel_scan`` as CANCELLED, the scan
timeout and a cancelled runner task as FAILED with the cancel event set. The
thread that ran the scan learns only afterwards which tools kept running past
the stop, and ``finish_scan`` leaves a closed entry alone by design, so that
outcome had nowhere to go: a stop whose tool was still running read back as a
clean one. ``record_cancel_outcome`` is the one way to attach it, as a warning
on the stopped entry naming each tool, with the ``(tool, pid)`` pairs kept on
the entry. It admitted a CANCELLED entry alone, so a timed-out scan whose tool
survived read back as a plain timeout; it now admits every entry the server
stopped and refuses the rest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    ScanRegistryEntry,
)

pytestmark = pytest.mark.unit


def _registry_with_running_scan(
    tmp_path: Path, scan_id: str = "scan-1"
) -> ScanRegistry:
    registry = ScanRegistry()
    entry = ScanRegistryEntry(
        scan_id=scan_id,
        directory_path=str(tmp_path / "project"),
        output_directory=str(tmp_path / "project" / ".ash" / "ash_output"),
    )
    entry.mark_running()
    registry._registry[scan_id] = entry
    return registry


def _stop_as_the_timeout_does(registry: ScanRegistry, scan_id: str, reason: str):
    """Close the entry FAILED with the timeout's reason, then set its event: the
    order mcp_tools._stop_at_timeout and _close_after_the_runner_failed use."""
    assert registry.finish_scan(scan_id, MCScanStatus.FAILED, reason) is True
    registry.get_scan(scan_id).cancel_event.set()


class TestRecordCancelOutcome:
    def test_a_cancelled_scan_carries_the_tools_that_could_not_stop(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        assert registry.cancel_scan("scan-1") is True

        attached = registry.record_cancel_outcome(
            "scan-1", (("bandit", 4242), ("semgrep", 4243))
        )

        assert attached is True
        entry = registry.get_scan("scan-1")
        assert entry.status == MCScanStatus.CANCELLED
        assert len(entry.warnings) == 1, entry.warnings
        warning = entry.warnings[0]
        assert "2 scanner tool(s) could not be stopped" in warning
        assert "bandit (pid 4242)" in warning
        assert "semgrep (pid 4243)" in warning
        # What a client polling the entry reads carries it too.
        assert entry.to_dict()["warnings"] == [warning]
        # The pairs stay on the entry for the directory hold.
        assert entry.could_not_stop == (("bandit", 4242), ("semgrep", 4243))

    def test_a_clean_cancel_attaches_nothing(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        registry.cancel_scan("scan-1")

        assert registry.record_cancel_outcome("scan-1", ()) is False
        assert registry.get_scan("scan-1").warnings == []
        assert registry.get_scan("scan-1").could_not_stop == ()

    def test_a_scan_the_timeout_stopped_carries_the_tools_that_could_not_stop(
        self, tmp_path
    ):
        """The timeout closes the entry FAILED with its reason and sets the
        cancel event; the scan then stops, and a tool that would not end is a
        stop outcome like any cancel's. The reason stays; the warning is added.

        Red at the base: the method turned a FAILED entry away, so the timed-out
        scan read back with no word of the tool still running."""
        registry = _registry_with_running_scan(tmp_path)
        _stop_as_the_timeout_does(registry, "scan-1", "Scan exceeded the limit")

        attached = registry.record_cancel_outcome("scan-1", (("bandit", 4242),))

        assert attached is True
        entry = registry.get_scan("scan-1")
        assert entry.status == MCScanStatus.FAILED
        assert entry.error_message == "Scan exceeded the limit"
        assert len(entry.warnings) == 1, entry.warnings
        assert "bandit (pid 4242)" in entry.warnings[0]

    def test_a_scan_nothing_stopped_takes_no_cancel_outcome(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        # Still RUNNING: the stop outcome belongs to a stop that did not happen.
        assert registry.record_cancel_outcome("scan-1", (("bandit", 1),)) is False
        assert registry.get_scan("scan-1").warnings == []

        # Closed FAILED by the runner on the scan's own error, its cancel event
        # clear: nothing stopped it, so a stop's records are not its own.
        registry.finish_scan("scan-1", MCScanStatus.FAILED, "the scanner crashed")
        assert registry.get_scan("scan-1").cancel_event.is_set() is False
        assert registry.record_cancel_outcome("scan-1", (("bandit", 1),)) is False
        assert registry.get_scan("scan-1").warnings == []

    def test_a_finished_scan_takes_no_cancel_outcome(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        registry.finish_scan("scan-1", MCScanStatus.COMPLETED)
        # Even with its event set afterwards: a scan that finished was not stopped.
        registry.get_scan("scan-1").cancel_event.set()

        assert registry.record_cancel_outcome("scan-1", (("bandit", 1),)) is False
        assert registry.get_scan("scan-1").warnings == []

    def test_the_same_tool_is_recorded_once(self, tmp_path):
        """The thread that ran the scan and the runner's arm may both report the
        same pairs; the entry carries one warning and one copy of each pair."""
        registry = _registry_with_running_scan(tmp_path)
        registry.cancel_scan("scan-1")

        assert registry.record_cancel_outcome("scan-1", (("bandit", 4242),)) is True
        assert registry.record_cancel_outcome("scan-1", (("bandit", 4242),)) is False
        # A new pair alongside a known one is recorded on its own.
        assert (
            registry.record_cancel_outcome(
                "scan-1", (("bandit", 4242), ("semgrep", 4243))
            )
            is True
        )

        entry = registry.get_scan("scan-1")
        assert entry.could_not_stop == (("bandit", 4242), ("semgrep", 4243))
        assert len(entry.warnings) == 2, entry.warnings
        assert "1 scanner tool(s)" in entry.warnings[1]
        assert "semgrep (pid 4243)" in entry.warnings[1]
        assert "bandit" not in entry.warnings[1]

    def test_the_warning_can_leave_the_process_ids_to_the_server_log(self, tmp_path):
        """On a network transport the caller asks for a warning that names the
        tools only: a server-side pid is nothing a remote client can act on.
        The entry still keeps the pairs."""
        registry = _registry_with_running_scan(tmp_path)
        registry.cancel_scan("scan-1")

        attached = registry.record_cancel_outcome(
            "scan-1", (("bandit", 4242),), name_process_ids=False
        )

        assert attached is True
        entry = registry.get_scan("scan-1")
        warning = entry.warnings[0]
        assert "bandit" in warning
        assert "4242" not in warning
        assert "server's log" in warning
        assert entry.could_not_stop == (("bandit", 4242),)

    def test_the_pid_free_warning_names_a_tool_by_its_basename(self, tmp_path):
        """A tool is recorded as argv0 as spawned, which can be a server path.
        The warning a remote client reads names the basename; the entry keeps
        the recorded pair, and the pid-naming warning (stdio) keeps the path."""
        registry = _registry_with_running_scan(tmp_path)
        registry.cancel_scan("scan-1")
        spawned = "/opt/scanners/venv/bin/bandit"

        assert (
            registry.record_cancel_outcome(
                "scan-1", ((spawned, 4242),), name_process_ids=False
            )
            is True
        )

        entry = registry.get_scan("scan-1")
        warning = entry.warnings[0]
        assert "bandit" in warning
        assert "/opt/scanners" not in warning
        assert "4242" not in warning
        assert entry.could_not_stop == ((spawned, 4242),)

        # The owner on stdio reads the path as recorded.
        local = _registry_with_running_scan(tmp_path, "scan-2")
        local.cancel_scan("scan-2")
        assert local.record_cancel_outcome("scan-2", ((spawned, 4242),)) is True
        assert f"{spawned} (pid 4242)" in local.get_scan("scan-2").warnings[0]

    def test_an_unknown_scan_is_reported_not_raised(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        assert registry.record_cancel_outcome("no-such-scan", (("bandit", 1),)) is False
