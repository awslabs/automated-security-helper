# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan can be told which scanner tools its stop could not end.

``cancel_scan`` closes the entry as CANCELLED at once. The runner learns only
afterwards, from ``ScanCancelled.could_not_stop``, which tools kept running past
the stop, and ``finish_scan`` leaves a closed entry alone by design, so that
outcome had nowhere to go: a cancel whose tool was still running read back as a
clean one. ``record_cancel_outcome`` is the one way to attach it, as a warning on
the CANCELLED entry naming each tool and its process id.
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

    def test_a_clean_cancel_attaches_nothing(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        registry.cancel_scan("scan-1")

        assert registry.record_cancel_outcome("scan-1", ()) is False
        assert registry.get_scan("scan-1").warnings == []

    def test_a_scan_that_was_not_cancelled_takes_no_cancel_outcome(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        # Still RUNNING: the stop outcome belongs to a cancel that did not happen.
        assert registry.record_cancel_outcome("scan-1", (("bandit", 1),)) is False
        assert registry.get_scan("scan-1").warnings == []

        # Closed by the timeout as FAILED: its reason is already recorded, and
        # the entry is not a cancelled one.
        registry.finish_scan("scan-1", MCScanStatus.FAILED, "timed out")
        assert registry.record_cancel_outcome("scan-1", (("bandit", 1),)) is False
        assert registry.get_scan("scan-1").warnings == []

    def test_an_unknown_scan_is_reported_not_raised(self, tmp_path):
        registry = _registry_with_running_scan(tmp_path)
        assert registry.record_cancel_outcome("no-such-scan", (("bandit", 1),)) is False
