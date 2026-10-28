"""Regression test: cancel_scan on a scan with no process id.

An MCP scan runs in a thread, so it has no process id to signal. Neither a silent
no-op nor a warning that the scan cannot be stopped is right for it: the
scan is stopped through its registry entry's cancel event, which its runner
checks (core/cancellation.py), so the expectation is that the event is set and
nothing claims the scan cannot be stopped.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
    ScanRegistryEntry,
    MCScanStatus,
)


def _make_registry_with_running_scan():
    registry = ScanRegistry()
    entry = ScanRegistryEntry(
        scan_id="test-scan-1",
        directory_path=str(Path(tempfile.gettempdir()) / "fakedir"),
        output_directory=str(Path(tempfile.gettempdir()) / "fakeout"),
    )
    entry.status = MCScanStatus.RUNNING
    entry.process_id = None
    registry._registry["test-scan-1"] = entry
    return registry


def test_cancel_scan_signals_a_scan_with_no_process_id_through_its_event():
    registry = _make_registry_with_running_scan()
    with patch.object(registry._logger, "warning") as mock_warn:
        result = registry.cancel_scan("test-scan-1")
    assert result is True
    assert registry.get_scan("test-scan-1").cancel_event.is_set()
    mock_warn.assert_not_called()


def test_cancel_scan_still_marks_cancelled_when_no_pid():
    registry = _make_registry_with_running_scan()
    registry.cancel_scan("test-scan-1")
    entry = registry.get_scan("test-scan-1")
    assert entry.status == MCScanStatus.CANCELLED
