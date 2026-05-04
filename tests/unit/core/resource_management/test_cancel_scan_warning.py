"""Regression test: cancel_scan warns when process_id is None (M1)."""

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


def test_cancel_scan_logs_warning_when_process_id_is_none():
    registry = _make_registry_with_running_scan()
    with patch.object(registry._logger, "warning") as mock_warn:
        result = registry.cancel_scan("test-scan-1")
    assert result is True
    mock_warn.assert_called_once()
    msg = mock_warn.call_args[0][0]
    assert "process" in msg.lower() or "thread" in msg.lower()


def test_cancel_scan_still_marks_cancelled_when_no_pid():
    registry = _make_registry_with_running_scan()
    registry.cancel_scan("test-scan-1")
    entry = registry.get_scan("test-scan-1")
    assert entry.status == MCScanStatus.CANCELLED
