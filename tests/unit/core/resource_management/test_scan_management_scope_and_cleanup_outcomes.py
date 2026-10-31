# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan management helpers honor the session and report cleanup as it went.

Each test is pinned against the behavior it replaced:

* ``list_all_scans``, ``cleanup_scan_resources``, ``cleanup_old_scans``,
  ``get_scan_statistics``, ``check_scan_exists`` and ``get_scan_by_directory``
  took no session and acted on, or revealed, any session's scans.
* ``cancel_scan`` reported a scan that ended between its unlocked pre-check and
  the registry's cancel as "Failed to cancel scan" with an unexpected_error
  category instead of the already-ended answer.
* ``cleanup_scan_resources`` ran ``shutil.rmtree`` of the whole output tree on
  the event loop thread, and ``check_scan_progress`` ran the registry's file
  reads and parses there too.
* ``cleanup_old_scans`` counted a scan removed by a concurrent cleanup as a
  failed cleanup and returned success False.

Doubles follow test_scan_management_lifecycle.py: a ``MagicMock(spec=ScanRegistry)``
registry and real ``ScanRegistryEntry`` instances.
"""

import asyncio
import threading
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.scan_management import (
    cancel_scan,
    check_scan_exists,
    check_scan_progress,
    cleanup_old_scans,
    cleanup_scan_resources,
    get_scan_by_directory,
    get_scan_statistics,
    list_all_scans,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    ScanRegistryEntry,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.core.resource_management.scan_management"


@pytest.fixture
def registry():
    registry = MagicMock(spec=ScanRegistry)
    registry.cleanup_scan.return_value = True
    registry.cancel_scan.return_value = True
    # The output delete goes through the registry, which runs the remover it
    # is handed and answers (reason, removed); the double runs it as a
    # registry that found no other scan on the directory does, so the rmtree
    # the tests patch is reached on the worker thread the tests measure.
    registry.remove_output_of_scan.side_effect = lambda entry, remover: (
        None,
        remover(),
    )
    return registry


@contextmanager
def _use(registry):
    with patch(f"{_MODULE}.get_scan_registry", return_value=registry):
        yield


def _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    entry = ScanRegistryEntry(
        scan_id="scan-1",
        directory_path=str(source),
        output_directory=str(source / ".ash" / "ash_output"),
    )
    entry.status = status
    entry.has_runner = has_runner
    return entry


class TestTheHelpersPassTheSessionThrough:
    def test_list_all_scans(self, registry):
        registry.list_scans.return_value = []
        with _use(registry):
            asyncio.run(list_all_scans(session_id="s1"))
        registry.list_scans.assert_called_once_with(session_id="s1")

    def test_check_scan_exists(self, registry):
        registry.get_scan.return_value = None
        with _use(registry):
            assert asyncio.run(check_scan_exists("scan-1", session_id="s1")) is False
        registry.get_scan.assert_called_once_with("scan-1", session_id="s1")

    def test_get_scan_by_directory(self, registry):
        registry.get_scan_by_directory.return_value = None
        with _use(registry):
            assert asyncio.run(get_scan_by_directory("/proj", session_id="s1")) is None
        registry.get_scan_by_directory.assert_called_once_with("/proj", session_id="s1")

    def test_get_scan_statistics(self, registry):
        registry.get_scan_statistics.return_value = {
            "total_scans": 1,
            "active_scans": 0,
            "status_counts": {},
        }
        with _use(registry):
            result = asyncio.run(get_scan_statistics(session_id="s1"))
        registry.get_scan_statistics.assert_called_once_with(session_id="s1")
        assert result["total_scans"] == 1

    def test_cleanup_scan_resources_looks_the_scan_up_for_the_session(
        self, registry, tmp_path
    ):
        registry.get_scan.return_value = None
        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", session_id="s2"))
        assert result["success"] is False
        assert result["error_category"] == "scan_not_found"
        registry.get_scan.assert_called_once_with("scan-1", session_id="s2")
        registry.cleanup_scan.assert_not_called()

    def test_cleanup_scan_resources_removes_for_the_session(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path)
        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", session_id="s1"))
        assert result["success"] is True
        registry.cleanup_scan.assert_called_once_with("scan-1", session_id="s1")

    def test_cleanup_old_scans_lists_and_cleans_for_the_session(self, registry):
        """One old scan is listed, so the cleaning half runs: the per-scan
        cleanup is handed the session too. With an empty listing nothing was
        cleaned, and a bulk cleanup that listed for the session and then
        cleaned unscoped would have passed."""
        registry.list_scans.return_value = [
            {
                "scan_id": "old-scan",
                "status": "completed",
                "end_time": "2000-01-01T00:00:00",
            }
        ]
        cleanup = AsyncMock(return_value={"success": True})
        with _use(registry), patch(f"{_MODULE}.cleanup_scan_resources", cleanup):
            result = asyncio.run(cleanup_old_scans(session_id="s1"))
        registry.list_scans.assert_called_once_with(session_id="s1")
        cleanup.assert_awaited_once_with("old-scan", False, session_id="s1")
        assert result["cleaned_up_scans"] == ["old-scan"]


class TestCancelScanRace:
    def test_a_scan_that_ended_during_the_cancel_is_the_already_ended_answer(
        self, registry, tmp_path
    ):
        entry = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.get_scan.return_value = entry

        def ended_meanwhile(scan_id, **kwargs):
            entry.mark_completed()
            return False

        registry.cancel_scan.side_effect = ended_meanwhile

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["status"] == "completed"
        assert "already in completed state" in result["message"]
        assert "error_category" not in result

    def test_a_scan_removed_during_the_cancel_is_the_not_found_answer(
        self, registry, tmp_path
    ):
        """The registry declines only a scan it cannot see or one no longer
        active; with the ended case answered above, a declined cancel whose
        re-lookup finds nothing means the scan was removed meanwhile. That read
        as an unexpected error carrying the pre-check's stale "running"."""
        entry = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.get_scan.side_effect = [entry, None]
        registry.cancel_scan.return_value = False

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "scan_not_found"
        assert result["operation"] == "cancel_scan"
        assert "status" not in result

    def test_a_decline_for_a_scan_still_active_stays_unexpected(
        self, registry, tmp_path
    ):
        """The control: a decline the two readings cannot explain is still the
        unexpected answer, with the status read now."""
        entry = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.get_scan.return_value = entry
        registry.cancel_scan.return_value = False

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["status"] == "running"


class TestFileWorkLeavesTheEventLoop:
    def test_the_output_tree_is_removed_on_a_worker_thread(self, registry, tmp_path):
        entry = _entry(tmp_path)
        output = tmp_path / "src" / ".ash" / "ash_output"
        output.mkdir(parents=True)
        registry.get_scan.return_value = entry
        seen = {}

        def record_thread(path, *args, **kwargs):
            seen["thread"] = threading.get_ident()
            seen["path"] = str(path)

        async def run():
            seen["loop_thread"] = threading.get_ident()
            return await cleanup_scan_resources("scan-1", remove_output=True)

        with (
            _use(registry),
            patch(f"{_MODULE}.shutil.rmtree", side_effect=record_thread),
        ):
            asyncio.run(run())

        assert seen["path"] == str(output)
        assert seen["thread"] != seen["loop_thread"]

    def test_the_progress_read_runs_on_a_worker_thread(self, registry):
        seen = {}

        def record_thread(scan_id, **kwargs):
            seen["thread"] = threading.get_ident()
            return {"success": True, "scan_id": scan_id}

        registry.check_scan_progress.side_effect = record_thread

        async def run():
            seen["loop_thread"] = threading.get_ident()
            return await check_scan_progress("scan-1")

        with _use(registry):
            result = asyncio.run(run())

        assert result == {"success": True, "scan_id": "scan-1"}
        assert seen["thread"] != seen["loop_thread"]


class TestCleanupOldScansCountsAConcurrentRemovalApart:
    def test_a_scan_already_removed_is_neither_cleaned_nor_failed(self, registry):
        registry.list_scans.return_value = [
            {
                "scan_id": "gone-scan",
                "status": "completed",
                "end_time": "2000-01-01T00:00:00",
            }
        ]
        not_found = {
            "success": False,
            "error_category": "scan_not_found",
            "error": "Scan gone-scan not found",
        }

        cleanup = AsyncMock(return_value=not_found)
        with _use(registry), patch(f"{_MODULE}.cleanup_scan_resources", cleanup):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_awaited_once_with("gone-scan", False)
        assert result["success"] is True
        assert result["failed_count"] == 0
        assert result["failed_cleanups"] == []
        assert result["already_removed"] == ["gone-scan"]
