"""Behavior tests for the scan management layer's error and cleanup paths.

scan_management wraps ScanRegistry with a "never raise, always return a response
dict" contract: every public coroutine here converts a failure into a structured
dict rather than propagating it, because these functions sit directly behind MCP
tool calls where an exception would kill the request. That contract is what these
tests pin down -- for each failure mode, which dict comes back.

Doubles are built with spec=ScanRegistry on purpose. A bare MagicMock answers any
attribute, so a test calling a registry method that does not exist would still
pass; the pre-existing test_scan_management.py has exactly that bug (it stubs
``get_scan_info``, which ScanRegistry has never defined).

The module logger is patched rather than captured with caplog: ASH_LOGGER sets
propagate = False (utils/log.py), so its records never reach the root handler
caplog installs, and a caplog-based assertion here would read an empty string.
"""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_management import (
    cancel_scan,
    check_scan_exists,
    check_scan_progress,
    cleanup_old_scans,
    cleanup_scan_resources,
    get_scan_by_directory,
    get_scan_statistics,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    ScanRegistryEntry,
)
from automated_security_helper.utils.log import ASHLogger

_MODULE = "automated_security_helper.core.resource_management.scan_management"


@pytest.fixture
def registry():
    """A registry double restricted to ScanRegistry's real method surface."""
    return MagicMock(spec=ScanRegistry)


@contextmanager
def _use(registry):
    """Install ``registry`` as the module's registry for the duration."""
    with patch(f"{_MODULE}.get_scan_registry", return_value=registry):
        yield


def _entry(tmp_path, scan_id="scan-1", status=MCScanStatus.PENDING, output_name="out"):
    """A real ScanRegistryEntry.

    Real instances rather than doubles: status/output_directory/is_active() are
    instance attributes set in __init__, so spec=ScanRegistryEntry would not
    include them and a double would silently fabricate them instead.
    """
    entry = ScanRegistryEntry(
        scan_id=scan_id,
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / output_name),
    )
    entry.status = status
    return entry


class TestCancelScan:
    def test_empty_scan_id_is_rejected_before_the_registry_is_touched(self, registry):
        with _use(registry):
            result = asyncio.run(cancel_scan(""))

        assert result["success"] is False
        assert result["operation"] == "cancel_scan"
        assert result["error_category"] == "invalid_parameter"
        assert "Scan ID cannot be empty" in result["error"]
        assert "Check that the scan ID is correct" in result["suggestions"]
        registry.get_scan.assert_not_called()

    def test_unknown_scan_id_reports_scan_not_found(self, registry):
        registry.get_scan.return_value = None

        with _use(registry):
            result = asyncio.run(cancel_scan("missing-scan"))

        assert result["success"] is False
        assert result["error_category"] == "scan_not_found"
        assert "Scan missing-scan not found" in result["error"]
        assert result["context"]["scan_id"] == "missing-scan"
        registry.cancel_scan.assert_not_called()

    @pytest.mark.parametrize(
        "status, expected_status",
        [
            (MCScanStatus.COMPLETED, "completed"),
            (MCScanStatus.FAILED, "failed"),
            (MCScanStatus.CANCELLED, "cancelled"),
        ],
    )
    def test_inactive_scan_is_not_cancellable(
        self, registry, tmp_path, status, expected_status
    ):
        registry.get_scan.return_value = _entry(tmp_path, status=status)

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["status"] == expected_status
        assert f"already in {expected_status} state" in result["message"]
        assert "No action needed" in result["suggestions"][0]
        registry.cancel_scan.assert_not_called()

    def test_successful_cancellation_reports_cancelled(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.return_value = True

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is True
        assert result["status"] == "cancelled"
        assert result["message"] == "Scan cancelled successfully"
        assert result["scan_id"] == "scan-1"
        registry.cancel_scan.assert_called_once_with("scan-1")

    def test_registry_refusing_to_cancel_keeps_the_original_status(
        self, registry, tmp_path
    ):
        """A False return means the scan raced to completion, not that it failed."""
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.return_value = False

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["message"] == "Failed to cancel scan"
        assert result["status"] == "running"
        assert result["error_category"] == "unexpected_error"
        assert "Check scan status using get_scan_progress" in result["suggestions"]

    def test_resource_error_from_the_registry_keeps_its_message(
        self, registry, tmp_path
    ):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.side_effect = MCPResourceError(
            "Permission denied when trying to terminate process 4242",
            context={"scan_id": "scan-1", "process_id": 4242},
        )

        with _use(registry):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["error_type"] == "MCPResourceError"
        assert "terminate process 4242" in result["error"]
        assert (
            "Check if you have permission to cancel the scan" in result["suggestions"]
        )

    def test_unexpected_error_is_typed_and_logged(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.side_effect = RuntimeError("registry exploded")

        with (
            _use(registry),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "RuntimeError"
        assert "registry exploded" in result["error"]
        assert logger.error.call_count == 1
        assert "Unexpected error cancelling scan scan-1" in logger.error.call_args[0][0]


class TestCleanupScanResources:
    def test_empty_scan_id_is_rejected_before_the_registry_is_touched(self, registry):
        with _use(registry):
            result = asyncio.run(cleanup_scan_resources(""))

        assert result["success"] is False
        assert result["operation"] == "cleanup_scan_resources"
        assert "Scan ID cannot be empty" in result["error"]
        registry.get_scan.assert_not_called()

    def test_unknown_scan_reports_not_found_with_cleanup_specific_advice(
        self, registry
    ):
        registry.get_scan.return_value = None

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("missing-scan"))

        assert result["success"] is False
        assert result["error_category"] == "scan_not_found"
        # Distinguishes cleanup's suggestion list from cancel_scan's, which is
        # otherwise identical for the first two entries.
        assert "The scan may have been cleaned up already" in result["suggestions"]
        registry.cleanup_scan.assert_not_called()

    def test_inactive_scan_is_removed_without_a_cancellation_attempt(
        self, registry, tmp_path
    ):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        assert result["removed_from_registry"] is True
        assert result["removed_output"] is False
        assert result["message"] == "Scan resources cleaned up successfully"
        assert "output_dir_error" not in result
        registry.cancel_scan.assert_not_called()

    def test_active_scan_is_cancelled_before_removal(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.return_value = True
        registry.cleanup_scan.return_value = True

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        registry.cancel_scan.assert_called_once_with("scan-1")
        registry.cleanup_scan.assert_called_once_with("scan-1")

    def test_failed_cancellation_warns_but_still_removes_the_scan(
        self, registry, tmp_path
    ):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cancel_scan.return_value = False
        registry.cleanup_scan.return_value = True

        with (
            _use(registry),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        warning = logger.warning.call_args[0][0]
        assert "Failed to cancel scan scan-1 during cleanup" in warning
        assert "Failed to cancel scan" in warning

    def test_cancellation_raising_does_not_abort_the_cleanup(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.cleanup_scan.return_value = True

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cancel_scan",
                AsyncMock(side_effect=RuntimeError("cancel blew up")),
            ),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        assert "cancel blew up" in logger.warning.call_args[0][0]

    def test_registry_refusing_removal_is_reported_as_failure(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = False

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is False
        assert result["removed_from_registry"] is False
        assert result["message"] == "Failed to clean up scan resources"

    def test_remove_output_deletes_the_directory_from_disk(self, registry, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        (output_dir / "ash_aggregated_results.json").write_text("{}")
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert not output_dir.exists()

    def test_remove_output_is_skipped_when_not_requested(self, registry, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=False))

        assert result["removed_output"] is False
        assert output_dir.exists()

    def test_permission_error_on_output_removal_is_reported_as_a_warning(
        self, registry, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with (
            _use(registry),
            patch(f"{_MODULE}.shutil.rmtree", side_effect=PermissionError("read-only")),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        # Registry removal still succeeded, so the operation as a whole did too.
        assert result["success"] is True
        assert result["removed_output"] is False
        assert "Permission denied" in result["output_dir_error"]
        assert "read-only" in result["output_dir_error"]
        assert result["warnings"] == [
            "Output directory could not be removed, but scan was removed from registry"
        ]
        assert "Permission denied" in logger.error.call_args[0][0]

    def test_already_missing_output_directory_counts_as_removed(
        self, registry, tmp_path
    ):
        """FileNotFoundError means someone else got there first, not a failure."""
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with (
            _use(registry),
            patch(f"{_MODULE}.shutil.rmtree", side_effect=FileNotFoundError("gone")),
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert "output_dir_error" not in result
        assert "warnings" not in result

    def test_other_output_removal_errors_are_reported_without_the_permission_wording(
        self, registry, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.return_value = True

        with (
            _use(registry),
            patch(f"{_MODULE}.shutil.rmtree", side_effect=OSError("device busy")),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)),
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert result["output_dir_error"] == (
            "Failed to remove output directory: device busy"
        )
        assert "Permission denied" not in result["output_dir_error"]

    def test_a_nonexistent_output_directory_is_left_alone(self, registry, tmp_path):
        """rmtree must not be called for a path that is not there."""
        registry.get_scan.return_value = _entry(
            tmp_path, status=MCScanStatus.COMPLETED, output_name="never-created"
        )
        registry.cleanup_scan.return_value = True

        with _use(registry), patch(f"{_MODULE}.shutil.rmtree") as rmtree:
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        rmtree.assert_not_called()
        assert result["removed_output"] is False

    def test_unexpected_error_during_cleanup_is_typed(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path, status=MCScanStatus.COMPLETED)
        registry.cleanup_scan.side_effect = RuntimeError("registry gone")

        with (
            _use(registry),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is False
        assert result["operation"] == "cleanup_scan_resources"
        assert result["context"]["error_type"] == "RuntimeError"
        assert "registry gone" in result["error"]
        assert logger.error.call_args.kwargs["exc_info"] is True


class TestCleanupOldScans:
    @staticmethod
    def _scan(scan_id, status, age_hours):
        stamp = (datetime.now() - timedelta(hours=age_hours)).isoformat()
        return {"scan_id": scan_id, "status": status, "end_time": stamp}

    def test_completed_scan_older_than_the_window_is_cleaned_up(self, registry):
        registry.list_scans.return_value = [
            self._scan("old-scan", "completed", age_hours=48)
        ]

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cleanup_scan_resources",
                AsyncMock(return_value={"success": True}),
            ) as cleanup,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        assert result["success"] is True
        assert result["cleaned_up_count"] == 1
        assert result["failed_count"] == 0
        assert result["cleaned_up_scans"] == ["old-scan"]
        assert result["message"] == "Cleaned up 1 old scans, 0 failed"
        cleanup.assert_awaited_once_with("old-scan", False)

    def test_remove_output_is_forwarded_to_each_cleanup(self, registry):
        registry.list_scans.return_value = [
            self._scan("old-scan", "completed", age_hours=48)
        ]

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cleanup_scan_resources",
                AsyncMock(return_value={"success": True}),
            ) as cleanup,
        ):
            asyncio.run(cleanup_old_scans(max_age_hours=24, remove_output=True))

        cleanup.assert_awaited_once_with("old-scan", True)

    def test_scan_inside_the_window_is_kept(self, registry):
        registry.list_scans.return_value = [
            self._scan("recent-scan", "completed", age_hours=1)
        ]

        with (
            _use(registry),
            patch(f"{_MODULE}.cleanup_scan_resources", AsyncMock()) as cleanup,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_not_awaited()
        assert result["cleaned_up_count"] == 0
        assert result["success"] is True

    @pytest.mark.parametrize("status", ["pending", "running"])
    def test_active_scans_are_never_cleaned_up_however_old(self, registry, status):
        registry.list_scans.return_value = [
            self._scan("busy-scan", status, age_hours=500)
        ]

        with (
            _use(registry),
            patch(f"{_MODULE}.cleanup_scan_resources", AsyncMock()) as cleanup,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_not_awaited()
        assert result["cleaned_up_count"] == 0

    def test_start_time_is_used_when_end_time_is_absent(self, registry):
        registry.list_scans.return_value = [
            {
                "scan_id": "no-end-scan",
                "status": "failed",
                "end_time": None,
                "start_time": (datetime.now() - timedelta(hours=48)).isoformat(),
            }
        ]

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cleanup_scan_resources",
                AsyncMock(return_value={"success": True}),
            ) as cleanup,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_awaited_once_with("no-end-scan", False)
        assert result["cleaned_up_scans"] == ["no-end-scan"]

    def test_scan_with_no_timestamp_at_all_is_skipped(self, registry):
        registry.list_scans.return_value = [
            {"scan_id": "undated", "status": "completed", "end_time": None}
        ]

        with (
            _use(registry),
            patch(f"{_MODULE}.cleanup_scan_resources", AsyncMock()) as cleanup,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_not_awaited()
        assert result["cleaned_up_count"] == 0

    def test_unparseable_timestamp_is_warned_about_and_skipped(self, registry):
        registry.list_scans.return_value = [
            {
                "scan_id": "bad-stamp",
                "status": "completed",
                "end_time": "not-a-timestamp",
            }
        ]

        with (
            _use(registry),
            patch(f"{_MODULE}.cleanup_scan_resources", AsyncMock()) as cleanup,
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        cleanup.assert_not_awaited()
        assert result["cleaned_up_count"] == 0
        assert (
            "Invalid timestamp format for scan bad-stamp"
            in logger.warning.call_args[0][0]
        )

    def test_unsuccessful_cleanup_is_counted_as_a_failure(self, registry):
        registry.list_scans.return_value = [
            self._scan("stuck-scan", "completed", age_hours=48)
        ]

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cleanup_scan_resources",
                AsyncMock(return_value={"success": False}),
            ),
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        assert result["success"] is False
        assert result["failed_count"] == 1
        assert result["failed_cleanups"] == ["stuck-scan"]
        assert result["cleaned_up_scans"] == []
        assert result["message"] == "Cleaned up 0 old scans, 1 failed"

    def test_cleanup_raising_is_counted_as_a_failure_not_propagated(self, registry):
        registry.list_scans.return_value = [
            self._scan("exploding-scan", "cancelled", age_hours=48)
        ]

        with (
            _use(registry),
            patch(
                f"{_MODULE}.cleanup_scan_resources",
                AsyncMock(side_effect=RuntimeError("cleanup blew up")),
            ),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        assert result["success"] is False
        assert result["failed_cleanups"] == ["exploding-scan"]
        assert "Error cleaning up scan exploding-scan" in logger.error.call_args[0][0]

    def test_mixed_batch_reports_both_tallies(self, registry):
        registry.list_scans.return_value = [
            self._scan("good-scan", "completed", age_hours=48),
            self._scan("bad-scan", "failed", age_hours=48),
            self._scan("young-scan", "completed", age_hours=1),
        ]
        outcomes = {"good-scan": {"success": True}, "bad-scan": {"success": False}}

        async def _cleanup(scan_id, remove_output):
            return outcomes[scan_id]

        with (
            _use(registry),
            patch(f"{_MODULE}.cleanup_scan_resources", AsyncMock(side_effect=_cleanup)),
        ):
            result = asyncio.run(cleanup_old_scans(max_age_hours=24))

        assert result["cleaned_up_scans"] == ["good-scan"]
        assert result["failed_cleanups"] == ["bad-scan"]
        assert result["cleaned_up_count"] == 1
        assert result["failed_count"] == 1
        assert result["success"] is False


class TestScanStatistics:
    def test_statistics_are_read_from_the_registry(self, registry):
        registry.get_scan_count.return_value = 7
        registry.get_active_scan_count.return_value = 2
        registry.get_scan_status_counts.return_value = {
            "pending": 1,
            "running": 1,
            "completed": 4,
            "failed": 1,
            "cancelled": 0,
        }

        with _use(registry):
            result = asyncio.run(get_scan_statistics())

        assert result["total_scans"] == 7
        assert result["active_scans"] == 2
        assert result["status_counts"]["completed"] == 4
        # A real ISO-8601 stamp, not a MagicMock repr.
        assert datetime.fromisoformat(result["timestamp"]) <= datetime.now()


class TestCheckScanExists:
    def test_known_scan_exists(self, registry, tmp_path):
        registry.get_scan.return_value = _entry(tmp_path)

        with _use(registry):
            assert asyncio.run(check_scan_exists("scan-1")) is True

    def test_unknown_scan_does_not_exist(self, registry):
        registry.get_scan.return_value = None

        with _use(registry):
            assert asyncio.run(check_scan_exists("missing-scan")) is False


class TestGetScanByDirectory:
    def test_active_scan_for_a_directory_is_returned_as_a_dict(
        self, registry, tmp_path
    ):
        entry = _entry(tmp_path, status=MCScanStatus.RUNNING)
        registry.get_scan_by_directory.return_value = entry

        with _use(registry):
            result = asyncio.run(get_scan_by_directory(str(tmp_path / "src")))

        assert isinstance(result, dict)
        assert result["scan_id"] == "scan-1"
        assert result["status"] == "running"
        assert result["directory_path"] == str(tmp_path / "src")
        registry.get_scan_by_directory.assert_called_once_with(str(tmp_path / "src"))

    def test_directory_with_no_active_scan_returns_none(self, registry, tmp_path):
        registry.get_scan_by_directory.return_value = None

        with _use(registry):
            result = asyncio.run(get_scan_by_directory(str(tmp_path / "src")))

        assert result is None


class TestCheckScanProgress:
    def test_empty_scan_id_is_rejected_before_the_registry_is_touched(self, registry):
        with _use(registry):
            result = asyncio.run(check_scan_progress(""))

        assert result["success"] is False
        assert result["operation"] == "check_scan_progress"
        assert "Scan ID cannot be empty" in result["error"]
        registry.check_scan_progress.assert_not_called()

    def test_progress_is_passed_through_untouched(self, registry):
        progress = {"scan_id": "scan-1", "status": "running", "completed_scanners": 3}
        registry.check_scan_progress.return_value = progress

        with _use(registry):
            result = asyncio.run(check_scan_progress("scan-1"))

        assert result == progress
        registry.check_scan_progress.assert_called_once_with("scan-1")

    def test_resource_error_becomes_an_error_response(self, registry):
        registry.check_scan_progress.side_effect = MCPResourceError(
            "Scan scan-1 not found in registry",
            context={"error_category": "scan_not_found"},
        )

        with _use(registry):
            result = asyncio.run(check_scan_progress("scan-1"))

        assert result["success"] is False
        assert result["operation"] == "check_scan_progress"
        assert result["error_category"] == "scan_not_found"
        assert "not found in registry" in result["error"]

    def test_unexpected_error_becomes_a_typed_error_response(self, registry):
        registry.check_scan_progress.side_effect = ValueError("bad progress data")

        with (
            _use(registry),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(check_scan_progress("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "ValueError"
        assert "bad progress data" in result["error"]
        assert (
            "Unexpected error checking scan progress for scan-1"
            in logger.error.call_args[0][0]
        )
