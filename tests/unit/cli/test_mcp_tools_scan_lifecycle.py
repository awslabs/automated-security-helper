#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the scan-lifecycle MCP tools and the background scan runner.

Every coroutine in this group is reachable directly from an MCP tool call, and
each one is written to swallow its exceptions and return a response dict. The
tests here pin the failure translation: which dict a caller gets for a refused
target, an invalid parameter, a registry that raises, and a scan that dies
mid-flight.

Two deliberate choices:

* ``ASH_MCP_ALLOWED_ROOTS`` is set explicitly to the test's own ``tmp_path``
  rather than left unset. Unset selects a default deny-list (/etc, /proc, ...)
  which happens to permit tmp_path today, so a test relying on that would pass
  for a reason unrelated to what it claims to check -- and would start failing
  if the deny-list ever grew.
* Registry doubles use ``spec=ScanRegistry``. A bare MagicMock answers any
  attribute, so it cannot catch a call to a registry method that does not exist.
"""

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_tools import (
    _run_scan_async,
    mcp_cancel_scan,
    mcp_check_installation,
    mcp_get_scan_progress,
    mcp_get_scan_results,
    mcp_list_active_scans,
    mcp_scan_directory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    ScanRegistryEntry,
)
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
_RUN_ASH_SCAN = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


@pytest.fixture
def allowed_root(tmp_path, monkeypatch):
    """Permit exactly this test's tmp_path as a scan target, and nothing else."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    return tmp_path


@pytest.fixture
def registry():
    return MagicMock(spec=ScanRegistry)


def _entry(tmp_path, scan_id="scan-1"):
    return ScanRegistryEntry(
        scan_id=scan_id,
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / "out"),
    )


class TestScanDirectoryValidation:
    def test_target_outside_the_allowed_roots_is_refused(self, tmp_path, monkeypatch):
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        refused.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        result = asyncio.run(mcp_scan_directory(str(refused)))

        assert result["success"] is False
        assert result["operation"] == "scan_directory"
        assert "outside the permitted roots" in result["error"]
        assert ASH_MCP_ALLOWED_ROOTS_ENV in result["suggestions"][0]

    def test_missing_directory_is_reported_as_missing(self, allowed_root):
        result = asyncio.run(mcp_scan_directory(str(allowed_root / "not-there")))

        assert result["success"] is False
        assert result["error_category"] == "file_not_found"
        assert (
            "Check that the directory exists and is accessible"
            in (result["suggestions"])
        )

    def test_unknown_severity_threshold_is_rejected(self, allowed_root):
        result = asyncio.run(
            mcp_scan_directory(str(allowed_root), severity_threshold="EXTREME")
        )

        assert result["success"] is False
        assert result["error_category"] == "invalid_parameter"
        assert "Invalid severity threshold: 'EXTREME'" in result["error"]
        assert (
            "Valid severity thresholds are: LOW, MEDIUM, HIGH, CRITICAL"
            in result["suggestions"]
        )

    def test_missing_config_file_is_rejected(self, allowed_root):
        result = asyncio.run(
            mcp_scan_directory(
                str(allowed_root),
                severity_threshold="HIGH",
                config_path=str(allowed_root / "absent.yaml"),
            )
        )

        assert result["success"] is False
        assert result["error_category"] == "file_not_found"
        assert "Configuration file not found" in result["error"]
        assert (
            "Ensure the file has a valid extension (.yaml, .yml, or .json)"
            in result["suggestions"]
        )

    def test_config_file_with_a_rejected_extension_is_reported(self, allowed_root):
        bad_config = allowed_root / "ash.txt"
        bad_config.write_text("project_name: demo\n")

        result = asyncio.run(
            mcp_scan_directory(str(allowed_root), config_path=str(bad_config))
        )

        assert result["success"] is False
        assert result["error_category"] == "invalid_format"
        assert "Invalid configuration file extension" in result["error"]


class TestScanDirectoryRegistryFailures:
    def test_registration_conflict_is_surfaced_with_its_own_message(
        self, allowed_root, registry
    ):
        registry.register_scan.side_effect = MCPResourceError(
            f"Directory {allowed_root} already has an active scan",
            context={"error_category": "resource_exhausted"},
        )

        with patch(f"{_TOOLS}.get_scan_registry", return_value=registry):
            result = asyncio.run(mcp_scan_directory(str(allowed_root)))

        assert result["success"] is False
        assert result["operation"] == "scan_directory"
        assert result["error_category"] == "resource_exhausted"
        assert "already has an active scan" in result["error"]
        assert (
            "Check that the directory exists and is accessible"
            in (result["suggestions"])
        )

    def test_unexpected_registration_failure_is_typed_and_logged(
        self, allowed_root, registry
    ):
        registry.register_scan.side_effect = RuntimeError("registry offline")

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_scan_directory(str(allowed_root)))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "RuntimeError"
        assert result["context"]["directory_path"] == str(allowed_root)
        assert "registry offline" in result["error"]
        assert "Unexpected error starting scan" in logger.error.call_args[0][0]

    def test_output_directory_is_created_under_the_target(self, allowed_root, registry):
        """The .ash/ash_output tree is made before registration, so it exists
        even on the path where registration then fails."""
        registry.register_scan.side_effect = RuntimeError("stop here")

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            asyncio.run(mcp_scan_directory(str(allowed_root)))

        assert (allowed_root / ".ash" / "ash_output").is_dir()


class TestRunScanAsync:
    def test_unknown_scan_id_logs_and_returns_without_running_anything(
        self, tmp_path, registry
    ):
        registry.get_scan.return_value = None

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
            patch(_RUN_ASH_SCAN) as run_ash_scan,
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="ghost-scan",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                )
            )

        run_ash_scan.assert_not_called()
        registry.update_scan_status.assert_not_called()
        assert "Scan ghost-scan not found in registry" in logger.error.call_args[0][0]

    def test_scan_without_a_session_runs_and_is_marked_completed(
        self, tmp_path, registry
    ):
        registry.get_scan.return_value = _entry(tmp_path)

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN) as run_ash_scan,
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="HIGH",
                )
            )

        statuses = [c.args[1] for c in registry.update_scan_status.call_args_list]
        assert statuses == [MCScanStatus.RUNNING, MCScanStatus.COMPLETED]

        kwargs = run_ash_scan.call_args.kwargs
        assert kwargs["source_dir"] == str(tmp_path / "src")
        assert kwargs["output_dir"] == str(tmp_path / "out")
        assert kwargs["config"] is None
        assert kwargs["fail_on_findings"] is False
        assert kwargs["show_summary"] is False

    def test_config_path_is_forwarded_to_the_scan(self, tmp_path, registry):
        registry.get_scan.return_value = _entry(tmp_path)
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: demo\n")

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN) as run_ash_scan,
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                    config_path=str(config),
                )
            )

        assert run_ash_scan.call_args.kwargs["config"] == str(config)

    def test_session_scan_holds_the_per_session_lock_while_scanning(
        self, tmp_path, registry
    ):
        """The lock must be held across run_ash_scan, not merely resolved.

        Checked from inside the fake scan: asserting after the fact would pass
        just as happily if the ``with session_lock`` block were deleted.
        """
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        session_id = "lock-probe-session"
        session_lock = get_default_registry().get_or_create(session_id).lock
        observed = {}

        def _fake_scan(**kwargs):
            observed["locked_during_scan"] = session_lock.locked()

        registry.get_scan.return_value = _entry(tmp_path)

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN, side_effect=_fake_scan),
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                    session_id=session_id,
                )
            )

        assert observed["locked_during_scan"] is True
        # Released again afterwards, or the session would deadlock on its next scan.
        assert session_lock.acquire(blocking=False) is True
        session_lock.release()

    def test_sessionless_scan_does_not_hold_any_session_lock(self, tmp_path, registry):
        """Counterpart to the test above: proves that assertion is discriminating."""
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        other_lock = get_default_registry().get_or_create("unrelated-session").lock
        observed = {}

        def _fake_scan(**kwargs):
            observed["locked_during_scan"] = other_lock.locked()

        registry.get_scan.return_value = _entry(tmp_path)

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN, side_effect=_fake_scan),
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                    session_id=None,
                )
            )

        assert observed["locked_during_scan"] is False

    def test_two_scans_on_one_session_serialize(self, tmp_path, registry):
        """The point of the per-session lock: same session, no overlap."""
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        session_id = "serialize-probe-session"
        get_default_registry().get_or_create(session_id)
        concurrent = threading.Semaphore(0)
        overlapped = []
        active = []
        active_guard = threading.Lock()

        def _fake_scan(**kwargs):
            with active_guard:
                active.append(1)
                overlapped.append(len(active) > 1)
            concurrent.release()
            with active_guard:
                active.pop()

        registry.get_scan.return_value = _entry(tmp_path)

        async def _both():
            await asyncio.gather(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                    session_id=session_id,
                ),
                _run_scan_async(
                    scan_id="scan-2",
                    directory_path=str(tmp_path / "src2"),
                    output_dir=str(tmp_path / "out2"),
                    severity_threshold="MEDIUM",
                    session_id=session_id,
                ),
            )

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN, side_effect=_fake_scan),
        ):
            asyncio.run(_both())

        assert overlapped == [False, False]

    def test_failing_scan_is_marked_failed_with_the_error_message(
        self, tmp_path, registry
    ):
        registry.get_scan.return_value = _entry(tmp_path)

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN, side_effect=RuntimeError("scanner crashed")),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                )
            )

        final = registry.update_scan_status.call_args_list[-1]
        assert final.args[1] is MCScanStatus.FAILED
        assert final.args[2] == "Error executing scan: scanner crashed"
        assert "Scan scan-1 failed" in logger.error.call_args[0][0]

    def test_failing_session_scan_still_releases_the_lock(self, tmp_path, registry):
        """A crash inside the ``with session_lock`` block must not wedge the session."""
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        session_id = "crash-probe-session"
        session_lock = get_default_registry().get_or_create(session_id).lock
        registry.get_scan.return_value = _entry(tmp_path)

        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(_RUN_ASH_SCAN, side_effect=RuntimeError("boom")),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            asyncio.run(
                _run_scan_async(
                    scan_id="scan-1",
                    directory_path=str(tmp_path / "src"),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                    session_id=session_id,
                )
            )

        assert session_lock.acquire(blocking=False) is True
        session_lock.release()


class TestGetScanProgress:
    def test_empty_scan_id_is_rejected(self):
        result = asyncio.run(mcp_get_scan_progress(""))

        assert result["success"] is False
        assert result["operation"] == "get_scan_progress"
        assert "Scan ID cannot be empty" in result["error"]
        assert "Ensure the scan ID format is valid" in result["suggestions"]

    def test_progress_is_stamped_with_the_operation_and_a_timestamp(self):
        progress = {"scan_id": "scan-1", "status": "running"}

        with patch(f"{_TOOLS}.check_scan_progress", AsyncMock(return_value=progress)):
            result = asyncio.run(mcp_get_scan_progress("scan-1"))

        assert result["operation"] == "get_scan_progress"
        assert result["status"] == "running"
        assert "timestamp" in result

    def test_resource_error_becomes_an_error_response(self):
        error = MCPResourceError(
            "Scan scan-1 not found in registry",
            context={"error_category": "scan_not_found"},
        )

        with patch(f"{_TOOLS}.check_scan_progress", AsyncMock(side_effect=error)):
            result = asyncio.run(mcp_get_scan_progress("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "scan_not_found"
        assert "Ensure the scan was started correctly" in result["suggestions"]

    def test_unexpected_error_is_typed_and_logged(self):
        with (
            patch(
                f"{_TOOLS}.check_scan_progress",
                AsyncMock(side_effect=OSError("disk gone")),
            ),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_get_scan_progress("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "OSError"
        assert result["context"]["scan_id"] == "scan-1"
        assert "Unexpected error getting scan progress" in logger.error.call_args[0][0]


class TestGetScanResults:
    def test_relative_output_dir_is_refused(self):
        result = asyncio.run(mcp_get_scan_results("relative/ash_output"))

        assert result["success"] is False
        assert result["operation"] == "get_scan_results"
        assert "Absolute path required" in result["error"]
        assert result["error_category"] == "invalid_parameter"

    def test_output_dir_outside_the_allowed_roots_is_refused(
        self, tmp_path, monkeypatch
    ):
        permitted = tmp_path / "permitted"
        permitted.mkdir()
        refused = tmp_path / "elsewhere"
        refused.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(permitted))

        result = asyncio.run(mcp_get_scan_results(str(refused)))

        assert result["success"] is False
        assert "outside the permitted roots" in result["error"]

    def test_missing_output_dir_is_reported_as_missing(self, allowed_root):
        result = asyncio.run(mcp_get_scan_results(str(allowed_root / "no-output")))

        assert result["success"] is False
        assert result["error_category"] == "file_not_found"
        assert "Check that the output directory exists" in result["suggestions"]

    def test_results_are_stamped_with_the_operation(self, allowed_root):
        with patch(
            f"{_TOOLS}.get_scan_results_with_error_handling",
            return_value={"status": "completed", "findings_count": 3},
        ):
            result = asyncio.run(mcp_get_scan_results(str(allowed_root)))

        assert result["operation"] == "get_scan_results"
        assert result["findings_count"] == 3
        assert "timestamp" in result

    def test_an_existing_timestamp_is_not_overwritten(self, allowed_root):
        with patch(
            f"{_TOOLS}.get_scan_results_with_error_handling",
            return_value={"status": "completed", "timestamp": "2020-01-01T00:00:00"},
        ):
            result = asyncio.run(mcp_get_scan_results(str(allowed_root)))

        assert result["timestamp"] == "2020-01-01T00:00:00"

    def test_unexpected_error_records_the_cwd_and_output_dir(self, allowed_root):
        with (
            patch(
                f"{_TOOLS}.get_scan_results_with_error_handling",
                side_effect=ValueError("corrupt results"),
            ),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_get_scan_results(str(allowed_root)))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "ValueError"
        assert result["context"]["output_dir"] == str(allowed_root)
        assert "cwd" in result["context"]
        assert "Unexpected error getting scan results" in logger.error.call_args[0][0]


class TestListActiveScans:
    def test_active_and_all_scans_are_reported_with_statistics(self, registry):
        registry.list_scans.return_value = [
            {"scan_id": "scan-1", "status": "running"},
            {"scan_id": "scan-0", "status": "completed"},
        ]
        registry.get_scan_count.return_value = 2
        registry.get_active_scan_count.return_value = 1
        registry.get_scan_status_counts.return_value = {"running": 1, "completed": 1}

        with (
            patch(
                f"{_TOOLS}.list_active_scans",
                AsyncMock(return_value=[{"scan_id": "scan-1", "status": "running"}]),
            ),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        ):
            result = asyncio.run(mcp_list_active_scans())

        assert result["success"] is True
        assert result["operation"] == "list_active_scans"
        assert [s["scan_id"] for s in result["active_scans"]] == ["scan-1"]
        assert len(result["all_scans"]) == 2
        assert result["stats"] == {
            "total_scans": 2,
            "active_scans": 1,
            "status_counts": {"running": 1, "completed": 1},
        }

    def test_registry_failure_becomes_an_error_response(self, registry):
        registry.list_scans.side_effect = RuntimeError("registry unreachable")

        with (
            patch(f"{_TOOLS}.list_active_scans", AsyncMock(return_value=[])),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_list_active_scans())

        assert result["success"] is False
        assert result["operation"] == "list_active_scans"
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "RuntimeError"
        assert "registry unreachable" in result["error"]
        assert "Unexpected error listing active scans" in logger.error.call_args[0][0]


class TestCancelScanTool:
    def test_empty_scan_id_is_rejected_without_delegating(self):
        with patch(f"{_TOOLS}.cancel_scan", AsyncMock()) as inner:
            result = asyncio.run(mcp_cancel_scan(""))

        inner.assert_not_awaited()
        assert result["success"] is False
        assert result["operation"] == "cancel_scan"
        assert "Scan ID cannot be empty" in result["error"]

    def test_result_is_stamped_with_operation_and_timestamp(self):
        with patch(
            f"{_TOOLS}.cancel_scan",
            AsyncMock(return_value={"success": True, "status": "cancelled"}),
        ):
            result = asyncio.run(mcp_cancel_scan("scan-1"))

        assert result["success"] is True
        assert result["operation"] == "cancel_scan"
        assert "timestamp" in result

    def test_existing_operation_and_timestamp_are_preserved(self):
        inner_result = {
            "success": False,
            "operation": "cancel_scan_inner",
            "timestamp": "2020-01-01T00:00:00",
        }

        with patch(f"{_TOOLS}.cancel_scan", AsyncMock(return_value=inner_result)):
            result = asyncio.run(mcp_cancel_scan("scan-1"))

        assert result["operation"] == "cancel_scan_inner"
        assert result["timestamp"] == "2020-01-01T00:00:00"

    def test_unexpected_error_is_typed_and_logged(self):
        with (
            patch(
                f"{_TOOLS}.cancel_scan",
                AsyncMock(side_effect=RuntimeError("kill failed")),
            ),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_cancel_scan("scan-1"))

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["scan_id"] == "scan-1"
        assert result["context"]["error_type"] == "RuntimeError"
        assert "Unexpected error cancelling scan" in logger.error.call_args[0][0]


class TestCheckInstallation:
    def test_version_lookup_failure_is_reported_as_not_installed(self):
        with (
            patch(f"{_TOOLS}.get_ash_version", side_effect=RuntimeError("no metadata")),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = asyncio.run(mcp_check_installation())

        assert result["success"] is False
        assert result["operation"] == "check_installation"
        assert result["context"]["installed"] is False
        assert result["context"]["error_type"] == "RuntimeError"
        assert "Try reinstalling ASH" in result["suggestions"]
        assert "Unexpected error checking installation" in logger.error.call_args[0][0]

    def test_successful_lookup_reports_the_version(self):
        with patch(f"{_TOOLS}.get_ash_version", return_value="9.9.9"):
            result = asyncio.run(mcp_check_installation())

        assert result["success"] is True
        assert result["installed"] is True
        assert result["version"] == "9.9.9"
        assert result["ash_command_output"] == "ASH version 9.9.9"
