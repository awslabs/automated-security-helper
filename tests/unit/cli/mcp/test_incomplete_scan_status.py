# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every terminal status an MCP scan can end in, decided by the runner.

WHY THIS EXISTS
---------------
``fail_on_incomplete_scanners`` defaults on, so a scan in which a selected scanner
was MISSING or ERROR exits 1. A crash also exits 1. ``_run_scan_async`` used to
close every exit 1 as ``failed`` with "ASH exited with code 1", so an MCP client
could not tell "the scan ran, here are partial results" from "the scan broke".
``incomplete`` is the status for the first.

The runner tells them apart by a structured signal, ``ScanIncompleteExit``.
``run_ash_scan`` raises it only where ``_compute_exit_code`` returned 1 with
results in hand, and it carries the ``ScanIncompleteness`` that verdict was
reached from. Neither the exit code nor the results file can carry that
signal. The crash case below is the reason: a run that dies after the SCAN phase
also exits 1, and the file it leaves behind names MISSING scanners just as a
finished incomplete scan's does.

HOW IT IS DRIVEN
----------------
The real ``run_ash_scan`` runs, with only ``_run_local_mode`` replaced. The
replacement writes the results file the way the real one does and returns a real
``AshAggregatedResults``, so ``_compute_exit_code``, the exception, the runner,
the registry, ``check_scan_progress`` and ``get_scan_results`` are all the
production code. The tests import nothing this change added at module level, so
on a tree without it they fail on the status they assert, not on an import.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

#: Scanners the roster declares, so the set-level arm reads these results the way
#: it reads a real run of the built-in scanners.
ROSTER = ["bandit", "detect-secrets", "grype", "semgrep", "syft"]


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


def _model(statuses: Dict[str, ScannerStatus]) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.scanner_results = {
        name: ScannerTargetStatusInfo(status=status)
        for name, status in statuses.items()
    }
    model.metadata.expected_scanners = list(ROSTER)
    return model


PASSING = {
    "bandit": ScannerStatus.PASSED,
    "detect-secrets": ScannerStatus.FAILED,  # ran and found something
    "grype": ScannerStatus.PASSED,
    "semgrep": ScannerStatus.PASSED,
    "syft": ScannerStatus.PASSED,
}


def _scan(
    tmp_path: Path, local_mode: Callable[[Path], Tuple[Any, Any]]
) -> Tuple[ScanRegistry, str, Path]:
    """Run one MCP scan through the real runner and the real ``run_ash_scan``.

    *local_mode* receives the output directory and plays ``_run_local_mode``.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.interactions import run_ash_scan as ras

    source = tmp_path / "proj"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(
            ras, "_run_local_mode", lambda opts, logger: local_mode(opts.output_dir)
        ),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold="MEDIUM",
            )
        )
    return registry, scan_id, output


def _finishes_with(
    statuses: Optional[Dict[str, ScannerStatus]],
) -> Callable[[Path], Tuple[Any, Any]]:
    """A ``_run_local_mode`` that writes and returns results, as the real one does."""

    def run(output_dir: Path) -> Tuple[Any, Any]:
        model = _model(statuses or {})
        model.save_model(output_dir)
        return model, None

    return run


def _incomplete_rows(payload: Dict[str, Any]) -> list:
    return sorted(
        (row["scanner"], row["status"], row["reason"])
        for row in payload["incomplete_scanners"]
    )


class TestTheRunnerDecidesEachTerminalStatus:
    def test_exit_zero_is_completed(self, tmp_path):
        registry, scan_id, _ = _scan(tmp_path, _finishes_with(PASSING))

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["coverage_complete"] is True
        assert progress["incomplete_scanners"] == []

    def test_missing_scanners_are_incomplete_not_failed(self, tmp_path):
        statuses = dict(
            PASSING, grype=ScannerStatus.MISSING, syft=ScannerStatus.MISSING
        )
        registry, scan_id, _ = _scan(tmp_path, _finishes_with(statuses))

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "incomplete", progress.get("error_message")
        # Terminal: every documented poll loop stops on is_complete.
        assert progress["is_complete"] is True
        assert progress["coverage_complete"] is False
        assert progress["error_message"] is None
        assert _incomplete_rows(progress) == [
            ("grype", "MISSING", "missing_dependencies"),
            ("syft", "MISSING", "missing_dependencies"),
        ]

    def test_an_errored_scanner_is_incomplete_not_failed(self, tmp_path):
        statuses = dict(PASSING, semgrep=ScannerStatus.ERROR)
        registry, scan_id, _ = _scan(tmp_path, _finishes_with(statuses))

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "incomplete", progress.get("error_message")
        assert progress["is_complete"] is True
        assert progress["coverage_complete"] is False
        assert _incomplete_rows(progress) == [("semgrep", "ERROR", "error")]

    def test_a_crash_after_the_scan_phase_is_failed_despite_its_results_file(
        self, tmp_path
    ):
        """The case that rules out deciding from the results file.

        The SCAN phase has written a parseable file naming MISSING scanners, and
        then the run dies -- the real ``_run_local_mode`` turns any exception into
        ``sys.exit(1)``. A runner that read "exit 1 and the file shows a coverage
        gap" as incomplete would report this crash as a finished scan.
        """

        def crash(output_dir: Path) -> Tuple[Any, Any]:
            _model(dict(PASSING, grype=ScannerStatus.MISSING)).save_model(output_dir)
            raise SystemExit(1)

        registry, scan_id, _ = _scan(tmp_path, crash)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert progress["error_message"] == "ASH exited with code 1"
        assert progress["coverage_complete"] is None

    def test_a_raised_exception_is_failed(self, tmp_path):
        def explode(output_dir: Path) -> Tuple[Any, Any]:
            raise RuntimeError("scanner process went away")

        registry, scan_id, _ = _scan(tmp_path, explode)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert "scanner process went away" in progress["error_message"]
        assert progress["coverage_complete"] is None

    def test_an_unparseable_results_file_is_failed(self, tmp_path):
        """No results model, so ``_compute_exit_code`` exits 1 from its None arm."""

        def garbage(output_dir: Path) -> Tuple[Any, Any]:
            (output_dir / "ash_aggregated_results.json").write_text("{ not json")
            return None, None

        registry, scan_id, _ = _scan(tmp_path, garbage)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert progress["error_message"] == "ASH exited with code 1"
        assert progress["coverage_complete"] is None

    def test_a_cancel_during_the_run_stays_cancelled(self, tmp_path):
        """The runner finishing later does not overwrite the cancel, even as incomplete."""
        holder: Dict[str, Any] = {}

        def cancelled_mid_run(output_dir: Path) -> Tuple[Any, Any]:
            assert holder["registry"].cancel_scan(holder["scan_id"])
            return _finishes_with(dict(PASSING, grype=ScannerStatus.MISSING))(
                output_dir
            )

        from automated_security_helper.cli import mcp_tools

        original = mcp_tools.get_scan_registry

        def capture(local_mode):
            def run(output_dir: Path):
                registry = mcp_tools.get_scan_registry()
                holder["registry"] = registry
                holder["scan_id"] = next(
                    entry["scan_id"] for entry in registry.list_scans()
                )
                return local_mode(output_dir)

            return run

        registry, scan_id, _ = _scan(tmp_path, capture(cancelled_mid_run))
        assert mcp_tools.get_scan_registry is original

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "cancelled"


class TestAScanThatRanNoScannerIsNeverCompleted:
    """#640's purpose, held at the MCP surface: nothing measured is not clean."""

    def test_every_scanner_skipped_is_incomplete(self, tmp_path):
        statuses = dict.fromkeys(ROSTER, ScannerStatus.SKIPPED)
        registry, scan_id, _ = _scan(tmp_path, _finishes_with(statuses))

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "incomplete"
        assert progress["no_scanner_ran"] is True
        assert progress["coverage_complete"] is False

    def test_no_scanner_recorded_against_a_roster_is_incomplete(self, tmp_path):
        registry, scan_id, _ = _scan(tmp_path, _finishes_with({}))

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "incomplete"
        assert progress["no_scanner_ran"] is True


class TestPartialResultsStayReadable:
    def test_get_scan_results_returns_the_findings_and_names_the_gap(self, tmp_path):
        from automated_security_helper.core.resource_management.scan_tracking import (
            get_scan_results,
        )

        statuses = dict(PASSING, grype=ScannerStatus.MISSING)
        registry, scan_id, output = _scan(tmp_path, _finishes_with(statuses))
        assert registry.check_scan_progress(scan_id)["status"] == "incomplete"

        results = get_scan_results(output)

        assert results["success"] is True
        assert results["status"] == "incomplete"
        assert results["is_complete"] is True
        assert results["coverage_complete"] is False
        assert _incomplete_rows(results) == [
            ("grype", "MISSING", "missing_dependencies")
        ]
        # The partial results themselves: every scanner that ran is there.
        assert set(results["raw_results"]["scanner_results"]) == set(ROSTER)

    def test_a_completed_scan_reads_completed_from_the_results_tool(self, tmp_path):
        from automated_security_helper.core.resource_management.scan_tracking import (
            get_scan_results,
        )

        _, _, output = _scan(tmp_path, _finishes_with(PASSING))

        results = get_scan_results(output)

        assert results["status"] == "completed"
        assert results["coverage_complete"] is True


class TestTheGateOffStillReportsTheGap:
    def test_gate_off_is_completed_with_coverage_complete_false(self, tmp_path):
        """An operator who turned the gate off has accepted the gap, not hidden it."""

        def gate_off(output_dir: Path) -> Tuple[Any, Any]:
            from automated_security_helper.config.ash_config import AshConfig

            model = _model(dict(PASSING, grype=ScannerStatus.MISSING))
            # The config the scan ran under, which is where the gate is read from
            # when no command-line flag was passed -- and the MCP runner passes none.
            model.ash_config = AshConfig(fail_on_incomplete_scanners=False)
            model.save_model(output_dir)
            return model, None

        registry, scan_id, _ = _scan(tmp_path, gate_off)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["coverage_complete"] is False
        assert _incomplete_rows(progress) == [
            ("grype", "MISSING", "missing_dependencies")
        ]


class TestTheRegistryRefusesAnUnexplainedIncomplete:
    def test_finish_scan_needs_the_gap(self, tmp_path):
        from automated_security_helper.core.resource_management.scan_registry import (
            MCScanStatus,
        )

        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(tmp_path), output_directory=str(tmp_path)
        )
        with pytest.raises(ValueError):
            registry.finish_scan(scan_id, MCScanStatus.INCOMPLETE)
        with pytest.raises(ValueError):
            registry.update_scan_status(scan_id, MCScanStatus.INCOMPLETE)
        assert registry.get_scan(scan_id).is_active()


class TestTheExitCodeAndTheStatusShareOneVerdict:
    """``_compute_exit_code`` exits 1 with results exactly when the runner says incomplete."""

    @pytest.mark.parametrize(
        "statuses",
        [
            PASSING,
            dict(PASSING, grype=ScannerStatus.MISSING),
            dict(PASSING, semgrep=ScannerStatus.ERROR),
            dict.fromkeys(ROSTER, ScannerStatus.SKIPPED),
            {},
        ],
        ids=["passing", "missing", "error", "all-skipped", "empty"],
    )
    def test_one_object_decides_both(self, statuses):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
            scan_incompleteness,
        )

        model = _model(statuses)
        opts = ScanOptions(
            source_dir=Path("."), output_dir=Path("."), fail_on_findings=False
        )

        exit_code = _compute_exit_code(model, opts)

        assert (exit_code == 1) == bool(scan_incompleteness(model, gate=True))


class TestWorkspaceProjectsFollowTheSameRule:
    def _close(self, tmp_path, **outcome_fields):
        from automated_security_helper.cli.mcp import workspace as ws
        from automated_security_helper.models.workspace import (
            ProjectRunStatus,
            WorkspaceProjectResult,
            WorkspaceResults,
        )

        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(tmp_path), output_directory=str(tmp_path)
        )
        outcome = WorkspaceProjectResult(
            project="app",
            relative_path="app",
            display_label="app",
            status=ProjectRunStatus.COMPLETED,
            output_path=str(tmp_path),
            **outcome_fields,
        )
        payload = WorkspaceResults.model_construct(projects=[outcome])
        with patch.object(ws, "get_scan_registry", return_value=registry):
            ws._close_registrations({"app": scan_id}, payload)
        return registry.get_scan(scan_id)

    def test_a_project_whose_gate_fired_is_incomplete(self, tmp_path):
        entry = self._close(
            tmp_path,
            scanners={"bandit": "PASSED", "grype": "MISSING"},
            incomplete_scanners=["grype"],
            scan_incomplete=True,
        )

        assert entry.status.value == "incomplete"
        assert [
            (row["scanner"], row["status"], row["reason"])
            for row in entry.coverage["incomplete_scanners"]
        ] == [("grype", "MISSING", "missing_dependencies")]

    def test_a_project_with_the_gate_off_is_completed_and_keeps_the_facts(
        self, tmp_path
    ):
        entry = self._close(
            tmp_path,
            scanners={"bandit": "PASSED", "grype": "MISSING"},
            incomplete_scanners=["grype"],
            scan_incomplete=False,
        )

        assert entry.status.value == "completed"
        assert entry.coverage["incomplete_scanners"][0]["scanner"] == "grype"

    def test_a_clean_project_is_completed(self, tmp_path):
        entry = self._close(tmp_path, scanners={"bandit": "PASSED"})

        assert entry.status.value == "completed"
