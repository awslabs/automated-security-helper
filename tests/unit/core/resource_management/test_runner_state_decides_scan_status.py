# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A readable results file means results exist. It does not mean the scan succeeded.

WHY THIS EXISTS
---------------
``check_scan_progress`` marked the registry entry completed whenever
``ash_aggregated_results.json`` parsed, whatever state the entry was in. That was wrong
in three directions:

* A scan its runner had marked FAILED or CANCELLED came back ``completed``, and the
  runner's reason was dropped from the answer.
* A RUNNING scan came back ``completed`` as soon as the SCAN phase wrote the file,
  before the REPORT phase had run. That was hidden only by a second defect:
  ``save_model`` dumped with ``exclude_unset``, and because the scan fills
  ``scanner_results`` and ``sarif`` in place, pydantic counted both as unset and left
  them out. So the early file read as "completed, no scanners". Fixing the dump makes
  that early file complete-looking, so the status has to come from the runner.
* ``run_ash_scan`` ends with ``sys.exit`` on a non-zero verdict. ``SystemExit`` is not
  an ``Exception``, so it escaped ``_run_scan_async`` and left the entry RUNNING for
  good. With the runner now deciding, that would read as running forever. The same
  holds for ``asyncio.CancelledError`` when the server shuts down.
* The runner closed its entry with ``update_scan_status``, which overwrites. A cancel
  cannot stop an in-process scan, so the run still returned afterwards and turned the
  cancelled scan back into a completed one. Runners now close with ``finish_scan``,
  which leaves an entry something else already closed as it is.

THE RULE
--------
A RUNNING entry has a runner that will close it: not complete, whatever the file says,
with whatever scanners the file holds shown as partial results. FAILED and CANCELLED
stand, reason included. Only a PENDING entry, which nothing has claimed, takes its
status from the file -- the contract
``test_completion_is_reported_from_the_aggregated_file_alone`` pins.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

RESULTS_FILE = "ash_aggregated_results.json"
SCANNERS = ("bandit", "semgrep")


def _model_built_the_way_the_scan_builds_it() -> AshAggregatedResults:
    """Mutated in place, never assigned -- how scan_phase.py fills scanner_results."""
    model = AshAggregatedResults()
    for name in SCANNERS:
        model.scanner_results[name] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )
    return model


def _registered(tmp_path: Path, model: AshAggregatedResults | None):
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    if model is not None:
        model.save_model(output_dir)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    return registry, scan_id, output_dir


def test_save_model_writes_fields_the_scan_filled_in_place(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    _model_built_the_way_the_scan_builds_it().save_model(output_dir)

    written = json.loads((output_dir / RESULTS_FILE).read_text(encoding="utf-8"))
    assert set(written.get("scanner_results", {})) == set(SCANNERS), (
        "save_model dropped scanner_results the scan had filled in place, so the "
        f"file claims no scanner ran. Top-level keys written: {sorted(written)}"
    )
    assert "sarif" in written


def _write_raw_document(output_dir: Path) -> None:
    """A results file that parses, independent of how save_model serializes."""
    document = {
        "scanner_results": {
            name: {"status": "PASSED", "finding_count": 0} for name in SCANNERS
        }
    }
    (output_dir / RESULTS_FILE).write_text(json.dumps(document), encoding="utf-8")


@pytest.mark.parametrize(
    "status,reason",
    [
        (MCScanStatus.FAILED, "scanner crashed"),
        (MCScanStatus.CANCELLED, None),
    ],
    ids=["failed", "cancelled"],
)
@pytest.mark.parametrize("writer", ["save_model", "raw_document"])
def test_a_readable_file_does_not_turn_a_closed_scan_into_a_completed_one(
    tmp_path, status, reason, writer
):
    if writer == "save_model":
        registry, scan_id, _ = _registered(
            tmp_path, _model_built_the_way_the_scan_builds_it()
        )
    else:
        registry, scan_id, output_dir = _registered(tmp_path, None)
        _write_raw_document(output_dir)
    registry.update_scan_status(scan_id, status, reason)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == status.value, (
        f"A scan its runner marked {status.value} was reported as "
        f"{progress['status']!r} because its results file parses."
    )
    assert registry.get_scan(scan_id).status is status
    assert progress["is_complete"] is True
    if reason is not None:
        assert progress["error_message"] == reason
    # The partial results stay readable.
    assert set(progress["scanners"]) == set(SCANNERS)


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(_model_built_the_way_the_scan_builds_it, id="scanners_so_far"),
        pytest.param(AshAggregatedResults, id="no_scanners_yet"),
    ],
)
def test_a_running_scan_is_not_complete_whatever_its_file_says(tmp_path, model):
    """What the SCAN phase leaves on disk while the REPORT phase is still running."""
    registry, scan_id, _ = _registered(tmp_path, model())
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "running"
    assert progress["is_complete"] is False, (
        "A scan still running reported is_complete, so a client following the "
        f"documented poll loop would stop here with scanners={progress['scanners']!r}."
    )
    assert registry.get_scan(scan_id).status is MCScanStatus.RUNNING


def test_the_runner_closing_the_scan_makes_it_completed(tmp_path):
    registry, scan_id, _ = _registered(
        tmp_path, _model_built_the_way_the_scan_builds_it()
    )
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    assert registry.check_scan_progress(scan_id)["is_complete"] is False

    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert set(progress["scanners"]) == set(SCANNERS)


def test_an_unclaimed_entry_still_takes_its_status_from_the_file(tmp_path):
    """Control: the PENDING contract the integration suite pins is unchanged."""
    registry, scan_id, _ = _registered(
        tmp_path, _model_built_the_way_the_scan_builds_it()
    )

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert set(progress["scanners"]) == set(SCANNERS)


@pytest.mark.parametrize(
    "code,expected",
    [(1, MCScanStatus.FAILED), (0, MCScanStatus.COMPLETED)],
    ids=["nonzero_exit", "zero_exit"],
)
def test_a_scan_ending_in_sys_exit_closes_its_entry(tmp_path, code, expected):
    from automated_security_helper.cli.mcp_tools import _run_scan_async

    (tmp_path / "out").mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_scan_registry",
            return_value=registry,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
            side_effect=SystemExit(code),
        ),
    ):
        asyncio.run(
            _run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(tmp_path / "out"),
                severity_threshold="MEDIUM",
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry.status is expected
    if expected is MCScanStatus.FAILED:
        assert entry.error_message == f"ASH exited with code {code}"


def test_a_workspace_claims_its_project_entries_as_running(tmp_path):
    """Otherwise a project reads as completed as soon as its SCAN phase writes."""
    from automated_security_helper.cli.mcp import workspace as mcp_workspace

    registry = ScanRegistry()
    project_dir = tmp_path / "api"
    project_dir.mkdir()
    project_output = tmp_path / "out" / "projects" / "api"
    project_output.mkdir(parents=True)
    plan = SimpleNamespace(
        active_projects=[
            SimpleNamespace(
                key="api",
                path=str(project_dir),
                gate_threshold="HIGH",
                config_source=None,
            )
        ]
    )

    with patch.object(mcp_workspace, "get_scan_registry", return_value=registry):
        registered = mcp_workspace._register_projects(plan, {"api": project_output})

    assert registry.get_scan(registered["api"]).status is MCScanStatus.RUNNING


def test_a_runner_finishing_after_a_cancel_does_not_undo_it(tmp_path):
    """cancel_scan cannot stop an in-process scan; the run still returns later."""
    from automated_security_helper.cli.mcp_tools import _run_scan_async

    (tmp_path / "out").mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )

    def cancelled_mid_run(**_kwargs):
        registry.cancel_scan(scan_id)

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_scan_registry",
            return_value=registry,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
            side_effect=cancelled_mid_run,
        ),
    ):
        asyncio.run(
            _run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(tmp_path / "out"),
                severity_threshold="MEDIUM",
            )
        )

    assert registry.get_scan(scan_id).status is MCScanStatus.CANCELLED


def test_a_cancelled_scan_task_closes_its_entry_and_still_propagates(tmp_path):
    """Server shutdown cancels the task. The entry must not stay RUNNING."""
    from automated_security_helper.cli.mcp_tools import _run_scan_async

    (tmp_path / "out").mkdir()
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(tmp_path / "out")
    )

    with (
        patch(
            "automated_security_helper.cli.mcp_tools.get_scan_registry",
            return_value=registry,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
            side_effect=asyncio.CancelledError(),
        ),
    ):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(
                _run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(tmp_path),
                    output_dir=str(tmp_path / "out"),
                    severity_threshold="MEDIUM",
                )
            )

    entry = registry.get_scan(scan_id)
    assert entry.status is MCScanStatus.FAILED
    assert entry.error_message == "Scan task ended without a result: CancelledError"
