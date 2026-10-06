# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of the scan tools' results, from start through every terminal status.

Covers run_ash_scan, get_scan_progress, get_scan_results, get_scan_summary,
get_scan_result_paths, list_active_scans and cancel_scan: each tool's success
payload, the refusals a client can trigger, and the status a scan reports as it
moves through pending, running, completed, incomplete, failed and cancelled.

The terminal statuses are reached through the real runner. ``run_ash_scan``
registers the scan and starts ``_run_scan_async`` as it does in production; only
the launcher it calls in an executor is replaced, by one that writes a results
file and returns, or raises the exit a real scan raises. So the status a snapshot
records is the one the runner decided, not one the test assigned. Pending and
running are read before the runner gets the loop, or from a registry entry the
test moves by hand, because those are the states a client polls during a scan.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict
from unittest.mock import AsyncMock

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import source_delivery
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    get_scan_registry,
)

from tests.snapshot.mcp.mcp_snapshot_support import (
    aggregated_results,
    drain_background_tasks,
    make_ctx,
    record,
    write_results,
)

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


def _missing_semgrep() -> Dict[str, Any]:
    """Results where one selected scanner never ran: the incomplete shape."""
    document = aggregated_results()
    document["scanner_results"]["semgrep"] = {
        "status": "MISSING",
        "finding_count": 0,
        "dependencies_satisfied": False,
        "excluded": False,
    }
    document["metadata"]["summary_stats"]["missing"] = 1
    return document


def _completes(kwargs: Dict[str, Any]):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    path = write_results(Path(kwargs["output_dir"]), aggregated_results())
    return AshAggregatedResults.from_json(path.read_text(encoding="utf-8"))


def _incomplete(kwargs: Dict[str, Any]):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanIncompleteExit,
        scan_incompleteness,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    path = write_results(Path(kwargs["output_dir"]), _missing_semgrep())
    results = AshAggregatedResults.from_json(path.read_text(encoding="utf-8"))
    raise ScanIncompleteExit(scan_incompleteness(results, gate=True), results)


def _exits_2(kwargs: Dict[str, Any]):
    raise SystemExit(2)


def _raises(kwargs: Dict[str, Any]):
    raise RuntimeError("scanner orchestration crashed")


LAUNCHERS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    "completed": _completes,
    "incomplete": _incomplete,
    "failed_on_exit_code": _exits_2,
    "failed_on_exception": _raises,
}


@pytest.fixture
def launcher(monkeypatch):
    """Replace the scan launcher and the progress monitor; nothing real runs."""
    behavior: Dict[str, Callable[[Dict[str, Any]], Any]] = {"run": _completes}

    def fake_run_ash_scan(**kwargs):
        return behavior["run"](kwargs)

    monkeypatch.setattr(_LAUNCHER, fake_run_ash_scan)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    return behavior


async def _call(tool: str, *args, headers=None, **kwargs) -> Dict[str, Any]:
    ctx = make_ctx(headers)
    result = await getattr(mcp_server, tool)(ctx, *args, **kwargs)
    return record(tool, result, ctx)


def _register(source: Path, status: MCScanStatus, **finish) -> str:
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    if status is MCScanStatus.RUNNING:
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    elif status is not MCScanStatus.PENDING:
        registry.finish_scan(scan_id, status, **finish)
    return scan_id


# ---------------------------------------------------------------------------
# A scan, start to finish, through the real runner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", list(LAUNCHERS))
async def test_a_scan_from_start_to_its_terminal_status(
    outcome, project, launcher, snapshot, snapshot_normalizer
):
    launcher["run"] = LAUNCHERS[outcome]

    started = await _call("run_ash_scan", source_dir=str(project))
    scan_id = started["result"]["scan_id"]
    snapshot_normalizer.add_literal(scan_id, "SCAN_ID")
    # Polled before the runner has had the loop: what a client sees first.
    first_poll = await _call("get_scan_progress", scan_id)

    await drain_background_tasks()

    final_poll = await _call("get_scan_progress", scan_id)
    output_dir = str(project / ".ash" / "ash_output")
    summary = await _call("get_scan_summary", output_dir=output_dir)
    active = await _call("list_active_scans")

    assert started == snapshot(name="run_ash_scan")
    assert first_poll == snapshot(name="first_poll")
    assert final_poll == snapshot(name="final_poll")
    assert summary == snapshot(name="summary")
    assert active == snapshot(name="list_active_scans")


# ---------------------------------------------------------------------------
# get_scan_progress for each status a registry entry can hold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "pending_without_results",
        "pending_with_results",
        "running_with_partial_results",
        "completed",
        "incomplete",
        "failed",
        "cancelled",
    ],
)
async def test_progress_for_each_status(state, allowed, snapshot, snapshot_normalizer):
    from automated_security_helper.core.resource_management.scan_tracking import (
        assess_coverage,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source = allowed / "project"
    output = source / ".ash" / "ash_output"
    document = _missing_semgrep() if state == "incomplete" else aggregated_results()
    if state != "pending_without_results":
        write_results(output, document)
    model = AshAggregatedResults.from_json(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
        if output.exists()
        else AshAggregatedResults().model_dump_json()
    )
    _, coverage = assess_coverage(model)

    if state.startswith("pending"):
        scan_id = _register(source, MCScanStatus.PENDING)
    elif state.startswith("running"):
        scan_id = _register(source, MCScanStatus.RUNNING)
    elif state == "completed":
        scan_id = _register(source, MCScanStatus.COMPLETED, coverage=coverage)
    elif state == "incomplete":
        scan_id = _register(source, MCScanStatus.INCOMPLETE, coverage=coverage)
    elif state == "failed":
        scan_id = _register(
            source, MCScanStatus.FAILED, error_message="ASH exited with code 2"
        )
    else:
        scan_id = _register(source, MCScanStatus.RUNNING)
        cancelled = await _call("cancel_scan", scan_id)
        snapshot_normalizer.add_literal(scan_id, "SCAN_ID")
        assert cancelled == snapshot(name="cancel_scan")
    snapshot_normalizer.add_literal(scan_id, "SCAN_ID")

    assert await _call("get_scan_progress", scan_id) == snapshot(name="progress")


@pytest.mark.asyncio
async def test_progress_errors(allowed, monkeypatch, snapshot, snapshot_normalizer):
    unknown = await _call("get_scan_progress", "no-such-scan")
    empty = await _call("get_scan_progress", "")

    # The wrapper's own scan_not_found: the scan was removed from the registry
    # between the progress check and the wrapper's lookup.
    scan_id = _register(allowed / "project", MCScanStatus.RUNNING)
    snapshot_normalizer.add_literal(scan_id, "SCAN_ID")

    class _Emptied:
        def get_scan(self, _scan_id):
            return None

    monkeypatch.setattr(mcp_server, "get_scan_registry", lambda: _Emptied())
    vanished = await _call("get_scan_progress", scan_id)

    assert unknown == snapshot(name="unknown_scan_id")
    assert empty == snapshot(name="empty_scan_id")
    assert vanished == snapshot(name="removed_between_lookups")


# ---------------------------------------------------------------------------
# run_ash_scan refusals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_ash_scan_refusals(
    allowed, tmp_path, launcher, monkeypatch, snapshot
):
    outside = tmp_path / "outside"
    outside.mkdir()
    source = allowed / "project"
    source.mkdir()

    results: Dict[str, Any] = {}
    results["invalid_session_id"] = await _call(
        "run_ash_scan", headers={"mcp-session-id": "../escape"}
    )
    results["no_source_delivered"] = await _call(
        "run_ash_scan", headers={"mcp-session-id": "session-a"}
    )

    other = tmp_path / "workspaces" / "session-b" / "source"
    other.mkdir(parents=True)
    source_delivery._set_session_source_dir("session-b", other)
    results["session_source_mismatch"] = await _call(
        "run_ash_scan", headers={"mcp-session-id": "session-a"}
    )

    gone = tmp_path / "workspaces" / "session-c" / "source"
    source_delivery._set_session_source_dir("session-c", gone)
    results["delivered_source_missing"] = await _call(
        "run_ash_scan", headers={"mcp-session-id": "session-c"}
    )

    results["scan_target_not_permitted"] = await _call(
        "run_ash_scan", source_dir=str(outside)
    )

    linked = allowed / "linked"
    linked.mkdir()
    (linked / ".ash").symlink_to(outside, target_is_directory=True)
    results["output_dir_not_permitted"] = await _call(
        "run_ash_scan", source_dir=str(linked)
    )

    results["scan_start_failure"] = await _call(
        "run_ash_scan", source_dir=str(source), severity_threshold="SEVERE"
    )

    config = outside / ".ash.yaml"
    config.write_text("project_name: outside\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    results["config_input_not_permitted"] = await _call(
        "run_ash_scan", source_dir=str(source), config_path=str(config)
    )

    for name, result in results.items():
        assert result == snapshot(name=name)


# ---------------------------------------------------------------------------
# Reading a completed scan's results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        {"filter_level": "full"},
        {"filter_level": "summary"},
        {"filter_level": "minimal"},
        {"filter_level": "minimal", "actionable_only": True},
        {"filter_level": "summary", "severities": "critical"},
        {"filter_level": "summary", "scanners": "bandit"},
        {"filter_level": "verbose"},
    ],
    ids=[
        "full",
        "summary",
        "minimal",
        "minimal_actionable_only",
        "summary_critical_only",
        "summary_bandit_only",
        "unknown_filter_level",
    ],
)
async def test_get_scan_results(arguments, project, snapshot):
    output_dir = str(project / ".ash" / "ash_output")
    assert await _call(
        "get_scan_results", output_dir=output_dir, **arguments
    ) == snapshot(name="result")


@pytest.mark.asyncio
async def test_result_readers_refuse_and_report(project, tmp_path, snapshot):
    outside = tmp_path / "outside"
    (outside / ".ash" / "ash_output").mkdir(parents=True)
    unfinished = project.parent / "unfinished" / ".ash" / "ash_output"
    unfinished.mkdir(parents=True)
    missing = project.parent / "never-scanned" / ".ash" / "ash_output"
    no_reports = project.parent / "no-reports" / ".ash" / "ash_output"
    write_results(no_reports, aggregated_results())

    calls = {
        "get_scan_results_outside_roots": (
            "get_scan_results",
            {"output_dir": str(outside / ".ash" / "ash_output")},
        ),
        "get_scan_results_missing_dir": (
            "get_scan_results",
            {"output_dir": str(missing)},
        ),
        "get_scan_results_scan_not_finished": (
            "get_scan_results",
            {"output_dir": str(unfinished)},
        ),
        "get_scan_results_relative_dir_resolves_against_cwd": (
            "get_scan_results",
            {"output_dir": ".ash/ash_output"},
        ),
        "get_scan_summary_missing_dir": (
            "get_scan_summary",
            {"output_dir": str(missing)},
        ),
        "get_scan_result_paths": (
            "get_scan_result_paths",
            {"output_dir": str(project / ".ash" / "ash_output")},
        ),
        "get_scan_result_paths_outside_roots": (
            "get_scan_result_paths",
            {"output_dir": str(outside / ".ash" / "ash_output")},
        ),
        "get_scan_result_paths_missing_dir": (
            "get_scan_result_paths",
            {"output_dir": str(missing)},
        ),
        "get_scan_result_paths_no_reports_dir": (
            "get_scan_result_paths",
            {"output_dir": str(no_reports)},
        ),
    }
    for name, (tool, kwargs) in calls.items():
        assert await _call(tool, **kwargs) == snapshot(name=name)

    invalid_session = await _call(
        "get_scan_results",
        headers={"mcp-session-id": "../escape"},
        output_dir=str(project / ".ash" / "ash_output"),
    )
    assert invalid_session == snapshot(name="get_scan_results_invalid_session_id")


# ---------------------------------------------------------------------------
# list_active_scans and cancel_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_active_scans_and_cancel_scan(
    allowed, snapshot, snapshot_normalizer
):
    empty = await _call("list_active_scans")
    running = _register(allowed / "running", MCScanStatus.RUNNING)
    finished = _register(allowed / "finished", MCScanStatus.COMPLETED)
    snapshot_normalizer.add_literal(running, "RUNNING_SCAN_ID")
    snapshot_normalizer.add_literal(finished, "FINISHED_SCAN_ID")

    listed = await _call("list_active_scans")
    cancelled = await _call("cancel_scan", running)
    cancelled_again = await _call("cancel_scan", running)
    cancel_finished = await _call("cancel_scan", finished)
    cancel_unknown = await _call("cancel_scan", "no-such-scan")
    cancel_empty = await _call("cancel_scan", "")

    assert empty == snapshot(name="list_active_scans_empty")
    assert listed == snapshot(name="list_active_scans")
    assert cancelled == snapshot(name="cancel_scan")
    assert cancelled_again == snapshot(name="cancel_scan_already_cancelled")
    assert cancel_finished == snapshot(name="cancel_scan_already_completed")
    assert cancel_unknown == snapshot(name="cancel_scan_unknown_scan_id")
    assert cancel_empty == snapshot(name="cancel_scan_empty_scan_id")
