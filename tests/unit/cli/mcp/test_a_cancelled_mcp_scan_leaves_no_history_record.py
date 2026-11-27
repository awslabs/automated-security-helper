# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan whose cancel lands after run_ash_scan's last check keeps no history record.

Why these tests exist
---------------------
``_run_local_mode`` discards the cancelled run's history record only when its own
``raise_if_cancelled`` before the final rewrite fires. A cancel that lands after
that check passes (during the atomic rewrite, or before this runner's settle)
ends the scan with the runner: ``_settle_previous_results`` sees the cancel event
set, puts the previous results back, and the client is told the scan was
cancelled. The record the orchestrator appended for the cancelled run stayed in
``history/``, so ``ash trend`` showed the taken-back run as a completed one. The
settle's restore path now discards it.

The scan is a stub standing in for ``run_ash_scan``; the cancel is injected by
setting the entry's cancel event inside the stub, after every check the real
function would have run.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
RESULTS = "ash_aggregated_results.json"
RECORD_ID = "ASH-20260101120000-abcdefabcdef"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield
    sessions.reset_default_registry_for_tests()
    clear_profile_registry()
    clear_all_session_state()


def _scan_with_a_recorded_run(tmp_path: Path):
    """A registered scan whose directory holds previous results and a run record.

    The previous results are set aside, as ``mcp_scan_directory`` leaves them,
    and the record is the one the orchestrator would append for THIS run: its id
    is the id the stubbed scan's results carry.
    """
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / RESULTS).write_text("previous results", encoding="utf-8")
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    PreviousResults(output).set_aside()
    assert not (output / RESULTS).exists()
    history = output / "history"
    history.mkdir()
    (history / f"{RECORD_ID}.json").write_text("{}", encoding="utf-8")
    return registry, scan_id, source, output


def _stub_run_ash_scan(
    monkeypatch: pytest.MonkeyPatch, registry, scan_id: str, *, cancel_after: bool
) -> None:
    """Stand in for ``run_ash_scan``: a run that recorded itself and returned.

    With ``cancel_after`` the cancel event is set before the return, standing
    for a cancel that lands after the real function's last
    ``raise_if_cancelled`` passed: the function returns results, and the runner
    is the first to see the event.
    """
    from automated_security_helper.interactions import run_ash_scan as run_module

    def fake(**_kwargs: Any) -> Any:
        if cancel_after:
            registry.get_scan(scan_id).cancel_event.set()
        return {"metadata": {"report_id": RECORD_ID}}

    monkeypatch.setattr(run_module, "run_ash_scan", fake)


def _run(registry, scan_id: str, source: Path, output: Path) -> None:
    from automated_security_helper.cli import mcp_tools

    with patch.object(mcp_tools, "get_scan_registry", return_value=registry):
        asyncio.run(
            mcp_tools._run_scan(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
                session_id=SESSION,
            )
        )


def test_a_cancel_after_the_last_check_discards_the_runs_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.core.previous_results import holds_restored_results

    registry, scan_id, source, output = _scan_with_a_recorded_run(tmp_path)
    _stub_run_ash_scan(monkeypatch, registry, scan_id, cancel_after=True)

    _run(registry, scan_id, source, output)

    # Red at the base: the restore put the previous results back and left the
    # cancelled run's record, so ``ash trend`` showed it as a completed run.
    assert not (output / "history" / f"{RECORD_ID}.json").exists()
    assert (output / RESULTS).read_text(encoding="utf-8") == "previous results"
    assert holds_restored_results(output)


def test_a_run_that_completed_keeps_its_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a scan settled as one with results stays in the history."""
    from automated_security_helper.core.previous_results import HELD_DIR_NAME

    registry, scan_id, source, output = _scan_with_a_recorded_run(tmp_path)
    _stub_run_ash_scan(monkeypatch, registry, scan_id, cancel_after=False)

    _run(registry, scan_id, source, output)

    assert (output / "history" / f"{RECORD_ID}.json").exists()
    assert not (output / HELD_DIR_NAME).exists()
