# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP scan that ends without results leaves the previous scan's results in place.

Why this file exists
--------------------
``ASHScanOrchestrator.initialize`` clears the output directory at the start of a
scan that does not keep the previous results: ``ensure_directories`` removes
``analysis``, ``reports``, ``scanners`` and ``converted``, and ``initialize`` then
deletes ``ash_aggregated_results.json``, ``ash-ignore-report.txt`` and
``ash-scan-set-files-list.txt``. Over MCP, a scan that then failed or was cancelled
would leave an output directory with the previous results gone and none of its
own: a scan cancelled right after it started would empty the previous complete
scan's ``reports/``. The MCP tool's ``clean_output`` sets the previous results
aside for the same reason, rather than deleting ``ash_aggregated_results.json``
before the scan starts.

For an MCP scan the previous results are set aside when it starts
(``core/previous_results.py``), dropped when the scan has results of its own, and
put back when it ends any other way. The MCP server asks the orchestrator for this
with ``keep_previous_results``, for its single scans and its workspace projects.
The CLI does not: ``ash scan`` deletes them when it starts, and
test_cli_scan_deletes_previous_results.py covers that.

Putting them back makes a second way to be wrong: the directory then holds
complete, parseable results that are not the last scan's, which the MCP progress
for the failed or cancelled scan could read as its own (scanners, findings,
counts). A restore leaves a marker, the runner records it on the scan's
registry entry, and that scan's progress reads nothing from the directory. An
earlier scan's entry, whose results those are, still reads them.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.previous_results import (
    RESTORED_MARKER_NAME,
    holds_restored_results,
)
from automated_security_helper.utils.output_dir_links import OUTPUT_GITIGNORE
from tests.utils.tasks import drain

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "reports/ash.summary.md": "# previous summary\n",
    "scanners/bandit/source/ASH.ScanResults.json": '{"status": "PASSED"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
    "ash-scan-set-files-list.txt": "previous/file.py\n",
}

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)


def _with_previous_results(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return source, output


def _contents(output: Path) -> Dict[str, str]:
    """Every file under the output directory except the run's own files.

    Those are the logs, the restored marker, and the ``.gitignore`` the
    orchestrator writes at the top of an output directory inside the scanned
    tree (core/orchestrator.ensure_directories,
    utils/output_dir_links.ignore_output_dir_in_git), as the fixture's is. None
    of them is a scan result: none is among ``RESULT_ENTRIES``, so a set aside
    leaves them and a restore does not remove them. Only the top-level
    ``.gitignore`` is left out; one under ``reports/`` or ``scanners/`` would be
    a previous result and is compared.
    """
    return {
        p.relative_to(output).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(output.rglob("*"))
        if p.is_file()
        and not p.name.startswith("ash.log")
        and p.name != RESTORED_MARKER_NAME
        and p.relative_to(output).as_posix() != OUTPUT_GITIGNORE
    }


def _marked(output: Path) -> bool:
    """Whether the directory says its results were put back after a failure."""
    return holds_restored_results(output)


def _orchestrator(source: Path, output: Path):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    return ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        show_progress=False,
        show_summary=False,
        keep_previous_results=True,
    )


@pytest.mark.unit
class TestTheOrchestratorPutsThePreviousResultsBack:
    @pytest.mark.parametrize(
        "ending",
        [
            RuntimeError("scanner orchestration crashed"),
            ScanCancelled("cancelled"),
            KeyboardInterrupt(),
        ],
        ids=["failed", "cancelled", "interrupted"],
    )
    def test_a_scan_that_ends_without_results(self, tmp_path, ending):
        source, output = _with_previous_results(tmp_path)
        orchestrator = _orchestrator(source, output)

        with patch(_ENGINE, side_effect=ending):
            with pytest.raises(BaseException):
                orchestrator.execute_scan()

        assert _contents(output) == PREVIOUS
        assert _marked(output), "a restore must say the results are the previous scan's"

    def test_while_the_scan_runs_the_previous_results_are_out_of_the_way(
        self, tmp_path
    ):
        """A poll during the scan must not read the previous scan's files as this one's."""
        source, output = _with_previous_results(tmp_path)
        seen: Dict[str, Any] = {}

        def phases(*args, **kwargs):
            seen.update(_contents(output))
            raise RuntimeError("stop here")

        orchestrator = _orchestrator(source, output)
        with patch(_ENGINE, side_effect=phases):
            with pytest.raises(BaseException):
                orchestrator.execute_scan()

        still_there = {k for k, v in seen.items() if PREVIOUS.get(k) == v}
        assert not still_there, sorted(still_there)

    def test_a_scan_that_finishes_replaces_them(self, tmp_path):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        source, output = _with_previous_results(tmp_path)
        orchestrator = _orchestrator(source, output)

        def phases(*args, **kwargs):
            (output / "reports" / "ash.sarif").write_text(
                '{"new": 1}', encoding="utf-8"
            )
            return AshAggregatedResults()

        with patch(_ENGINE, side_effect=phases):
            orchestrator.execute_scan()

        contents = _contents(output)
        assert contents["reports/ash.sarif"] == '{"new": 1}'
        assert "reports/ash.summary.md" not in contents
        assert "scanners/bandit/source/ASH.ScanResults.json" not in contents
        assert not any(".ash_previous_results" in p for p in contents)
        assert not _marked(output)

    def test_the_next_scan_clears_the_marker_when_it_starts(self, tmp_path):
        source, output = _with_previous_results(tmp_path)
        with patch(_ENGINE, side_effect=RuntimeError("fails")):
            with pytest.raises(BaseException):
                _orchestrator(source, output).execute_scan()
        assert _marked(output)

        _orchestrator(source, output)  # the next scan's set-up

        assert not _marked(output)

    def test_a_first_scan_that_fails_keeps_what_it_wrote_and_no_marker(self, tmp_path):
        """With nothing set aside there is nothing to put back: the output is its own."""
        source = tmp_path / "project"
        source.mkdir()
        output = source / ".ash" / "ash_output"

        def phases(*args, **kwargs):
            target = output / "scanners" / "bandit" / "source"
            target.mkdir(parents=True, exist_ok=True)
            (target / "ASH.ScanResults.json").write_text("{}", encoding="utf-8")
            raise RuntimeError("fails after one scanner")

        with patch(_ENGINE, side_effect=phases):
            with pytest.raises(BaseException):
                _orchestrator(source, output).execute_scan()

        assert "scanners/bandit/source/ASH.ScanResults.json" in _contents(output)
        assert not _marked(output)

    def test_a_scan_killed_mid_run_is_recovered_by_the_next(self, tmp_path):
        """A process killed during a scan cannot restore; the next scan does."""
        source, output = _with_previous_results(tmp_path)
        first = _orchestrator(source, output)  # sets the previous results aside
        # ...and is then killed: partial output, nothing put back.
        (output / "reports" / "partial.sarif").write_text("{}", encoding="utf-8")
        del first

        second = _orchestrator(source, output)
        with patch(_ENGINE, side_effect=RuntimeError("fails too")):
            with pytest.raises(BaseException):
                second.execute_scan()

        assert _contents(output) == PREVIOUS

    def test_a_scan_whose_set_up_fails_after_setting_them_aside(self, tmp_path):
        """initialize sets them aside, then prepares the output directory; a failure
        there puts them back."""
        source, output = _with_previous_results(tmp_path)
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        with patch.object(
            ASHScanOrchestrator,
            "_prepare_output_dir",
            side_effect=OSError("No space left on device"),
        ):
            with pytest.raises(OSError):
                ASHScanOrchestrator.create(
                    source_dir=source,
                    output_dir=output,
                    show_progress=False,
                    show_summary=False,
                    keep_previous_results=True,
                )

        assert _contents(output) == PREVIOUS
        assert _marked(output)

    def test_a_refused_selection_never_sets_them_aside(self, tmp_path):
        """Refused when the engine is built, before anything in the output
        directory is moved: the previous results stay where they were, unmarked."""
        source, output = _with_previous_results(tmp_path)
        from automated_security_helper.core.exceptions import ScannerSelectionError
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        with pytest.raises(ScannerSelectionError):
            ASHScanOrchestrator.create(
                source_dir=source,
                output_dir=output,
                show_progress=False,
                show_summary=False,
                keep_previous_results=True,
                enabled_scanners=["bandit"],
                excluded_scanners=["bandit"],
            )

        assert _contents(output) == PREVIOUS
        assert not _marked(output)


@pytest.mark.unit
def test_run_ash_scan_with_keep_previous_results_leaves_them_set_aside(tmp_path):
    """The MCP runner's path: run_ash_scan leaves the last step to its caller.

    A scan that returned has its results, and the previous ones are still set
    aside: the caller drops them once it has decided the scan really has results
    (a cancel can land after run_ash_scan's last check), and puts them back on
    any other ending.
    """
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        PreviousResults,
    )
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)
    with patch(_ENGINE, side_effect=lambda *a, **k: AshAggregatedResults()):
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(output),
            progress=False,
            show_summary=False,
            quiet=True,
            fail_on_findings=False,
            keep_previous_results=True,
        )

    held = output / HELD_DIR_NAME
    assert (held / "reports" / "ash.summary.md").read_text(encoding="utf-8") == (
        PREVIOUS["reports/ash.summary.md"]
    )
    new_results = (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    assert new_results != PREVIOUS["ash_aggregated_results.json"]

    # What the caller does with a scan that has results.
    PreviousResults(output).discard()
    assert not held.exists()
    assert (output / "ash_aggregated_results.json").read_text(
        encoding="utf-8"
    ) == new_results


@pytest.mark.unit
def test_run_ash_scan_with_keep_previous_results_that_fails_puts_them_back(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output = _with_previous_results(tmp_path)
    with patch(_ENGINE, side_effect=RuntimeError("scanner orchestration crashed")):
        with pytest.raises(SystemExit) as exited:
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
                keep_previous_results=True,
            )
    assert exited.value.code == 1
    assert _contents(output) == PREVIOUS
    assert _marked(output)


@pytest.mark.unit
def test_a_results_write_that_fails_puts_them_back(tmp_path):
    """The write runs after the phases, outside the arm that puts the previous
    results back on a failed phase; a write that fails is a failed scan all the
    same, and puts them back itself."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)

    def refuse(self, output_dir):
        raise OSError(28, "No space left on device", str(output_dir))

    with (
        patch(_ENGINE, side_effect=lambda *a, **k: AshAggregatedResults()),
        patch.object(AshAggregatedResults, "save_model", refuse),
    ):
        with pytest.raises(SystemExit) as exited:
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
                keep_previous_results=True,
            )
    assert exited.value.code == 1
    # Red at the base: the error left the orchestrator raw, the previous results
    # stayed set aside, and nothing was marked restored.
    assert _contents(output) == PREVIOUS
    assert _marked(output)


@pytest.mark.unit
def test_run_ash_scan_with_keep_previous_results_whose_set_up_fails(tmp_path):
    """A failure in initialize after they were set aside: they are put back."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output = _with_previous_results(tmp_path)
    with patch.object(
        ASHScanOrchestrator,
        "_prepare_output_dir",
        side_effect=OSError("No space left on device"),
    ):
        with pytest.raises(SystemExit):
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
                keep_previous_results=True,
            )
    assert _contents(output) == PREVIOUS
    assert _marked(output)


@pytest.mark.unit
def test_run_ash_scan_with_keep_previous_results_and_a_refused_selection(tmp_path):
    """A scanner both selected and excluded is refused before anything is moved."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output = _with_previous_results(tmp_path)
    with pytest.raises(SystemExit):
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(output),
            scanners=["bandit"],
            exclude_scanners=["bandit"],
            progress=False,
            show_summary=False,
            quiet=True,
            keep_previous_results=True,
        )
    assert _contents(output) == PREVIOUS
    assert not _marked(output)


@pytest.mark.unit
def test_a_cancel_after_the_last_phase_writes_no_results_file(tmp_path):
    """The check before run_ash_scan writes ash_aggregated_results.json.

    A scan cancelled once its phases are done must not leave a results file: a
    client reads that file as finished results. The previous results are still
    set aside, so the caller puts them back.
    """
    import threading

    from automated_security_helper.core.cancellation import cancel_scope
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)
    event = threading.Event()
    real_dump = AshAggregatedResults.model_dump_json

    def dump_then_cancel(self, *args, **kwargs):
        # After the orchestrator's own check, before the write.
        event.set()
        return real_dump(self, *args, **kwargs)

    with (
        patch(_ENGINE, side_effect=lambda *a, **k: AshAggregatedResults()),
        patch.object(AshAggregatedResults, "model_dump_json", dump_then_cancel),
        cancel_scope(event),
    ):
        with pytest.raises(ScanCancelled):
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
                fail_on_findings=False,
                keep_previous_results=True,
            )

    assert not (output / "ash_aggregated_results.json").exists()
    PreviousResults(output).restore()
    assert _contents(output) == PREVIOUS


@pytest.mark.asyncio
@pytest.mark.integration
async def test_an_mcp_scan_cancelled_right_after_it_starts(tmp_path, monkeypatch):
    """The reported case, through the MCP tool and the real run_ash_scan."""
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.utils.subprocess_utils import run_command

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    source, output = _with_previous_results(tmp_path)
    started = tmp_path / "started"

    def phases(*args, **kwargs):
        # A scanner's tool, through ASH's own choke point, so the cancel stops it.
        run_command(
            [
                sys.executable,
                "-c",
                "import pathlib, sys, time; pathlib.Path(sys.argv[1]).touch(); time.sleep(10)",
                str(started),
            ]
        )
        raise AssertionError("the cancel did not stop the scan")

    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    with patch(_ENGINE, side_effect=phases):
        begun = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
        assert begun["success"] is True, begun
        for _ in range(600):
            if await asyncio.to_thread(started.exists):
                break
            await asyncio.sleep(0.05)
        cancelled = await mcp_server.cancel_scan(ctx, begun["scan_id"])
        assert cancelled["success"] is True, cancelled
        await drain(timeout=40)

    assert _contents(output) == PREVIOUS
    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress
    # The restored files are the previous scan's, not this one's.
    assert progress["output_holds_previous_results"] is True, progress
    assert progress["scanners"] == {}, progress["scanners"]
    assert (progress["total_scanners"], progress["total_findings"]) == (0, 0)
    json.dumps(progress)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_an_mcp_scan_task_cancelled_mid_scan_stops_the_scan_thread(
    tmp_path, monkeypatch
):
    """Cancelling the runner's task does not stop its executor thread by itself.

    The runner sets the entry's cancel event, so the thread stops its scanner's
    child process and puts the previous results back itself. Put back from the
    event loop while the thread is still scanning, they would be written over as
    the scan went on.
    """
    import threading

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as module
    from automated_security_helper.utils.subprocess_utils import run_command

    source, output = _with_previous_results(tmp_path)
    started = tmp_path / "started"
    stopped = threading.Event()
    returned = threading.Event()

    def phases(*args, **kwargs):
        try:
            run_command(
                [
                    sys.executable,
                    "-c",
                    "import pathlib, sys, time; pathlib.Path(sys.argv[1]).touch(); time.sleep(60)",
                    str(started),
                ]
            )
        except ScanCancelled:
            stopped.set()
            raise
        raise AssertionError("the scan's child process ran to the end")

    real_run_ash_scan = module.run_ash_scan

    def run_ash_scan(*args, **kwargs):
        try:
            return real_run_ash_scan(*args, **kwargs)
        finally:
            returned.set()

    monkeypatch.setattr(module, "run_ash_scan", run_ash_scan)
    scan_id = get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    with patch(_ENGINE, side_effect=phases):
        task = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
            )
        )
        for _ in range(600):
            if await asyncio.to_thread(started.exists):
                break
            await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(returned.wait, 30), (
            "the scan thread was still running 30s after its task was cancelled"
        )
        # run_ash_scan has returned; the thread records how the directory was
        # settled just after, and sets runner_done once it has.
        entry = get_scan_registry().get_scan(scan_id)
        assert await asyncio.to_thread(entry.runner_done.wait, 30), (
            "the scan thread never finished settling the previous results"
        )

    assert stopped.is_set(), "the scan's child process was not stopped"
    assert _contents(output) == PREVIOUS
    entry = get_scan_registry().get_scan(scan_id)
    assert entry.status == MCScanStatus.FAILED
    assert entry.output_holds_previous_results is True


def _results_document(scanner: str) -> str:
    return json.dumps(
        {
            "scanner_results": {
                scanner: {"status": "FAILED", "finding_count": 1},
            }
        }
    )


@pytest.mark.asyncio
@pytest.mark.unit
async def test_an_earlier_scans_progress_reads_its_own_results(tmp_path, monkeypatch):
    """A failed scan's entry reads nothing; the scan whose results those are still does."""
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server, mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    source, output = _with_previous_results(tmp_path)
    (output / "ash_aggregated_results.json").write_text(
        _results_document("bandit"), encoding="utf-8"
    )
    registry = get_scan_registry()
    earlier = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    registry.update_scan_status(earlier, MCScanStatus.RUNNING)
    registry.finish_scan(earlier, MCScanStatus.COMPLETED)

    later = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    with patch(_ENGINE, side_effect=RuntimeError("scanner orchestration crashed")):
        await mcp_tools._run_scan_async(
            scan_id=later,
            directory_path=str(source),
            output_dir=str(output),
            severity_threshold=None,
        )

    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    failed = await mcp_server.get_scan_progress(ctx, later)
    assert failed["status"] == "failed", failed
    assert failed["output_holds_previous_results"] is True
    assert failed["total_scanners"] == 0 and failed["scanner_statuses"] == {}

    completed = await mcp_server.get_scan_progress(ctx, earlier)
    assert completed["status"] == "completed", completed
    assert completed["output_holds_previous_results"] is False
    assert completed["total_scanners"] == 1, completed


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_scan_the_executor_never_ran_still_gets_its_results_back(
    tmp_path, monkeypatch
):
    """If the thread never runs, the task is the only one left to put them back."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )

    source, output = _with_previous_results(tmp_path)
    PreviousResults(output).set_aside()  # what clean_output does once registered
    scan_id = get_scan_registry().register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    loop = asyncio.get_running_loop()

    def refuse(*args, **kwargs):
        raise RuntimeError("cannot schedule new futures after shutdown")

    monkeypatch.setattr(loop, "run_in_executor", refuse)
    await mcp_tools._run_scan_async(
        scan_id=scan_id,
        directory_path=str(source),
        output_dir=str(output),
        severity_threshold=None,
    )

    assert _contents(output) == PREVIOUS
    entry = get_scan_registry().get_scan(scan_id)
    assert entry.status == MCScanStatus.FAILED
    assert entry.output_holds_previous_results is True


@pytest.mark.unit
def test_the_handoff_gives_the_previous_results_to_exactly_one_side():
    from automated_security_helper.core.previous_results import SettleHandoff

    ran = SettleHandoff()
    assert ran.thread_starts() is True
    assert ran.task_abandons() is False  # the thread settles

    dropped = SettleHandoff()
    assert dropped.task_abandons() is True  # the task settles
    assert dropped.thread_starts() is False  # and the late thread does nothing


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_failed_workspace_project_gets_its_previous_results_back(
    tmp_path, monkeypatch
):
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    registry = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)

    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    out = tmp_path / "out"
    project_output = out / "projects" / "api"
    for rel, text in PREVIOUS.items():
        path = project_output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    seen: Dict[str, Any] = {}

    def execute_workspace(plan, settings, **kwargs):
        seen.update(_contents(project_output))
        raise RuntimeError("workspace execution crashed")

    monkeypatch.setattr(workspace_module, "execute_workspace", execute_workspace)
    response = await workspace_module.mcp_scan_workspace(
        workspace_file=str(workspace_file), output_dir=str(out)
    )

    assert response["success"] is False, response
    assert not {k for k, v in seen.items() if PREVIOUS.get(k) == v}
    assert _contents(project_output) == PREVIOUS
    (entry,) = [registry.get_scan(s["scan_id"]) for s in registry.list_scans()]
    assert entry.output_holds_previous_results is True


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_cancel_that_lands_as_the_scan_returns_puts_them_back(
    tmp_path, monkeypatch
):
    """After run_ash_scan's last check and before the runner settles.

    The scan wrote its results and returned, and a cancel arrived in between: the
    client was told the scan is cancelled. The runner settles it as a scan
    without results, so the cancelled scan's files go and the previous results
    come back, as for any other cancel.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as module
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    def finished_then_cancelled(*args, **kwargs):
        assert kwargs.get("keep_previous_results") is True, kwargs
        PreviousResults(output).set_aside()
        (output / "reports").mkdir(parents=True, exist_ok=True)
        (output / "reports" / "ash.sarif").write_text('{"new": 1}', encoding="utf-8")
        (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
        assert registry.cancel_scan(scan_id) is True
        return AshAggregatedResults()

    monkeypatch.setattr(module, "run_ash_scan", finished_then_cancelled)
    await mcp_tools._run_scan_async(
        scan_id=scan_id,
        directory_path=str(source),
        output_dir=str(output),
        severity_threshold=None,
    )

    assert _contents(output) == PREVIOUS
    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.CANCELLED
    assert entry.output_holds_previous_results is True


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_scan_with_results_drops_them_in_the_runner(tmp_path, monkeypatch):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        PreviousResults,
    )
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as module
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )

    def finished(*args, **kwargs):
        PreviousResults(output).set_aside()
        (output / "reports").mkdir(parents=True, exist_ok=True)
        (output / "reports" / "ash.sarif").write_text('{"new": 1}', encoding="utf-8")
        return AshAggregatedResults()

    monkeypatch.setattr(module, "run_ash_scan", finished)
    await mcp_tools._run_scan_async(
        scan_id=scan_id,
        directory_path=str(source),
        output_dir=str(output),
        severity_threshold=None,
    )

    assert not (output / HELD_DIR_NAME).exists()
    assert _contents(output) == {"reports/ash.sarif": '{"new": 1}'}
    assert registry.get_scan(scan_id).output_holds_previous_results is False


def _report_phase_only(self, phases=None, **kwargs):
    """execute_phases, running only the real report phase with the real reporters."""
    from automated_security_helper.core.phases.report_phase import ReportPhase

    phase = ReportPhase(
        plugins=self.plugins["reporter"],
        plugin_context=self._context,
        progress_display=self.progress_display,
        asharp_model=self._asharp_model,
    )
    return phase.execute(
        report_dir=self._context.output_dir.joinpath("reports"),
        cli_output_formats=["sarif", "markdown", "text", "html"],
        aggregated_results=self._asharp_model,
        python_based_plugins_only=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("previous", [True, False], ids=["previous", "first-scan"])
@pytest.mark.unit
async def test_a_cancel_during_the_report_phase_leaves_no_report_of_this_scan(
    tmp_path, monkeypatch, previous
):
    """cancel_scan lands after the first reporter wrote its report.

    The engine checked for a cancel only between phases, so every reporter went
    on to write. With previous results set aside, the restore removed the new
    reports. A first scan has nothing set aside, so the reports stayed, for a scan
    the client was told was cancelled.
    """
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.core.phases import report_phase
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    if previous:
        source, output = _with_previous_results(tmp_path)
    else:
        source = tmp_path / "project"
        source.mkdir()
        (source / "app.py").write_text("x = 1\n", encoding="utf-8")
        output = source / ".ash" / "ash_output"

    written = []
    real_write = report_phase.write_text_atomically

    def write_then_cancel(path, *args, **kwargs):
        real_write(path, *args, **kwargs)
        written.append(Path(path).name)
        if len(written) == 1:
            registry = get_scan_registry()
            for scan in registry.list_scans():
                registry.cancel_scan(scan["scan_id"])

    monkeypatch.setattr(report_phase, "write_text_atomically", write_then_cancel)
    monkeypatch.setattr(ScanExecutionEngine, "execute_phases", _report_phase_only)
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
    assert begun["success"] is True, begun
    await drain(timeout=60)

    assert written, "no reporter wrote a report"
    if previous:
        assert _contents(output) == PREVIOUS
    else:
        left = (
            sorted(p.name for p in (output / "reports").glob("*"))
            if (output / "reports").exists()
            else []
        )
        assert left == [], f"the cancelled scan left its reports: {left}"
        assert not (output / "ash_aggregated_results.json").exists()
    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress
    results = await mcp_server.get_scan_results(ctx, output_dir=str(output))
    assert results.get("status") not in ("completed", "incomplete"), results
    assert results.get("success") is not True or results.get("is_complete") is False, (
        results
    )


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_report_built_after_the_cancel_is_not_written(tmp_path, monkeypatch):
    """cancel_scan lands while a reporter builds its report: nothing is written.

    The reporter that was running when the cancel arrived returns its report as
    usual; the phase checks again before writing it.
    """
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.core.phases import report_phase
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )
    from automated_security_helper.plugins.events import AshEventType

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    written = []
    real_write = report_phase.write_text_atomically
    real_notify = report_phase.ReportPhase.notify_event

    def record_write(path, *args, **kwargs):
        written.append(Path(path).name)
        return real_write(path, *args, **kwargs)

    def cancel_at_the_first_reporter(self, event_type, **kwargs):
        if event_type == AshEventType.REPORT_START:
            registry = get_scan_registry()
            for scan in registry.list_scans():
                registry.cancel_scan(scan["scan_id"])
        return real_notify(self, event_type, **kwargs)

    monkeypatch.setattr(report_phase, "write_text_atomically", record_write)
    monkeypatch.setattr(
        report_phase.ReportPhase, "notify_event", cancel_at_the_first_reporter
    )
    monkeypatch.setattr(ScanExecutionEngine, "execute_phases", _report_phase_only)
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(source))
    assert begun["success"] is True, begun
    await drain(timeout=60)

    assert written == [], f"reports written after the cancel: {written}"
    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_timeout_after_the_scan_settled_its_results_leaves_it_completed(
    tmp_path, monkeypatch
):
    """The timer fires after the thread kept the new results, before the runner resumes.

    The thread drops the previous results and marks itself done, then the loop
    has to resume the runner to close the entry COMPLETED. A timeout that fell
    due in between closed it FAILED as timed out, with this scan's complete
    results on disk and the previous ones already gone. The loop is held busy
    past the timeout while the thread finishes, which puts the timer between the
    two.
    """
    import threading
    import time

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as module
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _with_previous_results(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    loop = asyncio.get_running_loop()
    loop_held = threading.Event()

    def hold_the_loop() -> None:
        loop_held.set()
        time.sleep(0.5)

    def finished(*args, **kwargs):
        loop.call_soon_threadsafe(hold_the_loop)
        assert loop_held.wait(10), "the loop never ran the hold"
        PreviousResults(output).set_aside()
        (output / "reports").mkdir(parents=True, exist_ok=True)
        (output / "reports" / "ash.sarif").write_text('{"new": 1}', encoding="utf-8")
        return AshAggregatedResults()

    monkeypatch.setattr(module, "run_ash_scan", finished)
    await mcp_tools._run_scan_async(
        scan_id=scan_id,
        directory_path=str(source),
        output_dir=str(output),
        severity_threshold=None,
        scan_timeout_seconds=0.05,
    )

    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert not entry.cancel_event.is_set()
    assert _contents(output) == {"reports/ash.sarif": '{"new": 1}'}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_a_runner_cancelled_before_its_thread_starts_puts_them_back(
    tmp_path, monkeypatch
):
    """The executor never runs the scan: the task settles the previous results.

    The thread settles them when it runs. A task cancelled while its job is still
    queued makes the executor drop the job, so the thread never runs and only
    the task can put them back (SettleHandoff). The executor here hands back a
    future that never completes.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )

    source, output = _with_previous_results(tmp_path)
    registry = get_scan_registry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    # As mcp_scan_directory's clean_output does before it starts the task.
    PreviousResults(output).set_aside()
    loop = asyncio.get_running_loop()
    queued = asyncio.Event()

    def never_runs(executor, func, *args):
        queued.set()
        return loop.create_future()

    monkeypatch.setattr(loop, "run_in_executor", never_runs)
    task = asyncio.create_task(
        mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(source),
            output_dir=str(output),
            severity_threshold=None,
        )
    )
    await asyncio.wait_for(queued.wait(), timeout=10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    entry = registry.get_scan(scan_id)
    assert _contents(output) == PREVIOUS
    assert entry.output_holds_previous_results is True
    assert entry.runner_done.is_set(), "the entry still occupies its directory"
    assert entry.status == MCScanStatus.FAILED, entry.status
