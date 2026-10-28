# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A report over existing results is stopped only by what it writes.

``--use-existing`` re-renders the reports from a results file. It deletes none of
the previous run's files and clears no working directory: it writes ``reports/``,
the results file and the log files, ``analysis/`` when the inspect phase runs,
and with ``--cleanup`` it removes ``converted/``. Refusing it for a committed
file anywhere a fresh scan writes would refuse it over ``scanners/`` and the
scan-set lists, which it never touches. It is refused for a committed file where
it writes, and only there.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.exceptions import CommittedOutputFilesError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.utils.output_dir_links import OUTPUT_GITIGNORE
from tests.unit.test_committed_output_refused_at_entry_points import _repo
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _snapshot,
)

#: Committed where a fresh scan writes, and where a report over existing results
#: does not.
UNTOUCHED = {
    "scanners/bandit/source/bandit.sarif": "committed scanner output\n",
    "analysis/notes.json": "committed notes\n",
    "converted/jupyter/notebook.py": "committed conversion\n",
    "ash-ignore-report.txt": "committed ignore report\n",
    "ash-scan-set-files-list.txt": "committed list\n",
    "ash-scan-set-run.json": "{}\n",
}


class _ReportingEngine:
    """Runs no phase: records which it was asked for and returns the model."""

    def __init__(self) -> None:
        self._asharp_model = AshAggregatedResults()
        self.phases: List[List[str]] = []

    def execute_phases(self, phases=None):
        self.phases.append(list(phases or []))
        return self._asharp_model


def _existing_results(tmp_path: Path) -> Path:
    """A completed run's results, as ``--use-existing`` reports on them: one
    scanner ran and found nothing. A file with no scanner results and no findings
    is what a run that stopped before its scan leaves, and the orchestrator
    refuses to report on one (utils/inner_run_outcome.existing_results_problem)."""
    model = AshAggregatedResults()
    model.metadata.project_name = "previous-run"
    model.scanner_results["bandit"] = ScannerTargetStatusInfo()
    path = tmp_path / "previous" / "ash_aggregated_results.json"
    path.parent.mkdir()
    path.write_text(model.model_dump_json(by_alias=True), encoding="utf-8")
    return path


def _written(output: Path) -> dict:
    """What the output directory holds, the ``.gitignore`` the run writes aside.

    An output directory inside the scanned tree gets one before any phase runs
    (core/orchestrator.ensure_directories,
    utils/output_dir_links.ignore_output_dir_in_git); it is the run's own file,
    not a change to anything the repository committed."""
    found = _snapshot(output)
    found.pop(OUTPUT_GITIGNORE, None)
    return found


def _report_over(
    source: Path,
    output: Path,
    existing: Path,
    *,
    phases: List[str],
    cleanup: bool = False,
) -> _ReportingEngine:
    """initialize and execute_scan over *existing*, as ``--use-existing`` does."""
    engine = _ReportingEngine()
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config_path=None,
        config_overrides=None,
        no_cleanup=not cleanup,
        metadata=None,
        ash_plugin_modules=[],
        existing_results_path=existing,
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=engine,
        ),
    ):
        orchestrator.initialize()
        orchestrator.execute_scan(phases=phases)
    return engine


def test_a_report_over_existing_results_is_not_stopped_where_it_never_writes(
    tmp_path, monkeypatch
):
    source, output = _repo(tmp_path, monkeypatch, committed=UNTOUCHED)
    existing = _existing_results(tmp_path)
    _confined(tmp_path, source, output, existing)
    before = _snapshot(output)

    engine = _report_over(source, output, existing, phases=["report"])

    assert engine.phases == [["report"]]
    assert _written(output) == before


@pytest.mark.parametrize(
    ("committed", "phases", "cleanup"),
    [
        ("reports/ash.sarif", ["report"], False),
        ("ash_aggregated_results.json", ["report"], False),
        ("ash.log", ["report"], False),
        ("analysis/notes.json", ["report", "inspect"], False),
        ("converted/jupyter/notebook.py", ["report"], True),
    ],
)
def test_a_report_over_existing_results_is_stopped_where_it_writes(
    tmp_path, monkeypatch, committed, phases, cleanup
):
    source, output = _repo(tmp_path, monkeypatch, committed={committed: "committed\n"})
    existing = _existing_results(tmp_path)
    _confined(tmp_path, source, output, existing)
    before = _snapshot(output)
    engine: Optional[_ReportingEngine] = None

    with pytest.raises(CommittedOutputFilesError) as refused:
        engine = _report_over(source, output, existing, phases=phases, cleanup=cleanup)

    assert committed in str(refused.value), refused.value
    assert engine is None
    # analysis/ is checked once the phases are known, in execute_scan, after
    # initialize wrote the output directory's .gitignore (_written).
    assert _written(output) == before


def _run_use_existing(source, output, existing, **kwargs):
    exit_code = None
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            existing_results=str(existing),
            mode=RunMode.local,
            progress=False,
            show_summary=False,
            **kwargs,
        )
    except SystemExit as exited:
        exit_code = exited.code
    return exit_code


def _orchestrator_reached(monkeypatch) -> None:
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "create",
        classmethod(
            lambda cls, **kw: (_ for _ in ()).throw(
                AssertionError("the orchestrator was reached")
            )
        ),
    )


def test_the_cli_does_not_stop_a_report_over_existing_results_where_it_never_writes(
    tmp_path, monkeypatch, capsys
):
    source, output = _repo(tmp_path, monkeypatch, committed=UNTOUCHED)
    existing = _existing_results(tmp_path)
    _confined(tmp_path, source, output, existing)
    _orchestrator_reached(monkeypatch)

    exit_code = _run_use_existing(source, output, existing)

    printed = capsys.readouterr().out.replace("\n", "")
    assert "the orchestrator was reached" in printed, printed
    assert exit_code == 1


@pytest.mark.parametrize(
    ("committed", "kwargs"),
    [
        ("reports/ash.sarif", {}),
        ("ash.log", {}),
        ("analysis/notes.json", {"inspect": True}),
        ("converted/jupyter/notebook.py", {"cleanup": True}),
    ],
)
def test_the_cli_stops_a_report_over_existing_results_where_it_writes(
    tmp_path, monkeypatch, capsys, committed, kwargs
):
    source, output = _repo(tmp_path, monkeypatch, committed={committed: "committed\n"})
    existing = _existing_results(tmp_path)
    _confined(tmp_path, source, output, existing)
    before = _snapshot(output)
    _orchestrator_reached(monkeypatch)

    exit_code = _run_use_existing(source, output, existing, **kwargs)

    assert _snapshot(output) == before
    assert exit_code == 3
    assert committed in capsys.readouterr().out.replace("\n", "")
