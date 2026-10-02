# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report files and per-project results are replaced, never truncated in place.

WHY THIS EXISTS
---------------
``ash_aggregated_results.json`` moved to ``write_text_atomically`` because a reader
polling it could open the file between truncation and the end of the write. Three
more writers had the same shape:

* ``ReportPhase`` wrote each ``reports/ash.*`` with ``open(path, "w")``. An MCP client
  that has seen completion waits for these files and reads them as soon as they exist.
* The changed-files mode of ``_run_local_mode`` rewrote ``reports/ash.sarif``, a file
  that already exists at that point, with ``Path.write_text``.
* A workspace wrote ``projects/<key>/ash_aggregated_results.json`` with
  ``Path.write_text``. That directory is the project's registry entry's output tree,
  so ``get_scan_progress`` parses the file while the workspace is still running.

HOW IT IS MEASURED
------------------
Without racing a reader. Each test makes the final rename fail and checks that the
previous file is still intact: a truncating write has no rename to fail, so on the
old code the file is already overwritten when the error would have come. Each test
also counts the rename it intercepted, so a pass cannot come from the write never
having been attempted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults

PREVIOUS = "previous contents, complete"
_REAL_REPLACE = os.replace


def _failing_replace_for(name: str, intercepted: List[str]):
    """An os.replace that fails for one target filename and passes the rest through."""

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == name:
            intercepted.append(str(dst))
            raise OSError("injected: disk full")
        return _REAL_REPLACE(src, dst, *args, **kwargs)

    return replace


def _leftover_staging_files(directory: Path) -> List[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".tmp"))


def test_a_failed_report_write_leaves_the_previous_report_intact(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import load_plugins

    output_dir = tmp_path / "out"
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True)
    report = reports_dir / "ash.csv"
    report.write_text(PREVIOUS, encoding="utf-8")

    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)

    def run_report_phase() -> None:
        ReportPhase(
            plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
            plugin_context=context,
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=AshAggregatedResults(),
        ).execute(
            report_dir=reports_dir,
            cli_output_formats=["csv"],
            aggregated_results=AshAggregatedResults(),
            python_based_plugins_only=False,
        )

    intercepted: List[str] = []
    with patch(
        "automated_security_helper.utils.atomic_write.os.replace",
        _failing_replace_for("ash.csv", intercepted),
    ):
        run_report_phase()

    assert report.read_text(encoding="utf-8") == PREVIOUS, (
        "The report was overwritten in place: a reader opening it during the write "
        "would have seen it truncated."
    )
    assert intercepted == [str(report)], (
        "The report write never reached a rename, so it is not atomic."
    )
    assert _leftover_staging_files(reports_dir) == []

    # Control: the same run without the injected failure does replace the file, so
    # the preserved contents above are the failed rename's doing.
    run_report_phase()
    assert report.read_text(encoding="utf-8") != PREVIOUS


def test_a_failed_changed_files_sarif_rewrite_leaves_the_previous_sarif_intact(
    tmp_path,
):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    output_dir = tmp_path / "out"
    (output_dir / "reports").mkdir(parents=True)
    sarif = output_dir / "reports" / "ash.sarif"
    sarif.write_text(PREVIOUS, encoding="utf-8")

    opts = ScanOptions(
        source_dir=tmp_path, output_dir=output_dir, changed_files_only=True
    )
    orchestrator = MagicMock()
    orchestrator.execute_scan.return_value = AshAggregatedResults()
    orchestrator.config.fail_on_findings = True

    intercepted: List[str] = []
    with (
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            return_value=orchestrator,
        ),
        # The changed-files filter anchors the diff on the repository root and
        # falls back to a full scan when there is none, which tmp_path is not.
        # Pinned so the rewrite under test actually runs.
        patch(
            "automated_security_helper.utils.get_scan_set.git_repository_root",
            return_value=tmp_path,
        ),
        patch(
            "automated_security_helper.utils.get_scan_set.get_changed_files",
            return_value=["a.py"],
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan._filter_results_to_changed_files",
            side_effect=lambda results, *_: results,
        ),
        patch(
            "automated_security_helper.utils.atomic_write.os.replace",
            _failing_replace_for("ash.sarif", intercepted),
        ),
    ):
        # _run_local_mode turns the injected OSError into exit 1. Captured rather than
        # asserted first, so that on a truncating write -- which raises nothing -- the
        # failure reported is the overwritten file, not the missing exit.
        exit_code = None
        try:
            _run_local_mode(opts, MagicMock())
        except SystemExit as exc:
            exit_code = exc.code

    assert sarif.read_text(encoding="utf-8") == PREVIOUS, (
        "ash.sarif was overwritten in place by the changed-files rewrite."
    )
    assert intercepted == [str(sarif)]
    assert exit_code == 1, "A failed report write must not look like a clean run."
    assert _leftover_staging_files(sarif.parent) == []


def test_a_failed_project_results_write_leaves_the_previous_file_intact(tmp_path):
    from automated_security_helper.workspace.execution import _write_project_results

    project_output = tmp_path / "projects" / "api"
    project_output.mkdir(parents=True)
    results_file = project_output / "ash_aggregated_results.json"
    results_file.write_text(PREVIOUS, encoding="utf-8")

    intercepted: List[str] = []
    with patch(
        "automated_security_helper.utils.atomic_write.os.replace",
        _failing_replace_for(results_file.name, intercepted),
    ):
        with pytest.raises(OSError, match="injected"):
            _write_project_results(project_output, AshAggregatedResults())

    assert results_file.read_text(encoding="utf-8") == PREVIOUS
    assert intercepted == [str(results_file)]
    assert _leftover_staging_files(project_output) == []
