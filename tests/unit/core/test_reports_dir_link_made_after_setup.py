# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``reports/`` that becomes a link after the run set it up is refused, not crashed on.

The orchestrator refuses a linked ``reports/`` when it sets up its directories.
A link that appears after that, while the run is under way, reaches the places
that create the directory again: the execution engine and the existing-results
load before the report phase, and ``save_model`` at the end of the scan phase.
Each creates it through ``ensure_reports_dir``, so a dangling link there is
refused with ``ReportPathLinkRefused`` rather than failing with
``FileExistsError``, and a link to a directory is refused rather than kept.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.report_path_links import ReportPathLinkRefused
from tests.utils.helpers import results_of_a_scan

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _link_reports(output: Path, to: Path) -> Path:
    reports = output / "reports"
    if reports.exists():
        shutil.rmtree(reports)
    reports.symlink_to(to, target_is_directory=True)
    return reports


@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "existing"])
def test_a_reports_link_made_after_setup_is_refused(tmp_path, existing):
    """By the engine for a fresh run, by the load step for existing results."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    kwargs = {}
    if existing:
        results = output / "ash_aggregated_results.json"
        results.write_text(
            results_of_a_scan().model_dump_json(by_alias=True), encoding="utf-8"
        )
        kwargs["existing_results_path"] = results
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        output_formats=[ExportFormat.YAML],
        config_overrides=["reporters.yaml.enabled=true"],
        show_progress=False,
        offline=True,
        **kwargs,
    )
    _link_reports(output, tmp_path / "nothing")

    with pytest.raises(ReportPathLinkRefused):
        orchestrator.execute_scan(phases=["report"])


@pytest.mark.parametrize("target", ["dangling", "a directory"])
def test_saving_the_model_refuses_a_linked_reports_dir(tmp_path, target):
    output = tmp_path / "out"
    output.mkdir()
    elsewhere = tmp_path / "elsewhere"
    if target == "a directory":
        elsewhere.mkdir()
    reports = _link_reports(output, elsewhere)

    with pytest.raises(ReportPathLinkRefused):
        AshAggregatedResults().save_model(output)

    assert reports.is_symlink()
    assert not (output / "ash_aggregated_results.json").exists()
