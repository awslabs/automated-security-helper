# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --output-dir <scanned root>`` works in the scan's output directory.

``--output-dir`` may name the scanned repository's root: the results are then
read from ``<dir>/.ash/ash_output/ash_aggregated_results.json``, the first
candidate. The plugin context, its work directory, the reports/ name check and
the reports/ link refusal used ``<dir>`` itself, so a reporter that writes files
of its own wrote them into ``<dir>/reports``, inside the scanned tree, while a
scan writes them under ``<dir>/.ash/ash_output/reports``. Every one of those now
follows the directory the results file was read from.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("own_environment")]

SARIF_REPORT = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters."
    "SarifReporter.report"
)


@pytest.fixture
def scanned_root(tmp_path: Path) -> Path:
    """A scanned tree whose scan wrote its results under .ash/ash_output."""
    root = tmp_path / "repo"
    output = root / ".ash" / "ash_output"
    output.mkdir(parents=True)
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    return root


def test_the_plugin_context_names_the_directory_the_results_came_from(scanned_root):
    seen: dict = {}

    def recording_context(**kwargs):
        seen.update(kwargs)
        return PluginContext(**kwargs)

    with (
        patch(SARIF_REPORT, return_value=json.dumps({"runs": []})),
        patch(
            "automated_security_helper.cli.report.PluginContext",
            side_effect=recording_context,
        ),
    ):
        result = CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(scanned_root)]
        )

    assert result.exit_code == 0, result.output
    expected = scanned_root / ".ash" / "ash_output"
    assert Path(seen["output_dir"]) == expected, seen
    assert Path(seen["work_dir"]) == expected / "work", seen


def test_the_reports_checks_look_in_the_scans_reports_directory(scanned_root):
    checked: list = []

    def recording_refusal(report_dir, names, *args, **kwargs):
        checked.append(Path(report_dir))

    with (
        patch(SARIF_REPORT, return_value=json.dumps({"runs": []})),
        patch(
            "automated_security_helper.cli.report.refuse_linked_report_paths",
            side_effect=recording_refusal,
        ),
    ):
        result = CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(scanned_root)]
        )

    assert result.exit_code == 0, result.output
    assert checked == [scanned_root / ".ash" / "ash_output" / "reports"], checked


def test_a_plain_output_directory_is_still_used_as_given(tmp_path):
    """The one-candidate shape: the results sit directly in --output-dir."""
    output = tmp_path / "out"
    output.mkdir()
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    seen: dict = {}

    def recording_context(**kwargs):
        seen.update(kwargs)
        return PluginContext(**kwargs)

    with (
        patch(SARIF_REPORT, return_value=json.dumps({"runs": []})),
        patch(
            "automated_security_helper.cli.report.PluginContext",
            side_effect=recording_context,
        ),
    ):
        result = CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(output)]
        )

    assert result.exit_code == 0, result.output
    assert Path(seen["output_dir"]) == output, seen
