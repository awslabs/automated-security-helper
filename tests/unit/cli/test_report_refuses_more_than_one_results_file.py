# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --output-dir`` refuses a directory that holds more than one results file.

An --output-dir is searched in three places (``.ash/ash_output``, ``ash_output``
and the directory itself). When more than one holds a results file, the command
reported on the first found and said nothing, so a report on one scan read as a
report on the other. The docs (how-to/read-results.md, reference/exit-codes.md)
say such a directory is refused: ``More than one scan results file found:`` with
each path in the order searched, nothing reported on, nothing created, exit 5.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("own_environment")]

SARIF_REPORT = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters."
    "SarifReporter.report"
)
DOCUMENT = json.dumps({"version": "2.1.0", "runs": []})


def _saved_results(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    results = directory / "ash_aggregated_results.json"
    results.write_text(model.model_dump_json(by_alias=True), encoding="utf-8")
    return results


def _entries(root: Path) -> set:
    return {path.relative_to(root).as_posix() for path in root.rglob("*")}


def _report(output_dir: Path):
    with patch(SARIF_REPORT, return_value=DOCUMENT):
        return CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(output_dir)]
        )


def test_a_results_file_in_two_searched_places_is_refused_naming_both(tmp_path):
    output_dir = tmp_path / "out"
    nested = _saved_results(output_dir / ".ash" / "ash_output")
    direct = _saved_results(output_dir)
    before = _entries(tmp_path)

    result = _report(output_dir)

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert result.stdout == ""
    assert (
        f"More than one scan results file found: {nested.as_posix()}, "
        f"{direct.as_posix()}."
    ) in result.stderr, result.stderr
    assert "Point --output-dir" in result.stderr
    assert _entries(tmp_path) == before


def test_a_results_file_in_all_three_searched_places_is_refused_naming_each(
    tmp_path,
):
    output_dir = tmp_path / "out"
    paths = [
        _saved_results(output_dir / ".ash" / "ash_output"),
        _saved_results(output_dir / "ash_output"),
        _saved_results(output_dir),
    ]

    result = _report(output_dir)

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert result.stdout == ""
    listed = ", ".join(path.as_posix() for path in paths)
    assert f"More than one scan results file found: {listed}." in result.stderr


@pytest.mark.parametrize(
    "place", [".ash/ash_output", "ash_output", "."], ids=["nested", "flat", "direct"]
)
def test_a_results_file_in_one_searched_place_is_reported_on(tmp_path, place):
    output_dir = tmp_path / "out"
    _saved_results(output_dir / place)

    result = _report(output_dir)

    assert result.exit_code == 0, result.output
    assert result.stdout == DOCUMENT
    assert "More than one" not in result.stderr
