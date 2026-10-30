# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --output-dir <dir>`` refuses a link on the way to the results, wherever
``<dir>`` is.

The output directory is the one the results were read from, ``<dir>/.ash/ash_output``
when ``--output-dir`` names the scanned root. The link guard rooted at the working
directory examines the components below the working directory only, so for a
``<dir>`` outside it a link at ``<dir>`` or at ``<dir>/.ash`` was written through:
the reporter wrote into reports/ behind the link. The guard now also runs from the
given directory's parent down to the resolved directory, so those components are
examined whatever the working directory is.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="symlink creation needs a privilege on Windows"
    ),
]

SARIF_REPORT = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters."
    "SarifReporter.report"
)


def _write_results(output: Path) -> None:
    output.mkdir(parents=True)
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )


def _report(output_dir: Path):
    with patch(SARIF_REPORT, return_value=json.dumps({"runs": []})):
        return CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(output_dir)]
        )


def test_a_link_at_the_given_directorys_ash_outside_cwd_is_refused(tmp_path):
    """The working directory is the test runner's, not under tmp_path."""
    assert not Path.cwd().is_relative_to(tmp_path)
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.mkdir()
    (target / ".ash").symlink_to(real / ".ash", target_is_directory=True)

    result = _report(target)

    assert result.exit_code == 3, result.output
    assert ".ash" in result.output
    assert "symbolic link" in result.output or "link" in result.output


def test_a_link_at_the_given_directory_outside_cwd_is_refused(tmp_path):
    assert not Path.cwd().is_relative_to(tmp_path)
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.symlink_to(real, target_is_directory=True)

    result = _report(target)

    assert result.exit_code == 3, result.output
    assert "target" in result.output


def test_a_plain_given_directory_outside_cwd_is_still_read(tmp_path):
    assert not Path.cwd().is_relative_to(tmp_path)
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")

    result = _report(real)

    assert result.exit_code == 0, result.output


def test_a_link_at_the_parents_ash_is_refused_when_the_directory_is_given_as_dot_dot(
    tmp_path, monkeypatch
):
    """``--output-dir ..`` from ``<repo>/sub``: pathlib's parent of a path ending in
    ``..`` drops the ``..`` instead of stepping up, which rooted the guard at the
    working directory and left ``<repo>/.ash`` below neither root."""
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    repo = tmp_path / "repo"
    sub = repo / "sub"
    sub.mkdir(parents=True)
    (repo / ".ash").symlink_to(real / ".ash", target_is_directory=True)
    monkeypatch.chdir(sub)

    result = _report(Path(".."))

    assert result.exit_code == 3, result.output
    assert ".ash" in result.output


def test_a_link_at_the_given_directorys_ash_under_cwd_is_refused(tmp_path, monkeypatch):
    """The in-cwd control: the working-directory guard already examined this."""
    monkeypatch.chdir(tmp_path)
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.mkdir()
    (target / ".ash").symlink_to(real / ".ash", target_is_directory=True)

    result = _report(Path("target"))

    assert result.exit_code == 3, result.output
