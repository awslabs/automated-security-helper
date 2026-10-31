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

The tests that name a directory outside the working directory run from a directory
of their own that does not hold the temporary directory, so the second guard is the
one that refuses; run from a directory above it, the first guard would.
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
    pytest.mark.usefixtures("own_environment"),
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
    """The result of the command, and the reporter's patched ``report``."""
    with patch(SARIF_REPORT, return_value=json.dumps({"runs": []})) as reporter:
        result = CliRunner().invoke(
            app, ["report", "--format", "sarif", "--output-dir", str(output_dir)]
        )
    return result, reporter


def _squeezed(text: str) -> str:
    """The text with its whitespace and panel borders removed, so a phrase and a
    path are found wherever a line broke."""
    return "".join(text.translate(str.maketrans("", "", "│╭╮╰╯─")).split())


@pytest.fixture
def elsewhere(own_environment, tmp_path_factory, monkeypatch) -> Path:
    """A working directory that does not hold the test's temporary directory.

    ``tmp_path_factory.mktemp`` makes a sibling of ``tmp_path``, so a directory
    below ``tmp_path`` is outside it, wherever the base temporary directory is
    (inside a checkout, say). Entered after ``own_environment``, which enters
    ``tmp_path``."""
    cwd = tmp_path_factory.mktemp("elsewhere")
    monkeypatch.chdir(cwd)
    return cwd


def test_a_link_at_the_given_directorys_ash_outside_cwd_is_refused(tmp_path, elsewhere):
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.mkdir()
    (target / ".ash").symlink_to(real / ".ash", target_is_directory=True)
    assert not target.is_relative_to(Path.cwd())

    result, reporter = _report(target)

    assert result.exit_code == 3, result.output
    assert _squeezed(
        f"{(target / '.ash').as_posix()} is a symlink, on the way to the output "
        "directory"
    ) in _squeezed(result.output), result.output
    reporter.assert_not_called()


def test_a_link_at_the_given_directory_outside_cwd_is_refused(tmp_path, elsewhere):
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.symlink_to(real, target_is_directory=True)
    assert not target.is_relative_to(Path.cwd())

    result, reporter = _report(target)

    assert result.exit_code == 3, result.output
    assert _squeezed(
        f"{target.as_posix()} is a symlink, on the way to the output directory"
    ) in _squeezed(result.output), result.output
    reporter.assert_not_called()


def test_a_plain_given_directory_outside_cwd_is_still_read(tmp_path, elsewhere):
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    assert not real.is_relative_to(Path.cwd())

    result, reporter = _report(real)

    assert result.exit_code == 0, result.output
    reporter.assert_called_once()


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

    result, reporter = _report(Path(".."))

    assert result.exit_code == 3, result.output
    assert _squeezed(
        f"{(repo / '.ash').as_posix()} is a symlink, on the way to the output directory"
    ) in _squeezed(result.output), result.output
    reporter.assert_not_called()


def test_a_link_at_the_given_directorys_ash_under_cwd_is_refused(tmp_path, monkeypatch):
    """The in-cwd control: the working-directory guard already examined this."""
    monkeypatch.chdir(tmp_path)
    real = tmp_path / "real"
    _write_results(real / ".ash" / "ash_output")
    target = tmp_path / "target"
    target.mkdir()
    (target / ".ash").symlink_to(real / ".ash", target_is_directory=True)

    result, reporter = _report(Path("target"))

    assert result.exit_code == 3, result.output
    assert (
        f"{(target / '.ash').as_posix()} is a symlink, on the way to the output "
        "directory"
    ) in _squeezed(result.output), result.output
    reporter.assert_not_called()
