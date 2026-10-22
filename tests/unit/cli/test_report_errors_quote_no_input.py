# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` describes a failed report without the input pydantic refused.

pydantic's text for a refused value quotes it (``input_value='...'``), and a
config value can be a secret read from the environment. A reporter that fails
with such an error, as a plugin's own model might raise one when the reporter
is built, is described in ``ash report``'s error line, and under ``--debug`` in
its traceback, without the refused input. The error here comes from a model
that does not hide its inputs.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import AshAggregatedResults

CANARY = "ash-canary-7f3e"
SARIF_REPORTER = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters."
    "sarif_reporter.SarifReporter.report"
)


class _Unhidden(BaseModel):
    flag: bool


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.mark.parametrize("debug", [[], ["--debug"]], ids=["default", "debug"])
def test_a_reporter_that_fails_on_a_refused_value(tmp_path, monkeypatch, debug):
    refused = _refused()

    def raise_it(*args, **kwargs):
        raise refused

    monkeypatch.setattr(SARIF_REPORTER, raise_it)
    output = tmp_path / "out"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    result = CliRunner().invoke(
        app,
        ["report", "--format", "sarif", "--output-dir", str(output), *debug],
        env={"COLUMNS": "300"},
    )

    assert result.exit_code == 1, result.output
    printed = f"{result.stdout}\n{result.stderr}"
    assert CANARY not in printed, printed
    # The control: the failure is named, by its field.
    assert "Error generating report" in printed, printed
    assert "Invalid value at 'flag'" in printed, printed


def test_debug_shows_a_reporter_section_without_its_env_value(tmp_path, monkeypatch):
    """--debug logs the config section each reporter is built with, whole, and
    a value the config file reads from the environment is the variable's value
    by then."""
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    config_file = tmp_path / "ash.yaml"
    config_file.write_text(
        "project_name: demo\n"
        "reporters:\n"
        "  gitlab-cyclonedx:\n"
        "    options:\n"
        "      language_override: ${ASH_PROBE_VALUE}\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "gitlab-cyclonedx",
            "--config",
            str(config_file),
            "--output-dir",
            str(output),
            "--debug",
        ],
        env={"COLUMNS": "300"},
    )

    printed = f"{result.stdout}\n{result.stderr}"
    # The control: the section was shown, with the marker where the value read
    # from the environment would be.
    assert "Found config for reporter plugin gitlab-cyclonedx" in printed, printed
    assert "'language_override': '<value>'" in " ".join(printed.split()), printed
    assert CANARY not in printed, printed
