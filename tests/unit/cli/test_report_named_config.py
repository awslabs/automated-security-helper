# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash report --config <file>` refuses a file it cannot use, with exit 3.

A file that does not parse is refused with exit 3, as a file the model refuses
is, and no report is rendered with the default configuration in its place:
other reporters, other masking.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import AshAggregatedResults


@pytest.fixture
def results_dir(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    out = tmp_path / "out"
    out.mkdir()
    (out / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    return out


@pytest.mark.parametrize(
    "text, reason",
    [
        pytest.param(
            "project_name: [unclosed\n", "could not be parsed", id="yaml-syntax"
        ),
        pytest.param(
            "project_name: demo\nfail_on_findings: sometimes\n",
            "Invalid value at 'fail_on_findings'",
            id="model",
        ),
    ],
)
def test_a_named_config_that_cannot_be_used_exits_3(
    results_dir: Path, tmp_path: Path, text, reason
):
    config = tmp_path / "ash.yaml"
    config.write_text(text, encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--output-dir",
            str(results_dir),
            "--config",
            str(config),
            "--format",
            "text",
        ],
    )

    assert result.exit_code == 3, result.output
    assert reason in " ".join(result.output.split()), result.output


def test_a_config_that_does_not_parse_is_refused_on_stderr_as_text(
    results_dir: Path, tmp_path: Path
):
    """The refusal goes through _print_error, as report's other errors do.

    It was printed with the builtin print: to stdout, which carries only the
    report, with rich's tags written out ("[red]Invalid configuration: ...[/red]"),
    and with the file's name as it is, so a "[/x]" in it read as markup.
    """
    named_dir = tmp_path / "[" / "x]dir"
    named_dir.mkdir(parents=True)
    config = named_dir / "ash.yaml"
    config.write_text("project_name: [unclosed\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--output-dir",
            str(results_dir),
            "--config",
            str(config),
            "--format",
            "text",
        ],
    )

    stderr = " ".join(result.stderr.split())
    assert result.exit_code == 3, (result.stdout, result.stderr)
    assert "could not be parsed" in stderr, result.stderr
    assert "[/x]dir" in stderr, result.stderr
    assert "[red]" not in result.stdout + result.stderr
    assert "could not be parsed" not in result.stdout, result.stdout


def test_without_a_named_config_the_report_uses_the_defaults(results_dir: Path):
    result = CliRunner().invoke(
        app, ["report", "--output-dir", str(results_dir), "--format", "text"]
    )

    assert result.exit_code == 0, result.output
