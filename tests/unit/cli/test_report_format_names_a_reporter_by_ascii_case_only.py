# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --format`` names a reporter by ASCII case only.

The format is compared with each reporter's own name, and then looked up as that
reporter's config key (``AshConfig.get_plugin_config``). Both go by the lowering
every other comparison of a plugin's name uses, ASCII case only
(``plugin_section_names.ascii_lower``), so a format spelled with a non-ASCII
letter whose lowercase is an ASCII letter names no reporter: the command exits
with the usage-error code, as it does for any format no reporter answers to.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.asharp_model import AshAggregatedResults

#: A non-ASCII letter whose Unicode lowercase is ASCII ``k``, written as an escape.
LOWERS_TO_K = "\N{KELVIN SIGN}"


@pytest.fixture
def output_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    return tmp_path


def _report(output_dir, fmt):
    return CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            fmt,
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
        ],
    )


def test_a_format_spelled_with_a_non_ascii_letter_names_no_reporter(output_dir):
    result = _report(output_dir, "mar" + LOWERS_TO_K + "down")

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "Traceback" not in result.output, result.output


@pytest.mark.parametrize("fmt", ["markdown", "Markdown", "MARKDOWN"])
def test_control_a_format_in_another_ascii_case_names_the_reporter(output_dir, fmt):
    result = _report(output_dir, fmt)

    assert result.exit_code != ASH_EXIT_USAGE_ERROR, result.output
    assert "not found" not in result.output, result.output
