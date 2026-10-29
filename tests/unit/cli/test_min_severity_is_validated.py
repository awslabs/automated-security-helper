# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--min-severity`` accepts its five values and refuses anything else.

The scan's exit code ranks the value with ``_SEVERITY_RANK``, and the workspace gate
with ``_MIN_SEVERITY_RANK``. A value neither ranks, a typo such as ``hihg`` or a word
such as ``error``, is refused where the command line is parsed (``scan`` and
``merge``), again where a scan's options are built, so a library or MCP caller cannot
reach the ranking with it either, and by the workspace gate.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: ASH_EXIT_USAGE_ERROR's published value; see tests/unit/cli/test_usage_error_exit_code.py.
USAGE_ERROR_EXIT = 5


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """The output without color codes, panel borders or rich's line wrapping."""
    text = _ANSI.sub("", text)
    return " ".join(text.replace("│", " ").replace("╭", " ").replace("╰", " ").split())


VALID = ["critical", "high", "medium", "low", "none"]


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _invoke(args):
    return CliRunner().invoke(app, list(args))


@pytest.mark.parametrize("value", ["bogus", "hihg", "error", "info", ""])
def test_scan_refuses_an_unknown_value(in_tmp, value):
    # --version ends the command before any scan, so a tree that accepts the value
    # exits 0 here.
    result = _invoke(["scan", "--min-severity", value, "--version"])

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert "--min-severity" in _plain(result.output)


@pytest.mark.parametrize("value", [*VALID, "HIGH", "Medium"])
def test_scan_accepts_each_documented_value_in_any_case(in_tmp, value):
    result = _invoke(["scan", "--min-severity", value, "--version"])

    assert result.exit_code == 0, result.output


def test_merge_refuses_an_unknown_value(in_tmp):
    result = _invoke(
        ["merge", "--output-dir", "o", "--results", "r", "--min-severity", "bogus"]
    )

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert "--min-severity" in _plain(result.output)


@pytest.mark.parametrize("value", ["HIGH", "Medium", "none"])
def test_merge_accepts_each_value_in_any_case(in_tmp, value):
    """The Terraform executor passes its MinSeverity variable through unchanged."""
    import typer.main

    command = typer.main.get_command(app).commands["merge"]
    ctx = command.make_context(
        "merge", ["--output-dir", "o", "--results", "r", "--min-severity", value]
    )
    from automated_security_helper.core.enums import MinSeverity

    assert MinSeverity(ctx.params["min_severity"]) == MinSeverity(value.lower())

    result = _invoke(
        ["merge", "--output-dir", "o", "--results", "r", "--min-severity", value]
    )
    # The merge itself then refuses the missing results; the severity was accepted.
    assert "--min-severity" not in _plain(result.output), result.output


def test_scan_options_refuse_an_unknown_value(tmp_path):
    """The library and MCP entry point builds ScanOptions without the CLI."""
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    with pytest.raises(ValidationError, match="min_severity"):
        ScanOptions(
            source_dir=tmp_path, output_dir=tmp_path / "out", min_severity="bogus"
        )


@pytest.mark.parametrize("value", [*VALID, "HIGH"])
def test_scan_options_accept_each_documented_value(tmp_path, value):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    opts = ScanOptions(
        source_dir=tmp_path, output_dir=tmp_path / "out", min_severity=value
    )

    assert opts.min_severity.lower() == value.lower()


def test_the_cli_choices_are_the_ranked_values():
    """One list: the values the CLI offers are exactly the ones both gates rank."""
    import typer.main

    from automated_security_helper.core.enums import MinSeverity
    from automated_security_helper.interactions.run_ash_scan import _SEVERITY_RANK
    from automated_security_helper.workspace.aggregation import _MIN_SEVERITY_RANK

    values = [member.value for member in MinSeverity]
    command = typer.main.get_command(app)
    for name in ("scan", "merge"):
        param = next(
            p for p in command.commands[name].params if p.name == "min_severity"
        )
        assert list(param.type.choices) == values, name
    assert values == VALID
    assert set(_SEVERITY_RANK) == set(values)
    assert _MIN_SEVERITY_RANK == _SEVERITY_RANK


def test_the_workspace_gate_refuses_an_unknown_value():
    from automated_security_helper.workspace.aggregation import (
        has_finding_at_min_severity,
    )

    with pytest.raises(ValueError, match="bogus"):
        has_finding_at_min_severity([], "bogus")
