# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #92/#94: --simple must be a discoverable CLI flag."""

import pytest
from typer.testing import CliRunner
from automated_security_helper.cli.main import app

runner = CliRunner()

import re

def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


@pytest.mark.unit
def test_simple_flag_in_help():
    """The --simple flag must appear in `ash scan --help` output.

    Issue #92/#94 reported that --simple was missing from the CLI.
    This test guards against that regression.
    """
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0, f"scan --help exited with {result.exit_code}"
    clean = _strip_ansi(result.output)
    assert "simple" in clean.lower(), (
        "--simple flag not found in scan --help output"
    )


@pytest.mark.unit
def test_simple_flag_in_root_help():
    """--simple should appear as a sub-command option (scan sub-command)."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "simple" in clean.lower()
