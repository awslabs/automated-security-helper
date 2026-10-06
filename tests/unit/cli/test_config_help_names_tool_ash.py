# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every --config help names the pyproject.toml table it reads.

The help is rendered as rich markup, which read the old "[tool.ash]" as a style tag
and dropped it, so the help said "then a  table in pyproject.toml".
"""

import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

COMMANDS = [
    ["scan"],
    ["config", "init"],
    ["config", "get"],
    ["config", "update"],
    ["dependencies", "install"],
]


@pytest.mark.parametrize("command", COMMANDS, ids=" ".join)
def test_config_help_names_the_tool_ash_table(command, monkeypatch):
    monkeypatch.setenv("COLUMNS", "300")
    monkeypatch.setenv("TERMINAL_WIDTH", "300")
    result = CliRunner().invoke(app, [*command, "--help"], prog_name="ash")
    assert result.exit_code == 0, result.output
    text = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    text = re.sub(r"[\s│]+", " ", text)
    assert "tool.ash table of pyproject.toml" in text
    assert " a table in pyproject.toml" not in text
