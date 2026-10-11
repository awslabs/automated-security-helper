# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report``, ``ash plugin`` and ``ash dependencies install`` refuse a config
file they cannot load, with exit 3 and a message that names the file.

Each resolves its config through ``resolve_config``, which used to answer a named
file that was missing, or a file that did not parse, with the built-in defaults:
the report was rendered, the plugins listed and the dependencies installed for a
configuration other than the one named. Now resolution raises, and each command
reports it the way ``ash scan`` does. Nothing is installed: the refusal comes
before any plugin is loaded.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

BAD_YAML = "project_name: demo\nscanners: [bandit\n"


def _flat(output: str) -> str:
    """The output with colors and all whitespace removed: rich wraps long paths."""
    return "".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


@pytest.fixture(autouse=True)
def _in_empty_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)


def _report(config: Path) -> List[str]:
    return ["report", "--config", str(config), "--output-dir", "out"]


def _plugin(config: Path) -> List[str]:
    return ["plugin", "list", "--config", str(config)]


def _dependencies(config: Path) -> List[str]:
    return ["dependencies", "install", "--config", str(config)]


COMMANDS = [
    pytest.param(_report, id="report"),
    pytest.param(_plugin, id="plugin"),
    pytest.param(_dependencies, id="dependencies_install"),
]


@pytest.mark.parametrize("command", COMMANDS)
def test_a_named_config_that_does_not_exist_exits_three(tmp_path, command):
    result = CliRunner().invoke(app, command(tmp_path / "missing.yaml"))

    assert result.exit_code == 3, result.output
    assert "Invalidconfiguration:Configurationfilenotfound" in _flat(result.output)
    assert "missing.yaml" in _flat(result.output)


@pytest.mark.parametrize("command", COMMANDS)
def test_a_named_config_that_does_not_parse_exits_three(tmp_path, command):
    config = tmp_path / "bad.yaml"
    config.write_text(BAD_YAML, encoding="utf-8")

    result = CliRunner().invoke(app, command(config))

    assert result.exit_code == 3, result.output
    assert "Invalidconfiguration:couldnotparse" in _flat(result.output)
    assert "bad.yaml" in _flat(result.output)


def test_a_discovered_config_that_does_not_parse_exits_three(tmp_path):
    """No --config: ``ash plugin`` discovers .ash/.ash.yaml in the working directory."""
    config = tmp_path / ".ash" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(BAD_YAML, encoding="utf-8")

    result = CliRunner().invoke(app, ["plugin", "list"])

    assert result.exit_code == 3, result.output
    assert ".ash/.ash.yaml" in _flat(result.output)


def test_control_a_config_that_loads_is_used(tmp_path):
    config = tmp_path / "good.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    result = CliRunner().invoke(app, _plugin(config))

    assert result.exit_code == 0, result.output
