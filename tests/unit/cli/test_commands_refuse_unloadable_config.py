# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report``, ``ash plugin`` and ``ash dependencies install`` refuse a config
file they cannot load, with exit 3 and a message that names the file.

Each resolves its config through ``resolve_config``, which raises for a named file
that is missing and for a file that does not parse, rather than answering with the
built-in defaults; each command reports that the way ``ash scan`` does, so no
report is rendered, no plugin listed and no dependency installed for a
configuration other than the one named. The refusal comes before any plugin is
loaded.
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


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(["plugin", "list"], id="plugin"),
        pytest.param(["config", "get"], id="config_get"),
    ],
)
def test_discovery_that_cannot_read_the_only_source_exits_three(tmp_path, command):
    """Discovery itself refuses: the only source is a pyproject.toml it cannot read.

    Reported as an invalid configuration, not as an uncaught exception.
    """
    (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

    result = CliRunner().invoke(app, command)

    assert result.exit_code == 3, result.output
    assert "Invalidconfiguration:" in _flat(result.output)
    assert "pyproject.toml" in _flat(result.output)


def test_config_get_on_a_named_file_that_does_not_exist_exits_three(tmp_path):
    """Exit 3 like every other command given a config file that cannot be used."""
    result = CliRunner().invoke(app, ["config", "get", str(tmp_path / "missing.yaml")])

    assert result.exit_code == 3, result.output
    assert "Configurationfilenotfound" in _flat(result.output)
    assert "missing.yaml" in _flat(result.output)


def test_config_get_on_an_empty_path_says_the_path_is_empty(tmp_path):
    result = CliRunner().invoke(app, ["config", "get", ""])

    assert result.exit_code == 3, result.output
    assert "pathisempty" in _flat(result.output)


class TestConfigGetConfigOption:
    """``ash config get`` takes ``--config``/``-c`` and ``ASH_CONFIG`` as ``ash scan`` does.

    A named file that does not exist exits 3, the code ``ash scan`` uses for it.
    The positional path is still accepted; it wins over ``ASH_CONFIG``, and naming
    two different files on one command line is refused.
    """

    @pytest.mark.parametrize("flag", ["--config", "-c"])
    def test_a_named_file_that_does_not_exist_exits_three(self, tmp_path, flag):
        result = CliRunner().invoke(
            app, ["config", "get", flag, str(tmp_path / "missing.yaml")]
        )

        assert result.exit_code == 3, result.output
        assert "Configurationfilenotfound" in _flat(result.output)
        assert "missing.yaml" in _flat(result.output)

    def test_a_named_file_that_loads_is_printed(self, tmp_path):
        config = tmp_path / "named.yaml"
        config.write_text("project_name: named-by-option\n", encoding="utf-8")

        result = CliRunner().invoke(app, ["config", "get", "--config", str(config)])

        assert result.exit_code == 0, result.output
        assert "named-by-option" in result.output

    def test_the_ash_config_variable_names_the_file(self, tmp_path):
        config = tmp_path / "from-env.yaml"
        config.write_text("project_name: named-by-variable\n", encoding="utf-8")
        (tmp_path / ".ash.yaml").write_text(
            "project_name: discovered\n", encoding="utf-8"
        )

        result = CliRunner().invoke(
            app, ["config", "get"], env={"ASH_CONFIG": str(config)}
        )

        assert result.exit_code == 0, result.output
        assert "named-by-variable" in result.output

    def test_the_positional_path_wins_over_the_variable(self, tmp_path):
        positional = tmp_path / "positional.yaml"
        positional.write_text("project_name: named-by-argument\n", encoding="utf-8")
        from_env = tmp_path / "from-env.yaml"
        from_env.write_text("project_name: named-by-variable\n", encoding="utf-8")

        result = CliRunner().invoke(
            app, ["config", "get", str(positional)], env={"ASH_CONFIG": str(from_env)}
        )

        assert result.exit_code == 0, result.output
        assert "named-by-argument" in result.output

    def test_two_different_files_on_one_command_line_are_refused(self, tmp_path):
        first = tmp_path / "first.yaml"
        second = tmp_path / "second.yaml"
        for path in (first, second):
            path.write_text(f"project_name: {path.stem}\n", encoding="utf-8")

        result = CliRunner().invoke(
            app, ["config", "get", str(first), "--config", str(second)]
        )

        assert result.exit_code == 2, result.output
        assert "first.yaml" in _flat(result.output)
        assert "second.yaml" in _flat(result.output)
