# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every `ash config` subcommand that reads a config takes it the same way.

Each of them takes `--config` (the docs show
`ash config get --config /path/to/config.yaml`), reads ASH_CONFIG the way
`ash scan --config` does; `get` also takes the path as a positional argument. Their
logging flags include `-v`/`-d`, and `validate` takes `--color`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3

# The subcommands that read a config file.
READERS = [
    "get",
    "update",
    "validate",
    "validate-plugin-dependencies",
    "lint",
    "wizard",
]
# The ones that resolve the config the way a scan does, so overrides apply.
RESOLVERS = ["get", "validate", "validate-plugin-dependencies"]


def _config_command(name: str):
    group = typer.main.get_command(app).commands["config"]
    return group.commands[name]


def _option(command, name: str):
    # By duck type: typer builds its options from its own copy of click, so
    # they are not instances of click.Option.
    for param in command.params:
        if getattr(param, "param_type_name", "") == "option" and name in param.opts:
            return param
    return None


@pytest.mark.parametrize("name", READERS)
def test_reader_takes_config_like_a_scan(name):
    command = _config_command(name)
    option = _option(command, "--config")

    assert option is not None, f"ash config {name} has no --config"
    assert "-c" in option.opts
    assert option.envvar == "ASH_CONFIG"


@pytest.mark.parametrize("name", READERS)
@pytest.mark.parametrize("flag, short", [("--verbose", "-v"), ("--debug", "-d")])
def test_reader_logging_flags(name, flag, short):
    option = _option(_config_command(name), flag)

    assert option is not None and short in option.opts, (name, flag)


@pytest.mark.parametrize("name", READERS)
def test_reader_color_flag(name):
    option = _option(_config_command(name), "--color")

    assert option is not None and "--no-color" in option.secondary_opts, name


@pytest.mark.parametrize("name", RESOLVERS)
def test_resolver_takes_config_overrides(name):
    assert _option(_config_command(name), "--config-overrides") is not None, name


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "other.yaml").write_text("project_name: from-other\n", encoding="utf-8")
    (tmp_path / "bad.yaml").write_text(
        "project_name: x\nfail_on_findings: banana\n", encoding="utf-8"
    )
    return tmp_path


class _Run:
    def __init__(self, result):
        self.exit_code = result.exit_code
        # Without color codes, which split the YAML `get` prints. NO_COLOR alone
        # is not enough: rich's shared console may already exist, with color on.
        self.output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)


def _run(*args: str, env: dict | None = None):
    return _Run(
        CliRunner().invoke(app, ["config", *args], env={"NO_COLOR": "1", **(env or {})})
    )


class TestConfigGet:
    @pytest.mark.parametrize("flag", ["--config", "-c"])
    def test_config_option(self, project, flag):
        result = _run("get", "--no-color", flag, "other.yaml")

        assert result.exit_code == 0, result.output
        assert "project_name: from-other" in result.output

    def test_ash_config_environment_variable(self, project):
        result = _run("get", "--no-color", env={"ASH_CONFIG": "other.yaml"})

        assert result.exit_code == 0, result.output
        assert "project_name: from-other" in result.output

    def test_positional_path_works(self, project):
        result = _run("get", "--no-color", "other.yaml")

        assert result.exit_code == 0, result.output
        assert "project_name: from-other" in result.output

    def test_positional_path_wins_over_ash_config(self, project):
        (project / "env.yaml").write_text("project_name: from-env\n", encoding="utf-8")

        result = _run("get", "--no-color", "other.yaml", env={"ASH_CONFIG": "env.yaml"})

        assert result.exit_code == 0, result.output
        assert "project_name: from-other" in result.output

    def test_two_different_paths_are_refused(self, project):
        result = _run("get", "other.yaml", "--config", "bad.yaml")

        assert result.exit_code not in (0, 1, INVALID_CONFIG_EXIT), result.output
        assert "two config files" in result.output

    def test_two_spellings_of_one_path_are_one_path(self, project):
        absolute = str(project / "other.yaml")
        result = _run("get", "--no-color", "other.yaml", "--config", absolute)

        assert result.exit_code == 0, result.output
        assert "project_name: from-other" in result.output

    def test_missing_file(self, project):
        result = _run("get", "--config", "missing.yaml")

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert "not found" in result.output

    def test_invalid_file_exits_3(self, project):
        result = _run("get", "--config", "bad.yaml")

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert "fail_on_findings" in result.output


class TestOtherReaders:
    def test_update_config_option(self, project):
        result = _run(
            "update", "--config", "other.yaml", "--set", "fail_on_findings=false"
        )

        assert result.exit_code == 0, result.output
        assert "fail_on_findings: false" in (project / "other.yaml").read_text()

    def test_update_reads_ash_config(self, project):
        result = _run(
            "update",
            "--set",
            "fail_on_findings=false",
            env={"ASH_CONFIG": "other.yaml"},
        )

        assert result.exit_code == 0, result.output
        assert "fail_on_findings: false" in (project / "other.yaml").read_text()

    def test_validate_plugin_dependencies_config_option(self, project):
        result = _run("validate-plugin-dependencies", "--config", "other.yaml")

        assert result.exit_code == 0, result.output

    def test_validate_plugin_dependencies_invalid_file_exits_3(self, project):
        result = _run("validate-plugin-dependencies", "--config", "bad.yaml")

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert "fail_on_findings" in result.output
