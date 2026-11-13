# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install`` describes a plugin's failure without its input.

A plugin that cannot be built, or cannot say what to install, fails with its
own error, and a plugin's model may raise a pydantic error whose text quotes
the refused value, which can be a secret read from the environment. The
command describes such a failure without that text, both in its output and in
the plugin's outcome. The error here comes from a model that does not hide its
inputs.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"


class _Unhidden(BaseModel):
    flag: bool


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


def _one_scanner(monkeypatch, tmp_path, factory):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    # The command reads the working directory's .ash/.ash.yaml.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "load_plugins", lambda *_a, **_k: {})
    monkeypatch.setattr(
        dependencies_module,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: [factory] if kind == "scanner" else []
        ),
    )
    monkeypatch.setattr(dependencies_module, "run_command", lambda cmd, shell=False: 0)


def _install(tmp_path):
    return CliRunner().invoke(
        dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
        env={"COLUMNS": "300"},
    )


def _assert_no_canary(result):
    printed = f"{result.stdout}\n{result.stderr}"
    assert CANARY not in printed, printed
    # The control: the failure is named, by its field.
    assert "Invalid value at 'flag'" in printed, printed


def test_a_plugin_that_cannot_be_built(tmp_path, monkeypatch):
    refused = _refused()

    def factory(**_kwargs):
        raise refused

    _one_scanner(monkeypatch, tmp_path, factory)
    _assert_no_canary(_install(tmp_path))


@pytest.mark.parametrize("step", ["skip check", "installation commands"])
def test_a_plugin_that_fails_a_step(tmp_path, monkeypatch, step):
    refused = _refused()
    fake = MagicMock()
    fake.config = SimpleNamespace(name="fake-scanner")
    fake.command = "fake-scanner"
    if step == "skip check":
        monkeypatch.setattr(
            dependencies_module,
            "_scan_skip",
            MagicMock(side_effect=refused),
        )
        fake.get_installation_commands.return_value = []
    else:
        fake.get_installation_commands.side_effect = refused
    _one_scanner(monkeypatch, tmp_path, lambda **_kw: fake)
    _assert_no_canary(_install(tmp_path))


def _install_trivy(tmp_path, monkeypatch, option: str):
    """ash dependencies install --tool trivy-repo, with trivy-repo loaded from
    ash_plugin_modules and ``option`` under its options. No install runs."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "run_command", lambda cmd, shell=False: 0)
    config = tmp_path / "op.yaml"
    config.write_text(
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
        "scanners:\n"
        "  trivy-repo:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      {option}\n",
        encoding="utf-8",
    )
    return CliRunner().invoke(
        dependencies_app,
        [
            "--config",
            str(config),
            "--tool",
            "trivy-repo",
            "--bin-path",
            str(tmp_path / "bin"),
        ],
        env={"COLUMNS": "300"},
    )


def test_a_loaded_plugin_with_an_env_read_option_key(tmp_path, monkeypatch):
    """The configuration is refused before any plugin is built, exit 3, as ash
    scan and ash report refuse it (config/plugin_option_check.py). A key the
    config file reads from the environment is the variable's value by then, and
    the refusal names no such key."""
    secret = f"{CANARY}-0123456789"
    monkeypatch.setenv("ASH_PROBE_VALUE", secret)

    result = _install_trivy(tmp_path, monkeypatch, "${ASH_PROBE_VALUE}: true")

    printed = f"{result.stdout}\n{result.stderr}"
    assert result.exit_code == 3, printed
    # The control: refused as an invalid configuration, at the plugin's
    # options, for a key read from the environment (the marker is where the
    # value would be).
    assert "Invalid configuration" in printed, printed
    assert "scanners.trivy-repo.options" in " ".join(printed.split()), printed
    assert "Unknown key '<value>'" in " ".join(printed.split()), printed
    assert "could not be loaded" not in printed, printed
    assert secret not in printed, printed


def test_a_loaded_plugin_with_valid_options_is_installed(tmp_path, monkeypatch):
    """The control for the refusal above: the same config with a declared
    option is not refused, and trivy-repo is installed."""
    result = _install_trivy(tmp_path, monkeypatch, "ignore_unfixed: true")

    printed = f"{result.stdout}\n{result.stderr}"
    assert result.exit_code != 3, printed
    assert "Invalid configuration" not in printed, printed
    assert "trivy" in printed.lower(), printed


def test_a_command_that_raises(monkeypatch, capsys):
    refused = _refused()
    # run_command imports it when it runs.
    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils.run_command",
        MagicMock(side_effect=refused),
    )
    monkeypatch.setenv("COLUMNS", "300")

    assert dependencies_module.run_command(["true"]) == 1
    printed = "".join(capsys.readouterr())
    assert CANARY not in printed, printed
    assert "Invalid value at 'flag'" in printed, printed
