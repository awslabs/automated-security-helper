# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``config get`` names every refused plugin module, the environment's included.

A scan combines ``ASH_PLUGIN_MODULES`` with the file's ``ash_plugin_modules``
and refuses them together, so its message names every refused entry. validate
judges the same combined list. get resolves the config first, and a file whose
own entry is refused raises there -- before the combined judgment -- so get's
message named only the file's entry while agreeing on the exit code. An
operator who fixes the named entry and reruns then meets the environment's
refusal one round later. get names both at once, as the scan does.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3

FILE_ENTRY = "wsgiref"
ENVIRONMENT_ENTRY = "sndhdr"


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A source tree whose config refuses one module, with another refused
    module in the environment."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", ENVIRONMENT_ENTRY)
    config_dir = tmp_path / ".ash"
    config_dir.mkdir()
    (config_dir / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {FILE_ENTRY}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_get_names_the_environments_refused_entry_beside_the_files(project):
    result = CliRunner().invoke(
        app, ["config", "get", "--source-dir", str(project)], env={"NO_COLOR": "1"}
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    # The control: the file's own refused entry is named.
    assert FILE_ENTRY in result.output, result.output
    assert ENVIRONMENT_ENTRY in result.output, result.output


def test_the_control_validate_names_both(project):
    result = CliRunner().invoke(
        app,
        ["config", "validate", "--source-dir", str(project)],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert FILE_ENTRY in result.output, result.output
    assert ENVIRONMENT_ENTRY in result.output, result.output


UNSET_ADVICE = "unset it in ASH_PLUGIN_MODULES"


def test_an_environment_only_refusal_advises_unsetting_the_variable(
    tmp_path, monkeypatch
):
    """With no config file and no overrides, the only place the refused entry
    exists is the environment, so advice to edit "the config file or
    --config-overrides" names two places the operator never used. The closing
    offers the one remedy that applies."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", ENVIRONMENT_ENTRY)
    result = CliRunner().invoke(
        app,
        ["config", "validate", "--source-dir", str(tmp_path)],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert ENVIRONMENT_ENTRY in result.output, result.output
    assert UNSET_ADVICE in result.output, result.output


def test_a_file_only_refusal_keeps_the_variable_out_of_the_advice(
    tmp_path, monkeypatch
):
    """The clause is conditional: an entry the config file added has the
    file's remedy, and naming the variable there sends the operator to an
    environment that holds nothing."""
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    config_dir = tmp_path / ".ash"
    config_dir.mkdir()
    (config_dir / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {FILE_ENTRY}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        ["config", "validate", "--source-dir", str(tmp_path)],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert FILE_ENTRY in result.output, result.output
    assert UNSET_ADVICE not in result.output, result.output


def test_get_with_a_valid_file_and_an_environment_refusal_advises_the_variable(
    tmp_path, monkeypatch
):
    """get with a valid file and a refused environment entry: the file is not
    at fault, so the message names the environment's entry and the remedy
    that applies to it."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", ENVIRONMENT_ENTRY)
    config_dir = tmp_path / ".ash"
    config_dir.mkdir()
    (config_dir / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["config", "get", "--source-dir", str(tmp_path)], env={"NO_COLOR": "1"}
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert ENVIRONMENT_ENTRY in result.output, result.output
    assert UNSET_ADVICE in result.output, result.output


def test_validate_plugin_dependencies_reads_the_environments_modules(
    tmp_path, monkeypatch
):
    """validate-plugin-dependencies is a dependency check under the
    resolve-like-a-scan contract, so the scan input ASH_PLUGIN_MODULES
    reaches it as it reaches validate and get: a refused environment entry
    exits 3 here too, instead of a 0 that validate contradicts for the same
    input."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", ENVIRONMENT_ENTRY)
    config_dir = tmp_path / ".ash"
    config_dir.mkdir()
    (config_dir / ".ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["config", "validate-plugin-dependencies", "--source-dir", str(tmp_path)],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert ENVIRONMENT_ENTRY in result.output, result.output


BOTH_ENTRY = "absent_both_ash_plugins"


@pytest.mark.parametrize("command", ["get", "validate", "validate-plugin-dependencies"])
def test_an_entry_in_both_file_and_environment_gets_no_unset_advice(
    tmp_path, monkeypatch, command
):
    """An entry the file also names has no environment-only remedy: unsetting
    ASH_PLUGIN_MODULES leaves the file's entry, so the refusal stands and the
    advice would read as if either fix sufficed. The check subtracts the
    file's entries before offering the clause, and every printer agrees with
    it (validate is the control that already did)."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", BOTH_ENTRY)
    # The config lives outside the scanned tree, so its ash_plugin_modules
    # entry is the operator's own and plugin_module_trust keeps it: inside
    # the tree the entry is dropped as untrusted, the refusal really is
    # environment-only, and the advice would be right -- the sibling cells'
    # case, not this one's.
    source = tmp_path / "src"
    source.mkdir()
    config = tmp_path / "ash.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {BOTH_ENTRY}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        ["config", command, "--config", str(config), "--source-dir", str(source)],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    # The control: the refusal still names the entry.
    assert BOTH_ENTRY in result.output, result.output
    assert UNSET_ADVICE not in result.output, result.output
