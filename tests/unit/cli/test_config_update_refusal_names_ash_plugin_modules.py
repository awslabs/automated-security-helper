# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config update`` refuses a plugin module a scan refuses in its own words.

``update`` (and the wizard, through the same helper) refused a config whose
``ash_plugin_modules`` a scan refuses with ``str(error)``: the raised naming
followed by the scan's closing sentences, which name a run ``update`` does not
make and option spellings it does not take, and which blame the config file for
an entry only ``ASH_PLUGIN_MODULES`` contributed. ``get`` and ``validate`` print
the same refusal through ``plugin_module_refusal_message``, closed in the config
commands' words, and head it "from ASH_PLUGIN_MODULES" when no file is what is
wrong. ``update`` now does the same. Exit 3 and the unwritten file are unchanged.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit

VALID_CONFIG = "project_name: demo\nfail_on_findings: true\n"
REFUSED_MODULE = "no_such_plugin_module_zz"


def _update(config_file):
    return CliRunner().invoke(
        config_cli.config_app,
        ["update", str(config_file), "--set", "project_name=renamed"],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    path = tmp_path / ".ashrc.yaml"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    return path


def test_an_entry_only_the_environment_added_is_refused_as_the_variables(
    config_file, monkeypatch
):
    monkeypatch.setenv("ASH_PLUGIN_MODULES", REFUSED_MODULE)

    result = _update(config_file)

    assert result.exit_code == config_cli.INVALID_CONFIG_EXIT_CODE, result.output
    assert "Invalid configuration from ASH_PLUGIN_MODULES" in result.output, (
        result.output
    )
    assert "unset it in ASH_PLUGIN_MODULES" in result.output, result.output
    assert str(config_file) not in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == VALID_CONFIG


def test_control_an_entry_the_file_names_is_refused_as_the_files(config_file):
    config_file.write_text(
        VALID_CONFIG + f"ash_plugin_modules:\n- {REFUSED_MODULE}\n", encoding="utf-8"
    )

    result = _update(config_file)

    assert result.exit_code == config_cli.INVALID_CONFIG_EXIT_CODE, result.output
    assert "Not updating" in result.output, result.output
    assert "ASH_PLUGIN_MODULES" not in result.output, result.output
    assert "--config-overrides" in result.output, result.output
