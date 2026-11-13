# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--source-dir ""`` is refused by the config commands that read a config, as the
scan refuses it, and is not read as the current directory.

The check lives in the shared ``_source_dir`` helper, and the test that pins it for
``update`` (test_config_update_refuses_a_source_dir_that_names_no_directory.py)
reaches it through one caller. These cases reach it through ``get``, ``validate``
and ``lint``, so a change that gives the empty value back to the working directory
fails here too, whichever command it was made for.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit

CONFIG = "project_name: demo\n"

COMMANDS = ["get", "validate", "lint"]


@pytest.fixture
def project(tmp_path, monkeypatch):
    # A config the working directory would find, so that reading the empty value
    # as the working directory would not end in "no config found".
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    (tmp_path / ".ashrc.yaml").write_text(CONFIG, encoding="utf-8")
    return tmp_path


def _invoke(command: str, *args: str):
    return CliRunner().invoke(
        config_cli.config_app,
        [command, *args],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


@pytest.mark.parametrize("command", COMMANDS)
def test_an_empty_source_dir_is_refused_with_the_scans_exit(project, command):
    result = _invoke(command, "--source-dir", "")

    assert result.exit_code == config_cli.ASH_EXIT_USAGE_ERROR, result.output
    assert "Source directory does not exist" in result.output, result.output


@pytest.mark.parametrize("command", COMMANDS)
def test_control_a_source_dir_that_exists_is_not_refused(project, command):
    result = _invoke(command, "--source-dir", str(project))

    assert result.exit_code != config_cli.ASH_EXIT_USAGE_ERROR, result.output
    assert "Source directory does not exist" not in result.output, result.output
