# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config update --source-dir DIR`` refuses a DIR a scan would refuse,
instead of ignoring the option.

``--source-dir`` was read only when no config path was given, to discover the
file; with a path it was not looked at, so a typo in it passed silently where
``init``, ``validate`` and ``lint`` exit 5 with the scan's own refusal. The given
value is now checked whether or not a path is named; with none given, the
working directory is still read only when the file has to be discovered.

An empty value is a value that was given and names no directory, as the scan
refuses it; it is not read as the current directory.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit

CONFIG = "project_name: demo\n"


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    path = tmp_path / ".ashrc.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def _update(*args):
    return CliRunner().invoke(
        config_cli.config_app,
        ["update", *args, "--set", "project_name=renamed"],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


def test_a_source_dir_that_names_no_directory_is_refused_with_the_scans_exit(
    config_file, tmp_path
):
    missing = tmp_path / "typo"

    result = _update(str(config_file), "--source-dir", str(missing))

    assert result.exit_code == config_cli.ASH_EXIT_USAGE_ERROR, result.output
    assert "Source directory does not exist" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == CONFIG


def test_control_a_source_dir_that_exists_is_accepted(config_file, tmp_path):
    result = _update(str(config_file), "--source-dir", str(tmp_path))

    assert result.exit_code == 0, result.output
    assert "project_name: renamed" in config_file.read_text(encoding="utf-8")


def test_an_empty_source_dir_beside_a_path_is_refused(config_file):
    result = _update(str(config_file), "--source-dir", "")

    assert result.exit_code == config_cli.ASH_EXIT_USAGE_ERROR, result.output
    assert "Source directory does not exist" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == CONFIG


def test_an_empty_source_dir_is_not_read_as_the_current_directory(config_file):
    # No path named: the file would be found in the working directory, which an
    # empty --source-dir must not stand for.
    result = _update("--source-dir", "")

    assert result.exit_code == config_cli.ASH_EXIT_USAGE_ERROR, result.output
    assert "Source directory does not exist" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == CONFIG


def test_control_no_source_dir_still_finds_the_file_in_the_working_directory(
    config_file,
):
    result = _update()

    assert result.exit_code == 0, result.output
    assert "project_name: renamed" in config_file.read_text(encoding="utf-8")
