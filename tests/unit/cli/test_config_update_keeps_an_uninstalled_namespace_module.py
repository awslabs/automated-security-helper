# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config update`` edits a file that names a plugin module inside ASH's
namespace which no installed package provides yet, as the wizard writes one.

The wizard writes such a module (an operator names it to install it next, and
``get`` and ``validate`` say so until then), but ``update`` refused the same file
with exit 3 before writing, so a ``--set`` of an unrelated key failed on a file
the wizard had just written. The two editors now apply one policy: a module
outside the namespace, which no install can admit, is refused by both; a module
inside it that is not installed yet is written by both.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit

NAMESPACE_MODULE = "not_installed_yet_ash_plugins"
OUTSIDE_MODULE = "no_such_plugin_module_zz"


def _config_naming(module):
    return f"project_name: demo\nash_plugin_modules:\n- {module}\n"


def _update(config_file):
    return CliRunner().invoke(
        config_cli.config_app,
        ["update", str(config_file), "--set", "project_name=renamed"],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


@pytest.fixture
def clean_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    return tmp_path


def test_a_namespace_module_no_package_provides_is_kept_and_the_set_applied(
    clean_environment,
):
    config_file = clean_environment / ".ashrc.yaml"
    config_file.write_text(_config_naming(NAMESPACE_MODULE), encoding="utf-8")

    result = _update(config_file)

    assert result.exit_code == 0, result.output
    assert "Not updating" not in result.output, result.output
    written = config_file.read_text(encoding="utf-8")
    assert "project_name: renamed" in written
    assert f"- {NAMESPACE_MODULE}" in written


def test_control_a_module_outside_the_namespace_is_still_refused(clean_environment):
    config_file = clean_environment / ".ashrc.yaml"
    text = _config_naming(OUTSIDE_MODULE)
    config_file.write_text(text, encoding="utf-8")

    result = _update(config_file)

    assert result.exit_code == config_cli.INVALID_CONFIG_EXIT_CODE, result.output
    assert "Not updating" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == text
