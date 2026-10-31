# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config wizard`` writes a plugin module inside ASH's namespace that no
installed package provides yet, and still refuses one outside the namespace.

The wizard refused, before its write, every ``ash_plugin_modules`` entry a scan
refuses: a name outside the plugin namespace, and a name inside it that no
installed package provides. The second half turned the wizard away from its own
purpose: an operator names a module there to install it next, the snapshot
wizard tests write ``my_org_ash_plugins`` with nothing installed, and ``get``
and ``validate`` already say so when they read the file before the install. The
wizard now writes such a module; a module outside the namespace, which no
install can admit, is refused when it is typed and asked about again, not added
(the control here, and tests/unit/cli/test_config_wizard_module_reprompt.py).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli
from tests.utils.wizard_script import script_wizard

pytestmark = pytest.mark.unit


def _wizard(target):
    return CliRunner().invoke(
        config_cli.config_app,
        ["wizard", "--config", str(target)],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


def test_a_namespace_module_no_package_provides_is_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    script_wizard(monkeypatch, ["demo", "not_installed_yet_ash_plugins", ""])
    target = tmp_path / "new.yaml"

    result = _wizard(target)

    assert result.exit_code == 0, result.output
    assert "Not writing" not in result.output, result.output
    assert "- not_installed_yet_ash_plugins" in target.read_text(encoding="utf-8")


def test_control_a_module_outside_the_namespace_is_asked_about_again(
    tmp_path, monkeypatch
):
    """Red at the base of the wizard change this file's first test follows: the
    module was kept until the end and the command exited 3 with no file. Now it
    is named and not added when typed, the prompt comes again, and the file is
    written with the module inside the namespace and without the other."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    script_wizard(
        monkeypatch,
        ["demo", "no_such_plugin_module_zz", "not_installed_yet_ash_plugins", ""],
    )
    target = tmp_path / "new.yaml"

    result = _wizard(target)

    assert result.exit_code == 0, result.output
    assert "The module is not added" in result.output, result.output
    text = target.read_text(encoding="utf-8")
    assert "no_such_plugin_module_zz" not in text
    assert "- not_installed_yet_ash_plugins" in text
