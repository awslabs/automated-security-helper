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
install can admit, is refused as before (the control here, and
tests/unit/cli/test_config_commands_refuse_before_tracebacks.py).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit


def _scripted_wizard(monkeypatch, answers):
    """Answer the wizard's prompts: project name, then module names, blank to end;
    every yes/no question is answered no; the toggle tables are skipped."""
    replies = iter(answers)
    monkeypatch.setattr(config_cli, "prompt", lambda *_a, **_k: next(replies))
    monkeypatch.setattr(config_cli, "confirm", lambda *_a, **_k: False)
    monkeypatch.setattr(config_cli, "_prompt_toggle_items", lambda *_a, **_k: {})


def _wizard(target):
    return CliRunner().invoke(
        config_cli.config_app,
        ["wizard", "--config", str(target)],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


def test_a_namespace_module_no_package_provides_is_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    _scripted_wizard(monkeypatch, ["demo", "not_installed_yet_ash_plugins", ""])
    target = tmp_path / "new.yaml"

    result = _wizard(target)

    assert result.exit_code == 0, result.output
    assert "Not writing" not in result.output, result.output
    assert "- not_installed_yet_ash_plugins" in target.read_text(encoding="utf-8")


def test_control_a_module_outside_the_namespace_is_still_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    _scripted_wizard(monkeypatch, ["demo", "no_such_plugin_module_zz", ""])
    target = tmp_path / "new.yaml"

    result = _wizard(target)

    assert result.exit_code == config_cli.INVALID_CONFIG_EXIT_CODE, result.output
    assert "Not writing" in result.output, result.output
    assert not target.exists()
