# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config checks refuse a misnamed plugin module in their own words.

The plugin loader's refusal closes with the scan's sentences: nothing was
scanned, and the entry can be removed from options only a scan has
(``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``). ``config validate``,
``config lint``, ``config get``, ``validate-plugin-dependencies`` and MCP
``validate_config`` show the same refusal through
``ConfigValidator._plugin_module_refusal``, and none of them scans or has
those options, so their closing fits a check instead.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

CONFIG = 'project_name: t\nash_plugin_modules:\n  - "json"\n'


def test_a_check_that_cannot_run_is_never_silent(tmp_path, monkeypatch):
    """The check's own resolution raising something unexpected answers with
    the warning channel naming the type: the file's errors stay empty (the
    failure is the check's, not the file's), and nothing reads as a silently
    judged module list."""
    from automated_security_helper.config import resolve_config as resolve_module
    from automated_security_helper.config.config_validator import ConfigValidator

    def _breaks(**_kwargs):
        raise TypeError("resolution broke before any judgment")

    monkeypatch.setattr(resolve_module, "resolve_config", _breaks)
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")

    refusals, warning = ConfigValidator._plugin_module_refusal(
        config_path=config,
        source_dir=None,
        config_overrides=None,
        permit_base=None,
        untrusted_config=False,
        reads={},
        texts={},
    )

    assert refusals == [], refusals
    assert warning is not None, "an unexpected resolution failure was silent"
    assert "could not run" in warning, warning
    assert "TypeError" in warning, warning


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_the_check_s_refusal_does_not_speak_for_a_scan(tmp_path, monkeypatch, command):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / ".ash.yaml"
    config.write_text(CONFIG, encoding="utf-8")

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "ash_plugin_modules names" in result.output, result.output
    assert "nothing was scanned" not in result.output.lower(), result.output
    assert "--ash-plugin-modules" not in result.output, result.output
    assert "ASH_PLUGIN_MODULES" not in result.output, result.output
