# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin list`` refuses a configuration with an invalid plugin option.

The options of a plugin loaded from ``ash_plugin_modules`` are checked once
the plugins load (config/plugin_option_check.py), and ash scan and ash report
refuse such a configuration with exit 3. ``ash plugin list`` refuses it the
same way before building any plugin, and the refusal names no key the config
file reads from the environment, whose text is the variable's value by then.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"


def _list(tmp_path: Path, monkeypatch, option: str):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
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
        app, ["plugin", "list", "--config", str(config)], env={"COLUMNS": "300"}
    )


def test_an_env_read_option_key_is_refused_without_its_value(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)

    result = _list(tmp_path, monkeypatch, "${ASH_PROBE_VALUE}: true")

    printed = f"{result.stdout}\n{result.stderr}"
    assert result.exit_code == 3, printed
    # The control: refused as an invalid configuration, at the plugin's
    # options, for a key read from the environment (the marker is where the
    # value would be).
    assert "Invalid configuration" in printed, printed
    assert "scanners.trivy-repo.options" in " ".join(printed.split()), printed
    assert "Unknown key '<value>'" in " ".join(printed.split()), printed
    assert CANARY not in printed, printed


def test_valid_options_are_listed(tmp_path, monkeypatch):
    """The control for the refusal above."""
    result = _list(tmp_path, monkeypatch, "ignore_unfixed: true")

    printed = f"{result.stdout}\n{result.stderr}"
    assert result.exit_code == 0, printed
    assert "trivy" in printed.lower(), printed
