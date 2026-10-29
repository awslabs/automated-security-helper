# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install`` shows an install's argv and output without the
values the configuration read from the environment, and shows any argv.

The command printed each plugin's argv as given and the child's stdout and
stderr as returned, and logged the run with no values to redact. A plugin option
read from the environment (a registry URL with a token in it, say) reaches the
argv the plugin declares, and a tool echoes what it was given, so the value was
printed in clear by the very command that redacts it from every failure line.
Both are now redacted with the configuration's environment values, and the
runner is passed the same values for the lines it logs itself.

The argv line was also built with ``' '.join(cmd)``, which raises TypeError on
an element that is not a str (a Path, a number) and ended the whole install run
with a traceback. It is now shown element by element, as text.
"""

from __future__ import annotations

import io
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

#: Long enough, and with a "-", to be hidden wherever it is printed.
CANARY = "ash-canary-value-xq9"


def test_a_command_line_is_shown_as_text_without_the_values():
    shown = dependencies_module._shown_command(
        ["pip", "install", Path("plain-path"), 3, CANARY], (CANARY,)
    )
    assert shown.startswith("pip install plain-path 3 "), shown
    assert CANARY not in shown, shown


@pytest.fixture
def install_values():
    token = dependencies_module._INSTALL_VALUES.set((CANARY,))
    yield (CANARY,)
    dependencies_module._INSTALL_VALUES.reset(token)


def test_the_childs_output_is_printed_without_the_values(
    monkeypatch, capsys, install_values
):
    monkeypatch.setenv("COLUMNS", "300")
    received = {}

    def child(**kwargs):
        received.update(kwargs)
        return subprocess.CompletedProcess(
            kwargs["args"], 0, f"token {CANARY} accepted\n", f"warning: {CANARY}\n"
        )

    monkeypatch.setattr(subprocess_utils, "run_command", child)

    assert dependencies_module.run_command(["echo", "x"]) == 0

    printed = "".join(capsys.readouterr())
    assert CANARY not in printed, printed
    # The controls: the rest of each line is shown, and the runner's own log
    # lines are passed the same values.
    assert "token" in printed and "accepted" in printed, printed
    assert "warning:" in printed, printed
    assert received["values"] == install_values, received


def test_a_spawn_error_is_printed_without_the_values(
    monkeypatch, capsys, install_values
):
    monkeypatch.setenv("COLUMNS", "300")

    def boom(**_kwargs):
        raise RuntimeError(f"no such host {CANARY}")

    monkeypatch.setattr(subprocess_utils, "run_command", boom)

    assert dependencies_module.run_command(["curl", CANARY]) == 1

    printed = "".join(capsys.readouterr())
    assert CANARY not in printed, printed
    assert "Error running command curl" in printed, printed


def _one_scanner_with(monkeypatch, tmp_path, commands):
    """One scanner whose declared install argv are ``commands``, built from a
    configuration that read CANARY from the environment. No install runs."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "load_plugins", lambda *_a, **_k: {})
    fake = MagicMock()
    fake.config = SimpleNamespace(name="fake-scanner")
    fake.command = "fake-scanner"
    fake.get_installation_commands.return_value = commands
    monkeypatch.setattr(
        dependencies_module,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: fake] if kind == "scanner" else []
            )
        ),
    )
    monkeypatch.setattr(dependencies_module, "run_command", lambda cmd, shell=False: 0)
    real_resolve = dependencies_module.resolve_config

    def resolved_with_the_canary(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        config._environment_values = [CANARY]
        return config

    monkeypatch.setattr(dependencies_module, "resolve_config", resolved_with_the_canary)
    lines = io.StringIO()
    monkeypatch.setattr(
        dependencies_module,
        "console",
        Console(file=lines, width=300, no_color=True),
    )
    return lines


def _install(tmp_path):
    return CliRunner().invoke(
        dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
        env={"COLUMNS": "300"},
    )


def test_the_running_command_line_hides_the_values(tmp_path, monkeypatch):
    lines = _one_scanner_with(monkeypatch, tmp_path, [["fetch", "--token", CANARY]])

    result = _install(tmp_path)

    printed = lines.getvalue() + result.stdout
    assert "Running command: fetch --token" in printed, printed
    assert CANARY not in printed, printed


def test_an_argv_with_a_path_element_is_shown_and_run(tmp_path, monkeypatch):
    """A Path in a plugin's argv ended the run with a TypeError from ' '.join."""
    lines = _one_scanner_with(monkeypatch, tmp_path, [["copy", Path("plain-path")]])

    result = _install(tmp_path)

    printed = lines.getvalue() + result.stdout
    assert "Running command: copy plain-path" in printed, printed
    assert "TypeError" not in printed + str(result.exception), result.exception
