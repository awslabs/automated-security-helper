# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Text that is not markup must reach the terminal intact.

``cli/dependencies.py`` prints through rich, which parses ``[...]`` as a style
tag. An install command such as ``pip install ash[sarif,toml]`` was printed as
``pip install ash`` because rich consumed ``[sarif,toml]`` as an unknown tag, so
the log showed a different command from the one that ran. The same applied to
the child's own output (pip prints ``[notice]`` lines) and to names the user
typed, such as an unknown ``--tool`` value.
"""

import re
from types import SimpleNamespace
from unittest.mock import MagicMock

from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    dependencies_app,
    run_command,
)

runner = CliRunner()

BRACKETED_ARGV = ["pip", "install", "ash[sarif,toml]"]

# rich's highlighter colors numbers and brackets when the environment forces
# color. Those escape codes are styling, not the text under test.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI.sub("", text)


def _patch_one_plugin(monkeypatch, tmp_path, commands):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("COLUMNS", "200")
    fake = MagicMock()
    fake.config = SimpleNamespace(name="fake-scanner")
    fake.command = "fake-scanner"
    fake.get_installation_commands.return_value = commands
    monkeypatch.setattr(dependencies_module, "load_plugins", lambda *_a, **_k: {})
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


def test_running_command_line_keeps_bracketed_extras(tmp_path, monkeypatch):
    _patch_one_plugin(monkeypatch, tmp_path, [BRACKETED_ARGV])

    result = runner.invoke(
        dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
    )

    running = [
        ln for ln in _plain(result.output).splitlines() if "Running command" in ln
    ]
    assert running == ["Running command: pip install ash[sarif,toml]"]


def test_unknown_tool_name_is_echoed_literally(tmp_path, monkeypatch):
    _patch_one_plugin(monkeypatch, tmp_path, [])

    result = runner.invoke(
        dependencies_app,
        [
            "--plugin-type",
            "scanner",
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "grype[bold]",
        ],
    )

    assert result.exit_code == EXIT_BAD_SELECTION
    assert "grype[bold]" in _plain(result.output)


def test_child_output_is_not_parsed_as_markup(monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "200")
    child = MagicMock(
        stdout="Successfully installed ash[sarif,toml]",
        stderr="[notice] A new release of pip is available",
        returncode=0,
    )
    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils.run_command",
        lambda **_kw: child,
    )

    assert run_command(BRACKETED_ARGV) == 0

    out = _plain(capsys.readouterr().out)
    assert "Successfully installed ash[sarif,toml]" in out
    assert "[notice] A new release of pip is available" in out


def test_error_line_keeps_the_failed_command(monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "200")

    def boom(**_kw):
        raise RuntimeError("no such extra [toml]")

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils.run_command", boom
    )

    assert run_command(BRACKETED_ARGV) == 1

    out = _plain(capsys.readouterr().out)
    assert "pip install ash[sarif,toml]" in out
    assert "no such extra [toml]" in out
