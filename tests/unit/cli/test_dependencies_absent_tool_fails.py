# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool the selection needs that is still absent after the install fails the run.

``ash dependencies install`` exits with its install-failed code when a needed tool
stays absent, whether or not that tool was named with ``--tool``: a full run that
installs grype and syft and leaves npm-audit without npm, or that runs cfn-nag's
install and finds no ``cfn_nag_scan`` after it, does not report "Installation
Complete" ahead of a scan that reports those scanners MISSING and exits 1.
"""

from __future__ import annotations

import pytest
import typer

from automated_security_helper.cli.dependencies import (
    EXIT_INSTALL_FAILED,
    EXIT_OK,
    PluginInstallOutcome,
    _report_and_exit,
)

pytestmark = pytest.mark.unit


def _outcome(**kwargs) -> PluginInstallOutcome:
    base = {"name": "tool", "plugin_type": "scanner", "command": "tool"}
    base.update(kwargs)
    return PluginInstallOutcome(**base)


def _installed(name: str) -> PluginInstallOutcome:
    return _outcome(
        name=name,
        command=name,
        commands_attempted=1,
        commands_succeeded=1,
        executable=f"/bin/{name}",
    )


def test_a_tool_with_no_install_path_still_absent_fails_a_full_run(capsys):
    outcomes = [
        _installed("grype"),
        _installed("syft"),
        _outcome(name="npm-audit", command="npm", executable=None),
    ]
    with pytest.raises(typer.Exit) as exc:
        _report_and_exit(outcomes, requested_tools=[])
    assert exc.value.exit_code == EXIT_INSTALL_FAILED
    out = " ".join(capsys.readouterr().out.split())
    assert "npm-audit" in out
    assert "Installation Incomplete" in out


def test_a_tool_whose_install_ran_but_is_not_found_fails_a_full_run(capsys):
    outcomes = [
        _installed("grype"),
        _outcome(
            name="cfn-nag",
            command="cfn_nag_scan",
            commands_attempted=1,
            commands_succeeded=1,
            executable=None,
        ),
    ]
    with pytest.raises(typer.Exit) as exc:
        _report_and_exit(outcomes, requested_tools=[])
    assert exc.value.exit_code == EXIT_INSTALL_FAILED
    assert "cfn-nag" in " ".join(capsys.readouterr().out.split())


def test_a_program_the_plugin_needs_besides_its_command_counts(capsys):
    """cdk-nag's command is python; Node.js is the program that can be missing."""
    outcomes = [
        _outcome(
            name="cdk-nag",
            command="python",
            commands_attempted=1,
            commands_succeeded=1,
            executable="/usr/bin/python",
            missing_executables=["node"],
        )
    ]
    with pytest.raises(typer.Exit) as exc:
        _report_and_exit(outcomes, requested_tools=[])
    assert exc.value.exit_code == EXIT_INSTALL_FAILED
    out = " ".join(capsys.readouterr().out.split())
    assert "cdk-nag" in out and "node" in out


def test_everything_present_is_success():
    """Positive control: the rule fires on absence, not on any run."""
    outcomes = [
        _installed("grype"),
        _outcome(name="npm-audit", command="npm", executable="/usr/bin/npm"),
        _outcome(name="sarif", plugin_type="reporter", command=None),
    ]
    assert _report_and_exit(outcomes, requested_tools=[]) == EXIT_OK


class TestThePostInstallSweep:
    """Through the CLI with one stand-in plugin, so the sweep's lookups are real."""

    def _run(self, tmp_path, monkeypatch, plugin, *, on_path, uv_lists=()):
        import io
        from types import SimpleNamespace

        from rich.console import Console
        from typer.testing import CliRunner

        from automated_security_helper.cli import dependencies
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(dependencies, "load_plugins", lambda *_a, **_k: {})
        monkeypatch.setattr(
            dependencies,
            "ash_plugin_manager",
            SimpleNamespace(
                plugin_modules=lambda kind: (
                    [lambda **_kw: plugin] if kind == "scanner" else []
                )
            ),
        )
        monkeypatch.setattr(dependencies, "run_command", lambda cmd, shell=False: 0)
        monkeypatch.setattr(
            dependencies,
            "find_executable_for_scan",
            lambda name, root: f"/usr/bin/{name}" if name in on_path else None,
        )
        fake_runner = SimpleNamespace(
            is_uv_available=lambda: True,
            is_tool_installed=lambda name: name in uv_lists,
        )
        monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: fake_runner)
        panels = io.StringIO()
        monkeypatch.setattr(
            dependencies, "console", Console(file=panels, width=300, no_color=True)
        )
        result = CliRunner().invoke(
            dependencies.dependencies_app,
            ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
        )
        return result, " ".join(panels.getvalue().split())

    def _plugin(self, command, **attributes):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        plugin = MagicMock()
        plugin.config = SimpleNamespace(name="stand-in")
        plugin.command = command
        plugin.use_uv_tool = attributes.get("use_uv_tool", False)
        plugin.external_executables = attributes.get("external_executables", ())
        plugin.get_installation_commands.return_value = [["installer", command]]
        return plugin

    def test_a_uv_tool_off_path_is_present(self, tmp_path, monkeypatch):
        """bandit runs through `uv tool run`; uv's bin directory need not be on PATH."""
        plugin = self._plugin("banditish", use_uv_tool=True)
        result, printed = self._run(
            tmp_path, monkeypatch, plugin, on_path=(), uv_lists=("banditish",)
        )
        assert result.exit_code == EXIT_OK, printed
        assert "uv tool banditish" in printed

    def test_a_uv_tool_uv_does_not_list_is_absent(self, tmp_path, monkeypatch):
        plugin = self._plugin("banditish", use_uv_tool=True)
        result, printed = self._run(tmp_path, monkeypatch, plugin, on_path=())
        assert result.exit_code == EXIT_INSTALL_FAILED, printed
        assert "stand-in" in printed

    def test_a_missing_external_program_fails_and_is_named(self, tmp_path, monkeypatch):
        plugin = self._plugin("python", external_executables=("node",))
        result, printed = self._run(tmp_path, monkeypatch, plugin, on_path=("python",))
        assert result.exit_code == EXIT_INSTALL_FAILED, printed
        assert "stand-in (node)" in printed
        assert "node not found" in printed
        assert "Programs ASH does not install, not found: stand-in (node)" in printed
        # Its own command is on PATH, but it cannot run: not counted as verified.
        assert "Tools verified on PATH: 0" in printed, printed

    def test_the_external_program_present_is_success(self, tmp_path, monkeypatch):
        plugin = self._plugin("python", external_executables=("node",))
        result, printed = self._run(
            tmp_path, monkeypatch, plugin, on_path=("python", "node")
        )
        assert result.exit_code == EXIT_OK, printed
