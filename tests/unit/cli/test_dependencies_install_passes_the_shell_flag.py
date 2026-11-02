# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install`` hands a custom command's shell flag to the runner.

``CustomCommand`` carries a ``shell`` flag, and the install loop reads it off the
command and passes it on: ``run_command(cmd, shell=shell) if shell else
run_command(cmd)``. Tests of what a plugin declares, and of how the installer
reads the declaration, passed while that line ran ``run_command(cmd)`` alone, so
``shell=True`` was unreachable again and nothing said so. These drive the real
command with one plugin's commands replaced, and record the call the loop makes.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)

pytestmark = pytest.mark.unit

_RUN_COMMAND = "automated_security_helper.cli.dependencies.run_command"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """Run the install for bandit with the given commands; return the calls."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    # The version probe runs `uv` per scanner and says nothing about what gets
    # installed; the loop's call to the runner is what is under test.
    monkeypatch.setattr(UVToolMixin, "_get_uv_tool_version", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.find_executable_for_scan",
        lambda cmd, root: f"/usr/bin/{cmd}",
    )
    calls: list[tuple[list[str], bool]] = []

    def _record(cmd, shell=False):
        calls.append((list(cmd), shell))
        return 0

    monkeypatch.setattr(_RUN_COMMAND, _record)

    def run(declared):
        monkeypatch.setattr(
            BanditScanner,
            "get_installation_commands",
            lambda self, platform, arch: declared,
        )
        result = CliRunner().invoke(
            dependencies_app,
            [
                "--plugin-type",
                "scanner",
                "--bin-path",
                str(tmp_path / "bin"),
                "--tool",
                "bandit",
            ],
        )
        assert result.exit_code == 0, result.output
        return calls

    return run


def test_a_shell_command_reaches_the_runner_with_shell_true(installed):
    calls = installed(
        [
            CustomCommand(args=["echo $HOME"], shell=True),
            CustomCommand(args=["echo", "ready"]),
        ]
    )

    # The first command carries its flag to the runner; the second, declared
    # without one, is run as an argv with no shell. A loop that dropped the flag
    # would record (["echo $HOME"], False) for the first.
    assert calls == [(["echo $HOME"], True), (["echo", "ready"], False)], calls


def test_control_a_plain_argv_never_gets_a_shell(installed):
    calls = installed([["echo", "ready"]])

    assert calls == [(["echo", "ready"], False)], calls
