# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A custom install command reaches the installer with its ``shell`` flag.

Why this exists
---------------
``CustomCommand`` carries a ``shell`` flag, and the installer runs a command
declared ``shell=True`` through the shell, as declared. ``get_installation_commands``
returned each custom command's bare ``args`` instead of the command, so the flag
was dropped before the installer saw it and ``shell=True`` was unreachable from a
plugin's declaration. The base now returns the command itself; dependency-rendered
commands stay arrays of arguments, which the installer reads as before.
"""

import pytest

from automated_security_helper.base.plugin_base import (
    CustomCommand,
    PluginBase,
    PluginDependency,
)
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.dependencies import _well_formed_commands
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import PackageManager

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir, output_dir=output_dir, work_dir=work_dir
    )


def _plugin(context) -> PluginBase:
    plugin = PluginBase(context=context)
    plugin.config = PluginConfigBase(name="shell-flag-probe")
    return plugin


def test_a_custom_command_is_returned_as_declared(plugin_context):
    """The shell=True example is a command line that needs the shell (a variable
    to expand); an argv that already names its program is declared shell=False.
    Neither is run here: the test pins the shape the installer is handed."""
    plugin = _plugin(plugin_context)
    through_the_shell = CustomCommand(args=["echo", "$HOME"], shell=True)
    plain = CustomCommand(args=["echo", "ready"])
    plugin.custom_install_commands = {"linux": {"amd64": [through_the_shell, plain]}}

    commands = plugin.get_installation_commands("linux", "amd64")

    assert commands == [through_the_shell, plain]
    assert all(isinstance(command, CustomCommand) for command in commands)


def test_the_installer_reads_the_shell_flag_off_the_returned_command(plugin_context):
    """The consumer's side: what the installer runs, and how."""
    plugin = _plugin(plugin_context)
    plugin.custom_install_commands = {
        "linux": {
            "amd64": [
                CustomCommand(args=["echo", "$HOME"], shell=True),
                CustomCommand(args=["echo", "ready"]),
            ]
        }
    }

    checked = _well_formed_commands(plugin.get_installation_commands("linux", "amd64"))

    assert checked == [(["echo", "$HOME"], True), (["echo", "ready"], False)]


def test_a_returned_custom_command_still_reads_as_its_argv(plugin_context):
    """Readers that take each entry as an argv (the install-gate tests index and
    slice it, the docs oracle iterates it) keep reading the words; the shell
    flag rides beside, by name."""
    plugin = _plugin(plugin_context)
    plugin.custom_install_commands = {
        "linux": {
            "amd64": [CustomCommand(args=["gem", "install", "cfn-nag", "-v", "1"])]
        }
    }

    (command,) = plugin.get_installation_commands("linux", "amd64")

    assert command[:3] == ["gem", "install", "cfn-nag"]
    assert command[2] == "cfn-nag"
    assert len(command) == 5
    assert list(command) == ["gem", "install", "cfn-nag", "-v", "1"]
    assert "-v" in command
    assert command.shell is False


def test_a_dependency_still_renders_as_an_argv_without_a_shell(plugin_context):
    """The control: a declared dependency is an array of arguments, run without
    a shell, as before."""
    plugin = _plugin(plugin_context)
    plugin.dependencies = {
        "linux": {
            "amd64": [
                PluginDependency(
                    name="pip-side", version="1.0.0", package_manager=PackageManager.PIP
                )
            ]
        }
    }

    commands = plugin.get_installation_commands("linux", "amd64")

    assert len(commands) == 1
    assert isinstance(commands[0], list)
    assert _well_formed_commands(commands)[0][1] is False
