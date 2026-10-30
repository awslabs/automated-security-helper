# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Packages added to ASH's own environment are installed with the tool that owns it.

``ash dependencies install`` ran ``<sys.executable> -m pip install`` for cdk-nag's
packages, for ferret-scan, and for any plugin dependency declared with the pip
package manager. An environment uv created -- ``uv tool install``, ``uvx``,
``uv venv`` -- has no pip, so each of those failed with "No module named pip", and
cdk-nag's hint told the user to run the command that had just failed.

The environment is simulated: whether pip is importable, whether ``sys.prefix``
carries a uv receipt, and which uv ``find_uv_or_none`` returns. Nothing is
installed.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.utils import python_installer, uv_tool_runner

pytestmark = pytest.mark.unit

UV = "/opt/ash-env/bin/uv"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    """A Python environment at tmp_path/env; tests choose pip, receipt and uv."""
    prefix = tmp_path / "env"
    prefix.mkdir()
    monkeypatch.setattr(sys, "prefix", str(prefix))
    state = SimpleNamespace(prefix=prefix)

    def configure(*, pip: bool, uv: str | None = UV, uv_tool: bool = False):
        # The seam the installer reads: pip_is_importable asks
        # importlib.machinery.PathFinder over the interpreter's own path entries,
        # not importlib.util.find_spec, so a fake find_spec answered nothing
        # here and the test environment's pip was whatever this process had.
        monkeypatch.setattr(python_installer, "pip_is_importable", lambda: pip)
        monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: uv)
        if uv_tool:
            prefix.joinpath("uv-receipt.toml").write_text("[tool]\n")
        return state

    return configure


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir(parents=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _cdk_install_command(plugin_context, monkeypatch) -> list[str]:
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    commands = CdkNagScanner(context=plugin_context).get_installation_commands(
        "linux", "amd64"
    )
    assert len(commands) == 1, commands
    return commands[0]


class TestCdkNagPackages:
    def test_a_uv_environment_without_pip_installs_with_uv(
        self, environment, plugin_context, monkeypatch
    ):
        environment(pip=False)
        command = _cdk_install_command(plugin_context, monkeypatch)
        assert command[:6] == [
            "uv",
            "pip",
            "install",
            "--no-config",
            "--python",
            sys.executable,
        ]
        assert {arg.split("<")[0].split(">")[0] for arg in command[6:]} == {
            "aws-cdk-lib",
            "cdk-nag",
            "constructs",
        }

    def test_a_uv_tool_environment_installs_with_uv_even_with_pip_present(
        self, environment, plugin_context, monkeypatch
    ):
        environment(pip=True, uv_tool=True)
        command = _cdk_install_command(plugin_context, monkeypatch)
        assert command[:6] == [
            "uv",
            "pip",
            "install",
            "--no-config",
            "--python",
            sys.executable,
        ]

    def test_an_environment_with_pip_uses_pip(
        self, environment, plugin_context, monkeypatch
    ):
        environment(pip=True)
        command = _cdk_install_command(plugin_context, monkeypatch)
        assert command[:4] == [sys.executable, "-m", "pip", "install"]

    def test_no_pip_and_no_uv_is_refused_with_what_to_do(
        self, environment, plugin_context, monkeypatch
    ):
        environment(pip=False, uv=None)
        monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
        scanner = CdkNagScanner(context=plugin_context)
        with pytest.raises(ToolNotProvisionableError) as raised:
            scanner.get_installation_commands("linux", "amd64")
        assert "ensurepip" in str(raised.value)
        assert "uv" in str(raised.value)

    def test_the_scan_hint_names_a_command_that_installs_cdk_nag(
        self, plugin_context, monkeypatch
    ):
        monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
        warned = []
        monkeypatch.setattr(
            cdk_nag_scanner.ASH_LOGGER,
            "warning",
            lambda msg, *a, **k: warned.append(msg),
        )
        scanner = CdkNagScanner(context=plugin_context)
        assert scanner.validate_plugin_dependencies() is False
        assert any("ash dependencies install --tool cdk-nag" in w for w in warned), (
            warned
        )


def test_ferret_scan_installs_with_uv_without_pip(environment, plugin_context):
    environment(pip=False)
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )

    commands = FerretScanScanner(context=plugin_context).get_installation_commands(
        "linux", "amd64"
    )
    installs = [c for c in commands if "ferret-scan" in " ".join(c)]
    assert installs, commands
    assert installs[-1][:6] == [
        "uv",
        "pip",
        "install",
        "--no-config",
        "--python",
        sys.executable,
    ]


def test_a_pip_plugin_dependency_installs_with_uv_without_pip(environment):
    environment(pip=False)
    from automated_security_helper.base.plugin_base import (
        _INSTALL_COMMAND_BUILDERS,
        PluginDependency,
    )
    from automated_security_helper.core.enums import PackageManager

    command = _INSTALL_COMMAND_BUILDERS[PackageManager.PIP](
        PluginDependency(
            name="ferret-scan", version=">=2.4.5,<2.6.0", package_manager="pip"
        )
    )
    assert command == [
        "uv",
        "pip",
        "install",
        "--no-config",
        "--python",
        sys.executable,
        "ferret-scan>=2.4.5,<2.6.0",
    ]


class TestRebuildNote:
    def test_a_uv_tool_environment_is_told_what_removes_the_packages(self, environment):
        from automated_security_helper.utils import python_installer

        environment(pip=False, uv_tool=True)
        note = python_installer.environment_rebuild_note(["cdk-nag>=3"])
        assert note is not None and "uv tool upgrade" in note
        # And how to keep them through either.
        assert "--with 'cdk-nag>=3'" in note
        assert "uv tool install" in note

    def test_a_uvx_environment_is_told_how_to_keep_them(self, tmp_path, monkeypatch):
        prefix = tmp_path / "cache" / "archive-v0" / "abc123"
        prefix.mkdir(parents=True)
        prefix.joinpath("pyvenv.cfg").write_text("home = /usr\n")
        monkeypatch.setattr(sys, "prefix", str(prefix))
        from automated_security_helper.utils import python_installer

        note = python_installer.environment_rebuild_note(["cdk-nag>=3"])
        assert note is not None and "--with 'cdk-nag>=3'" in note

    def test_a_plain_venv_needs_no_note(self, environment):
        from automated_security_helper.utils import python_installer

        environment(pip=True)
        assert python_installer.environment_rebuild_note(["x"]) is None


def test_dependencies_install_runs_uv_pip_in_a_pip_less_environment(
    environment, plugin_context, tmp_path, monkeypatch
):
    """Through the CLI: the command run for cdk-nag, and the note after it."""
    from automated_security_helper.cli import dependencies

    environment(pip=False, uv_tool=True)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    # The uv-managed scanners probe their tool's version while they are built;
    # nothing here may start a real uv.
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(plugin_context.source_dir)
    ran = []
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: ran.append(cmd) or 0
    )
    printed = io.StringIO()
    monkeypatch.setattr(
        dependencies, "print", Console(file=printed, width=300, no_color=True).print
    )
    monkeypatch.setattr(
        dependencies, "console", Console(file=io.StringIO(), width=300, no_color=True)
    )
    result = CliRunner().invoke(
        dependencies.dependencies_app,
        ["--tool", "cdk-nag", "--bin-path", str(tmp_path / "bin")],
    )
    assert ran, result.output
    assert ran[0][:6] == [
        "uv",
        "pip",
        "install",
        "--no-config",
        "--python",
        sys.executable,
    ]
    assert "uv tool upgrade" in printed.getvalue()
    assert Path(sys.prefix).joinpath("uv-receipt.toml").is_file()


def test_a_pip_install_into_a_uvx_environment_gets_the_rebuild_note(
    environment, plugin_context, tmp_path, monkeypatch
):
    """The pip form of the install is read for its requirements too.

    A uvx environment can import pip (``uvx --with pip``), and then the pip command
    is what runs. The note that tells the reader how to keep the packages through a
    rebuilt uvx environment has to name the requirements that command installed.
    """
    from automated_security_helper.cli import dependencies
    from automated_security_helper.utils import python_installer

    environment(pip=True)
    monkeypatch.setattr(python_installer, "is_uvx_environment", lambda: True)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(plugin_context.source_dir)
    ran = []
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: ran.append(cmd) or 0
    )
    printed = io.StringIO()
    monkeypatch.setattr(
        dependencies, "print", Console(file=printed, width=400, no_color=True).print
    )
    monkeypatch.setattr(
        dependencies, "console", Console(file=io.StringIO(), width=300, no_color=True)
    )
    result = CliRunner().invoke(
        dependencies.dependencies_app,
        ["--tool", "cdk-nag", "--bin-path", str(tmp_path / "bin")],
    )
    assert ran and ran[0][:4] == [sys.executable, "-m", "pip", "install"], ran
    note = " ".join(printed.getvalue().split())
    assert "runs under uvx" in note, result.output + note
    for requirement in ran[0][4:]:
        assert f"--with '{requirement}'" in note, note
