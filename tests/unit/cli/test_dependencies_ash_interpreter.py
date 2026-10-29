# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdk-nag's tool is the interpreter running ASH, whatever it is called.

cdk-nag runs inside ASH's own Python process, and its plugin declares its command
as "python". A post-install sweep that looked that name up like any other program
would fail on an interpreter that has only ``python3`` beside it (python.org
macOS framework builds, Homebrew, Debian without python-is-python3): a full
``ash dependencies install`` would exit 1 with "needed tool(s) still absent after
install: cdk-nag", and so would ``--tool cdk-nag``. A scan never looks for
``python``.

Both tests use the real ``find_executable`` for the names that matter: PATH holds
only a ``node`` stand-in, and the interpreter's directory holds only ``python3``.
"""

from __future__ import annotations

import re
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies
from automated_security_helper.cli.dependencies import EXIT_OK, dependencies_app
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.utils import (
    python_installer,
    subprocess_utils,
    uv_tool_runner,
)
from tests.snapshot.dependencies.test_snapshot_dependencies_install import (
    Scenario,
    _fake_machine,
)
from tests.snapshot.support.cli import LINUX_AMD64, run_cli, simulated_host

pytestmark = pytest.mark.unit

EXE = ".exe" if sys.platform == "win32" else ""
REAL_FIND_EXECUTABLE = subprocess_utils.find_executable


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _flat(output: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


@pytest.fixture
def python3_only(tmp_path, monkeypatch):
    """An interpreter named python3 with no python beside it, and node on PATH."""
    interpreter = _executable(tmp_path / "env" / "bin" / f"python3{EXE}")
    node_dir = _executable(tmp_path / "path" / f"node{EXE}").parent
    monkeypatch.setenv("PATH", str(node_dir))
    bin_dir = tmp_path / "ash-bin"
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
    # Only the stand-in interpreter's directory: the real environment's scripts
    # directory, and /usr/local/bin on the host running the tests, may hold a python.
    monkeypatch.setattr(subprocess_utils, "_sysconfig_scripts_dir", lambda: None)
    real_dirs = subprocess_utils.path_independent_dirs
    monkeypatch.setattr(
        subprocess_utils,
        "path_independent_dirs",
        lambda: [d for d in real_dirs() if d != Path("/usr/local/bin")],
    )
    monkeypatch.setattr(sys, "executable", str(interpreter))
    subprocess_utils.clear_find_executable_cache()
    assert REAL_FIND_EXECUTABLE("python") is None, "the layout has a python"
    assert REAL_FIND_EXECUTABLE("node") is not None
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    yield interpreter, bin_dir
    subprocess_utils.clear_find_executable_cache()


def _cdk_packages_missing(monkeypatch):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_CDK_MISSING_DISTRIBUTIONS",
        list(cdk_nag_scanner._CDK_REQUIRED_DISTRIBUTIONS),
    )
    monkeypatch.setattr(python_installer, "pip_is_importable", lambda: True)
    monkeypatch.setattr(python_installer, "is_uv_tool_environment", lambda: False)


def test_tool_cdk_nag_counts_the_interpreter_running_ash(python3_only, monkeypatch):
    _interpreter, bin_dir = python3_only
    _cdk_packages_missing(monkeypatch)
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    ran = []
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: ran.append(cmd) or 0
    )

    result = CliRunner().invoke(
        dependencies_app, ["--tool", "cdk-nag", "--bin-path", str(bin_dir)]
    )
    out = _flat(result.output)
    assert ran, out
    assert result.exit_code == EXIT_OK, out
    assert "Tools verified on PATH: 1 -- cdk-nag" in out, out


class _PythonAndNodeAreReal(Scenario):
    """The fake machine, except that python and node are looked up for real."""

    def find_executable(self, command, *args, **kwargs):
        if command in ("python", "node"):
            return REAL_FIND_EXECUTABLE(command)
        return super().find_executable(command, *args, **kwargs)


def test_a_full_run_counts_the_interpreter_running_ash(python3_only, monkeypatch):
    interpreter, bin_dir = python3_only
    scenario = _PythonAndNodeAreReal()
    _fake_machine(monkeypatch, scenario)
    # _fake_machine pins a relative "python3"; this machine's is absolute.
    monkeypatch.setattr(sys, "executable", str(interpreter))
    subprocess_utils.clear_find_executable_cache()
    with simulated_host(monkeypatch, LINUX_AMD64):
        run = run_cli(["dependencies", "install", "--bin-path", str(bin_dir)])
    out = _flat(run.output)
    assert "still absent" not in out, out
    assert run.exit_code == EXIT_OK, out
    assert re.search(r"Tools verified on PATH: \d+ -- [^│]*\bcdk-nag\b", out), out


def test_a_relative_interpreter_falls_back_to_the_lookup(python3_only, monkeypatch):
    """Only an absolute sys.executable stands for the command; otherwise PATH decides."""
    _interpreter, bin_dir = python3_only
    _cdk_packages_missing(monkeypatch)
    monkeypatch.setattr(sys, "executable", "python3")
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    monkeypatch.setattr(dependencies, "run_command", lambda cmd, shell=False: 0)
    result = CliRunner().invoke(
        dependencies_app, ["--tool", "cdk-nag", "--bin-path", str(bin_dir)]
    )
    out = _flat(result.output)
    assert result.exit_code != EXIT_OK, out
    assert "requested tool(s) still not on PATH: cdk-nag" in out, out
