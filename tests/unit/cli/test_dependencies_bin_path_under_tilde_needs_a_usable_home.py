# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install --bin-path ~/...`` installs nowhere without a usable home.

A shell expands ``~``; a quoted value, or ``ASH_BIN_PATH`` set to one, reaches the
command unexpanded, and ``Path.expanduser`` takes HOME as given. An empty HOME
made ``~/.ash/bin`` the filesystem's ``/.ash/bin``, and a relative HOME put it
under the working directory, the repository being scanned. The command expands a
leading ``~`` only from a usable home (``core.constants.usable_home``), and
otherwise refuses with the no-bin-directory text and the invalid-configuration
code before anything is created, as it does when no bin path was given at all.

The installer runs with ``--tool sarif``, one reporter with nothing to install.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import (
    EXIT_INVALID_CONFIG,
    EXIT_OK,
    dependencies_app,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.download_utils import NO_BIN_DIRECTORY

pytestmark = pytest.mark.unit


def _flat(output: str) -> str:
    """The output on one line, without the colors rich adds."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A working directory with no ASH_BIN_PATH, where no uv is probed."""
    directory = tmp_path / "project"
    directory.mkdir()
    monkeypatch.chdir(directory)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    subprocess_utils.clear_find_executable_cache()
    yield directory
    os.environ.pop("ASH_BIN_PATH", None)
    subprocess_utils.clear_find_executable_cache()


def _home(monkeypatch, value: str) -> None:
    # Both spellings, so the home the command reads is this one on every platform.
    monkeypatch.setenv("HOME", value)
    monkeypatch.setenv("USERPROFILE", value)


def _install(bin_path: str):
    # Wide, so the panel does not fold a long temporary path across lines.
    return CliRunner().invoke(
        dependencies_app,
        ["--tool", "sarif", "--bin-path", bin_path],
        env={"COLUMNS": "300"},
    )


def test_an_empty_home_refuses_a_bin_path_under_tilde(project, monkeypatch):
    """With HOME empty, ~/.ash/bin used to expand to the filesystem's /.ash/bin."""
    _home(monkeypatch, "")
    made: list[str] = []
    real_mkdir = Path.mkdir

    def no_directory_outside_the_test(self, *args, **kwargs):
        # The control that nothing is created at the root: a directory the
        # command would make outside this test's tree is recorded and refused,
        # never made.
        if project not in self.parents and self != project:
            made.append(str(self))
            raise PermissionError(str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", no_directory_outside_the_test)

    result = _install("~/.ash/bin")

    assert result.exit_code == EXIT_INVALID_CONFIG, result.output
    assert _flat(NO_BIN_DIRECTORY) in _flat(result.output), result.output
    assert made == [], made


def test_a_relative_home_refuses_a_bin_path_under_tilde(project, monkeypatch):
    """With HOME relative, ~/.ash/bin used to land under the working directory."""
    _home(monkeypatch, "home")

    result = _install("~/.ash/bin")

    assert result.exit_code == EXIT_INVALID_CONFIG, result.output
    assert _flat(NO_BIN_DIRECTORY) in _flat(result.output), result.output
    assert not (project / "home").exists(), sorted(project.rglob("*"))


def test_a_usable_home_expands_a_bin_path_under_tilde(project, tmp_path, monkeypatch):
    """The control: an absolute HOME still expands ~ to it, as given."""
    home = tmp_path / "home"
    home.mkdir()
    _home(monkeypatch, str(home))

    result = _install("~/tools")

    assert result.exit_code == EXIT_OK, result.output
    assert (home / "tools").is_dir()
    assert f"Target bin path: {home / 'tools'}" in _flat(result.output), result.output


def test_a_doubled_separator_after_tilde_stays_under_the_home(
    project, tmp_path, monkeypatch
):
    """`~//.ash/bin` used to leave `/.ash/bin` after the `~/`, which joinpath took
    whole, dropping the home and installing at the filesystem's root."""
    home = tmp_path / "home"
    home.mkdir()
    _home(monkeypatch, str(home))
    made: list[str] = []
    real_mkdir = Path.mkdir

    def no_directory_outside_the_test(self, *args, **kwargs):
        if tmp_path not in self.parents and self != tmp_path:
            made.append(str(self))
            raise PermissionError(str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", no_directory_outside_the_test)

    result = _install("~//.ash/bin")

    assert result.exit_code == EXIT_OK, result.output
    assert made == [], made
    assert (home / ".ash" / "bin").is_dir()


@pytest.mark.parametrize(
    ("bin_path", "pure", "expected"),
    [
        ("~//.ash/bin", PurePosixPath, ("home", ".ash", "bin")),
        ("~", PurePosixPath, ("home",)),
        ("~\\\\x", PureWindowsPath, ("home", "x")),
        ("~/\\x", PureWindowsPath, ("home", "x")),
    ],
)
def test_the_components_after_tilde_are_joined_under_the_home(bin_path, pure, expected):
    home = Path("home")
    assert dependencies_module._is_under_tilde(bin_path, pure)
    assert dependencies_module._bin_path_under_home(bin_path, home, pure) == Path(
        *expected
    )


def test_a_tilde_inside_a_component_is_not_a_home_path():
    """Only a first component of exactly `~` is expanded, as pathlib does."""
    assert not dependencies_module._is_under_tilde("~user/x", PurePosixPath)
    assert not dependencies_module._is_under_tilde(" ~/x", PurePosixPath)
    assert not dependencies_module._is_under_tilde("x/~/y", PurePosixPath)
