# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash dependencies install --bin-path X`` leaves behind, and who finds it.

A scan finds tools in X only when ``ASH_BIN_PATH`` names X, and nothing about X is
remembered between runs: the installer ends by saying how to set it, for POSIX
shells and for PowerShell.

The installer runs with ``--tool sarif``, one reporter with nothing to install; a
stand-in executable placed in X stands for what an install would have written.
"""

from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from rich.text import Text
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.core.constants import is_blank_bin_path
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from tests.utils.env_assertions import environ_value
from tests.utils.helpers import checkout_env

EXE = ".exe" if sys.platform == "win32" else ""


def _standin(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / f"{name}{EXE}"
    tool.write_text("#!/bin/sh\necho stand-in\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    return tool


@pytest.fixture
def fresh_lookup(tmp_path, monkeypatch):
    """A process that never had ASH_BIN_PATH set, as a later scan is, in its own home."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    # Building the uv-managed plugins probes uv; nothing here may start one.
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False
    )
    subprocess_utils.clear_find_executable_cache()
    yield home
    os.environ.pop("ASH_BIN_PATH", None)
    subprocess_utils.clear_find_executable_cache()


def _install(project: Path, *args: str):
    project.mkdir(exist_ok=True)
    cwd = os.getcwd()
    os.chdir(project)
    try:
        return CliRunner().invoke(dependencies_app, [*args, "--tool", "sarif"])
    finally:
        os.chdir(cwd)


def _flat(output: str) -> str:
    """The output on one line, without the colors rich adds."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


@pytest.mark.unit
def test_a_later_lookup_finds_the_bin_path_only_through_ash_bin_path(
    tmp_path, fresh_lookup
):
    bin_dir = tmp_path / "chosen-bin"
    result = _install(tmp_path / "project", "--bin-path", str(bin_dir))
    assert result.exit_code == 0, result.output
    tool = _standin(bin_dir, "ash-standin-tool")

    # The installer exported ASH_BIN_PATH into this process; a scan is a new one.
    os.environ.pop("ASH_BIN_PATH", None)
    subprocess_utils.clear_find_executable_cache()
    assert subprocess_utils.find_executable("ash-standin-tool") is None, (
        "the --bin-path directory is still searched without ASH_BIN_PATH"
    )
    assert bin_dir not in subprocess_utils.path_independent_dirs()

    os.environ["ASH_BIN_PATH"] = str(bin_dir)
    subprocess_utils.clear_find_executable_cache()
    assert subprocess_utils.find_executable("ash-standin-tool") == tool.as_posix()


@pytest.mark.unit
def test_the_install_writes_nothing_to_the_home_directory(tmp_path, fresh_lookup):
    home = fresh_lookup
    result = _install(tmp_path / "project", "--bin-path", str(tmp_path / "bin"))
    assert result.exit_code == 0, result.output
    assert not any(home.rglob("*")), sorted(map(str, home.rglob("*")))


@pytest.mark.unit
def test_a_relative_bin_path_is_exported_absolute(tmp_path, fresh_lookup):
    """A scan ignores a relative ASH_BIN_PATH, so the install's children get it absolute."""
    project = tmp_path / "project"
    result = _install(project, "--bin-path", "tools")
    assert result.exit_code == 0, result.output
    assert environ_value("ASH_BIN_PATH") == str(project / "tools")
    assert (project / "tools").is_dir()


@pytest.mark.unit
def test_the_install_ends_with_how_to_set_ash_bin_path(tmp_path, fresh_lookup):
    project = tmp_path / "project"
    result = _install(project, "--bin-path", "tools")
    assert result.exit_code == 0, result.output
    # A relative --bin-path is named absolutely: a scan elsewhere needs that.
    absolute = str(project / "tools")
    out = _flat(result.output)
    assert f"export ASH_BIN_PATH={shlex.quote(absolute)}" in out, out
    assert f"$env:ASH_BIN_PATH = '{absolute}'" in out, out
    # Last: after the results panel.
    assert out.rindex("ASH_BIN_PATH") > out.index("Installation Complete")


@pytest.mark.unit
def test_a_failed_install_ends_with_the_hint_too(tmp_path, fresh_lookup, monkeypatch):
    monkeypatch.setattr(dependencies, "run_command", lambda *_a, **_k: 1)
    bin_dir = tmp_path / "bin dir"
    project = tmp_path / "project"
    project.mkdir()
    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = CliRunner().invoke(
            dependencies_app, ["--bin-path", str(bin_dir), "--tool", "grype"]
        )
    finally:
        os.chdir(cwd)
    assert result.exit_code == dependencies.EXIT_INSTALL_FAILED, result.output
    out = _flat(result.output)
    assert "Installation Incomplete" in out, out
    assert f"export ASH_BIN_PATH={shlex.quote(str(bin_dir))}" in out, out


@pytest.mark.unit
@pytest.mark.parametrize("source", ["environment", "default"])
def test_no_hint_when_scans_already_look_there(
    source, tmp_path, fresh_lookup, monkeypatch
):
    if source == "environment":
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "env-bin"))
        args: list = []
    else:
        args = ["--bin-path", str(fresh_lookup / ".ash" / "bin")]
    result = _install(tmp_path / "project", *args)
    assert result.exit_code == 0, result.output
    assert "export ASH_BIN_PATH" not in result.output, result.output


@pytest.mark.unit
def test_an_ash_bin_path_spelled_differently_is_the_same_directory(
    tmp_path, fresh_lookup
):
    spelled = f"{tmp_path.as_posix()}/b/../c"
    assert dependencies._bin_path_hint(tmp_path / "c", spelled) is None


#: Values that name no directory. Path() drops a trailing separator, so "  /" was
#: the relative path "  " under the working directory, like " ".
BLANK_VALUES = [
    pytest.param("", id="empty"),
    pytest.param(" ", id="space"),
    pytest.param(" \t", id="whitespace"),
    pytest.param("  /", id="spaces-slash"),
    pytest.param(" /", id="space-slash"),
    pytest.param("\t/", id="tab-slash"),
]


@pytest.mark.unit
@pytest.mark.parametrize("blank", BLANK_VALUES)
def test_blank_values_name_no_directory(blank):
    assert is_blank_bin_path(blank)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["/", ".", " /x", "x/ ", "bin"])
def test_other_values_are_used_as_given(value):
    """A value with a component that is not blank names a directory, relative or not."""
    assert not is_blank_bin_path(value)


@pytest.mark.unit
@pytest.mark.parametrize("blank", BLANK_VALUES)
def test_a_blank_ash_bin_path_is_unset(blank, tmp_path, fresh_lookup):
    """ASH_BIN_PATH that is empty or only whitespace means the default directory."""
    default = fresh_lookup / ".ash" / "bin"
    assert dependencies._bin_path_hint(default, blank) is None
    assert dependencies._bin_path_hint(tmp_path / "other", blank) is not None


def _blank_environment(tmp_path, blank):
    """A home, an empty project and an environment; ASH_BIN_PATH unset for None."""
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "NO_COLOR": "1",
        "COLUMNS": "300",
        "UV_OFFLINE": "1",
    }
    env.pop("ASH_BIN_PATH", None)
    if blank is not None:
        env["ASH_BIN_PATH"] = blank
    return home, project, env


@pytest.mark.integration
@pytest.mark.parametrize("blank", BLANK_VALUES)
def test_a_blank_ash_bin_path_does_not_point_into_the_working_directory(
    blank, tmp_path
):
    """A new process with a blank ASH_BIN_PATH: the default directory everywhere.

    A blank value ("" or " ") means the default directory, so neither the install
    nor a scan's tool lookup points into the working directory.
    """
    home, project, env = _blank_environment(tmp_path, blank)
    probe = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            (
                "from automated_security_helper.core.constants import ASH_BIN_PATH;"
                "from automated_security_helper.utils.subprocess_utils import _bin_path;"
                "from automated_security_helper.utils.download_utils import "
                "current_bin_path;"
                "print(repr(str(ASH_BIN_PATH)));"
                "print(repr(str(_bin_path())));"
                "print(repr(str(current_bin_path())))"
            ),
        ],
        env=checkout_env(env),
        cwd=project,
        capture_output=True,
        text=True,
        check=True,
    )
    expected = repr(str(home / ".ash" / "bin"))
    assert probe.stdout.splitlines() == [expected] * 3, probe.stdout


def _install_in_a_new_process(tmp_path, blank, *args):
    """``ash dependencies install --tool sarif *args`` run as a scan's caller runs it."""
    ash = Path(sys.executable).with_name(f"ash{EXE}")
    if not ash.is_file():
        pytest.skip("the ash console script is not beside the interpreter")
    home, project, env = _blank_environment(tmp_path, blank)
    result = subprocess.run(  # nosec B603
        [str(ash), "dependencies", "install", "--tool", "sarif", *args],
        env=checkout_env(env),
        cwd=project,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return home, project, result, _flat(result.stdout + result.stderr)


@pytest.mark.integration
@pytest.mark.parametrize("blank", BLANK_VALUES)
def test_a_blank_ash_bin_path_installs_into_the_default_directory(blank, tmp_path):
    """The installer, in a new process: no directory named " " in the repository."""
    home, project, result, out = _install_in_a_new_process(tmp_path, blank)
    assert result.returncode == 0, out
    assert sorted(p.name for p in project.iterdir()) == [], out
    assert (home / ".ash" / "bin").is_dir(), out
    assert "export ASH_BIN_PATH" not in out, out


@pytest.mark.integration
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--bin-path", ""], id="bin-path-empty"),
        pytest.param(["--bin-path="], id="bin-path-equals"),
        pytest.param(["-b", ""], id="b-empty"),
        pytest.param(["--bin-path", " "], id="bin-path-space"),
        pytest.param(["--bin-path", "  /"], id="bin-path-spaces-slash"),
    ],
)
def test_a_blank_bin_path_option_installs_into_the_default_directory(args, tmp_path):
    """``--bin-path "$TOOLS_DIR"`` with TOOLS_DIR unset is no --bin-path.

    A blank --bin-path is treated as no --bin-path: the install goes into the
    default directory and exports nothing that points at the working directory.
    """
    home, project, result, out = _install_in_a_new_process(tmp_path, None, *args)
    assert result.returncode == 0, out
    assert sorted(p.name for p in project.iterdir()) == [], out
    assert (home / ".ash" / "bin").is_dir(), out
    assert "Target bin path: ." not in out, out
    assert "export ASH_BIN_PATH" not in out, out


@pytest.mark.unit
def test_an_explicit_dot_bin_path_is_the_working_directory(tmp_path, fresh_lookup):
    """A dot names a directory: it is used as given, unlike "" or " "."""
    project = tmp_path / "project"
    result = _install(project, "--bin-path", ".")
    assert result.exit_code == 0, result.output
    assert f"export ASH_BIN_PATH={shlex.quote(str(project))}" in _flat(result.output)
    assert not (fresh_lookup / ".ash").exists()


@pytest.mark.unit
def test_a_console_script_beside_the_interpreter_is_found(
    tmp_path, monkeypatch, fresh_lookup
):
    """Packages installed into ASH's own environment put their scripts there.

    ``ash dependencies install`` adds ferret-scan to ASH's environment; under pipx
    or a uv tool that environment's bin directory is not on PATH.
    """
    env_bin = tmp_path / "env" / ("Scripts" if sys.platform == "win32" else "bin")
    python = _standin(env_bin, "python")
    tool = _standin(env_bin, "ferret-scan-standin")
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert subprocess_utils.find_executable("ferret-scan-standin") == tool.as_posix()


@pytest.mark.unit
def test_the_default_directory_gets_the_hint_when_ash_bin_path_points_elsewhere(
    tmp_path, fresh_lookup, monkeypatch
):
    """With ASH_BIN_PATH set to another directory, a scan does not look in ~/.ash/bin."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "elsewhere"))
    default = fresh_lookup / ".ash" / "bin"
    result = _install(tmp_path / "project", "--bin-path", str(default))
    assert result.exit_code == 0, result.output
    assert f"export ASH_BIN_PATH={shlex.quote(str(default))}" in _flat(result.output)


@pytest.mark.unit
def test_a_relative_ash_bin_path_gets_the_absolute_hint(
    tmp_path, fresh_lookup, monkeypatch
):
    """A relative ASH_BIN_PATH means another directory as soon as a scan runs elsewhere."""
    monkeypatch.setenv("ASH_BIN_PATH", "rel-bin")
    project = tmp_path / "project"
    result = _install(project)
    assert result.exit_code == 0, result.output
    absolute = str(project / "rel-bin")
    assert f"export ASH_BIN_PATH={shlex.quote(absolute)}" in _flat(result.output)


@pytest.mark.unit
@pytest.mark.parametrize("quote", ["'", "‘", "’", "‚", "‛"])
def test_the_powershell_line_doubles_every_quote_powershell_ends_a_string_on(
    quote, tmp_path, fresh_lookup
):
    directory = tmp_path / f"o{quote}brien"
    hint = dependencies._bin_path_hint(directory, None)
    assert hint is not None
    doubled = str(directory).replace(quote, quote * 2)
    # The hint is Rich markup: the escape closes a value holding a colon off with
    # empty style tags, which every absolute Windows path (its drive colon) gets,
    # so the line is read as it renders, the text a user sees.
    rendered = Text.from_markup(hint).plain
    assert f"$env:ASH_BIN_PATH = '{doubled}'" in rendered, hint


@pytest.mark.unit
def test_the_hint_does_not_claim_tools_went_there(tmp_path, fresh_lookup):
    """A uv tool or a failed command puts nothing in the directory."""
    hint = dependencies._bin_path_hint(tmp_path / "bin", None)
    assert hint is not None
    assert "were installed into" not in hint, hint
