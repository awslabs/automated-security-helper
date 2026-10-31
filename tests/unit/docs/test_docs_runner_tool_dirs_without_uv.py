# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs runner finds the installed tools without running uv.

WHY THIS EXISTS
---------------
The docs-example runner builds each session's PATH itself: the interpreter's bin
directory, the directories ``ash dependencies install`` writes to for the invoking user
(ash_tool_dirs), then the system's. It never inherits the pytest process's PATH, so a
PATH export in the workflow cannot reach the tools a docs block runs. ash_tool_dirs
used to learn uv's tool bin directory only by running ``uv tool dir --bin``, with uv
found beside the interpreter or on the process's PATH. On a runner that installs the
tools with its own uv and then runs pytest from a virtual environment that has no uv,
that route added nothing, the sessions ran without the Python tools, and the e2e tools
test reported the install directories as absent although both existed with the files.

Now the uv tool bin directory is resolved from the invoking environment the way uv
resolves it (UV_TOOL_BIN_DIR, else XDG_BIN_HOME, else HOME/.local/bin) before uv is
asked, and the uv route stays as a further source. These tests prove the environment
route alone: ``shutil.which`` answers None for everything, so neither uv route exists,
and a child-process start would be a failure of the test.

The invoking environment is the process's, with what the test session changed put
back from the record tests/conftest.py exports. The session also removes uv's
directory variables, so a developer or runner that set UV_TOOL_BIN_DIR or XDG_BIN_HOME
would otherwise get HOME/.local/bin from both routes. Those two names are therefore
restored from the record as well, and a name the record lacks is removed from the
copy, since the session removed it: a value the process holds now is not trusted.

The runner is loaded by path, as every test of it is, because tests/integration/docs
is not a package. Nothing here runs a docs command or any program.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = REPO_ROOT / "tests" / "integration" / "docs" / "docs_runner.py"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    # The runner imports tests.utils.runner_state by package name.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("_ash_docs_runner", RUNNER_PATH)


def _planted_tool(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True)
    tool = directory / name
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def _no_program_runs(*args, **kwargs):
    raise AssertionError(f"the runner started a program: {args!r} {kwargs!r}")


@pytest.fixture
def without_uv(tmp_path, monkeypatch):
    """A recorded developer home holding a tool in each default directory, no uv anywhere.

    The pytest process's own HOME is a private directory with nothing in it, so a
    directory found here came from the recorded home, not from Path.home().
    """
    real_home = tmp_path / "real-home"
    ash_tool = _planted_tool(real_home / ".ash" / "bin", "ash-docs-ash-bin-tool")
    local_tool = _planted_tool(real_home / ".local" / "bin", "ash-docs-local-bin-tool")
    private_home = tmp_path / "private-home"
    private_home.mkdir()
    for name in ("ASH_BIN_PATH", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(private_home))
    # The record tests/conftest.py exports (read by developer_environment_record).
    monkeypatch.setenv(
        "ASH_TEST_DEVELOPER_HOME",
        json.dumps({"env": {"HOME": str(real_home)}, "home": str(real_home)}),
    )
    # No uv beside the interpreter and none on PATH: both uv routes are gone with
    # this one patch, and a program start would be a child process the test forbids.
    monkeypatch.setattr(runner.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.subprocess, "run", _no_program_runs)
    return real_home, ash_tool.parent, local_tool.parent


def _found() -> list[Path]:
    return [directory.resolve() for directory in runner.ash_tool_dirs()]


def _record_developer_env(monkeypatch, real_home: Path, **recorded: str) -> None:
    """Replace the fixture's record with one that also holds ``recorded``.

    The process keeps none of these variables: the session removed them, and the
    fixture has already deleted them from the environment. A variable the developer
    set reaches the runner only through this record.
    """
    env = {"HOME": str(real_home), **recorded}
    monkeypatch.setenv(
        "ASH_TEST_DEVELOPER_HOME",
        json.dumps({"env": env, "home": str(real_home)}),
    )


def test_the_default_directories_are_found_with_no_uv(without_uv):
    real_home, ash_bin, local_bin = without_uv
    assert runner._uv_executable() is None
    assert _found() == [ash_bin.resolve(), local_bin.resolve()]


def test_uv_tool_bin_dir_replaces_the_local_bin_default(
    without_uv, tmp_path, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    uv_tool = _planted_tool(tmp_path / "uv-tool-bin", "ash-docs-uv-tool")
    _record_developer_env(monkeypatch, real_home, UV_TOOL_BIN_DIR=str(uv_tool.parent))
    found = _found()
    assert found == [ash_bin.resolve(), uv_tool.parent.resolve()]
    assert local_bin.resolve() not in found


def test_xdg_bin_home_replaces_the_local_bin_default_when_uv_tool_bin_dir_is_unset(
    without_uv, tmp_path, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    xdg_tool = _planted_tool(tmp_path / "xdg-bin", "ash-docs-xdg-tool")
    _record_developer_env(monkeypatch, real_home, XDG_BIN_HOME=str(xdg_tool.parent))
    assert _found() == [ash_bin.resolve(), xdg_tool.parent.resolve()]
    # UV_TOOL_BIN_DIR comes first when both are set, as uv itself reads them.
    uv_tool = _planted_tool(tmp_path / "uv-tool-bin", "ash-docs-uv-tool")
    _record_developer_env(
        monkeypatch,
        real_home,
        XDG_BIN_HOME=str(xdg_tool.parent),
        UV_TOOL_BIN_DIR=str(uv_tool.parent),
    )
    assert _found() == [ash_bin.resolve(), uv_tool.parent.resolve()]


def test_a_named_directory_that_does_not_exist_is_left_out(
    without_uv, tmp_path, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    never_made = tmp_path / "never-made"
    _record_developer_env(monkeypatch, real_home, UV_TOOL_BIN_DIR=str(never_made))
    assert _found() == [ash_bin.resolve()]


def test_the_same_directory_named_twice_is_listed_once(without_uv, monkeypatch):
    real_home, ash_bin, local_bin = without_uv
    _record_developer_env(monkeypatch, real_home, UV_TOOL_BIN_DIR=str(ash_bin))
    assert _found() == [ash_bin.resolve()]


def test_a_recorded_uv_tool_bin_dir_is_used_though_the_session_removed_it(
    without_uv, tmp_path, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    recorded = _planted_tool(tmp_path / "recorded-uv-tool-bin", "ash-docs-uv-tool")
    _record_developer_env(monkeypatch, real_home, UV_TOOL_BIN_DIR=str(recorded.parent))
    assert "UV_TOOL_BIN_DIR" not in os.environ
    found = _found()
    assert found == [ash_bin.resolve(), recorded.parent.resolve()]
    assert local_bin.resolve() not in found


def test_a_recorded_xdg_bin_home_is_used_though_the_session_removed_it(
    without_uv, tmp_path, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    recorded = _planted_tool(tmp_path / "recorded-xdg-bin", "ash-docs-xdg-tool")
    _record_developer_env(monkeypatch, real_home, XDG_BIN_HOME=str(recorded.parent))
    assert "XDG_BIN_HOME" not in os.environ
    found = _found()
    assert found == [ash_bin.resolve(), recorded.parent.resolve()]
    assert local_bin.resolve() not in found


def test_the_invoking_environment_carries_the_recorded_uv_directory_variables(
    without_uv, monkeypatch
):
    real_home, ash_bin, local_bin = without_uv
    _record_developer_env(
        monkeypatch,
        real_home,
        UV_TOOL_BIN_DIR="/recorded/uv-tool-bin",
        XDG_BIN_HOME="/recorded/xdg-bin",
    )
    env = runner.invoking_user_environment()
    assert env["UV_TOOL_BIN_DIR"] == "/recorded/uv-tool-bin"
    assert env["XDG_BIN_HOME"] == "/recorded/xdg-bin"
    # The home variables are restored as before.
    assert env["HOME"] == str(real_home)

    # A name the record lacks was unset for the developer and removed by the
    # session, so a value the process holds now is not trusted.
    _record_developer_env(monkeypatch, real_home)
    monkeypatch.setenv("UV_TOOL_BIN_DIR", "/stray/uv-tool-bin")
    monkeypatch.setenv("XDG_BIN_HOME", "/stray/xdg-bin")
    env = runner.invoking_user_environment()
    assert "UV_TOOL_BIN_DIR" not in env
    assert "XDG_BIN_HOME" not in env
