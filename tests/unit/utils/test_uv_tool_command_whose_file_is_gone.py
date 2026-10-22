# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command ``get_uv_tool_command`` remembered is answered only while its file is.

``get_uv_tool_command`` remembers its answer for the life of the process, so the
version probe runs once per tool. A remembered command given again after
the file it starts, the uv its probe ran or the tool's own executable, is gone
would have a scanner that asks whether its tool can run (bandit, checkov, semgrep,
detect-secrets) count a tool that was deleted mid-run. The answer is None
and an error names the file; the probe is not run again.
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX execute permission and shell scripts"
)


@pytest.fixture
def tool_name() -> str:
    """A name no directory on the host holds."""
    return f"ash-uv-lookup-probe-{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def _lookups_of_our_own(monkeypatch):
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    # Only the PATH a test sets: no tool from ASH's bin directory or /usr/local/bin.
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", list)

    def reset():
        uv_tool_runner._reset_uv_tool_runner_caches()
        subprocess_utils.clear_find_executable_cache()

    reset()
    yield
    reset()


def _executable(directory: Path, name: str, body: str = "exit 0\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_uv(directory: Path) -> tuple[Path, Path]:
    """A uv that answers every call with success and records each one."""
    calls = directory / "calls.txt"
    uv = _executable(
        directory, "uv", f'echo "$*" >> "{calls}"\necho "tool 1.0.0"\nexit 0\n'
    )
    return uv, calls


def _probes(calls: Path) -> list[str]:
    if not calls.exists():
        return []
    return [line for line in calls.read_text().splitlines() if "--version" in line]


def _no_longer_runs(tool: Path, how: str, tmp_path: Path) -> None:
    """Leave ``tool``'s path as something that does not run, or, for the control, as
    a link to a file that does."""
    if how == "gone":
        tool.unlink()
    elif how == "no execute bit":
        tool.chmod(0o644)
    elif how == "a directory":
        tool.unlink()
        tool.mkdir()
    elif how == "a FIFO":
        tool.unlink()
        os.mkfifo(tool)
    elif how == "a dangling link":
        tool.unlink()
        tool.symlink_to(tmp_path / "not-there")
    elif how == "a link to an executable":
        target = _executable(tmp_path / "elsewhere", tool.name)
        tool.unlink()
        tool.symlink_to(target)


@pytest.mark.parametrize(
    "how",
    ["gone", "no execute bit", "a directory", "a FIFO", "a dangling link"],
)
def test_a_direct_command_whose_binary_no_longer_runs_is_not_the_answer(
    tmp_path, monkeypatch, tool_name, caplog, how
):
    """Still there by name is not enough: it has to be an executable file."""
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    tool = _executable(tmp_path / "a", tool_name)
    monkeypatch.setenv("PATH", str(tool.parent))
    assert get_uv_tool_command(tool_name) == [str(tool)]

    _no_longer_runs(tool, how, tmp_path)

    with caplog.at_level(logging.ERROR):
        assert get_uv_tool_command(tool_name) is None
    assert str(tool) in caplog.text, caplog.text


def test_a_direct_command_whose_binary_became_a_link_to_one_is_the_answer(
    tmp_path, monkeypatch, tool_name, caplog
):
    """The control: a link to an executable file runs, so the command stands."""
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    tool = _executable(tmp_path / "a", tool_name)
    monkeypatch.setenv("PATH", str(tool.parent))
    assert get_uv_tool_command(tool_name) == [str(tool)]

    _no_longer_runs(tool, "a link to an executable", tmp_path)

    with caplog.at_level(logging.ERROR):
        assert get_uv_tool_command(tool_name) == [str(tool)]
    assert "no longer an executable file" not in caplog.text, caplog.text


def test_a_uv_command_whose_uv_is_gone_is_an_error_not_a_new_probe(
    tmp_path, monkeypatch, tool_name, caplog
):
    uv, calls = _fake_uv(tmp_path / "a")
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: str(uv))
    assert get_uv_tool_command(tool_name) == ["uv", "tool", "run", tool_name]
    assert len(_probes(calls)) == 1

    uv.unlink()
    # Another uv is found now, and it records every call: a new probe would reach it
    # and succeed, where one through the deleted uv would record nothing.
    other_uv, other_calls = _fake_uv(tmp_path / "b")
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: str(other_uv))

    with caplog.at_level(logging.ERROR):
        assert get_uv_tool_command(tool_name) is None
    assert str(uv) in caplog.text, caplog.text
    assert len(_probes(calls)) == 1
    assert _probes(other_calls) == []


def test_a_remembered_command_whose_file_is_still_there_is_the_answer(
    tmp_path, monkeypatch, tool_name, caplog
):
    """The control: the remembered command, and no new probe or lookup."""
    uv, calls = _fake_uv(tmp_path / "a")
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: str(uv))
    command = ["uv", "tool", "run", tool_name]
    assert get_uv_tool_command(tool_name) == command

    with caplog.at_level(logging.ERROR):
        assert get_uv_tool_command(tool_name) == command
        assert get_uv_tool_command(tool_name) == command
    assert len(_probes(calls)) == 1
    assert "no longer an executable file" not in caplog.text, caplog.text


@pytest.mark.parametrize("how", ["no execute bit", "a directory"])
def test_a_file_in_the_bin_directory_that_does_not_run_is_not_the_tool(
    tmp_path, monkeypatch, tool_name, caplog, how
):
    """ASH_BIN_PATH and /usr/local/bin count only an executable file, as PATH does:
    a file of the tool's name there that does not run is not answered, and so is not
    reported later as one that stopped running."""
    bin_dir = tmp_path / "bin"
    tool = _executable(bin_dir, tool_name)
    _no_longer_runs(tool, how, tmp_path)
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", lambda: [bin_dir])
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    assert subprocess_utils.find_executable(tool_name) is None
    with caplog.at_level(logging.ERROR):
        assert get_uv_tool_command(tool_name) is None
        assert get_uv_tool_command(tool_name) is None
    assert "no longer an executable file" not in caplog.text, caplog.text


def test_an_executable_file_in_the_bin_directory_is_the_tool(
    tmp_path, monkeypatch, tool_name
):
    """The control for the test above."""
    bin_dir = tmp_path / "bin"
    tool = _executable(bin_dir, tool_name)
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", lambda: [bin_dir])
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    assert subprocess_utils.find_executable(tool_name) == tool.as_posix()
    assert get_uv_tool_command(tool_name) == [tool.as_posix()]
