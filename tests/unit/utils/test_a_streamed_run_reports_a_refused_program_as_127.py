# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A streamed run of a program ASH will not start returns 127, as every runner does.

Why this file exists
--------------------
``run_command_stream_output`` documents 127 for a command that could not be started,
and ``run_command_with_output_handling`` answers it for a program ASH refuses (an
in-tree copy, a path relative to the working directory, a name found only through the
working directory): the refusal is raised inside the try that reports a spawn failure.
In ``run_command_stream_output`` the same refusal was raised outside that try, so it
escaped to the caller as a ``FileNotFoundError`` and no exit code was returned.

The refusal is now raised inside the spawn's own try there too. Nothing is started.
A program that can be started keeps its own code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    SPAWN_FAILURE_RETURNCODE,
    run_command_stream_output,
    run_command_with_output_handling,
    scanning_tree,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the planted tools are POSIX shell scripts"
)


def _plant(directory: Path, name: str, ran: Path) -> Path:
    """An executable ``name`` in ``directory``; when run, it creates ``ran``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\n: > '{ran}'\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture(autouse=True)
def hermetic(monkeypatch, tmp_path):
    """Lookups see the PATH a test sets, and the cache does not carry answers over."""
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)
    subprocess_utils.clear_find_executable_cache()
    yield
    subprocess_utils.clear_find_executable_cache()


@pytest.fixture
def started(monkeypatch) -> list:
    """Every ``Popen`` the test makes. A refused program makes none."""
    calls: list = []

    def popen(*args, **kwargs):
        calls.append(args)
        raise AssertionError("a refused program was started")

    monkeypatch.setattr(subprocess_utils.subprocess, "Popen", popen)
    return calls


@pytest.mark.unit
def test_a_program_path_relative_to_the_working_directory_returns_127(
    tmp_path, monkeypatch, started
):
    monkeypatch.chdir(tmp_path)

    code = run_command_stream_output(["./tool", "--version"])

    assert code == SPAWN_FAILURE_RETURNCODE == 127
    assert started == []


@pytest.mark.unit
@posix_only
def test_an_in_tree_copy_of_a_program_returns_127_and_does_not_run(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    ran = tmp_path / "ran"
    in_tree = _plant(repo / ".venv" / "bin", "tool", ran)
    monkeypatch.setenv("PATH", str(in_tree.parent))

    with scanning_tree(repo):
        code = run_command_stream_output(["tool"], cwd=repo)

    assert code == SPAWN_FAILURE_RETURNCODE
    assert not ran.exists()


@pytest.mark.unit
@posix_only
def test_a_program_found_only_through_a_relative_path_entry_returns_127(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    ran = tmp_path / "ran"
    _plant(repo / "bin", "tool", ran)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", "bin")

    code = run_command_stream_output(["tool"], cwd=repo)

    assert code == SPAWN_FAILURE_RETURNCODE
    assert not ran.exists()


@pytest.mark.unit
def test_the_response_runner_gives_the_same_answer_for_the_same_program(
    tmp_path, monkeypatch
):
    """The contract the streamed runner is held to."""
    monkeypatch.chdir(tmp_path)

    response = run_command_with_output_handling(["./tool", "--version"])

    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
    assert response["spawn_failed"] is True


@pytest.mark.integration
@pytest.mark.parametrize("exit_code", [0, 3])
def test_control_a_program_that_can_be_started_keeps_its_own_code(exit_code):
    command = [sys.executable, "-c", f"import sys; sys.exit({exit_code})"]

    assert run_command_stream_output(command) == exit_code


@pytest.mark.unit
def test_control_the_recorder_sees_a_start(started):
    """A program that is not refused does reach ``Popen``, so ``started == []``
    above is the refusal and not a recorder that sees nothing."""
    code = run_command_stream_output([sys.executable, "-c", "pass"])

    assert started, "Popen was never reached"
    assert code == SPAWN_FAILURE_RETURNCODE
