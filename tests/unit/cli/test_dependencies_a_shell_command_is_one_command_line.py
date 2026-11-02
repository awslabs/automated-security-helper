# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command declared with ``shell=True`` is one command line, run as written.

The installer joined the words of a shell command with spaces, and the shell then
read the joined line again. A plugin that declared
``["bash", "-c", "cd d && make"]`` ran ``bash -c cd d`` and then ``make`` in the
directory the installer started in, and a Windows path with a space in it lost the
quoting ``list2cmdline`` would have given it. A line for the shell is one string:
that string reaches the shell unchanged, and a command of several words under
``shell=True`` is refused, where it was joined without a word. No bundled plugin
declares ``shell=True``; a plugin from a configured module can.

The first test runs through the real runner, with nothing in its place.
"""

from __future__ import annotations

import subprocess

import pytest

from automated_security_helper.cli import dependencies
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


def test_a_one_string_shell_command_runs_as_written_through_the_real_runner(
    monkeypatch, capsys
):
    """The shell reads the whole line, `&&` included, and both halves run."""
    monkeypatch.setenv("COLUMNS", "300")

    code = dependencies.run_command(["echo first && echo second"], shell=True)

    printed = "".join(capsys.readouterr())
    assert code == 0, printed
    assert "first" in printed and "second" in printed, printed


@pytest.fixture
def seen_by_the_runner(monkeypatch):
    """The arguments the install's runner is called with; nothing is spawned."""
    seen: list = []

    def fake_run(args, **kwargs):
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", fake_run)
    monkeypatch.setattr(subprocess_utils, "run_succeeded", lambda result: True)
    return seen


def test_the_one_string_reaches_the_runner_unchanged(seen_by_the_runner):
    line = 'bash -c "cd d && make"'

    assert dependencies.run_command([line], shell=True) == 0

    [(args, kwargs)] = seen_by_the_runner
    assert args == line, args
    assert kwargs["shell"] is True


def test_a_shell_command_of_several_words_is_refused_not_joined(
    seen_by_the_runner, capsys, monkeypatch
):
    """Joined, `["bash", "-c", "cd d && make"]` was `bash -c cd d && make`: the
    shell ran `bash -c cd d`, then `make` where the installer started."""
    monkeypatch.setenv("COLUMNS", "300")

    code = dependencies.run_command(["bash", "-c", "cd d && make"], shell=True)

    printed = " ".join("".join(capsys.readouterr()).split())
    assert code == 1
    assert seen_by_the_runner == [], seen_by_the_runner
    assert "Not run" in printed and "3 separate words" in printed, printed
    assert "Declare the whole line as one string" in printed, printed


def test_a_shell_command_with_no_words_is_refused_not_run_as_an_empty_list(
    seen_by_the_runner, capsys, monkeypatch
):
    """`CustomCommand(args=[], shell=True)` is well formed to the list check and
    was covered by neither arm: the one-string hand-over needs one word and the
    refusal needed two, so `[]` reached the runner with shell=True."""
    monkeypatch.setenv("COLUMNS", "300")

    code = dependencies.run_command([], shell=True)

    printed = " ".join("".join(capsys.readouterr()).split())
    assert code == 1
    assert seen_by_the_runner == [], seen_by_the_runner
    assert "Not run" in printed and "has no words" in printed, printed
    assert "Declare the whole line as one string" in printed, printed


def test_a_command_without_the_shell_keeps_its_words(seen_by_the_runner):
    """The control: an argv list outside a shell is not one line, and several
    words are what it is made of."""
    assert dependencies.run_command(["echo", "a", "b"]) == 0

    [(args, kwargs)] = seen_by_the_runner
    assert args == ["echo", "a", "b"], args
    assert kwargs["shell"] is False
