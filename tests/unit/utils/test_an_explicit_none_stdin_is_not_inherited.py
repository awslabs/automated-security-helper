# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A child ASH starts never inherits ASH's own standard input by default.

Why this file exists
--------------------
Under ``ash mcp`` ASH's standard input is the MCP client's channel, and under the
CLI it is a terminal; neither belongs to a tool. The spawn runners give the child
``subprocess.DEVNULL`` when the caller says nothing about ``stdin``. A caller that
passes ``stdin=None`` explicitly said something, but ``Popen`` reads None as
"inherit", so filling only a missing key left that child on ASH's own input.

What it pins
------------
- no ``stdin`` and an explicit ``stdin=None`` both reach ``Popen`` as DEVNULL, in
  the helper every runner calls and in each runner;
- an explicit ``subprocess.PIPE``, a file object, descriptor ``0`` and DEVNULL
  reach ``Popen`` unchanged.

Nothing here starts a process: ``Popen`` is replaced by a recorder that raises.
"""

from __future__ import annotations

import subprocess
import threading
from typing import Any, Callable, Dict, List

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


class _Captured(Exception):
    """Raised by the recorder so no runner goes on to wait for a child."""


def _record_popen(monkeypatch) -> List[Dict[str, Any]]:
    seen: List[Dict[str, Any]] = []

    def recorder(*args: Any, **kwargs: Any):
        seen.append(dict(kwargs))
        raise _Captured

    monkeypatch.setattr(subprocess_utils.subprocess, "Popen", recorder)
    return seen


def _plain(**kwargs: Any) -> Any:
    return subprocess_utils._run_plain(["tool"], **kwargs)


def _stoppable(**kwargs: Any) -> Any:
    return subprocess_utils._run_stoppable(["tool"], **kwargs)


def _cancellable(**kwargs: Any) -> Any:
    return subprocess_utils._run_cancellable(
        ["tool"],
        cancel_event=threading.Event(),
        graceful_timeout=False,
        **kwargs,
    )


RUNNERS = [
    pytest.param(_plain, id="plain"),
    pytest.param(_stoppable, id="stoppable"),
    pytest.param(_cancellable, id="cancellable"),
]


def _stdin_popen_gets(runner: Callable[..., Any], monkeypatch, **kwargs: Any) -> Any:
    seen = _record_popen(monkeypatch)
    with pytest.raises(_Captured):
        runner(**kwargs)
    assert len(seen) == 1
    return seen[0]["stdin"]


def test_the_pipes_helper_turns_an_explicit_none_into_devnull():
    kwargs: Dict[str, Any] = {"stdin": None}
    subprocess_utils._pipes_for(kwargs, None, False)
    assert kwargs["stdin"] is subprocess.DEVNULL


def test_the_pipes_helper_defaults_a_missing_stdin_to_devnull():
    kwargs: Dict[str, Any] = {}
    subprocess_utils._pipes_for(kwargs, None, False)
    assert kwargs["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_given_stdin_none_starts_the_child_on_devnull(runner, monkeypatch):
    assert _stdin_popen_gets(runner, monkeypatch, stdin=None) is subprocess.DEVNULL


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_given_no_stdin_starts_the_child_on_devnull(runner, monkeypatch):
    assert _stdin_popen_gets(runner, monkeypatch) is subprocess.DEVNULL


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_passes_an_explicit_pipe_through(runner, monkeypatch):
    got = _stdin_popen_gets(runner, monkeypatch, stdin=subprocess.PIPE)
    assert got == subprocess.PIPE


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_passes_an_explicit_devnull_through(runner, monkeypatch):
    got = _stdin_popen_gets(runner, monkeypatch, stdin=subprocess.DEVNULL)
    assert got is subprocess.DEVNULL


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_passes_descriptor_zero_through(runner, monkeypatch):
    # stdin=0 is the deliberate way to hand the child ASH's own input; it is
    # falsy but is not None, so it must reach Popen as the integer 0.
    got = _stdin_popen_gets(runner, monkeypatch, stdin=0)
    assert got == 0
    assert got is not subprocess.DEVNULL


@pytest.mark.parametrize("runner", RUNNERS)
def test_a_runner_passes_a_file_object_through(runner, monkeypatch, tmp_path):
    path = tmp_path / "input.txt"
    path.write_text("data")
    with path.open("rb") as handle:
        got = _stdin_popen_gets(runner, monkeypatch, stdin=handle)
        assert got is handle
