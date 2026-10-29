# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandboxed and cancellable runners take the arguments subprocess.run takes.

Why this file exists
--------------------
``_run_stoppable`` (a sandboxed spawn) and ``_run_cancellable`` (every spawn in a
scan's cancel scope) stand in for subprocess.run, and are documented as taking
its arguments. Three of them differed:

- ``input=`` was popped and handed to communicate(), but stdin was never set to
  PIPE, so the child never received it: it read whatever stdin it inherited;
- ``input=`` with ``stdin=`` given was accepted, where subprocess.run raises
  ValueError;
- ``capture_output=True`` with ``stdout=None`` (or ``stderr=None``) raised
  ValueError, where subprocess.run checks ``is not None`` and accepts it.

And the sandboxed runner raised a TimeoutExpired of its own after the stop, where
subprocess.run raises the one communicate() raised. The cancellable runner waits
in slices, so the TimeoutExpired it raises is its own by design; for it the cell
holds the command and the timeout asked for, as subprocess.run reports them.

No ASH caller passes ``input=`` to these runners today, so the first two were
latent.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any, Iterator
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils

PY = sys.executable

WRITES_AND_EXITS_3 = [
    PY,
    "-c",
    "import sys; sys.stdout.write('out\\n'); sys.stderr.write('err\\n'); sys.exit(3)",
]
ECHOES_STDIN = [PY, "-c", "import sys; sys.stdout.write(sys.stdin.read())"]
_PARTIAL_PROGRAM = (
    "import sys, time; sys.stdout.write('partial\\n'); sys.stdout.flush(); "
    "time.sleep(60)"
)
PARTIAL_THEN_SLEEPS = [PY, "-c", _PARTIAL_PROGRAM]

#: Bounds a child that, on a runner that drops input=, reads an inherited stdin.
_BOUND = 15.0


def _stoppable(args, **kwargs):
    return subprocess_utils._run_stoppable(args, **kwargs)


def _cancellable(args, **kwargs):
    return subprocess_utils._run_cancellable(
        args, cancel_event=threading.Event(), graceful_timeout=False, **kwargs
    )


RUNNERS = [
    pytest.param(_stoppable, id="sandboxed-runner"),
    pytest.param(_cancellable, id="cancellable-runner"),
]


def _text(captured: Any) -> str:
    if isinstance(captured, bytes):
        return captured.decode("utf-8", errors="replace")
    return captured or ""


@pytest.mark.integration
@pytest.mark.parametrize("runner", RUNNERS)
def test_input_is_written_to_the_childs_stdin(runner):
    result = runner(
        ECHOES_STDIN, input="hello\n", capture_output=True, text=True, timeout=_BOUND
    )

    assert result.stdout == "hello\n", result


@pytest.mark.unit
@pytest.mark.parametrize("runner", RUNNERS)
def test_input_with_stdin_given_is_a_value_error(runner):
    with pytest.raises(ValueError, match="stdin and input arguments may not both"):
        runner(ECHOES_STDIN, input="x", stdin=subprocess.DEVNULL, timeout=_BOUND)


@pytest.mark.integration
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("runner", RUNNERS)
def test_capture_output_with_a_stream_given_as_none_is_allowed(runner, stream):
    result = runner(
        WRITES_AND_EXITS_3, capture_output=True, text=True, **{stream: None}
    )

    assert result.returncode == 3, result
    assert result.stdout == "out\n", result
    assert result.stderr == "err\n", result


@pytest.mark.unit
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("runner", RUNNERS)
def test_control_capture_output_with_a_stream_given_is_a_value_error(runner, stream):
    with pytest.raises(ValueError, match="may not be used with capture_output"):
        runner(WRITES_AND_EXITS_3, capture_output=True, **{stream: subprocess.PIPE})


@contextlib.contextmanager
def _watched_communicate() -> Iterator[Any]:
    real = subprocess.Popen.communicate
    seen = SimpleNamespace(raised=[])

    def communicate(self, *args, **kwargs):
        try:
            return real(self, *args, **kwargs)
        except BaseException as error:
            seen.raised.append(error)
            raise

    with patch.object(subprocess.Popen, "communicate", communicate):
        yield seen


@pytest.mark.integration
def test_the_sandboxed_runner_raises_the_timeout_expired_communicate_raised():
    """As subprocess.run does, with the output read before and after the stop."""
    with (
        _watched_communicate() as seen,
        pytest.raises(subprocess.TimeoutExpired) as info,
    ):
        _stoppable(PARTIAL_THEN_SLEEPS, capture_output=True, text=True, timeout=2.0)

    assert seen.raised, "communicate() never raised, so the cell shows nothing"
    assert info.value is seen.raised[0], (info.value, seen.raised)
    assert "partial" in _text(info.value.output), info.value.output


@pytest.mark.integration
@pytest.mark.parametrize("runner", RUNNERS)
def test_control_a_timeout_names_the_command_and_the_timeout_asked_for(runner):
    with pytest.raises(subprocess.TimeoutExpired) as info:
        runner(PARTIAL_THEN_SLEEPS, capture_output=True, text=True, timeout=2.0)

    assert info.value.cmd == PARTIAL_THEN_SLEEPS
    assert info.value.timeout == 2.0
    assert "partial" in _text(info.value.output), info.value.output
