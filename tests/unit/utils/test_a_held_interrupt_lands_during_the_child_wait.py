# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A Ctrl-C can land while a scan child runs, not only when the child is done.

On Windows, ``Popen.communicate`` joins its reader threads and waits on the
process handle, and neither wait lets Python's SIGINT handler run. A Ctrl-C, the
first or the second, then pended until the child exited on its own, which for a
child that ignores the interrupt was its own deadline. The two runners wait for
the child through ``_communicate_sliced``, which asks ``communicate`` for at most
``INTERRUPT_WAIT_SLICE_SECONDS`` at a time, so the retry between two slices is
where a pending KeyboardInterrupt lands.

Real Windows does not run here. The slice bound and the retry rules are pinned
with a stand-in process, the output and timeout contract with real children, and
the two call sites by reading their source.
"""

from __future__ import annotations

import inspect
import os
import re
import subprocess  # nosec B404 - spawns the running interpreter, fixed argv
import sys
from typing import Any, List, Optional

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    INTERRUPT_WAIT_SLICE_SECONDS,
    _communicate_sliced,
)

pytestmark = pytest.mark.unit


class _SlowProcess:
    """A process whose communicate() times out ``misses`` times, then answers."""

    args = ["stand-in"]

    def __init__(self, misses: int, interrupt_on: Optional[int] = None) -> None:
        self.misses = misses
        self.interrupt_on = interrupt_on
        self.calls: List[Any] = []

    def communicate(self, input_data: Any = None, timeout: Optional[float] = None):
        self.calls.append((input_data, timeout))
        if self.interrupt_on == len(self.calls):
            raise KeyboardInterrupt
        if len(self.calls) <= self.misses:
            raise subprocess.TimeoutExpired(self.args, timeout)
        return b"out", b"err"


def test_every_pass_waits_at_most_one_slice_and_the_input_goes_once() -> None:
    process = _SlowProcess(misses=3)

    result = _communicate_sliced(process, b"input", None)  # type: ignore[arg-type]

    assert result == (b"out", b"err")
    assert [call[0] for call in process.calls] == [b"input", None, None, None]
    assert all(call[1] == INTERRUPT_WAIT_SLICE_SECONDS for call in process.calls)


def test_an_interrupt_between_slices_ends_the_wait_at_once() -> None:
    process = _SlowProcess(misses=100, interrupt_on=3)

    with pytest.raises(KeyboardInterrupt):
        _communicate_sliced(process, None, 3600)  # type: ignore[arg-type]

    assert len(process.calls) == 3


def test_the_last_timeout_carries_the_callers_timeout() -> None:
    process = _SlowProcess(misses=10**6)

    with pytest.raises(subprocess.TimeoutExpired) as raised:
        _communicate_sliced(process, None, 0.3)  # type: ignore[arg-type]

    assert raised.value.timeout == 0.3
    assert all(call[1] <= INTERRUPT_WAIT_SLICE_SECONDS for call in process.calls)


_PRINTS = "import sys; print('out'); sys.stderr.write('err')"
_PARTIAL_THEN_SLEEPS = (
    "import sys, time; sys.stdout.write('partial'); sys.stdout.flush(); time.sleep(60)"
)
_ECHOES_AFTER_A_PAUSE = (
    "import sys, time; data = sys.stdin.read(); time.sleep(0.8); sys.stdout.write(data)"
)


def _child(code: str) -> "subprocess.Popen[bytes]":
    return subprocess.Popen(  # nosec B603 - fixed argv
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_the_output_is_what_one_long_communicate_returns() -> None:
    sliced = _child(_PRINTS)
    plain = _child(_PRINTS)

    assert _communicate_sliced(sliced, None, None) == plain.communicate()


def test_input_given_once_survives_more_than_one_slice() -> None:
    child = _child(_ECHOES_AFTER_A_PAUSE)

    stdout, _ = _communicate_sliced(child, b"hello", 30)

    assert stdout == b"hello"


def test_a_timeout_keeps_the_output_read_so_far() -> None:
    child = _child(_PARTIAL_THEN_SLEEPS)
    try:
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            _communicate_sliced(child, None, 1.0)
        assert raised.value.timeout == 1.0
        if os.name != "nt":
            # Windows reads in threads that deliver at EOF; there the output is
            # collected after the stop, as the runners do.
            assert raised.value.output == b"partial"
    finally:
        child.kill()
    stdout, _ = child.communicate(timeout=30)
    assert stdout == b"partial"


@pytest.mark.parametrize("runner", ["_run_plain", "_run_stoppable"])
def test_both_runners_wait_through_the_sliced_helper(runner: str) -> None:
    source = inspect.getsource(getattr(subprocess_utils, runner))

    assert "_communicate_sliced(process, input_data, timeout)" in source
    assert not re.search(r"process\.communicate\(\s*input_data\s*,\s*timeout", source)


def test_the_helper_slices_by_the_interrupt_wait_slice() -> None:
    source = inspect.getsource(_communicate_sliced)

    assert "INTERRUPT_WAIT_SLICE_SECONDS" in source
