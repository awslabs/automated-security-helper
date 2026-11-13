# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SIGTERM during the container run step stops the runtime through the cancel.

The console script points SIGTERM at the cancellation module's handler, which
sets the registered scope's event; ``run_cmd_direct``'s wait loop reads it,
stops the runtime, and raises ``ScanCancelled``, which unwinds through the
``finally`` that removes the container env file. The run step wraps
``_execute_container`` in ``_termination_raises``, and that wrapper must leave
the installed handler alone whenever the cooperative path can run: a swap
there makes the first SIGTERM exit at once, with no stop line and the runtime
left running. The swap stays for a scopeless run that wrote an env file,
where SIGTERM's disposition would otherwise end the process without the
``finally``; a run that wrote none keeps the installed handler, and a swapped
ordinary handler is still called before the exit unwinds.

Every signal these cells send goes to this process itself
(``signal.raise_signal``, ``os.kill(os.getpid())``), and the fake runtime
records this process's own pid, so a die-now kill, which these cells never
arm (one signal, a fresh latch, a registered scope), would end this test
loudly rather than reach any other process.
"""

from __future__ import annotations

import contextlib
import os
import signal

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    shutdown_cancels,
)
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="a signal raised at this process is POSIX"
    ),
]


@pytest.fixture
def default_sigint():
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    yield
    signal.signal(signal.SIGINT, previous)


@pytest.fixture
def real_sigterm(monkeypatch):
    """cancellation's own SIGTERM handler installed with fresh state; all put back."""
    for name, value in (
        ("_SIGTERM_SEEN", False),
        ("_SHUTDOWN_REQUESTED", False),
        ("_SHUTDOWN_SCOPES", ()),
        ("_PREVIOUS_SIGTERM", None),
        ("_TOOL_GROUPS", ()),
    ):
        monkeypatch.setattr(cancellation, name, value)
    previous = signal.signal(signal.SIGTERM, cancellation._handle_sigterm)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _sigterm_to_myself() -> None:
    """A SIGTERM to this process, never at its default disposition."""
    handler = signal.getsignal(signal.SIGTERM)
    assert callable(handler), handler
    if handler is cancellation._handle_sigterm:
        assert cancellation._SHUTDOWN_SCOPES, (
            "no registered scope: the die-now branch would run"
        )
        assert not cancellation._SIGTERM_SEEN, (
            "a second SIGTERM: the die-now branch would run"
        )
    signal.raise_signal(signal.SIGTERM)
    for _ in range(1000):
        pass


def _stop_recorder(monkeypatch):
    stops = []

    def _stop(process, **kwargs):
        stops.append(kwargs)
        process.returncode = -2

    monkeypatch.setattr(run_ash_container, "_stop_after_interrupt", _stop)
    return stops


@pytest.mark.parametrize(
    "run_step",
    [
        pytest.param(False, id="plain-run_cmd_direct"),
        pytest.param(True, id="under-the-run-step-wrapper"),
    ],
)
def test_a_sigterm_while_the_runtime_runs_stops_it_through_the_cancel(
    monkeypatch, default_sigint, real_sigterm, run_step, tmp_path, runtime_stand_in
):
    runtime = runtime_stand_in(on_poll=_sigterm_to_myself)
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )
    stops = _stop_recorder(monkeypatch)
    event = CancelEvent()
    with shutdown_cancels(event), cancel_scope(event):
        with pytest.raises(BaseException) as raised:
            if run_step:
                with run_ash_container._termination_raises(tmp_path):
                    run_ash_container.run_cmd_direct(["runtime", "run", "scan"])
            else:
                run_ash_container.run_cmd_direct(["runtime", "run", "scan"])
    assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm
    assert isinstance(raised.value, ScanCancelled), raised.value
    assert stops == [{"child_got_the_interrupt": False}]


def test_an_ordinary_handler_is_chained_then_the_exit_unwinds(real_sigterm, tmp_path):
    """A callable handler someone installed is still told, not discarded: the
    wrapper calls it, and when it returns, the exit that guarantees the
    env-file ``finally`` unwinds as before."""
    seen = []

    def operators_handler(signum, frame):
        seen.append(signum)

    signal.signal(signal.SIGTERM, operators_handler)
    with pytest.raises(SystemExit) as raised:
        with run_ash_container._termination_raises(tmp_path):
            assert signal.getsignal(signal.SIGTERM) is not operators_handler
            signal.raise_signal(signal.SIGTERM)
            for _ in range(1000):
                pass
    assert raised.value.code == 143
    assert seen == [signal.SIGTERM], "the installed handler was discarded"
    assert signal.getsignal(signal.SIGTERM) is operators_handler


def test_the_cooperative_handler_without_a_scope_is_swapped_not_chained(
    real_sigterm, tmp_path
):
    """Scopeless, the cooperative handler's no-scan branch re-raises the signal
    at the default disposition, which would end the process without the
    env-file ``finally``: the wrapper exits on its own instead of calling it."""
    with pytest.raises(SystemExit) as raised:
        with run_ash_container._termination_raises(tmp_path):
            assert signal.getsignal(signal.SIGTERM) is not cancellation._handle_sigterm
            signal.raise_signal(signal.SIGTERM)
            for _ in range(1000):
                pass
    assert raised.value.code == 143
    assert cancellation._SIGTERM_SEEN is False, "the cooperative handler ran"
    assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm


def test_the_cooperative_handler_with_a_scope_is_left_alone(real_sigterm, tmp_path):
    event = CancelEvent()
    with contextlib.ExitStack() as scope:
        scope.enter_context(cancel_scope(event))
        scope.enter_context(shutdown_cancels(event))
        with run_ash_container._termination_raises(tmp_path):
            assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm
    assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm


def test_a_scope_with_no_registration_gets_the_relay(real_sigterm, tmp_path):
    """A cancel scope can be active with nothing registered for the shutdown
    handlers to stop: the scope has a different owner, so the ambient event is
    a stand-in, not the registration. The cooperative handler's no-scan branch
    re-raises at the default disposition, which would end the process without
    the env-file ``finally``, so with a scope and no registration the wrapper
    installs the relay instead of leaving that handler in charge."""
    event = CancelEvent()
    with contextlib.ExitStack() as scope:
        scope.enter_context(cancel_scope(event))
        with run_ash_container._termination_raises(tmp_path):
            installed = signal.getsignal(signal.SIGTERM)
            assert installed is not cancellation._handle_sigterm, installed
    assert signal.getsignal(signal.SIGTERM) is cancellation._handle_sigterm


def test_an_ignored_sigterm_stays_ignored(tmp_path):
    """An ignored SIGTERM cannot end the process, so the ``finally`` the
    wrapper guards is not at risk, and installing the relay would turn the
    operator's ignore into an exit. The disposition is left in place and the
    signal stays ignored under the wrapper."""
    previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        with run_ash_container._termination_raises(tmp_path):
            assert signal.getsignal(signal.SIGTERM) is signal.SIG_IGN
            signal.raise_signal(signal.SIGTERM)  # ignored: nothing is raised
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGTERM, previous)


def test_a_run_with_no_env_file_keeps_the_installed_handler(real_sigterm):
    """No env file means nothing for the ``finally`` to clean, so the wrapper
    installs nothing and SIGTERM keeps the semantics the caller gave it."""

    def operators_handler(signum, frame):
        raise AssertionError("no signal is raised in this cell")

    signal.signal(signal.SIGTERM, operators_handler)
    with run_ash_container._termination_raises(None):
        assert signal.getsignal(signal.SIGTERM) is operators_handler
    assert signal.getsignal(signal.SIGTERM) is operators_handler
