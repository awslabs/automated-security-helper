# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the console-script entry point prints when ASH fails before it can explain.

``cli/entrypoint.py`` exists so that a failure is never silent. These snapshots pin
each channel it degrades through: ASH's shown traceback, the banner for a process
that started without a usable stderr, the plain traceback when ASH's traceback
itself fails, and the raw descriptor write when there is no stream object at all.

The exceptions are constructed rather than raised wherever the frames are not the
point, so the report contains only what the entry point adds. The one end-to-end
case raises for real; its frames are masked by the shared normalizer.
"""

from __future__ import annotations

import signal
import sys
from contextlib import contextmanager

import pytest

from automated_security_helper.cli import entrypoint
from automated_security_helper.cli import main as cli_main

pytestmark = pytest.mark.unit


def _fd_output(capfd) -> dict[str, str]:
    captured = capfd.readouterr()
    return {"stdout": captured.out, "stderr": captured.err}


def _hook_that_fails(*_args):
    raise RuntimeError("the excepthook itself failed")


@pytest.fixture
def plain_excepthook(monkeypatch):
    # The interpreter's own hook, whatever a library installed over it.
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)


@contextmanager
def _process_signals_restored():
    """Put the process's SIGINT and SIGTERM handlers back afterwards.

    ``main()`` installs ASH's shutdown handlers as a documented side effect
    (its docstring calls it the one place that installs them). The snapshot
    here is about the report, not the shutdown contract, so the handlers the
    process had before go back once the body is done; otherwise every test
    that runs after this file inherits ASH's handlers.
    """
    previous = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@pytest.fixture
def restored_signal_handlers():
    with _process_signals_restored():
        yield


def test_reported_through_excepthook(snapshot, capfd, plain_excepthook):
    entrypoint._report_failure(ImportError("cannot import name 'Model' from 'x'"))
    assert _fd_output(capfd) == snapshot


def test_started_without_stderr(snapshot, capfd, plain_excepthook):
    entrypoint._report_failure(
        ImportError("cannot import name 'Model' from 'x'"), repaired=("stderr",)
    )
    assert _fd_output(capfd) == snapshot


def test_started_without_either_stream(snapshot, capfd, plain_excepthook):
    entrypoint._report_failure(
        ImportError("cannot import name 'Model' from 'x'"),
        repaired=("stdout", "stderr"),
    )
    assert _fd_output(capfd) == snapshot


def test_excepthook_fails(snapshot, capfd, monkeypatch, plain_excepthook):
    # The interpreter's hook is reported by ASH's traceback, and an installed
    # hook that fails is too, so the reporter that fails here is ASH's own.
    monkeypatch.setattr(entrypoint, "_ash_traceback", _hook_that_fails)
    entrypoint._report_failure(ImportError("cannot import name 'Model' from 'x'"))
    assert _fd_output(capfd) == snapshot


def test_no_stream_object_left(snapshot, capfd, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)
    entrypoint._report_failure(ImportError("cannot import name 'Model' from 'x'"))
    assert _fd_output(capfd) == snapshot


def test_main_exits_1_with_the_report(
    snapshot, capfd, monkeypatch, plain_excepthook, restored_signal_handlers
):
    def _broken_cli():
        raise ImportError("cannot import name 'Model' from 'x'")

    monkeypatch.setattr(cli_main, "run_app", _broken_cli)
    with pytest.raises(SystemExit) as exited:
        entrypoint.main()
    assert {"exit_code": exited.value.code, **_fd_output(capfd)} == snapshot


def test_main_puts_the_signal_handlers_back(
    capfd, monkeypatch, plain_excepthook, restored_signal_handlers
):
    """The end-to-end body, run under the restorer, leaves the handlers alone.

    Deterministic restatement of the leak: start from the interpreter's own
    handlers, run exactly what ``test_main_exits_1_with_the_report`` runs, and
    the process ends up with the handlers it started with. The outer fixture
    puts the worker's incoming handlers back, so the pin below never leaks
    either.
    """

    def _broken_cli():
        raise ImportError("cannot import name 'Model' from 'x'")

    monkeypatch.setattr(cli_main, "run_app", _broken_cli)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    with _process_signals_restored():
        with pytest.raises(SystemExit):
            entrypoint.main()
        # Inside the body ASH's handlers are in place, so the restore below
        # is doing real work rather than confirming a no-op.
        assert signal.getsignal(signal.SIGINT) is not signal.default_int_handler
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    capfd.readouterr()  # drop the report the body printed
