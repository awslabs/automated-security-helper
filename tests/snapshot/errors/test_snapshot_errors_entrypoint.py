# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the console-script entry point prints when ASH fails before it can explain.

``cli/entrypoint.py`` exists so that a failure is never silent. These snapshots pin
each channel it degrades through: the interpreter's excepthook, the banner for a
process that started without a usable stderr, the plain traceback when the hook
itself fails, and the raw descriptor write when there is no stream object at all.

The exceptions are constructed rather than raised wherever the frames are not the
point, so the report contains only what the entry point adds. The one end-to-end
case raises for real; its frames are masked by the shared normalizer.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.cli import entrypoint
from automated_security_helper.cli import main as cli_main


def _fd_output(capfd) -> dict[str, str]:
    captured = capfd.readouterr()
    return {"stdout": captured.out, "stderr": captured.err}


def _hook_that_fails(*_args):
    raise RuntimeError("the excepthook itself failed")


@pytest.fixture
def plain_excepthook(monkeypatch):
    # The interpreter's own hook, whatever a library installed over it.
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)


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


def test_excepthook_fails(snapshot, capfd, monkeypatch):
    monkeypatch.setattr(sys, "excepthook", _hook_that_fails)
    entrypoint._report_failure(ImportError("cannot import name 'Model' from 'x'"))
    assert _fd_output(capfd) == snapshot


def test_no_stream_object_left(snapshot, capfd, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)
    entrypoint._report_failure(ImportError("cannot import name 'Model' from 'x'"))
    assert _fd_output(capfd) == snapshot


def test_main_exits_1_with_the_report(snapshot, capfd, monkeypatch, plain_excepthook):
    def _broken_cli():
        raise ImportError("cannot import name 'Model' from 'x'")

    monkeypatch.setattr(cli_main, "run_app", _broken_cli)
    with pytest.raises(SystemExit) as exited:
        entrypoint.main()
    assert {"exit_code": exited.value.code, **_fd_output(capfd)} == snapshot
