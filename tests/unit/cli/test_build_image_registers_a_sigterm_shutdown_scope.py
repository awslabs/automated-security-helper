# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash build-image`` runs its container scan inside a SIGTERM shutdown scope.

The entry point's SIGTERM handler cooperates only while a scan is registered
with it (``core/cancellation.shutdown_cancels``); with none registered it keeps
SIGTERM's kill semantics and the process dies at once. ``ash scan --mode
container`` registers its scope and gets the cooperative stop (the OCI runner
stopped through the launcher's interrupt path, one exit line, exit
ASH_EXIT_TERMINATED). ``ash build-image`` starts the same container scan and
registered nothing, so a SIGTERM to it took the die-now kill.

The stand-in scan looks at the registration from inside the command, as the
scan command's own test does; no signal is delivered to the test runner.
"""

from __future__ import annotations

import sys

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    current_cancel_event,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_INTERRUPTED,
    ASH_EXIT_TERMINATED,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="the SIGTERM handler is a no-op on Windows, so no scope cooperates there",
    ),
]


def _build_image_app() -> typer.Typer:
    from automated_security_helper.cli.image import build_ash_image_cli_command

    app = typer.Typer()
    app.command(name="build-image")(build_ash_image_cli_command)
    return app


@pytest.fixture
def shutdown_state(monkeypatch):
    """The handler's registration state fresh, so each test reads only its own."""
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    return cancellation


@pytest.mark.parametrize(
    "args",
    [[], ["--no-build"], ["--no-run"]],
    ids=["build-and-run", "no-build", "no-run"],
)
def test_the_container_scan_runs_inside_a_registered_shutdown_scope(
    shutdown_state, monkeypatch, args
):
    """Every path through the command (the image build is the long phase where
    a SIGTERM is most likely) runs the scan inside the registered scope, and the
    registration is gone once the command has returned."""
    seen: dict = {}

    def stand_in_scan(**kwargs):
        seen["event"] = current_cancel_event()
        seen["registered"] = tuple(cancellation._SHUTDOWN_SCOPES)
        raise AssertionError("the stand-in stops the command here")

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), args)

    assert "event" in seen, result.output
    assert isinstance(seen["event"], CancelEvent), (
        "the command must run the scan inside a cancel scope of its own"
    )
    assert seen["registered"] == (seen["event"],), (
        "the scan's scope is not registered with the shutdown handler, so a "
        "SIGTERM takes the default-kill branch"
    )
    assert cancellation._SHUTDOWN_SCOPES == (), (
        "the scope is still registered after the command ended, so a later "
        "SIGTERM would cancel a scan that is over"
    )


def test_a_stopped_scan_exits_terminated_with_one_line(shutdown_state, monkeypatch):
    def stand_in_scan(**kwargs):
        # What the handler leaves behind when it cancels the registered scope,
        # and what the phases then raise through raise_if_cancelled.
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", True)
        raise ScanCancelled("stopped")

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), [])

    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert result.output.count("stopped by SIGTERM") == 1, result.output
    assert "ASH build-image stopped by SIGTERM" in result.output
    assert "did not complete" in result.output
    assert cancellation._SHUTDOWN_SCOPES == (), "the scope leaked its registration"


def test_an_interrupted_run_cancels_its_event_before_exiting(
    shutdown_state, monkeypatch
):
    """As ``ash scan`` does: a cancellable spawn running in another thread polls
    the event, and would keep going on a run the operator interrupted."""
    seen: dict = {}

    def stand_in_scan(**kwargs):
        seen["event"] = current_cancel_event()
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), [])

    assert result.exit_code == ASH_EXIT_INTERRUPTED, result.output
    assert "ASH build-image interrupted" in result.output
    assert "event" in seen, result.output
    assert seen["event"].is_set()
    assert seen["event"].stop_promptly is True


def test_a_stopped_build_only_run_owes_no_verdict(shutdown_state, monkeypatch):
    def stand_in_scan(**kwargs):
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", True)
        raise ScanCancelled("stopped")

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), ["--no-run"])

    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert "ASH build-image stopped by SIGTERM" in result.output
    assert "did not complete" not in result.output
    assert cancellation._SHUTDOWN_SCOPES == (), "the scope leaked its registration"


def test_a_sigterm_nothing_polled_still_ends_the_command_terminated(
    shutdown_state, monkeypatch
):
    """The handler sets the event and the phases raise on their next poll. A
    SIGTERM that lands where nothing polls (between the build and the run, or
    after a --no-run build) let the scan return as if nothing happened, and the
    command exited 0 after a termination."""

    def stand_in_scan(**kwargs):
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", True)
        return None

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), ["--no-run"])

    assert result.exit_code == ASH_EXIT_TERMINATED, result.output
    assert "ASH build-image stopped by SIGTERM" in result.output
    assert cancellation._SHUTDOWN_SCOPES == (), "the scope leaked its registration"


def test_an_interrupt_cancels_the_scope_before_the_exit(shutdown_state, monkeypatch):
    """Ctrl-C lands in one frame; a spawn still running on another thread polls
    the scope's event, so the command cancels it before exiting, as ash scan
    does. Exiting with the event clear left that thread running a scan the
    operator stopped."""
    seen: dict = {}

    def stand_in_scan(**kwargs):
        seen["event"] = current_cancel_event()
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan", stand_in_scan
    )
    result = CliRunner().invoke(_build_image_app(), [])

    assert result.exit_code == ASH_EXIT_INTERRUPTED, result.output
    assert "ASH build-image interrupted" in result.output
    event = seen["event"]
    assert event.is_set(), "the scope's event is left clear after the interrupt"
    assert event.stop_promptly is True
    assert cancellation._SHUTDOWN_SCOPES == (), "the scope leaked its registration"
