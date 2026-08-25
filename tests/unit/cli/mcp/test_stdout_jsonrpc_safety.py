# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash mcp` must never write to stdout.

Why this file exists
--------------------
On the stdio transport, stdout *is* the JSON-RPC channel. Anything else written
there lands mid-stream and the client fails to parse it -- the reported symptom
was `Expecting value`, because a human-readable line arrived where a JSON frame
was expected.

The command used `from rich import print`, which writes to stdout. The startup
message was already gated behind `if not quiet`, and `quiet` defaults to True,
so the default invocation was safe. That is not enough:

* `validate_command_options` rejects `--quiet` combined with `--verbose` or
  `--debug`, so anyone debugging a stdio MCP server has to pass `--no-quiet`,
  which is exactly when the stream gets corrupted.
* The dependency-missing and validation-error paths printed unconditionally,
  with no `quiet` gate at all.

So the destination is the bug, not the gate. These tests assert on stdout being
empty rather than on the gate being present, so a future message added without
a `quiet` check cannot reintroduce the failure.

Why these particular paths
--------------------------
Each case below exits before a server is started, so none of them need a
transport, a socket, or a running event loop. The invalid-transport path is
useful twice over: with `--no-quiet` it emits the startup message at one line
and then fails validation a few lines later, which covers the banner without
blocking on a server.
"""

import os
from unittest.mock import patch

import pytest
import typer

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.utils.log import get_logger


class TestTheLoggerHonoursTheStderrSwitch:
    """The logger is the larger stdout source, and it only attaches during a scan."""

    def test_records_go_to_stderr_when_the_switch_is_set(self, capsys):
        original = os.environ.get("ASH_LOG_TO_STDERR")
        os.environ["ASH_LOG_TO_STDERR"] = "1"
        try:
            # A fresh name each time: loggers are cached, so reusing one would
            # reuse the handler built under the previous setting.
            get_logger(name="ash-stderr-probe", show_progress=False).info("MARKER")
        finally:
            if original is None:
                os.environ.pop("ASH_LOG_TO_STDERR", None)
            else:
                os.environ["ASH_LOG_TO_STDERR"] = original

        captured = capsys.readouterr()
        assert "MARKER" not in captured.out, (
            "A log record reached stdout with ASH_LOG_TO_STDERR set, so it would "
            "corrupt the JSON-RPC stream."
        )
        assert "MARKER" in captured.err

    def test_the_cli_default_is_unchanged(self, capsys):
        """Guard against over-correcting.

        CLI users' logs belong on stdout where they have always been; only the MCP
        path opts in. Moving everyone to stderr would be a silent behaviour change
        for every non-MCP consumer.
        """
        original = os.environ.get("ASH_LOG_TO_STDERR")
        os.environ.pop("ASH_LOG_TO_STDERR", None)
        try:
            get_logger(name="ash-stdout-probe", show_progress=False).info("MARKER")
        finally:
            if original is not None:
                os.environ["ASH_LOG_TO_STDERR"] = original

        captured = capsys.readouterr()
        assert "MARKER" in captured.out


class _Ctx:
    """Minimal stand-in for typer.Context.

    mcp_command only reads ``resilient_parsing`` before the code under test.
    """

    resilient_parsing = False


def _run(deps_available=True, **kwargs):
    """Call the command directly and return the typer.Exit it raises.

    Every parameter of mcp_command has a concrete default, so a direct call is
    equivalent to a CLI invocation for these paths and avoids CliRunner's own
    stream handling.

    validate_mcp_dependencies is always patched rather than left to the
    environment. Without that, a runner whose `mcp` package does not import
    exits at the dependency gate and never reaches the path under test, so the
    assertions would pass or fail based on what happens to be installed.
    """
    with patch(
        "automated_security_helper.cli.mcp.validate_mcp_dependencies",
        return_value=deps_available,
    ):
        with pytest.raises(typer.Exit) as excinfo:
            mcp_command(ctx=_Ctx(), **kwargs)
    return excinfo.value


class TestNothingIsWrittenToStdout:
    def test_invalid_transport_error_avoids_stdout(self, capsys):
        exc = _run(transport="not-a-transport")

        captured = capsys.readouterr()
        assert exc.exit_code == 3
        assert captured.out == ""
        assert "not-a-transport" in captured.err

    def test_startup_message_avoids_stdout_when_not_quiet(self, capsys):
        """The regression case from the issue.

        --no-quiet is the only way to combine MCP with --verbose/--debug, so
        this is the path a user debugging a stdio server actually takes.
        """
        exc = _run(quiet=False, transport="not-a-transport")

        captured = capsys.readouterr()
        assert exc.exit_code == 3
        assert captured.out == ""
        # Both the startup message and the error land on stderr.
        assert "Starting MCP server" in captured.err
        assert "not-a-transport" in captured.err

    def test_conflicting_quiet_and_verbose_error_avoids_stdout(self, capsys):
        exc = _run(quiet=True, verbose=True)

        captured = capsys.readouterr()
        assert exc.exit_code == 3
        assert captured.out == ""
        assert "quiet" in captured.err.lower()

    def test_the_command_redirects_the_logger_away_from_stdout(self, capsys):
        """The banner was never the biggest source of stdout writes.

        The MCP server runs scans *in-process*: mcp_tools hands run_ash_scan to
        loop.run_in_executor, a thread in this same process. That scan calls
        get_logger, which attaches a RichHandler to the shared "ash" logger. Before
        this, that handler's Console was bound to stdout, so from the moment a scan
        started every record from the scan phase, suppression matching and the
        reporters went into the JSON-RPC stream.

        Gating the command's own prints on --quiet could never have covered that,
        because the handler does not exist until a scan begins. Asserted on the
        command rather than on the logger so the wiring cannot be dropped.
        """
        original = os.environ.get("ASH_LOG_TO_STDERR")
        try:
            os.environ.pop("ASH_LOG_TO_STDERR", None)
            _run(transport="not-a-transport")

            assert os.environ.get("ASH_LOG_TO_STDERR", "").upper() in (
                "YES",
                "1",
                "TRUE",
            ), (
                "The mcp command does not redirect logging to stderr, so an "
                "in-process scan will write its log records into the JSON-RPC "
                "stream."
            )
        finally:
            if original is None:
                os.environ.pop("ASH_LOG_TO_STDERR", None)
            else:
                os.environ["ASH_LOG_TO_STDERR"] = original
        capsys.readouterr()

    def test_missing_dependency_guidance_avoids_stdout(self, capsys):
        """This path had no `quiet` gate at all, so the gate was never the fix."""
        exc = _run(deps_available=False)

        captured = capsys.readouterr()
        assert exc.exit_code == 1
        assert captured.out == ""
        assert "MCP dependencies are not available" in captured.err
        # The remediation guidance has to be readable, just not on stdout.
        assert "force-reinstall" in captured.err
