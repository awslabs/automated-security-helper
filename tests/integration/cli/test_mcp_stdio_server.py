# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The `ash mcp` process, started for real and spoken to over a real pipe.

WHY THIS EXISTS
---------------
Everything else in this directory imports ``automated_security_helper.cli.mcp_server``
and talks to the ``mcp`` object in-process. That covers the tool layer but skips the
whole entry point: ``mcp_command`` in cli/mcp/__init__.py validates its options, sets
``ASH_LOG_TO_STDERR``, chooses a transport and calls ``run_mcp_server()``, which wraps
``mcp.run()`` in its own error handling. An adopter who configures ASH in an MCP client
gets that path, not the in-process one.

The deleted test_mcp_integration.py had a ``TestMcpServerLifecycle`` class here. It
patched ``mcp.run``, patched ``signal.signal`` and asserted the patches were called,
so it could not have caught a server that started and then corrupted its own output
stream. This module launches the process instead.

THE ONE THING THIS MODULE CAN CHECK THAT NOTHING ELSE CAN
---------------------------------------------------------
On the stdio transport, stdout *is* the JSON-RPC channel, and ASH has already shipped
a bug where it wasn't: ``mcp_command`` used ``rich.print``, which writes to stdout, and
a human-readable banner landed mid-stream. The reported symptom was a client failing
with ``Expecting value``.

tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py covers that, and its own docstring
says how far it reaches: "Each case below exits before a server is started, so none of
them need a transport, a socket, or a running event loop." Every path it checks is a
path that never starts a server. What it cannot check is a *running* server writing to
stdout -- the scan logger attaching a RichHandler, a library printing a warning, a
deprecation notice from the SDK. ``test_stdout_carries_only_jsonrpc_frames`` reads the
actual bytes off the actual pipe while the server answers requests, which is the only
way to see that.

It also deliberately runs with ``--no-quiet --debug``, the combination the unit test
identifies as the dangerous one: the banner is gated behind ``if not quiet`` and
``quiet`` defaults to True, so the default invocation was safe and the broken one was
the invocation anybody debugging a stdio server has to use.

WHAT THIS MODULE DOES NOT CHECK
-------------------------------
Signal handling. The old file asserted that ``signal.signal`` had been called with a
mock; the real behavior is that the SDK's stdio loop exits on EOF, which is what
``test_closing_the_input_stream_ends_the_process`` exercises. Delivering SIGINT to a
child and asserting on the exit status is timing-dependent in a way that would flake
under a 192-wide run, and the code path it would cover -- ``run_mcp_server``'s
``except KeyboardInterrupt`` -- is three lines that log.

Scans. A scan through the subprocess would pay the subprocess cost on top of the scan
cost and measure nothing the in-process scan in test_mcp_scan_workflow.py does not.

The HTTP transports. They need a port; see the note in
test_mcp_protocol_integration.py.

ISOLATION
---------
One subprocess per test, no port, no shared path, communicating over its own pipes.
The subprocess is started from ``sys.executable`` rather than from an ``ash`` console
script so that the test runs against the interpreter running the suite rather than
against whatever is first on PATH.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any, Dict, List

import pytest

# Long enough that a cold import of ASH under a 192-wide run is not mistaken for a
# hang. Startup measured 1.7 seconds unloaded.
PROCESS_TIMEOUT_SECONDS = 180

SERVER_ARGV = [
    "-m",
    "automated_security_helper.cli.main",
    "mcp",
    "--transport",
    "stdio",
]


def _server_env() -> Dict[str, str]:
    """Return the child environment.

    ``ASH_MCP_ALLOWED_ROOTS`` is cleared rather than inherited. Nothing here scans, but
    a value leaked from another test's environment would change what the child's policy
    permits, and a test whose behavior depends on a sibling's leftovers is not a test.
    """
    env = dict(os.environ)
    env.pop("ASH_MCP_ALLOWED_ROOTS", None)
    return env


@pytest.mark.asyncio
async def test_the_real_process_serves_the_full_tool_surface() -> None:
    """A client that spawns `ash mcp` gets the same server the in-process tests get.

    This is the adopter's path: a client launches a command, speaks MCP over its stdin
    and stdout, and expects tools. Asserting the surface here as well as in
    test_mcp_protocol_integration.py is not duplication -- the in-process test proves
    the tools are registered on the ``mcp`` object, and this one proves the CLI actually
    serves that object. A ``mcp_command`` that exited early, chose the wrong transport,
    or failed its own dependency check would pass the first test and fail this one.
    """
    from mcp import Client, StdioServerParameters

    params = StdioServerParameters(
        command=sys.executable, args=SERVER_ARGV, env=_server_env()
    )

    async with Client(params, raise_exceptions=True) as client:
        assert client.server_info.name == "ASH Security Scanner"

        tools = {tool.name for tool in (await client.list_tools()).tools}
        assert "run_ash_scan" in tools
        assert "get_scan_progress" in tools
        assert "get_scan_results" in tools
        assert len(tools) >= 21, (
            f"The subprocess served only {len(tools)} tools: {sorted(tools)}. The "
            "in-process surface is asserted exactly in "
            "test_mcp_protocol_integration.py; a smaller surface here means the CLI "
            "is not serving the same server object."
        )

        result = await client.call_tool("check_installation", {})
        assert result.is_error is False, f"check_installation failed: {result.content}"
        payload = result.structured_content["result"]
        assert payload["installed"] is True
        assert payload["version"]

        read = await client.read_resource("ash://help")
        assert read.contents[0].text.strip()


def _frame(payload: Dict[str, Any]) -> bytes:
    """Encode one newline-delimited JSON-RPC frame the way the stdio transport does."""
    return (json.dumps(payload) + "\n").encode("utf-8")


def _exchange(
    extra_args: List[str], frames: List[bytes], expect_ids: set[int]
) -> tuple[List[str], str, int]:
    """Send ``frames`` to a real `ash mcp` process and return everything it wrote.

    Reads responses *before* closing stdin, which is load-bearing rather than
    stylistic. Writing every frame with ``Popen.communicate(input=...)`` closes stdin as
    soon as the last one is written, and the server's stdio loop then races its own
    shutdown against the request still in flight: measured, the ``initialize`` response
    came back and the ``tools/list`` response never did, because EOF cancelled the
    handler. A test written that way reports "the server does not answer tools/list",
    which is a false finding about the server and a true one about the harness.

    A watchdog kills the child if it stops answering, so a hung server fails the test
    instead of hanging the suite. ``readline`` on a dead process returns empty, which
    ends the loop on its own.

    Returns the non-empty stdout lines in order, the child's stderr, and its exit code.
    """
    process = subprocess.Popen(
        [sys.executable, *SERVER_ARGV, *extra_args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_server_env(),
    )
    watchdog = threading.Timer(PROCESS_TIMEOUT_SECONDS, process.kill)
    watchdog.start()

    lines: List[str] = []
    try:
        for frame in frames:
            process.stdin.write(frame)
        process.stdin.flush()

        answered: set[int] = set()
        while answered != expect_ids:
            raw = process.stdout.readline()
            if not raw:
                break
            lines.append(raw.decode("utf-8", errors="replace"))
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") in expect_ids:
                answered.add(message["id"])

        # Do not close stdin here: communicate() closes it itself (sending EOF
        # after every response has been read above), and closing it first left
        # communicate() flushing an already-closed pipe -- "ValueError: flush of
        # closed file" under Python 3.12, though 3.14 tolerated it, which is why
        # this passed locally and failed in CI.
        remaining, stderr = process.communicate(timeout=PROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        remaining, stderr = process.communicate()
    finally:
        watchdog.cancel()

    lines.extend(remaining.decode("utf-8", errors="replace").splitlines(keepends=True))
    return (
        [line for line in lines if line.strip()],
        stderr.decode("utf-8", errors="replace"),
        process.returncode,
    )


def test_stdout_carries_only_jsonrpc_frames() -> None:
    """Every line the running server writes to stdout parses as JSON-RPC.

    Driven with a hand-built exchange rather than through ``mcp.Client`` on purpose. A
    client consumes stdout and decides for itself what to do with a line it cannot
    parse; some versions skip it, which would make a corrupted stream look clean. Owning
    the pipe is the only way to see every byte.

    ``--no-quiet --debug`` is the configuration under test because it is the one that
    broke: the startup banner is gated behind ``if not quiet``, ``quiet`` defaults to
    True, and ``validate_command_options`` refuses ``--quiet`` together with
    ``--debug``, so anyone debugging a stdio server necessarily runs the ungated path.
    ``--debug`` additionally turns on the log level whose records the scan logger would
    route to stdout if ``ASH_LOG_TO_STDERR`` were not set.

    The exchange is a real initialize handshake followed by a real ``tools/list``, so
    the server has answered two requests and emitted whatever it emits at startup
    before stdout is inspected.
    """
    from mcp.types import LATEST_PROTOCOL_VERSION

    lines, stderr, _ = _exchange(
        ["--no-quiet", "--debug"],
        [
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": LATEST_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "ash-integration-test", "version": "0"},
                    },
                }
            ),
            _frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            _frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ],
        expect_ids={1, 2},
    )

    assert lines, (
        "The server wrote nothing to stdout, so this test proved nothing about what it "
        "writes there. Either the handshake was rejected or the process died; stderr "
        f"tail: {stderr[-2000:]}"
    )

    offenders: List[str] = []
    responses: List[Dict[str, Any]] = []
    for line in lines:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            offenders.append(line)
            continue
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            offenders.append(line)
            continue
        responses.append(message)

    assert not offenders, (
        "These lines arrived on stdout and are not JSON-RPC frames, which is what a "
        f"client reports as `Expecting value`: {offenders[:5]}. Everything that is not "
        "a protocol message belongs on stderr -- see cli/mcp/__init__.py, which sets "
        "ASH_LOG_TO_STDERR for this reason."
    )

    by_id = {message.get("id"): message for message in responses}
    assert 1 in by_id, f"No response to initialize: {responses}"
    assert 2 in by_id, f"No response to tools/list: {responses}"
    assert by_id[1]["result"]["serverInfo"]["name"] == "ASH Security Scanner"
    assert by_id[2]["result"]["tools"], "tools/list came back empty over real stdio"

    assert stderr.strip(), (
        "Nothing reached stderr at all. `--no-quiet --debug` should produce the startup "
        "banner and debug records there; if both streams are empty, the logging "
        "configuration changed and the stdout assertion above may be passing because "
        "the server has stopped saying anything rather than because it is saying it in "
        "the right place."
    )


def test_closing_the_input_stream_ends_the_process() -> None:
    """EOF on stdin shuts the server down, and it exits reporting success.

    The real shutdown path for a stdio server. An MCP client stops a server by closing
    its stdin, and a server that ignored EOF would be left running after its client
    disconnected -- one leaked process per client restart, each holding whatever the
    last scan allocated. That is the failure the commit which deleted the old tests was
    written to address ("deadlock issues causing memory leaks"), so leaving it uncovered
    is the least defensible gap of the three.

    Exit code 0 is asserted, not merely termination. ``run_mcp_server`` catches
    ``ClosedResourceError`` and ``TaskGroup`` failures and logs them as warnings; a
    non-zero status would mean the shutdown went through the unexpected-error branch,
    and a client watching the child would report a crash on every ordinary disconnect.
    """
    process = subprocess.Popen(
        [sys.executable, *SERVER_ARGV],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_server_env(),
    )

    try:
        # No requests at all: the server must exit on EOF whether or not it was ever
        # initialized, because a client that fails during startup closes the pipe
        # without having spoken.
        _, stderr = process.communicate(timeout=PROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        _, stderr = process.communicate()
        pytest.fail(
            f"`ash mcp` was still running {PROCESS_TIMEOUT_SECONDS}s after stdin "
            "closed. A stdio server that ignores EOF leaks one process per client "
            f"restart. stderr tail: {stderr.decode(errors='replace')[-2000:]}"
        )

    assert process.returncode == 0, (
        f"`ash mcp` exited {process.returncode} on an ordinary client disconnect. "
        "run_mcp_server treats a closed stream as expected and logs a warning, so a "
        "non-zero status means shutdown took the unexpected-error branch. stderr tail: "
        f"{stderr.decode(errors='replace')[-2000:]}"
    )
