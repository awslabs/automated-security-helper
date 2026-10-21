# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` writes the log lines of the libraries it serves with their CI commands broken.

Why this exists
---------------
``MCPServer()`` configures logging for the MCP SDK
(``mcp.server.mcpserver.utilities.logging.configure_logging``). When the root
logger has no handler it installs a ``RichHandler`` on a Console of its own, on
stderr, and that Console has no CI-command check. The SDK logs a ``tools/call``'s
tool name through it ("Tool %r failed: %r"), so ``ash mcp`` sends that handler's
lines through the CI-command check, and a client's tool name holding ``##vso[``
is written with the command broken. ``%r``
keeps a line feed from starting a line, and leaves ``##vso[`` as it is. On the
HTTP transports uvicorn configures handlers of its own, on stdout and stderr, that
write what they are given as it is. ASH's own records were already checked.

The server is reached three ways: the ``ash`` console script
(``cli.entrypoint.main``), ``python -m automated_security_helper.cli.main``, which
goes through the same ``main``, and ``python -m
automated_security_helper.cli.mcp_server``, which does not and serves stdio only.
Each is a cell on stdio, and the first two on streamable HTTP. Each starts a real
server and calls a tool that does not exist. A test process's root logger has
pytest's handlers, so the SDK would install nothing there: the cells need the
child.

uvicorn writes no client text through its own handlers while ASH runs it: ASH
turns its access log off. One cell has uvicorn's error logger write a stand-in
line from the running command; another sends a request path holding a command and
checks that nothing writes it as one.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typing_extensions import Self

from tests.utils.helpers import checkout_env

#: Long enough for a cold import under a wide run.
TIMEOUT_SECONDS = 180

#: A tool name a client sends, holding commands: the SDK logs it as the call fails.
#: Each runner's form, mid-line and at a line start, indented by a tab or spaces,
#: and in capitals. The SDK writes the name through %r, so its line feeds stay
#: "\n"; its handler still wraps the line at a space, and at 80 columns the
#: indented "::add-mask::x" starts a line there. The uvicorn cell writes the same
#: text through %s, where each form starts a line of its own.
TOOL_NAME = (
    "probe\n::add-mask::CANA x##vso[task.setvariable variable=x]CANB"
    "\n##[warning]x"
    "\n##teamcity[message text='x']"
    "\n\t::warning::x"
    "\n   ::add-mask::x"
    "\n##VSO[task.setvariable variable=x]"
)

#: "::" at a line start, after optional whitespace.
_LINE_START_COMMAND = re.compile(r"\s*::")

#: "##name[", any case, anywhere: Azure Pipelines reads "##vso[" mid-line too, so
#: this holds more than a line start or a whitespace before it
#: (cli/report_yaml.py's _COMMAND_START).
_NAMED_HASH_COMMAND = re.compile(r"##[A-Za-z]*\[")

_ASH_SCRIPT = (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', *sys.argv[1:]]\n"
    "sys.exit(main())\n"
)

#: How each entry point is started, before the ``mcp`` command's own arguments.
ENTRY_POINTS = {
    "ash-script": ["-c", _ASH_SCRIPT, "mcp"],
    "python-m-cli-main": ["-m", "automated_security_helper.cli.main", "mcp"],
}


def _env() -> Dict[str, str]:
    env = checkout_env()
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_TRANSPORT",
        "ASH_LOG_TO_STDERR",
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "TEAMCITY_VERSION",
    ):
        env.pop(name, None)
    # The width the handlers wrap at, so the lines are the same on every host.
    env["COLUMNS"] = "80"
    return env


def _assert_no_command(stderr: str) -> None:
    """No line of *stderr*, as a runner splits it, holds a command."""
    lines = re.split(r"\r\n|\r|\n", stderr)
    assert [line for line in lines if _LINE_START_COMMAND.match(line)] == [], stderr
    assert [line for line in lines if _NAMED_HASH_COMMAND.search(line)] == [], stderr


def _frame(payload: Dict[str, Any]) -> bytes:
    return (json.dumps(payload) + "\n").encode("utf-8")


FRAMES = [
    _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }
    ),
    _frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    _frame(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": TOOL_NAME, "arguments": {}},
        }
    ),
]


def _over_stdio(argv: List[str], cwd: Path) -> tuple[List[bytes], List[dict], str]:
    """Every line the server wrote to stdout, its replies, and its stderr, with
    stdin closed only once both requests are answered: closed earlier, EOF can
    cancel the call in flight."""
    process = subprocess.Popen(
        [sys.executable, *argv],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_env(),
        cwd=cwd,
    )
    watchdog = threading.Timer(TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    lines: List[bytes] = []
    replies: List[dict] = []
    try:
        for frame in FRAMES:
            process.stdin.write(frame)
        process.stdin.flush()
        answered: set = set()
        while answered != {1, 2}:
            raw = process.stdout.readline()
            if not raw:
                break
            lines.append(raw)
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") in (1, 2):
                answered.add(message["id"])
                replies.append(message)
        rest, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
        lines.extend(rest.splitlines(keepends=True))
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
            process.communicate()
    return lines, replies, stderr.decode("utf-8", errors="replace")


def _assert_only_json_rpc(lines: List[bytes], carried: str) -> None:
    """stdout is the JSON-RPC channel, written byte for byte: no line of it is
    anything else, the command check's escapes included, and *carried*, a string
    a reply quotes, is on it in json.dumps's own encoding. Byte for byte is
    checked on the bytes: parsing alone would also accept a frame whose "#" or
    ":" the server re-encoded (JSON reads "\\u0023" and "#" as the same
    string)."""
    for line in lines:
        message = json.loads(line)
        assert isinstance(message, dict) and message.get("jsonrpc") == "2.0", line
    encoded = json.dumps(carried)[1:-1].encode("utf-8")
    assert any(encoded in line for line in lines), (encoded, lines)


STDIO_ENTRIES = {
    **{name: [*argv, "--transport", "stdio"] for name, argv in ENTRY_POINTS.items()},
    "python-m-mcp-server": ["-m", "automated_security_helper.cli.mcp_server"],
}


@pytest.mark.parametrize("entry", list(STDIO_ENTRIES))
def test_the_sdks_line_on_stdio_is_written_with_its_commands_broken(entry, tmp_path):
    lines, replies, stderr = _over_stdio(STDIO_ENTRIES[entry], tmp_path)

    # The control: the call was answered as a failure, and the SDK logged it.
    call = [reply for reply in replies if reply.get("id") == 2]
    assert call and call[0].get("result", {}).get("isError") is True, (replies, stderr)
    assert "failed" in stderr and "CANB" in stderr, stderr
    _assert_no_command(stderr)
    # The reply quotes the name as the client sent it: only stderr is checked.
    assert TOOL_NAME in call[0]["result"]["content"][0]["text"], call
    # And carries it byte for byte.
    _assert_only_json_rpc(lines, carried=TOOL_NAME)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _HttpServer:
    """``ash mcp --transport streamable-http`` on a free local port, its stderr in a
    file so that a full pipe cannot stop it."""

    def __init__(self, argv: List[str], tmp_path: Path) -> None:
        self.port = _free_port()
        self.stderr_path = tmp_path / "server-stderr.txt"
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        with open(self.stderr_path, "wb") as stderr:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    *argv,
                    "--transport",
                    "streamable-http",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(self.port),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
                env=_env(),
                cwd=tmp_path,
            )

    def __enter__(self) -> Self:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while True:
            assert self.process.poll() is None, self.stderr()
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return self
            except OSError:
                assert time.monotonic() < deadline, "the server never listened"
                time.sleep(0.05)

    def __exit__(self, *exc_info) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def stderr(self) -> str:
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")


def _call_the_tool(url: str):
    import anyio
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    results: list = []

    async def run() -> None:
        async with httpx.AsyncClient(timeout=60.0) as http_client:
            async with streamable_http_client(url, http_client=http_client) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    results.append(await session.call_tool(TOOL_NAME, {}))

    anyio.run(run)
    return results[0]


@pytest.mark.parametrize("entry", list(ENTRY_POINTS))
def test_the_sdks_line_over_http_is_written_with_its_commands_broken(entry, tmp_path):
    with _HttpServer(ENTRY_POINTS[entry], tmp_path) as server:
        result = _call_the_tool(server.url)
    stderr = server.stderr()

    # The control: the call failed, and the SDK logged it.
    assert result.is_error is True, result
    assert "failed" in stderr and "CANB" in stderr, stderr
    _assert_no_command(stderr)
    # The reply quotes the name as the client sent it: only stderr is checked.
    assert TOOL_NAME in result.content[0].text, result


#: uvicorn's server replaced: its error logger writes a stand-in line, as the
#: command left it configured, and returns.
_UVICORN_STAND_IN = (
    "import logging, sys\n"
    "import uvicorn\n"
    "LINE = sys.argv.pop()\n"
    "def run(self, *args, **kwargs):\n"
    "    logging.getLogger('uvicorn.error').warning(LINE)\n"
    "uvicorn.Server.run = run\n"
) + _ASH_SCRIPT


def test_uvicorns_own_handler_writes_with_its_commands_broken(tmp_path):
    argv = [
        "-c",
        _UVICORN_STAND_IN,
        "mcp",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        str(_free_port()),
        TOOL_NAME,
    ]

    done = subprocess.run(
        [sys.executable, *argv],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=_env(),
        cwd=tmp_path,
        timeout=TIMEOUT_SECONDS,
    )
    stderr = done.stderr.decode("utf-8", errors="replace")

    # The control: uvicorn's handler wrote the line.
    assert "CANB" in stderr and "CANA" in stderr, stderr
    _assert_no_command(stderr)


def test_a_request_path_holding_commands_is_not_written_as_one(tmp_path):
    """A guard for a later change, not a red cell: it passes without the routing
    too, because _run_uvicorn passes access_log=False and uvicorn then logs no
    request path. Should the access log be turned on, its line goes through the
    same check."""
    with _HttpServer(ENTRY_POINTS["ash-script"], tmp_path) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=30) as conn:
            conn.sendall(
                b"GET /::add-mask::CANA/x##vso[task.setvariable%20variable=x]CANB "
                b"HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            answer = b""
            while chunk := conn.recv(65536):
                answer += chunk
    stderr = server.stderr()

    # The control: the server answered the request.
    assert answer.startswith(b"HTTP/1.1 "), answer
    _assert_no_command(stderr)
