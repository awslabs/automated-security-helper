# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An HTTP server started on ``--port 0`` says which port it listens on.

uvicorn logs "Uvicorn running on http://<host>:<port>" once it listens, and a
caller that starts ``ash mcp`` on port 0 learns its port from that line. ASH binds
the socket itself for port 0 and hands it to uvicorn, and uvicorn 0.54.0 logs the
line only for a socket it bound itself, so the line went missing on both HTTP
transports, with and without ``--quiet``.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import List

import httpx
import pytest

from tests.utils.helpers import KillAfter

_RUNNING = re.compile(
    r"^INFO: +Uvicorn running on http://127\.0\.0\.1:(\d+) \(Press CTRL\+C to quit\)$"
)


_COLOR = re.compile(r"\x1b\[[0-9;]*m")


def _plain(line: str) -> str:
    """The line without color codes, which uvicorn writes on Windows runners."""
    return _COLOR.sub("", line)


def _a_free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _serve(
    transport: str, quiet_flag: str, port: int, tmp_path: Path
) -> subprocess.Popen:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("ASH_MCP_", "ASH_CONFIG"))
    }
    env["ASH_MCP_WORKSPACE_ROOT"] = str(tmp_path / "workspaces")
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "automated_security_helper.cli.main",
            "mcp",
            "--transport",
            transport,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            quiet_flag,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
        cwd=tmp_path,
        text=True,
    )


@pytest.mark.parametrize("quiet_flag", ["--quiet", "--no-quiet"])
@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
@pytest.mark.parametrize("port_asked", ["0", "a free port"])
def test_a_server_names_the_port_it_listens_on(
    tmp_path, transport, quiet_flag, port_asked
) -> None:
    """Port 0 is the case that lost the line; a port given is the control, where
    uvicorn binds the socket and logs the line itself, and only once."""
    asked = 0 if port_asked == "0" else _a_free_port()
    server = _serve(transport, quiet_flag, asked, tmp_path)
    lines: List[str] = []
    port = None
    try:
        # Reading stderr blocks until the server writes a line or exits; the
        # kill ends a server that never names its port.
        with KillAfter(server, "the ash mcp server"):
            assert server.stderr is not None
            for line in server.stderr:
                lines.append(line.rstrip("\n"))
                found = _RUNNING.match(_plain(lines[-1]))
                if found:
                    port = int(found.group(1))
                    break
            assert port is not None, "stderr ended without the port line:\n" + (
                "\n".join(lines)
            )
            assert port > 0 and asked in (0, port), (asked, port)
            # Once at the first try, with no retry: the line comes once the
            # server listens, not once the socket is merely bound.
            socket.create_connection(("127.0.0.1", port), timeout=10).close()
            response = httpx.get(f"http://127.0.0.1:{port}/no-such-route", timeout=10)
            assert response.status_code >= 400, response.status_code
            server.terminate()
            rest = server.stderr.read()
            server.wait(timeout=30)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=30)

    everything = lines + rest.splitlines()
    named = [line for line in everything if _RUNNING.match(_plain(line))]
    assert len(named) == 1, everything


class _BoundTo:
    """A socket's address, without binding one: the line reads only its port."""

    def __init__(self, host: str, port: int) -> None:
        self._address = (host, port)

    def getsockname(self):
        return self._address


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


async def _no_app(scope, receive, send) -> None:
    """An ASGI app for a Config that is loaded and never served."""


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_the_line_is_the_one_uvicorn_logs_for_a_socket_it_binds(host) -> None:
    """Message, colored message, logger and level, checked against uvicorn's own."""
    import uvicorn

    from automated_security_helper.cli.mcp import _log_where_the_server_listens

    port = 43210
    config = uvicorn.Config(app=_no_app, host=host, port=port, log_config=None)
    config.load()
    listening = _BoundTo(host, port)

    handler = _Records()
    logger = logging.getLogger("uvicorn.error")
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        # uvicorn's own method for the line, private, read here only as the
        # reference: if a uvicorn release renames it, this test says so.
        uvicorn.Server(config)._log_started_message([listening])
        _log_where_the_server_listens(config, listening)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)

    assert len(handler.records) == 2, handler.records
    theirs, ours = handler.records
    assert (ours.name, ours.levelno) == (theirs.name, theirs.levelno)
    assert ours.getMessage() == theirs.getMessage()
    assert getattr(ours, "color_message", None) == getattr(
        theirs, "color_message", None
    )
    assert ours.args == theirs.args
