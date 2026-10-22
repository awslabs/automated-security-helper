# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Ctrl-C stops an HTTP `ash mcp` with exit status 130, as it stops a stdio one.

Why this exists
---------------
On every transport, a user's interrupt is exit status 130 (128 + SIGINT, what a
shell reports for a process SIGINT ended). uvicorn handles SIGINT itself: it
stops the server gracefully, which ends the app's lifespan and with it the scans
(cli/mcp._stop_scans_when_the_app_stops), and then raises SIGINT again, which
reaches `ash mcp` as KeyboardInterrupt. `ash mcp` turned that into exit 0, the
status of a client that closed the connection.

These tests drive a real `ash mcp --transport streamable-http` or `sse` process
and send it SIGINT: once with no client, and once with a client session open and
a scan running, whose scanner's tool ignores SIGTERM and starts a child that
ignores it too, as in test_mcp_stdio_shutdown.py. SIGTERM, for comparison, ends
the process by SIGTERM: uvicorn raises it again once it has stopped.

A scan busy in Python, where no cancel check reaches it, would hold a Ctrl-C or
a SIGHUP for as long as it had left to run: the stop is done within 1.5 s, but
asyncio would then wait for the scan's thread before uvicorn returned, and the
interpreter would wait for it again at exit, so with a phase busy for 30 s,
Ctrl-C would exit 130 after about 32 s. The server exits once the stop is done,
as a stdio server does.

A second Ctrl-C has to end a server whose stop is waiting for a request a
client kept open. uvicorn's first Ctrl-C waits for the open connections to close
before the app's lifespan stops the scans, and its second, the "force quit" it
offers while it waits, skips that lifespan; measured on uvicorn 0.54.0 under
Python 3.14, the server went on waiting all the same, in asyncio's
Server.wait_closed (which waits for every connection since Python 3.12.1), for
as long as the client kept the request open: 20 s and 60 s, with the scan's
tool and its child running throughout, and SIGKILL, the one signal left that
ends it, would leave them both running. The second Ctrl-C kills the tools'
process groups and exits with 130 at once.

A server started with SIGINT ignored is the exception, as it is on stdio. A
shell starts a background job (`ash mcp --transport streamable-http &`) with
SIGINT ignored, so that a Ctrl-C meant for the job in the foreground does not
reach it. uvicorn installed a SIGINT handler of its own whatever was set before,
so that Ctrl-C stopped the background server. So is one started with SIGHUP
ignored, as nohup starts one so that it outlives its terminal: the server's own
SIGHUP handler replaced that, so that closing the terminal stopped it.
"""

from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import anyio
import pytest

from automated_security_helper.cli.mcp import _GRACEFUL_SHUTDOWN_SECONDS
from automated_security_helper.cli.mcp_server import STDIO_SCAN_STOP_TIMEOUT_SECONDS
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORING_DIR_NAME,
    holds_restored_results,
)
from tests.utils.helpers import checkout_env
from tests.utils.processes import process_running

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

STARTUP_TIMEOUT_SECONDS = 180

#: Long enough to tell a server that does not stop from a slow one.
SIGNAL_WAIT_SECONDS = 20

#: `ash mcp`'s exit status on Ctrl-C, on every transport.
INTERRUPTED = 130

#: How long a server started with a signal ignored must outlive that signal.
IGNORED_SIGNAL_WAIT_SECONDS = 2

#: Runs the command after the signal number with that signal ignored, as a shell
#: starts a background job (SIGINT) and nohup starts a command (SIGHUP). An
#: ignored signal stays ignored across exec, and Python leaves it so.
SIGNAL_IGNORED = (
    "import os, signal, sys\n"
    "signal.signal(int(sys.argv.pop(1)), signal.SIG_IGN)\n"
    "os.execv(sys.executable, [sys.executable] + sys.argv[1:])\n"
)

BOOTSTRAP = r"""
import sys
from unittest.mock import patch

from automated_security_helper.utils.subprocess_utils import run_command

out, transport, port = sys.argv.pop(1), sys.argv.pop(1), sys.argv.pop(1)

TOOL = (
    "import os, pathlib, signal, subprocess, sys, time\n"
    "out = pathlib.Path(sys.argv[1])\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "subprocess.Popen([sys.executable, '-c', "
    "'import os, pathlib, signal, sys, time\\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\\n"
    "time.sleep(120)\\n', str(out / 'grandchild.pid')])\n"
    "for _ in range(400):\n"
    "    if (out / 'grandchild.pid').exists(): break\n"
    "    time.sleep(0.05)\n"
    "(out / 'tool.pid').write_text(str(os.getpid()))\n"
    "time.sleep(120)\n"
)


def phases(*args, **kwargs):
    run_command([sys.executable, "-c", TOOL, out])
    raise AssertionError("the scan was not stopped")


with patch(
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases",
    side_effect=phases,
):
    from automated_security_helper.cli.entrypoint import main

    sys.argv = [
        "ash", "mcp", "--transport", transport, "--host", "127.0.0.1", "--port", port
    ]
    main()
"""

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
}


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = project / ".ash" / "ash_output"
    for rel, text in PREVIOUS.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return project


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _start(
    tmp_path: Path,
    project: Path,
    transport: str,
    port: int,
    stderr,
    ignored: Optional[int] = None,
    bootstrap_text: str = BOOTSTRAP,
):
    bootstrap = tmp_path / "bootstrap.py"
    bootstrap.write_text(bootstrap_text, encoding="utf-8")
    env = checkout_env()
    env["ASH_MCP_ALLOWED_ROOTS"] = str(tmp_path)
    env.pop("ASH_MCP_TRANSPORT", None)
    command = [sys.executable, str(bootstrap), str(tmp_path), transport, str(port)]
    if ignored is not None:
        command[1:1] = ["-c", SIGNAL_IGNORED, str(int(ignored))]
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr,
        cwd=str(project),
        env=env,
    )


def _wait_until_listening(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while True:
        assert process.poll() is None, "the server exited before it listened"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            assert time.monotonic() < deadline, "the server never listened"
            time.sleep(0.05)


def _wait_after_signal(process: subprocess.Popen) -> Optional[int]:
    """The process's exit status, or None if it is still running."""
    try:
        return process.wait(timeout=SIGNAL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        return None


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
        process.wait()


def _wait_for_tree(tmp_path: Path) -> Dict[str, int]:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while not (tmp_path / "tool.pid").exists():
        assert time.monotonic() < deadline, "the scanner's tool never started"
        time.sleep(0.05)
    return {
        name: int((tmp_path / f"{name}.pid").read_text())
        for name in ("tool", "grandchild")
    }


def _kill_leftovers(pids: Dict[str, int]) -> None:
    for pid in pids.values():
        if process_running(pid):
            os.kill(pid, signal.SIGKILL)


#: _still_running's answer when the server ended the tool and its child.
NOTHING_RUNNING = {"tool": False, "grandchild": False}


def _still_running(pids: Dict[str, int]) -> Dict[str, bool]:
    """Which of the tool and its child are running.

    Read as soon as the server has exited, before _kill_leftovers. Read after
    it, the answer raced the test's own SIGKILL, so it could say a process the
    server had left running was gone.
    """
    return {name: process_running(pid) for name, pid in pids.items()}


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_ctrl_c_stops_an_idle_http_server_with_130(tmp_path, transport):
    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, transport, port, stderr)
    try:
        _wait_until_listening(process, port)
        sent = time.monotonic()
        process.send_signal(signal.SIGINT)
        status = _wait_after_signal(process)
        took = time.monotonic() - sent
    finally:
        _stop(process)

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert status == INTERRUPTED, (status, stderr_text[-2000:])
    assert took < 10.0, (took, stderr_text[-2000:])


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_sigterm_ends_an_idle_http_server_by_sigterm(tmp_path, transport):
    """uvicorn stops gracefully and then raises SIGTERM again, which ends the process."""
    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, transport, port, stderr)
    try:
        _wait_until_listening(process, port)
        sent = time.monotonic()
        process.send_signal(signal.SIGTERM)
        status = _wait_after_signal(process)
        took = time.monotonic() - sent
    finally:
        _stop(process)

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert status == -signal.SIGTERM, (status, stderr_text[-2000:])
    assert took < 10.0, (took, stderr_text[-2000:])


#: A request each transport's own endpoint answers without opening a session:
#: method, path, headers, and the status and body text it answers with.
PROBES = {
    "streamable-http": (
        "GET",
        "/mcp",
        {"mcp-session-id": "not-a-session"},
        404,
        "Session not found",
    ),
    "sse": (
        "POST",
        "/messages/",
        {"content-type": "application/json"},
        400,
        "session_id is required",
    ),
}


def _probe(port: int, transport: str) -> tuple:
    """The status and body the transport's endpoint answers PROBES' request with."""
    import httpx

    method, path, headers, _, _ = PROBES[transport]
    response = httpx.request(
        method, f"http://127.0.0.1:{port}{path}", headers=headers, timeout=10.0
    )
    return response.status_code, response.text


@pytest.mark.parametrize(
    "ignored", [signal.SIGINT, signal.SIGHUP], ids=["sigint", "sighup"]
)
@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_an_http_server_started_with_a_signal_ignored_keeps_it_ignored(
    tmp_path, transport, ignored
):
    """As a stdio server does. SIGTERM still stops it, as it stops one that did not
    start with the signal ignored."""
    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, transport, port, stderr, ignored=ignored)
    answer = None
    try:
        _wait_until_listening(process, port)
        process.send_signal(ignored)
        try:
            after_ignored = process.wait(timeout=IGNORED_SIGNAL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            after_ignored = None
            answer = _probe(port, transport)
        alive = process.poll() is None
        process.send_signal(signal.SIGTERM)
        after_sigterm = _wait_after_signal(process)
    finally:
        _stop(process)

    name = signal.Signals(ignored).name
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert after_ignored is None, (
        f"the server exited with {after_ignored} on a {name} it started with ignored",
        stderr_text[-2000:],
    )
    _, _, _, status, text = PROBES[transport]
    assert answer is not None and answer[0] == status and text in answer[1], (
        answer,
        stderr_text[-2000:],
    )
    assert alive, stderr_text[-2000:]
    assert after_sigterm == -signal.SIGTERM, (after_sigterm, stderr_text[-2000:])


def test_ctrl_c_stops_the_scans_of_a_streamable_http_server(tmp_path):
    """With a client session open, as a client that has not left holds one."""
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, "streamable-http", port, stderr)
    found: Dict[str, object] = {}

    async def _run() -> None:
        url = f"http://127.0.0.1:{port}/mcp"
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            async with streamable_http_client(url, http_client=http_client) as (
                read,
                write,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    begun = await session.call_tool(
                        "run_ash_scan", {"source_dir": str(project)}
                    )
                    found["begun"] = begun.structured_content
                    pids = await anyio.to_thread.run_sync(_wait_for_tree, tmp_path)
                    found["pids"] = pids
                    sent = time.monotonic()
                    process.send_signal(signal.SIGINT)
                    found["status"] = await anyio.to_thread.run_sync(
                        _wait_after_signal, process
                    )
                    found["took"] = time.monotonic() - sent
                    found["running"] = _still_running(pids)
                    # The server is gone; leaving the session would only report
                    # that the connection broke.
                    raise _Done

    try:
        _wait_until_listening(process, port)
        try:
            anyio.run(_run)
        except BaseException as error:  # noqa: BLE001 -- see _Done
            if not _left_with_done(error):
                raise
    finally:
        _stop(process)
        _kill_leftovers(found.get("pids", {}))

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert found["begun"]["result"]["success"] is True, found["begun"]
    assert found["status"] == INTERRUPTED, (found["status"], stderr_text[-2000:])
    assert found["took"] < 10.0, (found["took"], stderr_text[-2000:])
    assert found["running"] == NOTHING_RUNNING, (
        "the tool or its child outlived the server",
        found["running"],
    )
    output = project / ".ash" / "ash_output"
    results = {rel: (output / rel).read_text(encoding="utf-8") for rel in PREVIOUS}
    assert results == PREVIOUS, "the previous results were not put back"
    assert holds_restored_results(output)
    assert not (output / HELD_DIR_NAME).exists(), "a held set was left behind"


#: A scan busy in Python for 30 s, where no cancel check reaches it, while its
#: scanner's tool (BOOTSTRAP's) runs on a thread of the scan's own. The cancel
#: stops the tool, but the scan's thread is still running when the server's stop
#: is done, and asyncio's shutdown waited for it before uvicorn returned: the
#: server exited 30 s after the signal.
BUSY_BOOTSTRAP = r"""
import contextvars
import pathlib
import sys
import threading
import time
from unittest.mock import patch

from automated_security_helper.utils.subprocess_utils import run_command

out, transport, port = sys.argv.pop(1), sys.argv.pop(1), sys.argv.pop(1)

TOOL = (
    "import os, pathlib, signal, subprocess, sys, time\n"
    "out = pathlib.Path(sys.argv[1])\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "subprocess.Popen([sys.executable, '-c', "
    "'import os, pathlib, signal, sys, time\\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\\n"
    "time.sleep(120)\\n', str(out / 'grandchild.pid')])\n"
    "for _ in range(400):\n"
    "    if (out / 'grandchild.pid').exists(): break\n"
    "    time.sleep(0.05)\n"
    "(out / 'tool.pid').write_text(str(os.getpid()))\n"
    "time.sleep(120)\n"
)


def phases(*args, **kwargs):
    # The scan's context, so the tool is a cancellable spawn of this scan.
    threading.Thread(
        target=contextvars.copy_context().run,
        args=(run_command, [sys.executable, "-c", TOOL, out]),
        daemon=True,
    ).start()
    while not (pathlib.Path(out) / "tool.pid").exists():
        time.sleep(0.05)
    (pathlib.Path(out) / "busy").write_text("1")
    time.sleep(30)
    raise AssertionError("the busy scan finished")


with patch(
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases",
    side_effect=phases,
):
    from automated_security_helper.cli.entrypoint import main

    sys.argv = [
        "ash", "mcp", "--transport", transport, "--host", "127.0.0.1", "--port", port
    ]
    main()
"""

#: What `ash mcp` over HTTP exits with when each signal stops it: 130 for Ctrl-C,
#: as on every transport, and 0 for SIGHUP. uvicorn raises SIGTERM again once it
#: has stopped, which ends the process by SIGTERM.
STOPPED_BY = {
    signal.SIGINT: INTERRUPTED,
    signal.SIGHUP: 0,
    signal.SIGTERM: -signal.SIGTERM,
}


def _client(transport: str, port: int, http_client):
    """The SDK's own client for ``transport``: its (read, write) streams."""
    from mcp.client.sse import sse_client
    from mcp.client.streamable_http import streamable_http_client

    if transport == "streamable-http":
        return streamable_http_client(
            f"http://127.0.0.1:{port}/mcp", http_client=http_client
        )
    return sse_client(f"http://127.0.0.1:{port}/sse")


def _wait_until_busy(tmp_path: Path) -> Dict[str, int]:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while not (tmp_path / "busy").exists():
        assert time.monotonic() < deadline, "the busy scan never started"
        time.sleep(0.05)
    return _wait_for_tree(tmp_path)


@pytest.mark.parametrize(
    "signum",
    [signal.SIGINT, signal.SIGHUP, signal.SIGTERM],
    ids=["sigint", "sighup", "sigterm"],
)
@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_a_signal_stops_an_http_server_promptly_while_a_scan_is_busy_in_python(
    tmp_path, transport, signum
):
    """The stop is done within 1.5 s; the server then exits without waiting for
    the scan's thread, as a stdio server does (cli/mcp_server._stop_on_signal).

    The scan's previous results stay held in .ash_previous_results, where the
    next scan in that directory takes them back: its thread never got to put
    them back.
    """
    import httpx
    from mcp.client.session import ClientSession

    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(
            tmp_path, project, transport, port, stderr, bootstrap_text=BUSY_BOOTSTRAP
        )
    found: Dict[str, object] = {}

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            async with _client(transport, port, http_client) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    begun = await session.call_tool(
                        "run_ash_scan", {"source_dir": str(project)}
                    )
                    found["begun"] = begun.structured_content
                    pids = await anyio.to_thread.run_sync(_wait_until_busy, tmp_path)
                    found["pids"] = pids
                    sent = time.monotonic()
                    process.send_signal(signum)
                    found["status"] = await anyio.to_thread.run_sync(
                        _wait_after_signal, process
                    )
                    found["took"] = time.monotonic() - sent
                    found["running"] = _still_running(pids)
                    raise _Done

    try:
        _wait_until_listening(process, port)
        try:
            anyio.run(_run)
        except BaseException as error:  # noqa: BLE001 -- see _Done
            if not _left_with_done(error):
                raise
    finally:
        _stop(process)
        _kill_leftovers(found.get("pids", {}))

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert found["begun"]["result"]["success"] is True, found["begun"]
    assert found["status"] == STOPPED_BY[signum], (
        found["status"],
        found["took"],
        stderr_text[-2000:],
    )
    assert found["took"] < 10.0, (found["took"], stderr_text[-2000:])
    assert found["running"] == NOTHING_RUNNING, (
        "the tool or its child outlived the server",
        found["running"],
    )
    held = project / ".ash" / "ash_output" / HELD_DIR_NAME
    kept = {rel: (held / rel).read_text(encoding="utf-8") for rel in PREVIOUS}
    assert kept == PREVIOUS, "the previous results were not kept"


#: What uvicorn logs once its stop is waiting for the open connections to close.
DRAINING = "Waiting for connections to close"


def _hold_a_request_open(transport: str, port: int) -> List[socket.socket]:
    """Send a request whose headers are complete and whose body never comes.

    As from a client still uploading: uvicorn's graceful stop waits for it to be
    answered or dropped. The endpoint has to be one that reads the body before
    it answers, so streamable HTTP's /mcp, and on sse the /messages/ endpoint of
    a session that exists, which takes an event stream of its own to learn.
    Returns the sockets, for the caller to close.
    """
    held: List[socket.socket] = []
    target = "/mcp"
    if transport == "sse":
        stream = socket.create_connection(("127.0.0.1", port), timeout=10)
        held.append(stream)
        stream.sendall(
            f"GET /sse HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "Accept: text/event-stream\r\n\r\n".encode()
        )
        received = b""
        found = None
        while found is None:
            chunk = stream.recv(4096)
            assert chunk, (
                f"the event stream ended before it named a session: {received!r}"
            )
            received += chunk
            found = re.search(rb"session_id=([0-9a-f]+)\r?\n", received)
        target = f"/messages/?session_id={found.group(1).decode()}"
    request = socket.create_connection(("127.0.0.1", port), timeout=10)
    held.append(request)
    request.sendall(
        f"POST {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json, text/event-stream\r\n"
        "Content-Length: 1000\r\n\r\n{".encode()
    )
    return held


def _wait_until_draining(process: subprocess.Popen, stderr_path: Path) -> None:
    """Wait until the server's stop says it is waiting for the open connections."""
    deadline = time.monotonic() + SIGNAL_WAIT_SECONDS
    while DRAINING not in stderr_path.read_text(encoding="utf-8", errors="replace"):
        assert process.poll() is None, (
            "the server exited before it waited for the request"
        )
        assert time.monotonic() < deadline, (
            "the server's stop never waited for the request"
        )
        time.sleep(0.05)


def _previous_results_kept(output: Path) -> bool:
    """Whether each previous result is back in place or held for the next scan.

    A server that exits at once may do so before, or while, a stopped scan puts
    them back. Held, or halfway back, they are taken back by the next scan in
    that directory (core/previous_results).
    """
    places = (output, output / HELD_DIR_NAME, output / RESTORING_DIR_NAME)
    return all(
        any(
            (place / rel).is_file()
            and (place / rel).read_text(encoding="utf-8") == text
            for place in places
        )
        for rel, text in PREVIOUS.items()
    )


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_a_second_ctrl_c_ends_the_tools_and_the_server_while_a_request_is_open(
    tmp_path, transport
):
    """uvicorn's force quit, while its stop waits for a request a client keeps open.

    The first Ctrl-C makes the server wait for the request before the app's
    lifespan stops the scans. The second skips that lifespan, so it is the
    second that has to end the scanners' tools, and the server has to exit
    then rather than wait on for the request.
    """
    import httpx
    from mcp.client.session import ClientSession

    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, transport, port, stderr)
    found: Dict[str, object] = {}
    held: List[socket.socket] = []

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            async with _client(transport, port, http_client) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    begun = await session.call_tool(
                        "run_ash_scan", {"source_dir": str(project)}
                    )
                    found["begun"] = begun.structured_content
                    pids = await anyio.to_thread.run_sync(_wait_for_tree, tmp_path)
                    found["pids"] = pids
                    held.extend(_hold_a_request_open(transport, port))
                    process.send_signal(signal.SIGINT)
                    await anyio.to_thread.run_sync(
                        _wait_until_draining, process, stderr_path
                    )
                    sent = time.monotonic()
                    process.send_signal(signal.SIGINT)
                    found["status"] = await anyio.to_thread.run_sync(
                        _wait_after_signal, process
                    )
                    found["took"] = time.monotonic() - sent
                    found["running"] = _still_running(pids)
                    raise _Done

    try:
        _wait_until_listening(process, port)
        try:
            anyio.run(_run)
        except BaseException as error:  # noqa: BLE001 -- see _Done
            if not _left_with_done(error):
                raise
    finally:
        for connection in held:
            connection.close()
        _stop(process)
        _kill_leftovers(found.get("pids", {}))

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert found["begun"]["result"]["success"] is True, found["begun"]
    assert found["status"] == INTERRUPTED, (
        found["status"],
        found["running"],
        stderr_text[-2000:],
    )
    assert found["took"] < 10.0, (found["took"], stderr_text[-2000:])
    assert found["running"] == NOTHING_RUNNING, (
        "the tool or its child outlived the server",
        found["running"],
    )
    output = project / ".ash" / "ash_output"
    assert _previous_results_kept(output), "the previous results were lost"


#: How long a stop that waits for an open request may take, all told: the
#: server's bound on that wait, the prompt stop of the scans after it, and two
#: seconds for the rest of the shutdown on a loaded host.
BOUNDED_STOP_SECONDS = _GRACEFUL_SHUTDOWN_SECONDS + STDIO_SCAN_STOP_TIMEOUT_SECONDS + 2

#: The grace ``docker stop`` gives a Linux container between SIGTERM and SIGKILL
#: (https://docs.docker.com/reference/cli/docker/container/stop/). The whole
#: bounded stop has to fit inside it.
DOCKER_STOP_GRACE_SECONDS = 10


@pytest.mark.parametrize(
    "signum",
    [signal.SIGINT, signal.SIGTERM, signal.SIGHUP],
    ids=["sigint", "sigterm", "sighup"],
)
@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_one_stop_signal_ends_the_server_while_a_request_is_open(
    tmp_path, transport, signum
):
    """A stop that waits for a request a client keeps open waits a bounded time.

    It waited for as long as the client kept the request open, with the scans'
    tools running, so a service manager's stop (SIGTERM, then SIGKILL once its
    own grace runs out) ended in the SIGKILL, which leaves the tools running.
    Once the bound is up the server stops the scans and ends the tools, and
    exits as that signal makes it exit when nothing waits.
    """
    import httpx
    from mcp.client.session import ClientSession

    project = _project(tmp_path)
    port = _free_port()
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = _start(tmp_path, project, transport, port, stderr)
    found: Dict[str, object] = {}
    held: List[socket.socket] = []

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            async with _client(transport, port, http_client) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    begun = await session.call_tool(
                        "run_ash_scan", {"source_dir": str(project)}
                    )
                    found["begun"] = begun.structured_content
                    pids = await anyio.to_thread.run_sync(_wait_for_tree, tmp_path)
                    found["pids"] = pids
                    held.extend(_hold_a_request_open(transport, port))
                    sent = time.monotonic()
                    process.send_signal(signum)
                    await anyio.to_thread.run_sync(
                        _wait_until_draining, process, stderr_path
                    )
                    found["status"] = await anyio.to_thread.run_sync(
                        _wait_after_signal, process
                    )
                    found["took"] = time.monotonic() - sent
                    found["running"] = _still_running(pids)
                    raise _Done

    try:
        _wait_until_listening(process, port)
        try:
            anyio.run(_run)
        except BaseException as error:  # noqa: BLE001 -- see _Done
            if not _left_with_done(error):
                raise
    finally:
        for connection in held:
            connection.close()
        _stop(process)
        _kill_leftovers(found.get("pids", {}))

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert found["begun"]["result"]["success"] is True, found["begun"]
    assert found["status"] == STOPPED_BY[signum], (
        found["status"],
        found["running"],
        stderr_text[-2000:],
    )
    assert BOUNDED_STOP_SECONDS < DOCKER_STOP_GRACE_SECONDS, BOUNDED_STOP_SECONDS
    assert found["took"] < BOUNDED_STOP_SECONDS, (found["took"], stderr_text[-2000:])
    assert found["running"] == NOTHING_RUNNING, (
        "the tool or its child outlived the server",
        found["running"],
    )
    output = project / ".ash" / "ash_output"
    assert _previous_results_kept(output), "the previous results were lost"


class _Done(Exception):
    """Raised to leave a client session whose server has exited."""


def _left_with_done(error: BaseException) -> bool:
    """Whether ``error`` is, or groups, the _Done that left the session.

    The client's own errors about the server going away may be grouped beside it.
    """
    inner = getattr(error, "exceptions", None)
    if isinstance(inner, tuple):
        return any(_left_with_done(e) for e in inner)
    return isinstance(error, _Done)
