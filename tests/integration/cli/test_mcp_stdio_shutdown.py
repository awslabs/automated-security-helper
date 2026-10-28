# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stdio server stops its scans inside the window its client gives it.

Why this exists
---------------
The MCP SDK's stdio client shuts a server down by closing its stdin, waiting
two seconds, sending SIGTERM to the server's process group, waiting two more
and sending SIGKILL. An `ash mcp` that gave each scanner's tool ten seconds
after SIGTERM, waited up to sixty seconds in all and did not handle SIGTERM
would be ended by the client's SIGTERM in the middle of that wait, with the
previous results still set aside and, since a scanner's tool runs in a process
group of its own, with that tool still running.

The server stops its scans promptly when its client leaves (each tool gets
half a second after SIGTERM, and the server waits at most a second and a half),
and handles SIGTERM the same way. These tests drive a real `ash mcp` process,
once through the SDK's own client and its real shutdown sequence, and once with
a bare SIGTERM. Its scanner is a tool that ignores SIGTERM and starts a child
that ignores it too.

Ctrl-C (SIGINT) is a user's interrupt and takes the same path, with exit status
130. Cancelling the serving instead cannot finish while stdin is open: the
transport reads stdin on a worker thread that a cancel cannot interrupt, so a
server whose client kept the pipe open would still be running 20 seconds after
Ctrl-C. The signal tests below hold stdin open for that reason.

SIGHUP, from a closed terminal or a supervisor, takes it too, with exit status
0. Unhandled, it would end the process at once, with -1: the scanner's tool and
its child would keep running in their own session, and the previous results
would stay in .ash_previous_results.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

import anyio
import pytest

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    holds_restored_results,
)
from tests.utils.helpers import checkout_env
from tests.utils.processes import process_running

# Windows has no SIGHUP, and STOPPED_BY below reads signal.SIGHUP when the module is
# imported, which raised AttributeError at collection. The whole module is about
# POSIX signals, so it is skipped before that line runs.
if sys.platform == "win32":
    pytest.skip("POSIX signals", allow_module_level=True)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

STARTUP_TIMEOUT_SECONDS = 180

BOOTSTRAP = r"""
import sys
from unittest.mock import patch

from automated_security_helper.utils.subprocess_utils import run_command

out = sys.argv.pop(1)

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

    sys.argv = ["ash", "mcp", "--transport", "stdio"]
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


def _env(tmp_path: Path) -> Dict[str, str]:
    """The server's environment, importing ASH from this checkout (checkout_env)."""
    env = checkout_env()
    env["ASH_MCP_ALLOWED_ROOTS"] = str(tmp_path)
    env.pop("ASH_MCP_TRANSPORT", None)
    return env


def _alive(pid: int) -> bool:
    # Not /proc alone: without one (macOS) every check here passed.
    return process_running(pid)


def _wait_for_tree(tmp_path: Path) -> Dict[str, int]:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while not (tmp_path / "tool.pid").exists():
        assert time.monotonic() < deadline, "the scanner's tool never started"
        time.sleep(0.05)
    return {
        name: int((tmp_path / f"{name}.pid").read_text())
        for name in ("tool", "grandchild")
    }


def _settled(project: Path) -> None:
    output = project / ".ash" / "ash_output"
    results = {rel: (output / rel).read_text(encoding="utf-8") for rel in PREVIOUS}
    assert results == PREVIOUS, "the previous results were not put back"
    assert holds_restored_results(output)
    assert not (output / HELD_DIR_NAME).exists(), "a held set was left behind"


def _kill_leftovers(pids: Dict[str, int]) -> None:
    for pid in pids.values():
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)


def test_the_sdk_clients_own_shutdown_leaves_nothing_running(tmp_path):
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    project = _project(tmp_path)
    bootstrap = tmp_path / "bootstrap.py"
    bootstrap.write_text(BOOTSTRAP, encoding="utf-8")
    errlog_path = tmp_path / "server.stderr"
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(bootstrap), str(tmp_path)],
        env=_env(tmp_path),
        cwd=str(project),
    )
    found: Dict[str, object] = {}

    async def _run() -> None:
        with errlog_path.open("w", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    begun = await session.call_tool(
                        "run_ash_scan", {"source_dir": str(project)}
                    )
                    found["begun"] = begun.structured_content
                    found["pids"] = await anyio.to_thread.run_sync(
                        _wait_for_tree, tmp_path
                    )
                found["closed_at"] = time.monotonic()
            # stdio_client has closed stdin and, if it had to, sent SIGTERM and
            # SIGKILL; it returns once the server process is gone.
            found["gone_at"] = time.monotonic()

    anyio.run(_run)
    pids = found["pids"]
    try:
        assert found["begun"]["result"]["success"] is True, found["begun"]
        stderr = errlog_path.read_text(encoding="utf-8", errors="replace")
        assert not _alive(pids["tool"]), (
            f"the tool outlived the server; {stderr[-2000:]}"
        )
        assert not _alive(pids["grandchild"]), "the tool's child outlived the server"
        # Before the client's SIGKILL, which comes four seconds after stdin closes.
        assert found["gone_at"] - found["closed_at"] < 4.0, stderr[-2000:]
        _settled(project)
    finally:
        _kill_leftovers(pids)


def _request(process: subprocess.Popen, request_id: int, method: str, params) -> dict:
    process.stdin.write(
        (
            json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
            + "\n"
        ).encode("utf-8")
    )
    process.stdin.flush()
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        assert line, "the server closed stdout"
        message = json.loads(line)
        if message.get("id") == request_id:
            return message
    raise AssertionError(f"no answer to {method}")


#: What `ash mcp` exits with when each signal stops it. SIGTERM is a request to
#: stop, as a client closing the connection is, and so is SIGHUP, a closed
#: terminal or a supervisor's; SIGINT is the user's interrupt, 130 (128 + SIGINT)
#: as a shell reports one.
STOPPED_BY = {signal.SIGTERM: 0, signal.SIGINT: 130, signal.SIGHUP: 0}

STOP_SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]
STOP_SIGNAL_IDS = ["sigterm", "sigint", "sighup"]

#: Long enough to tell a server that does not stop from a slow one.
EXIT_WAIT_SECONDS = 20


def _wait_for_exit(process: subprocess.Popen):
    """The process's exit status, or None if it is still running."""
    try:
        return process.wait(timeout=EXIT_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        return None


@pytest.mark.parametrize("signum", STOP_SIGNALS, ids=STOP_SIGNAL_IDS)
def test_a_signal_stops_the_scans_as_a_disconnect_does(tmp_path, signum):
    """With stdin still open, as a client that has not left holds it."""
    from mcp.types import LATEST_PROTOCOL_VERSION

    project = _project(tmp_path)
    bootstrap = tmp_path / "bootstrap.py"
    bootstrap.write_text(BOOTSTRAP, encoding="utf-8")
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(bootstrap), str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=str(project),
            env=_env(tmp_path),
        )
    pids: Dict[str, int] = {}
    try:
        _request(
            process,
            1,
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ash-sigterm-test", "version": "0"},
            },
        )
        process.stdin.write(
            b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n'
        )
        process.stdin.flush()
        begun = _request(
            process,
            2,
            "tools/call",
            {"name": "run_ash_scan", "arguments": {"source_dir": str(project)}},
        )
        assert begun["result"]["structuredContent"]["result"]["success"] is True
        pids = _wait_for_tree(tmp_path)

        sent = time.monotonic()
        process.send_signal(signum)
        status = _wait_for_exit(process)
        took = time.monotonic() - sent
        # Before _kill_leftovers: read after it, the answer raced the test's own
        # SIGKILL, so it could say a process the server had left was gone.
        running = {name: _alive(pid) for name, pid in pids.items()}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        _kill_leftovers(pids)

    name = signal.Signals(signum).name
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert status is not None, (
        f"still running {EXIT_WAIT_SECONDS}s after {name}; {stderr_text[-2000:]}"
    )
    assert status == STOPPED_BY[signum], (status, stderr_text[-2000:])
    assert name in stderr_text, stderr_text[-2000:]
    assert took < 4.0, (took, stderr_text[-2000:])
    assert running == {"tool": False, "grandchild": False}, (
        "the tool or its child outlived the server",
        running,
    )
    _settled(project)


#: A scan busy in Python for 8 s, which no cancel check reaches: the interpreter
#: then waits for its thread after the transport has returned.
BUSY_BOOTSTRAP = r"""
import pathlib
import sys
import time
from unittest.mock import patch

out = pathlib.Path(sys.argv.pop(1))


def phases(*args, **kwargs):
    (out / "busy").write_text("1")
    time.sleep(8)
    raise AssertionError("the busy scan finished")


with patch(
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases",
    side_effect=phases,
):
    from automated_security_helper.cli.entrypoint import main

    sys.argv = ["ash", "mcp", "--transport", "stdio"]
    main()
"""


@pytest.mark.parametrize("signum", STOP_SIGNALS, ids=STOP_SIGNAL_IDS)
def test_a_signal_while_the_server_waits_for_a_scan_thread(tmp_path, signum):
    """The SDK client's shutdown: stdin closed, then SIGTERM two seconds later.

    The lifespan stops the scans within STDIO_SCAN_STOP_TIMEOUT_SECONDS and the
    transport returns, but the interpreter still waits for a scan thread busy in
    Python. The watcher must outlive the transport: gone by then, the client's
    SIGTERM would end the server with -15 instead of the 0 a SIGTERM gets while
    it serves, and a Ctrl-C then would be taken for an ordinary return: the
    server would go on waiting for the thread and exit 0.
    """
    from mcp.types import LATEST_PROTOCOL_VERSION

    project = _project(tmp_path)
    bootstrap = tmp_path / "busy_bootstrap.py"
    bootstrap.write_text(BUSY_BOOTSTRAP, encoding="utf-8")
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(bootstrap), str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=str(project),
            env=_env(tmp_path),
        )
    try:
        _request(
            process,
            1,
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ash-late-sigterm-test", "version": "0"},
            },
        )
        process.stdin.write(
            b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n'
        )
        process.stdin.flush()
        begun = _request(
            process,
            2,
            "tools/call",
            {"name": "run_ash_scan", "arguments": {"source_dir": str(project)}},
        )
        assert begun["result"]["structuredContent"]["result"]["success"] is True
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not (tmp_path / "busy").exists():
            assert time.monotonic() < deadline, "the busy scan never started"
            time.sleep(0.05)

        process.stdin.close()
        closed = time.monotonic()
        time.sleep(2.0)
        process.send_signal(signum)
        status = _wait_for_exit(process)
        took = time.monotonic() - closed
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert status == STOPPED_BY[signum], (status, stderr_text[-2000:])
    assert took < 6.0, (took, stderr_text[-2000:])


#: A scan whose phases raise ScannerError, the error a scanner raises when it
#: cannot run.
FAILING_BOOTSTRAP = r"""
import sys
from unittest.mock import patch

from automated_security_helper.core.exceptions import ScannerError


def phases(*args, **kwargs):
    raise ScannerError("the scanner could not run")


with patch(
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases",
    side_effect=phases,
):
    from automated_security_helper.cli.entrypoint import main

    sys.argv = ["ash", "mcp", "--transport", "stdio"]
    main()
"""


def test_a_failed_scan_does_not_end_the_server_or_set_its_exit_status(tmp_path):
    """A scan's failure is the scan's, reported to the client; `ash mcp` exits 0.

    The server goes on serving after the scan fails, and exits 0 when its client
    closes the connection. A mcp_command mapping of ScannerError to exit 2 would
    be dead code: a scan's exceptions end that scan as failed and never reach it.
    """
    from mcp.types import LATEST_PROTOCOL_VERSION

    project = _project(tmp_path)
    bootstrap = tmp_path / "failing_bootstrap.py"
    bootstrap.write_text(FAILING_BOOTSTRAP, encoding="utf-8")
    stderr_path = tmp_path / "server.stderr"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(bootstrap)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=str(project),
            env=_env(tmp_path),
        )
    try:
        _request(
            process,
            1,
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ash-failed-scan-test", "version": "0"},
            },
        )
        process.stdin.write(
            b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n'
        )
        process.stdin.flush()
        begun = _request(
            process,
            2,
            "tools/call",
            {"name": "run_ash_scan", "arguments": {"source_dir": str(project)}},
        )
        started = begun["result"]["structuredContent"]["result"]
        assert started["success"] is True, started
        request_id = 3
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while True:
            answer = _request(
                process,
                request_id,
                "tools/call",
                {
                    "name": "get_scan_progress",
                    "arguments": {"scan_id": started["scan_id"]},
                },
            )
            progress = answer["result"]["structuredContent"]["result"]
            if progress.get("is_complete"):
                break
            assert time.monotonic() < deadline, progress
            request_id += 1
            time.sleep(0.2)
        # Still serving after the failure.
        listed = _request(
            process,
            request_id + 1,
            "tools/call",
            {"name": "list_active_scans", "arguments": {}},
        )

        process.stdin.close()
        status = _wait_for_exit(process)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    assert progress["status"] == "failed", progress
    assert "result" in listed, listed
    assert status == 0, (status, stderr_text[-2000:])


#: `ash mcp` exactly as the CLI runs it, with nothing patched.
PLAIN_SERVER = (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', 'mcp', '--transport', 'stdio']\n"
    "main()\n"
)


def test_an_invalid_operator_config_refuses_to_start_with_exit_3(tmp_path):
    """The nearest real ASHValidationError an `ash mcp` process meets.

    ASH_CONFIG names the operator's config, and the base it extends is missing,
    so loading it raises ASHConfigSourceError, an ASHValidationError. ASH_CONFIG
    is the policy of every scan that names no config of its own, so the server
    loads it once, at startup (mcp_command's _ash_config_refusal), before
    anything is served: a file it cannot load is refused there with exit 3, the
    code an invalid config exits with, and the error on stderr names the base.
    Nothing is served first, so a client that connects reads EOF on stdout. A
    server that read the file per scan instead would start, and every scan that
    named no config would then run on the built-in default in place of the
    operator's policy.
    """
    project = _project(tmp_path)
    operator_config = tmp_path / "operator-ash.yaml"
    operator_config.write_text("extends: ./missing-base.yaml\n", encoding="utf-8")
    env = _env(tmp_path)
    env["ASH_CONFIG"] = str(operator_config)
    stderr_path = tmp_path / "server.stderr"
    # stdin is EOF from the start: a server that wrongly starts serving reads
    # the EOF, exits, and fails the status assertion below, instead of waiting
    # on stdin for a client that never writes. communicate bounds the wait by
    # the cold-start allowance and reads stdout to its end, so a slow start is
    # not reported as a wrong exit status.
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-c", PLAIN_SERVER],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=str(project),
            env=env,
        )
    try:
        served, _ = process.communicate(timeout=STARTUP_TIMEOUT_SECONDS)
        status = process.returncode
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    # The refusal is printed through a console that wraps at 80 columns when
    # stderr is not a terminal, so the text is read with its line breaks and
    # spaces removed: a path or a sentence split across lines still matches.
    compact = "".join(stderr_text.split())
    assert status == 3, (status, stderr_text[-2000:])
    assert "ValidationError:" in compact, stderr_text[-2000:]
    assert "missing-base.yaml" in compact, stderr_text[-2000:]
    assert served == b"", served[:2000]
