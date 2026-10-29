# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan through a real `ash mcp` stdio process: cancelled, or left by its client.

Why this exists
---------------
On the stdio transport stdout is the JSON-RPC channel. An `ash mcp` server was
seen writing an ANSI Rich panel there around a cancelled scan. The SDK points fd 1
at stderr while it serves, so a scan's output is safe while the client is
connected. It is not safe after: when the client closes the connection the SDK
puts fd 1 back on the client's pipe, and a scan still running then writes
straight into it. Three things did that:

* MCP scans ran with the Rich live progress display on (run_ash_scan's default),
  which redraws a panel four times a second from its own thread and replaces
  ``sys.stdout`` while it runs;
* ``print`` output is block-buffered when stdout is a pipe, so text a scan printed
  while fd 1 was diverted sat in the buffer and was flushed to the wire at exit;
* nothing stopped the scan when the client left, so it went on printing until it
  finished.

test_mcp_stdio_server.py checks the stream while a server answers requests, and
its docstring says why it runs no scan. These tests do run one, because the
failure is in how a scan ends: they read every byte the process writes to stdout
until it exits.

What a stdio disconnect does to a running scan
----------------------------------------------
A stdio server's lifetime is its client's: the client started the process and
nothing else can talk to it, so a scan nobody can poll or collect has no one to
report to. When the client closes the connection, the server cancels every scan
still running, waits for each to stop (its scanner's child process is stopped
the way cancel_scan stops one), and exits 0. The previous scan's results in each
output directory are put back, as for any cancelled scan. These tests pin that.

How the scan is made deterministic
----------------------------------
The child process runs a small bootstrap that replaces the scan phases with one
that prints through every path a scan prints through (a Rich panel, a plain
buffered print, a child process inheriting fd 1) and then waits on a child
process through ASH's own ``run_command``, which is where a cancel reaches a
real scanner. Everything else, from ``ash mcp`` and the transport to the
registry, the runner and run_ash_scan, is the real code.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tests.utils.helpers import checkout_env

# Long enough for a cold import of ASH under a wide parallel run.
STARTUP_TIMEOUT_SECONDS = 180
# A cancelled scanner's child gets SANDBOX_STOP_GRACE_SECONDS (10s) after SIGTERM.
STOP_TIMEOUT_SECONDS = 60

PRINTED = (
    "PANEL-WHILE-SCANNING",
    "PLAIN-WHILE-SCANNING",
    "CHILD-WHILE-SCANNING",
    "PANEL-AFTER-STOP",
    "PLAIN-AFTER-STOP",
)

BOOTSTRAP = r"""
import sys
from pathlib import Path
from unittest.mock import patch

from rich import print as rich_print
from rich.panel import Panel

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.utils.subprocess_utils import run_command

started, pid_file = sys.argv.pop(1), sys.argv.pop(1)

CHILD = (
    "import os, sys, time, pathlib\n"
    "print('CHILD-WHILE-SCANNING', flush=True)\n"
    "pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))\n"
    "pathlib.Path(sys.argv[1]).touch()\n"
    "time.sleep(120)\n"
)


def phases(*args, **kwargs):
    rich_print(Panel("PANEL-WHILE-SCANNING"))
    print("PLAIN-WHILE-SCANNING")
    try:
        run_command(
            [sys.executable, "-c", CHILD, started, pid_file], capture_output=False
        )
    except ScanCancelled:
        rich_print(Panel("PANEL-AFTER-STOP"))
        print("PLAIN-AFTER-STOP")
        raise
    raise AssertionError("the scan was not stopped")


with patch(
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases",
    side_effect=phases,
):
    from automated_security_helper.cli.entrypoint import main

    sys.argv = ["ash", "mcp", "--transport", "stdio"]
    main()
"""


class _Server:
    """An `ash mcp` child spoken to over its own pipes, every byte of stdout kept."""

    def __init__(self, tmp_path: Path, project: Path) -> None:
        self.started = tmp_path / "started"
        self.pid_file = tmp_path / "child.pid"
        bootstrap = tmp_path / "bootstrap.py"
        bootstrap.write_text(BOOTSTRAP, encoding="utf-8")
        env = checkout_env()
        env["ASH_MCP_ALLOWED_ROOTS"] = str(tmp_path)
        env.pop("ASH_MCP_TRANSPORT", None)
        # What a client started from a terminal gets: Rich renders with ANSI codes.
        env["FORCE_COLOR"] = "1"
        env.pop("CI", None)
        self.process = subprocess.Popen(
            [sys.executable, str(bootstrap), str(self.started), str(self.pid_file)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(project),
            env=env,
        )
        self.stdout: List[bytes] = []
        self.stderr: List[bytes] = []
        self._frames: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self._readers:
            reader.start()
        self._next_id = 0

    def _read_stdout(self) -> None:
        for raw in iter(self.process.stdout.readline, b""):
            self.stdout.append(raw)
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self._frames.put(message)
        self._frames.put(None)

    def _read_stderr(self) -> None:
        for raw in iter(self.process.stderr.readline, b""):
            self.stderr.append(raw)

    def send(self, payload: Dict[str, Any]) -> None:
        self.process.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self.send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"no answer to {method}; stderr: {self.stderr_tail()}"
            message = self._frames.get(timeout=remaining)
            assert message is not None, (
                f"the server exited before answering {method}; "
                f"stderr: {self.stderr_tail()}"
            )
            if message.get("id") == request_id:
                return message

    def call(self, tool: str, **arguments: Any) -> Dict[str, Any]:
        response = self.request("tools/call", {"name": tool, "arguments": arguments})
        assert "result" in response, response
        return response["result"]["structuredContent"]["result"]

    def initialize(self) -> None:
        from mcp.types import LATEST_PROTOCOL_VERSION

        response = self.request(
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ash-stdio-scan-test", "version": "0"},
            },
        )
        assert "result" in response, response
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def wait_for_the_scanner(self) -> int:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not self.started.exists():
            assert self.process.poll() is None, self.stderr_tail()
            assert time.monotonic() < deadline, (
                f"the scanner never started; stderr: {self.stderr_tail()}"
            )
            time.sleep(0.05)
        return int(self.pid_file.read_text())

    def close_and_wait(self) -> int:
        """Close the client's end, read stdout to EOF, return the exit status."""
        self.process.stdin.close()
        try:
            status = self.process.wait(timeout=STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            pytest.fail(
                f"`ash mcp` was still running {STOP_TIMEOUT_SECONDS}s after its "
                f"client closed the connection; stderr: {self.stderr_tail()}"
            )
        for reader in self._readers:
            reader.join(timeout=STOP_TIMEOUT_SECONDS)
        return status

    def stderr_tail(self) -> str:
        return b"".join(self.stderr).decode("utf-8", errors="replace")[-3000:]

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def _project_with_previous_results(tmp_path: Path) -> tuple[Path, Dict[str, str]]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    previous = {
        "reports/ash.sarif": '{"previous": "sarif"}',
        "ash_aggregated_results.json": '{"previous": "results"}',
    }
    output = project / ".ash" / "ash_output"
    for rel, text in previous.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return project, previous


def _results(project: Path, previous: Dict[str, str]) -> Dict[str, str]:
    output = project / ".ash" / "ash_output"
    return {rel: (output / rel).read_text(encoding="utf-8") for rel in previous}


def _assert_only_frames(server: _Server) -> None:
    offenders = []
    for raw in server.stdout:
        line = raw.decode("utf-8", errors="replace")
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            offenders.append(line)
            continue
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            offenders.append(line)
    assert not offenders, (
        "These lines reached stdout, the JSON-RPC channel, and are not frames: "
        f"{offenders[:5]}"
    )
    assert b"\x1b[" not in b"".join(server.stdout), "ANSI escape codes on stdout"
    # The test proves something only if the scan did print: on stderr.
    stderr = b"".join(server.stderr).decode("utf-8", errors="replace")
    missing = [marker for marker in PRINTED if marker not in stderr]
    assert not missing, (
        f"{missing} never reached stderr either, so the scan did not print what "
        "this test needs it to print; the stdout check above proves nothing. "
        f"stderr: {server.stderr_tail()}"
    )


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def test_a_cancelled_scan_writes_nothing_but_frames_to_stdout(tmp_path):
    project, previous = _project_with_previous_results(tmp_path)
    server = _Server(tmp_path, project)
    try:
        server.initialize()
        begun = server.call("run_ash_scan", source_dir=str(project))
        assert begun["success"] is True, begun
        child = server.wait_for_the_scanner()

        cancelled = server.call("cancel_scan", scan_id=begun["scan_id"])
        assert cancelled["success"] is True, cancelled
        deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
        while True:
            progress = server.call("get_scan_progress", scan_id=begun["scan_id"])
            if _gone(child) and progress["is_complete"]:
                break
            assert time.monotonic() < deadline, progress
            time.sleep(0.2)
        assert progress["status"] == "cancelled", progress

        status = server.close_and_wait()
    finally:
        server.kill()

    assert status == 0, server.stderr_tail()
    _assert_only_frames(server)
    assert _results(project, previous) == previous


def test_a_client_that_disconnects_mid_scan_stops_the_scan_cleanly(tmp_path):
    project, previous = _project_with_previous_results(tmp_path)
    server = _Server(tmp_path, project)
    try:
        server.initialize()
        begun = server.call("run_ash_scan", source_dir=str(project))
        assert begun["success"] is True, begun
        child = server.wait_for_the_scanner()

        status = server.close_and_wait()
    finally:
        server.kill()

    assert status == 0, (
        f"`ash mcp` exited {status} when its client disconnected mid-scan; "
        f"stderr: {server.stderr_tail()}"
    )
    assert _gone(child), "the scan's child process outlived the server"
    # Stopped by the server because its client left, not by the event loop's
    # teardown cancelling whatever was still running.
    assert "the stdio client closed the connection" in server.stderr_tail(), (
        server.stderr_tail()
    )
    _assert_only_frames(server)
    assert _results(project, previous) == previous, (
        "the previous scan's results were not put back after the disconnect"
    )
