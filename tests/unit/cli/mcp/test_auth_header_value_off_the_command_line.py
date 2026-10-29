# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` takes the auth header value from a file or a descriptor, off its argv.

A process's command line is readable by every local user (``/proc/<pid>/cmdline``),
so ``--auth-header-value <value>`` shows the value to anyone on the host.
``--auth-header-value-file PATH`` and ``--auth-header-value-fd N`` hand it over
instead, read once at startup:

- the file must be a regular file, not a symlink, with no permission bits for the
  group or other users (POSIX); the descriptor must not be 0, 1 or 2, and is
  closed once read;
- one trailing newline is dropped, and an empty value, a value with a line break or
  NUL, or one over 16 KiB, is refused;
- only one of the three forms may be given.

The argv form still works, and ``ash mcp`` warns on stderr that it puts the value on
the command line, naming the two options. Every refusal exits with the usage-error
code (``ASH_EXIT_USAGE_ERROR``) before anything is served.
"""

from __future__ import annotations

import io
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from typing import Dict, List, Optional

import httpx
import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.helpers import KillAfter

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and fifos")
PROC = pytest.mark.skipif(
    not Path("/proc/self/cmdline").exists(), reason="needs /proc/<pid>/cmdline"
)
HEADER = "X-Ash-Token"


class _Ctx:
    resilient_parsing = False


@pytest.fixture
def stderr(monkeypatch) -> io.StringIO:
    buffer = io.StringIO()
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._stderr",
        Console(file=buffer, width=400, color_system=None),
    )
    return buffer


@pytest.fixture
def built(monkeypatch) -> Dict[str, object]:
    """Record what the app is built with, instead of serving it."""
    record: Dict[str, object] = {}
    for name in ("ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)

    def build(**kwargs):
        record.update(kwargs)
        return object()

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", build
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: record.update(served=True),
    )
    return record


def _start(**kwargs) -> None:
    mcp_command(
        ctx=_Ctx(),
        transport="streamable-http",
        host="127.0.0.1",
        port=8765,
        auth_header_name=HEADER,
        quiet=True,
        **kwargs,
    )


def _secret_file(tmp_path: Path, content: bytes, mode: int = 0o600) -> Path:
    path = tmp_path / "header-value"
    path.write_bytes(content)
    path.chmod(mode)
    return path


# -- the file ---------------------------------------------------------------


@pytest.mark.unit
def test_a_private_file_supplies_the_value(tmp_path, built) -> None:
    path = _secret_file(tmp_path, b"from-a-file\n")

    _start(auth_header_value_file=path)

    assert built["auth_header_value"] == "from-a-file"
    assert built.get("served") is True


@pytest.mark.unit
def test_only_one_trailing_newline_is_dropped(tmp_path, built) -> None:
    path = _secret_file(tmp_path, b"crlf-ended\r\n")

    _start(auth_header_value_file=path)

    assert built["auth_header_value"] == "crlf-ended"


@POSIX
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o620, 0o644])
@pytest.mark.unit
def test_a_file_other_users_can_read_or_write_is_refused(
    tmp_path, built, stderr, mode
) -> None:
    path = _secret_file(tmp_path, b"too-open\n", mode)

    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_file=path)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "served" not in built
    assert "too-open" not in stderr.getvalue()


@POSIX
@pytest.mark.unit
def test_a_symlink_is_refused(tmp_path, built) -> None:
    target = _secret_file(tmp_path, b"behind-a-link\n")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_file=link)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "served" not in built


@POSIX
@pytest.mark.unit
def test_a_fifo_is_refused_without_blocking(tmp_path, built) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)

    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_file=fifo)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


@pytest.mark.parametrize(
    "case",
    ["missing", "directory", "empty", "only-a-newline", "too-large", "two-lines"],
)
@pytest.mark.unit
def test_a_file_that_holds_no_usable_value_is_refused(tmp_path, built, case) -> None:
    path = tmp_path / "header-value"
    if case == "directory":
        path.mkdir()
    elif case != "missing":
        content = {
            "empty": b"",
            "only-a-newline": b"\n",
            "too-large": b"x" * (16 * 1024 + 1),
            "two-lines": b"first\nsecond\n",
        }[case]
        _secret_file(tmp_path, content)

    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_file=path)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "served" not in built


# -- the descriptor ---------------------------------------------------------


@pytest.mark.unit
def test_a_pipe_descriptor_supplies_the_value_and_is_closed(built) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b"from-a-pipe\n")
    os.close(write_end)

    _start(auth_header_value_fd=read_end)

    assert built["auth_header_value"] == "from-a-pipe"
    with pytest.raises(OSError):
        os.fstat(read_end)


@pytest.mark.unit
def test_a_file_descriptor_is_read_from_its_start(tmp_path, built) -> None:
    path = tmp_path / "written"
    handle = open(path, "w+b")
    handle.write(b"already-written\n")  # the offset is now at the end
    handle.flush()
    fd = os.dup(handle.fileno())
    handle.close()

    _start(auth_header_value_fd=fd)

    assert built["auth_header_value"] == "already-written"


@pytest.mark.parametrize("fd", [0, 1, 2, -1])
@pytest.mark.unit
def test_a_standard_or_negative_descriptor_is_refused(built, fd) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_fd=fd)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "served" not in built


@pytest.mark.unit
def test_a_descriptor_that_is_not_open_is_refused(built) -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    os.close(write_end)

    with pytest.raises(typer.Exit) as excinfo:
        _start(auth_header_value_fd=read_end)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


# -- the forms together and the argv form ------------------------------------


@pytest.mark.parametrize("pair", ["value+file", "value+fd", "file+fd"])
@pytest.mark.unit
def test_only_one_form_may_be_given(tmp_path, built, pair) -> None:
    path = _secret_file(tmp_path, b"one\n")
    read_end, write_end = os.pipe()
    os.write(write_end, b"two\n")
    os.close(write_end)
    forms = {
        "value": {"auth_header_value": "zero"},
        "file": {"auth_header_value_file": path},
        "fd": {"auth_header_value_fd": read_end},
    }
    kwargs: Dict[str, object] = {}
    for name in pair.split("+"):
        kwargs.update(forms[name])

    try:
        with pytest.raises(typer.Exit) as excinfo:
            _start(**kwargs)
    finally:
        try:
            os.close(read_end)
        except OSError:
            pass

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert "served" not in built


@pytest.mark.unit
def test_a_name_with_no_value_in_any_form_is_refused(built) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        _start()

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


@pytest.mark.unit
def test_the_argv_form_still_works_and_warns(built, stderr) -> None:
    _start(auth_header_value="on-the-command-line")

    assert built["auth_header_value"] == "on-the-command-line"
    message = " ".join(stderr.getvalue().split())
    assert "--auth-header-value-file" in message, message
    assert "--auth-header-value-fd" in message, message
    assert "on-the-command-line" not in message


@pytest.mark.unit
def test_the_file_form_does_not_warn(tmp_path, built, stderr) -> None:
    _start(auth_header_value_file=_secret_file(tmp_path, b"quiet\n"))

    assert "--auth-header-value-file" not in stderr.getvalue()


# -- a real server -------------------------------------------------------------


def _command_lines() -> List[bytes]:
    lines = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            lines.append((entry / "cmdline").read_bytes())
        except OSError:
            continue
    return lines


def _serve(argv_tail: List[str], tmp_path: Path, pass_fds=()) -> subprocess.Popen:
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
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--auth-header-name",
            HEADER,
            *argv_tail,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
        cwd=tmp_path,
        pass_fds=pass_fds,
        text=True,
    )


def _listening_port(server: subprocess.Popen) -> int:
    for line in server.stderr:
        found = re.search(r"listening on http://127\.0\.0\.1:(\d+)/mcp", line)
        if found:
            return int(found.group(1))
    raise AssertionError(f"the server exited before listening: {server.wait()}")


def _wait_for(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.5)):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def _statuses(port: int, value: str) -> List[int]:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ash-test", "version": "0"},
        },
    }
    base = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    url = f"http://127.0.0.1:{port}/mcp"
    statuses = []
    for extra in ({}, {HEADER: "not-" + value}, {HEADER: value}):
        response = httpx.post(url, json=body, headers={**base, **extra}, timeout=10)
        statuses.append(response.status_code)
    return statuses


def _run(form: str, value: str, tmp_path: Path) -> Dict[str, object]:
    pass_fds: tuple = ()
    read_end: Optional[int] = None
    if form == "file":
        tail = [
            "--auth-header-value-file",
            str(_secret_file(tmp_path, value.encode() + b"\n")),
        ]
    elif form == "fd":
        read_end, write_end = os.pipe()
        os.write(write_end, value.encode() + b"\n")
        os.close(write_end)
        tail = ["--auth-header-value-fd", str(read_end)]
        pass_fds = (read_end,)
    else:
        tail = ["--auth-header-value", value]
    server = _serve(tail, tmp_path, pass_fds)
    if read_end is not None:
        os.close(read_end)
    try:
        # Reading the server's stderr for its listening line blocks until it
        # writes one or exits; the kill ends a server that does neither.
        with KillAfter(server, "the ash mcp server"):
            port = _listening_port(server)
            _wait_for(port)
            on_a_command_line = any(value.encode() in line for line in _command_lines())
            statuses = _statuses(port, value)
        return {"statuses": statuses, "on_a_command_line": on_a_command_line}
    finally:
        server.terminate()
        try:
            server.wait(timeout=30)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=30)


@PROC
@pytest.mark.parametrize("form", ["file", "fd"])
@pytest.mark.e2e
def test_a_served_value_is_on_no_command_line_and_still_checked(tmp_path, form) -> None:
    value = "ash-" + secrets.token_hex(16)

    outcome = _run(form, value, tmp_path)

    assert outcome["on_a_command_line"] is False, "the value is on a command line"
    assert outcome["statuses"] == [401, 401, 200], outcome


@PROC
@pytest.mark.e2e
def test_the_command_line_check_sees_the_argv_form(tmp_path) -> None:
    """The control: the same scan finds the value when it is passed on argv."""
    value = "ash-" + secrets.token_hex(16)

    outcome = _run("argv", value, tmp_path)

    assert outcome["on_a_command_line"] is True
    assert outcome["statuses"] == [401, 401, 200], outcome
