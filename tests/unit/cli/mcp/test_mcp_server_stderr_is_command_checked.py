# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python's writes to the MCP server's stderr and stdout carry no CI command,
whichever sink wrote the line. An ``os.write`` on the fd and a child process
that inherits it are outside this check, and so are bytes written to
``sys.stdout.buffer``, which carries the SDK's JSON-RPC frames; bytes written
to ``sys.stderr.buffer`` are checked.

Why this exists
---------------
route_library_handlers_through_command_check routes the handlers that are there
when it runs, so a sink that is not a handler still writes to stderr as given:
logging.lastResort for a library logger with no handler, warnings.showwarning,
and the thread and sys excepthooks. Each writes text that can hold what a
client sent. When the server starts (run_mcp_server for stdio, cli/mcp's
_run_uvicorn for the HTTP transports), sys.stderr and sys.stdout are each
wrapped once in CommandSafeStream, so those sinks go through the check too, and
a line a runner would read as a command ("::" at a line start, "##name[") comes
out broken. A handler whose stream was already wrapped writes byte-identically
through both, so the double wrap changes nothing. Importing the server module
wraps neither stream: a program that imports it for its tool registry, or a
test, keeps its own.

The one wrap of a stream is written from many threads, each under a lock of its
own or none (two Rich consoles, lastResort, the hooks, a scan thread's print).
Whether the next text starts a line is read and acted on under the wrap's own
lock, so a write that read "mid-line" cannot land after another thread's line
break. A signal handler's write on the same thread, inside an outer write,
is deferred: it lands once the outer text has, checked from the line state
that text left, so neither write lands at a state the check did not read.

The wrap stands in for the stream for every reader of it. It reports the
stream's encoding, errors, isatty and buffer, so Rich sees a terminal where
there is one and the SDK finds fd 1. click and typer write through it: on
stdout, a stream whose encoding is ASCII, which click replaces with a writer
of its own on the binary buffer, is set to UTF-8 first; on stderr, the buffer
the wrap hands out checks bytes itself, under the same lock and line state,
decoding them only to find command forms, so the stream's own encoding, and
every byte outside an inserted escape, stays as it was. On Windows, the UTF-8
writer configure_windows_safe_logging puts in a stream's place, when it cannot
reconfigure the stream, is wrapped again.

A server started with no stderr at all (pythonw, or a start whose fd 2 was
closed, which ensure_std_streams leaves None) has nothing to wrap: a wrap of
None turned every write Python makes with no stderr into an AttributeError.

Most children import the server module and make the two calls the server's
start makes, then emit through one raw sink; the parent reads the real process
stderr. Two children start a transport itself, and one only imports.
"""

from __future__ import annotations

import io
import locale
import os
import platform
import re
import signal
import subprocess  # nosec B404 - the code under test runs in a child process
import sys
import threading

import pytest

from tests.utils.helpers import checkout_env, importing_this_checkout

#: A line a runner reads as a command: "::" at a line start, after optional
#: whitespace, or "##name[" anywhere.
_LINE_START_COMMAND = re.compile(r"^\s*::", re.MULTILINE)
_NAMED_HASH_COMMAND = re.compile(r"##[A-Za-z]*\[")

#: The two calls run_mcp_server and cli/mcp's _run_uvicorn make as the server
#: starts.
_STARTED = """
from automated_security_helper.utils.log import (
    check_commands_of_stderr,
    check_commands_of_stdout,
)

check_commands_of_stderr()
check_commands_of_stdout()
"""

_CHILD = (
    """
import logging
import sys
import threading
import warnings

import automated_security_helper.cli.mcp_server  # noqa: F401
"""
    + _STARTED
    + """
sink = sys.argv[1]
if sink == "library-logger":
    # No handler anywhere on its chain: logging.lastResort writes it.
    logging.getLogger("somelib.transport").propagate = False
    logging.getLogger("somelib.transport").warning(
        "retrying\\n::add-mask::CANLOG x##vso[task.setvariable variable=x]CANLOG2"
    )
elif sink == "warnings":
    warnings.warn("deprecated\\n::add-mask::CANWARN")
elif sink == "thread-exception":
    def boom():
        raise RuntimeError("thread said\\n::add-mask::CANTHREAD")

    worker = threading.Thread(target=boom)
    worker.start()
    worker.join()
elif sink == "sys-excepthook":
    # Uncaught at the top level: sys.excepthook writes the traceback.
    raise RuntimeError("top level said\\n::add-mask::CANHOOK")
else:
    raise SystemExit(f"unknown sink {sink}")
"""
)

SINKS = {
    "library-logger": ("CANLOG", "CANLOG2"),
    "warnings": ("CANWARN",),
    "thread-exception": ("CANTHREAD",),
    "sys-excepthook": ("CANHOOK",),
}


def _env():
    env = checkout_env()
    for name in ("ASH_LOG_TO_STDERR", "GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION"):
        env.pop(name, None)
    env["COLUMNS"] = "100"
    return env


def _run_child(code: str, tmp_path, *args: str, stdin=None):
    return subprocess.run(  # nosec B603 - this interpreter, fixed code
        [sys.executable, "-c", importing_this_checkout(code), *args],
        cwd=tmp_path,
        env=_env(),
        input=stdin,
        capture_output=True,
        timeout=120,
        text=True,
    )


def _assert_no_command(text: str) -> None:
    assert not _LINE_START_COMMAND.search(text), text
    assert not _NAMED_HASH_COMMAND.search(text), text


@pytest.mark.parametrize("sink", sorted(SINKS))
@pytest.mark.integration
def test_a_raw_sinks_line_on_stderr_has_its_commands_broken(sink, tmp_path):
    child = _run_child(_CHILD, tmp_path, sink)

    stderr = child.stderr
    # The control: the sink wrote its text, canaries included.
    for canary in SINKS[sink]:
        assert canary in stderr, (sink, stderr)
    _assert_no_command(stderr)


_IMPORT_CHILD = """
import sys

import automated_security_helper.cli.mcp  # noqa: F401
import automated_security_helper.cli.mcp_server  # noqa: F401
from automated_security_helper.utils.command_safe_stream import CommandSafeStream

sys.stdout.write(f"STDERR {isinstance(sys.stderr, CommandSafeStream)}\\n")
sys.stdout.write(f"STDOUT {isinstance(sys.stdout, CommandSafeStream)}\\n")
"""


@pytest.mark.integration
def test_importing_the_server_leaves_the_std_streams_as_they_are(tmp_path):
    """A program that imports the server for its tool registry, or a test, keeps
    its own sys.stderr and sys.stdout: the server wraps them when it starts."""
    child = _run_child(_IMPORT_CHILD, tmp_path)

    assert child.returncode == 0, child.stderr[-2000:]
    lines = child.stdout.splitlines()
    assert "STDERR False" in lines, (child.stdout, child.stderr)
    assert "STDOUT False" in lines, (child.stdout, child.stderr)


_START_CHILD = """
import sys
import warnings


def emit():
    warnings.warn(
        "deprecated\\n::add-mask::CANSTART x##vso[task.setvariable variable=x]CANSTART2"
    )
    print("stray\\n::add-mask::CANPRINT", flush=True)


if sys.argv[1] == "stdio":
    import automated_security_helper.cli.mcp_server as server

    async def serve():
        emit()

    # The server's own start, serving this in place of the tools.
    server._serve_stdio = serve
    server.run_mcp_server()
else:
    import automated_security_helper.cli.mcp as cli_mcp
    from automated_security_helper.core.enums import AshLogLevel

    served = cli_mcp._uvicorn_server_class()

    class Served(served):
        # uvicorn's own server, serving this in place of the app. A server that
        # served has started, as uvicorn's startup records; the runner treats
        # one that never started as a failed start.
        def run(self, sockets=None):
            self.started = True
            emit()

    cli_mcp._uvicorn_server_class = lambda: Served
    cli_mcp._run_uvicorn(None, host="127.0.0.1", port=0, log_level=AshLogLevel.INFO)
"""


@pytest.mark.parametrize("transport", ["http", "stdio"])
@pytest.mark.integration
def test_each_transports_start_checks_stderr_and_stdout(transport, tmp_path):
    """run_mcp_server (stdio) and _run_uvicorn (the HTTP transports) wrap both
    streams before they serve."""
    child = _run_child(_START_CHILD, tmp_path, transport, stdin="")

    assert child.returncode == 0, child.stderr[-2000:]
    # The control: the warning and the print were written.
    assert "CANSTART2" in child.stderr, child.stderr
    assert "CANPRINT" in child.stdout, child.stdout
    _assert_no_command(child.stderr)
    _assert_no_command(child.stdout)


_UVICORN_SHARES_THE_WRAP_CHILD = """
import logging
import sys

import automated_security_helper.cli.mcp as cli_mcp
from automated_security_helper.core.enums import AshLogLevel

served = cli_mcp._uvicorn_server_class()


class Served(served):
    # uvicorn's own server, serving this in place of the app: a line written to
    # stderr in two parts, with a uvicorn log line landing between them. It
    # records that it started, as uvicorn's startup does.
    def run(self, sockets=None):
        self.started = True
        sys.stderr.write("abc")
        logging.getLogger("uvicorn.error").info("served")
        sys.stderr.write("::add-mask::CANUVICORN\\n")
        sys.stderr.flush()


cli_mcp._uvicorn_server_class = lambda: Served
cli_mcp._run_uvicorn(None, host="127.0.0.1", port=0, log_level=AshLogLevel.INFO)
"""


@pytest.mark.integration
def test_uvicorns_log_lines_and_stderr_writes_share_one_line_state(tmp_path):
    """uvicorn's handlers take sys.stderr when uvicorn.Config sets up logging, so
    stderr is wrapped before that: their lines and the process's other stderr
    writes then go through one wrap, and one line state sees both."""
    child = _run_child(_UVICORN_SHARES_THE_WRAP_CHILD, tmp_path, stdin="")

    assert child.returncode == 0, child.stderr[-2000:]
    # The control: uvicorn's line landed between the two writes.
    assert "served\n" in child.stderr and "CANUVICORN" in child.stderr, child.stderr
    _assert_no_command(child.stderr)


_STRAY_STDOUT_CHILD = """
import automated_security_helper.cli.mcp_server as server
from mcp.server.stdio import stdio_server


async def serve_then_stop():
    async with stdio_server() as (read_stream, write_stream):
        # While the server serves, fd 1 points at stderr: a raw write to stdout,
        # a print or a library's, lands there.
        print(
            "stray line\\n::add-mask::CANSTDOUT x##vso[task.setvariable variable=x]CANSTDOUT2",
            flush=True,
        )
        await write_stream.aclose()
        await read_stream.aclose()


# The server's own start, serving this in place of the tools.
server._serve_stdio = serve_then_stop
server.run_mcp_server()
"""


@pytest.mark.integration
def test_a_raw_stdout_write_while_serving_has_its_commands_broken(tmp_path):
    """The stdio server writes its frames through its own copy of fd 1 and points
    fd 1 at stderr, so a stray stdout write reaches stderr, which a CI step reads."""
    child = _run_child(_STRAY_STDOUT_CHILD, tmp_path, stdin="")

    assert child.returncode == 0, child.stderr[-2000:]
    # The control: the line missed the wire and reached stderr.
    assert "CANSTDOUT" not in child.stdout, child.stdout
    assert "CANSTDOUT2" in child.stderr, child.stderr
    _assert_no_command(child.stderr)


_IDENTITY_CHILD = """
import logging
import sys

import automated_security_helper.cli.mcp_server  # noqa: F401
from automated_security_helper.utils.command_safe_stream import CommandSafeStream
from automated_security_helper.utils.log import check_commands_of_stderr

if sys.argv[1] == "with-the-wrap":
    # As the server's start wraps it.
    check_commands_of_stderr()

sys.stdout.write(f"WRAPPED {isinstance(sys.stderr, CommandSafeStream)}\\n")
sys.stdout.flush()
# Propagates to the root logger, whose handler is the MCP SDK's RichHandler. Its
# console looks sys.stderr up at each write, so with the stderr wrap the line goes
# through two command checks.
logging.getLogger("somelib.client").warning(
    "client sent\\n::add-mask::CANROUTED x##vso[task.setvariable variable=x]CANROUTED2"
)
"""

#: The time column RichHandler writes, which differs between two runs.
_TIME_COLUMN = re.compile(r"\[\d\d/\d\d/\d\d \d\d:\d\d:\d\d\]")


@pytest.mark.integration
def test_a_routed_handlers_line_is_byte_identical_through_the_stderr_wrap(tmp_path):
    """The SDK's routed handler writes through its own wrap and, with the stderr
    wrap, through that one too; the second check finds nothing to break again."""
    written = {}
    for variant in ("with-the-wrap", "without-the-wrap"):
        child = _run_child(_IDENTITY_CHILD, tmp_path, variant)
        assert child.returncode == 0, child.stderr[-2000:]
        written[variant] = (child.stdout, child.stderr)

    # The control: the two runs differ in the wrap, and the line was written.
    assert "WRAPPED True" in written["with-the-wrap"][0].splitlines()
    assert "WRAPPED False" in written["without-the-wrap"][0].splitlines()
    for _stdout, stderr in written.values():
        assert "CANROUTED2" in stderr, stderr
        _assert_no_command(stderr)

    with_wrap, without_wrap = (
        _TIME_COLUMN.sub("[time]", written[variant][1])
        for variant in ("with-the-wrap", "without-the-wrap")
    )
    assert with_wrap == without_wrap


_NO_STDERR_CHILD = (
    """
import logging
import sys
import warnings

# As a start with no console stderr: pythonw, or fd 2 closed.
sys.stderr = None
import automated_security_helper.cli.mcp_server  # noqa: F401
"""
    + _STARTED
    + """
call = sys.argv[1]
try:
    if call == "warnings":
        warnings.warn("deprecated")
    elif call == "library-logger":
        logging.getLogger("somelib.transport").propagate = False
        logging.getLogger("somelib.transport").warning("retrying")
    elif call == "print":
        # print(file=None) writes to sys.stdout.
        print("note", file=sys.stderr)
    else:
        raise SystemExit(f"unknown call {call}")
except Exception as error:
    outcome = type(error).__name__
else:
    outcome = "quiet"
sys.stdout.write(f"OUTCOME {outcome}\\n")
"""
)


@pytest.mark.parametrize("call", ["library-logger", "print", "warnings"])
@pytest.mark.integration
def test_a_server_started_with_no_stderr_writes_as_python_does(call, tmp_path):
    """With sys.stderr None there is no stream to check, and each call does what
    Python does with no stderr, instead of raising from a wrap around None:
    lastResort and warnings write nothing, and print, given file=None, writes to
    sys.stdout."""
    child = _run_child(_NO_STDERR_CHILD, tmp_path, call)

    assert child.returncode == 0, child.stderr[-2000:]
    lines = child.stdout.splitlines()
    assert "OUTCOME quiet" in lines, (child.stdout, child.stderr)
    assert ("note" in lines) == (call == "print"), (child.stdout, child.stderr)


@pytest.mark.unit
def test_two_threads_on_one_wrap_put_no_command_at_a_line_start():
    """Thread B's write decides that its text does not start a line, and is held
    in the stream below until thread A has ended the line or a second has gone
    by. Under the wrap's lock A's write waits for B's, so B's text lands where it
    was checked, in the middle of the line; without it, A's line break lands
    first and B's "::" starts the next line unchecked."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []
    b_in_write = threading.Event()
    a_done = threading.Event()

    class Below:
        def write(self, text):
            if threading.current_thread().name == "B":
                b_in_write.set()
                a_done.wait(1)
            written.append(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    wrap.write("mid")

    def b():
        wrap.write("::add-mask::CANRACE")

    def a():
        b_in_write.wait(5)
        wrap.write("x\n")
        a_done.set()

    threads = [threading.Thread(target=b, name="B"), threading.Thread(target=a)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    text = "".join(written)
    # The control: both writes landed.
    assert "CANRACE" in text and "x\n" in text, text
    _assert_no_command(text)


@pytest.mark.unit
def test_a_checked_buffer_outliving_its_stream_closes_quietly(monkeypatch):
    """The buffer view belongs to the wrapped stream, not the other way around:
    closing the view flushes it and marks it closed without closing the stream
    below, which a test's teardown or the interpreter's shutdown may already
    have closed. On a target that is already closed the flush is quiet, so the
    finalizer's close of a view dropped with its wrap raises nothing into the
    unraisable hook."""
    import gc

    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    def wrap_a_closed_stream():
        target = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True)
        wrap = CommandSafeStream(lambda: target, check_buffer=True)
        wrap.buffer.write(b"note\n")
        target.close()
        return wrap

    # The finalizer path: the wrap and its view become garbage together.
    wrap = wrap_a_closed_stream()
    unraisable: list = []
    monkeypatch.setattr(sys, "unraisablehook", unraisable.append)
    del wrap
    gc.collect()
    assert unraisable == [], [u.exc_value for u in unraisable]

    # Closed by hand, the view is closed, and a later flush stays quiet.
    view = wrap_a_closed_stream().buffer
    view.close()
    assert view.closed
    view.flush()


def _pty_text():
    master, slave = os.openpty()
    return open(slave, "w", encoding="utf-8"), master


def _pipe_text():
    read_end, write_end = os.pipe()
    return open(write_end, "w", encoding="utf-8"), read_end


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(
            _pty_text,
            id="tty",
            marks=pytest.mark.skipif(
                not hasattr(os, "openpty"), reason="no pseudo-terminal here"
            ),
        ),
        pytest.param(_pipe_text, id="pipe"),
    ],
)
@pytest.mark.unit
def test_the_wrap_reports_its_streams_attributes(make):
    """What the stream's readers ask of it: its encoding and errors (click), whether
    it is a terminal (Rich's color), and its buffer and fd (the SDK's claim of fd
    1, _stdout_is_fd_1)."""
    from rich.console import Console

    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    stream, other_end = make()
    try:
        wrap = CommandSafeStream(lambda: stream)

        assert wrap.encoding == stream.encoding
        assert wrap.errors == stream.errors
        assert wrap.isatty() == stream.isatty()
        assert wrap.buffer is stream.buffer
        assert wrap.fileno() == stream.fileno()
        assert Console(file=wrap).is_terminal == Console(file=stream).is_terminal
    finally:
        stream.close()
        os.close(other_end)


def _stream_in_place(monkeypatch, name: str, encoding: str, errors: str = "strict"):
    raw = io.BytesIO()
    monkeypatch.setattr(
        sys,
        name,
        io.TextIOWrapper(raw, encoding=encoding, errors=errors, write_through=True),
    )
    return raw


@pytest.mark.parametrize("encoding", ["ascii", "utf-8"])
@pytest.mark.parametrize("err", [False, True], ids=["stdout", "stderr"])
@pytest.mark.parametrize("writer", ["click", "typer"])
@pytest.mark.unit
def test_echo_through_a_checked_stream_has_its_commands_broken(
    writer, err, encoding, monkeypatch
):
    """click.echo and typer.echo write through the wrap the server's start puts on
    each stream, whatever encoding the stream has."""
    import click
    import typer

    from automated_security_helper.utils.log import (
        check_commands_of_stderr,
        check_commands_of_stdout,
    )

    raw = _stream_in_place(monkeypatch, "stderr" if err else "stdout", encoding)
    if err:
        check_commands_of_stderr()
    else:
        check_commands_of_stdout()

    echo = click.echo if writer == "click" else typer.echo
    echo("note\n::add-mask::CANECHO", err=err)

    text = raw.getvalue().decode("utf-8")
    # The control: the line was written to this stream.
    assert "CANECHO" in text, text
    _assert_no_command(text)


@pytest.mark.unit
def test_control_click_writes_past_a_bare_wrap_of_an_ascii_stream(monkeypatch):
    """The hazard the start's check of an ASCII stream guards against: click
    finds the stream misconfigured, and writes UTF-8 to its binary buffer through
    a writer of its own, below any wrap of the text stream."""
    import click

    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", write_through=True)
    monkeypatch.setattr(sys, "stdout", CommandSafeStream(lambda: stream))

    click.echo("::add-mask::CANECHO")

    assert raw.getvalue().startswith(b"::add-mask::CANECHO"), raw.getvalue()


@pytest.mark.unit
def test_a_write_to_stderrs_buffer_has_its_commands_broken(monkeypatch):
    """click's own writer on a misconfigured stream, and any code that writes
    bytes, reach stderr through sys.stderr.buffer: the buffer the wrap hands
    out checks those bytes too."""
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()

    sys.stderr.buffer.write(
        "note\n::add-mask::CANBUF x##vso[task.setvariable variable=x]CANBUF2\n".encode()
    )
    sys.stderr.buffer.flush()

    text = raw.getvalue().decode("utf-8")
    # The control: the bytes reached this stream.
    assert "CANBUF2" in text, text
    _assert_no_command(text)


_TEXT_THEN_BYTES_CHILD = """
import sys

from automated_security_helper.utils.log import check_commands_of_stderr

# The control: the process's own stderr holds text it is given until a line
# ends, so bytes written below it can overtake that text.
sys.stdout.write(
    f"LAYER {sys.stderr.line_buffering} {sys.stderr.write_through}\\n"
)
check_commands_of_stderr()
sys.stderr.write("abc")
sys.stderr.buffer.write(b"::add-mask::CANORDER\\n")
sys.stderr.flush()
"""


@pytest.mark.integration
def test_bytes_after_text_ending_mid_line_land_after_that_text(tmp_path):
    """Python's own stderr is line buffered, not write-through: a text write that
    ends mid-line waits in the text layer. A byte write after it lands after it,
    in call order, so the line the check reads is the line the stream gets."""
    child = subprocess.run(  # nosec B603 - this interpreter, fixed code
        [sys.executable, "-c", importing_this_checkout(_TEXT_THEN_BYTES_CHILD)],
        cwd=tmp_path,
        env=_env(),
        capture_output=True,
        timeout=120,
    )

    assert child.returncode == 0, child.stderr[-2000:]
    assert b"LAYER True False" in child.stdout.splitlines(), child.stdout
    text = child.stderr.decode("utf-8")
    # The control: both writes reached stderr.
    assert "abc" in text and "CANORDER" in text, text
    _assert_no_command(text)


#: Unicode whitespace a runner trims at a line start, as the check does, by its
#: UTF-8 bytes: the first goes out on its own, held and then emitted, the rest
#: with the command after it.
_SPLIT_LEADS = {
    "nbsp": (b"\xc2", b"\xa0"),
    "ideographic-space": (b"\xe3", b"\x80\x80"),
    "en-quad": (b"\xe2\x80", b"\x80"),
}

#: What emits held bytes between the two byte writes.
_EMIT_TRIGGERS = {
    "stream-flush": lambda: sys.stderr.flush(),
    "buffer-flush": lambda: sys.stderr.buffer.flush(),
    "empty-text-write": lambda: sys.stderr.write(""),
}


@pytest.mark.parametrize("trigger", sorted(_EMIT_TRIGGERS))
@pytest.mark.parametrize("lead", sorted(_SPLIT_LEADS))
@pytest.mark.unit
def test_a_line_lead_split_across_byte_writes_still_breaks_the_command(
    lead, trigger, monkeypatch
):
    """A space character at a line start whose bytes reach the buffer in two
    writes, with its first bytes emitted on their own in between, still leads
    the line: the "::" after it is checked as a line start."""
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    first, rest = _SPLIT_LEADS[lead]

    sys.stderr.buffer.write(b"start\n" + first)
    _EMIT_TRIGGERS[trigger]()
    sys.stderr.buffer.write(rest + b"::add-mask::CANLEAD\n")
    sys.stderr.flush()

    text = raw.getvalue().decode("utf-8")
    # The control: the bytes rejoined into the space character on the stream,
    # which the line check reads as a line lead.
    space = (first + rest).decode("utf-8")
    assert space.isspace() and "\n" + space in text and "CANLEAD" in text, text
    _assert_no_command(text)


@pytest.mark.unit
def test_held_buffer_bytes_land_before_a_text_write(monkeypatch):
    """A buffer write can end inside a multi-byte character, whose first bytes
    the check holds for the character's rest. A text write emits them first, so
    the stream carries the same bytes in the same order as without the wrap."""
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()

    sys.stderr.buffer.write(b"caf\xc3")
    sys.stderr.write("X\n")
    sys.stderr.buffer.write(b"\xa9\n")
    sys.stderr.flush()

    assert raw.getvalue() == b"caf\xc3X\n\xa9\n", raw.getvalue()


_HELD_TAIL_CHILD = """
import os
import sys

from automated_security_helper.utils.log import check_commands_of_stderr

check_commands_of_stderr()
sys.stderr.buffer.write(b"held:caf\\xc3")
sys.stderr.flush()
os._exit(0)
"""


@pytest.mark.integration
def test_held_buffer_bytes_survive_a_flush_before_exit(tmp_path):
    """A process that flushes and exits at once (os._exit after a stop signal)
    still writes the bytes a buffer write left held: flush emits them."""
    child = subprocess.run(  # nosec B603 - this interpreter, fixed code
        [sys.executable, "-c", importing_this_checkout(_HELD_TAIL_CHILD)],
        cwd=tmp_path,
        env=_env(),
        capture_output=True,
        timeout=120,
    )

    assert child.returncode == 0, child.stderr[-2000:]
    assert child.stderr == b"held:caf\xc3", child.stderr


@pytest.mark.unit
def test_a_non_utf8_stderr_keeps_writing_the_bytes_it_wrote(monkeypatch):
    """Python's own stderr on a console that cannot encode a character writes it
    as a backslash escape. The check changes no stream's encoding on stderr, so
    a write carries the same bytes with the wrap as without it."""
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "ascii", errors="backslashreplace")
    check_commands_of_stderr()

    sys.stderr.write("café\n")
    sys.stderr.flush()

    assert raw.getvalue() == b"caf\\xe9\n", raw.getvalue()


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_signal_handlers_write_during_a_write_is_checked():
    """A signal handler runs on the same thread, inside an outer write. Its
    write is deferred until the outer text has landed and is checked from the
    state that text left, so a command form in it is read against the line it
    really lands on. The stream below raises SIGUSR1 at the start of the outer
    text's write, as a signal delivered there would run the handler."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []

    class Below:
        armed = False

        def write(self, text):
            if Below.armed:
                Below.armed = False
                signal.raise_signal(signal.SIGUSR1)
            written.append(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: wrap.write("::add-mask::INNER\n")
    )
    try:
        wrap.write("start\n")
        Below.armed = True
        wrap.write("abc")
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = "".join(written)
    # The handler's line lands after the outer text, mid-line there, where
    # its "::" is no command.
    assert text == "start\nabc::add-mask::INNER\n", text
    _assert_no_command(text)


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_signal_handlers_write_during_the_targets_write_starts_no_command_line():
    """The target's write can run Python code before the outer bytes land (a
    test double, pytest's tee capture, any Python wrapper), so a signal
    delivered there runs its handler inside the outer write. If the handler's
    line landed first, the outer text, checked as mid-line, would land at the
    real line start that line break made, and its "::" would read as a
    command. The handler's write is deferred until the outer text has landed,
    so the "::" stays on the line the check read."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []

    class Below:
        armed = False

        def write(self, text):
            if Below.armed:
                Below.armed = False
                signal.raise_signal(signal.SIGUSR1)
            written.append(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    previous = signal.signal(signal.SIGUSR1, lambda signum, frame: wrap.write("note\n"))
    try:
        wrap.write("prefix")
        Below.armed = True
        wrap.write("::add-mask::CANMID\n")
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = "".join(written)
    # The control: the handler's line and the outer line both landed.
    assert "note" in text and "CANMID" in text, text
    assert text.index("CANMID") < text.index("note"), text
    _assert_no_command(text)


@pytest.mark.unit
def test_a_write_in_the_held_tail_emits_window_leaves_the_tail_with_its_line():
    """Emitting a held tail takes the bytes out of the decoder and only then
    writes them. A write in between (a signal handler's; the target lookup is
    a Python call, so a signal can run there) must not land first: the taken
    tail would land after it, cut off from the line it belongs to. The write
    in the window is deferred until the tail has landed. The window is hit
    from the target callable itself, the same Python-level point a signal
    handler would run at."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    raw = io.BytesIO()
    target = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    state: dict = {"wrap": None, "armed": False}

    def targets():
        if state["armed"]:
            state["armed"] = False
            state["wrap"].write("note\n")
        return target

    wrap = CommandSafeStream(targets, check_buffer=True)
    state["wrap"] = wrap
    wrap.buffer.write(b"caf\xc3")
    state["armed"] = True
    wrap.write("X\n")
    wrap.buffer.write(b"\xa9\n")
    wrap.flush()

    value = raw.getvalue()
    # The control: the nested line and both outer writes landed.
    assert b"note\n" in value and b"X\n" in value and b"\xa9" in value, value
    assert b"caf\xc3" in value, value


@pytest.mark.unit
def test_a_deferred_write_that_fails_does_not_strand_the_writes_after_it():
    """A deferred write whose landing raises must not strand the writes
    deferred after it: the drain writes past it, the rest land in order,
    and its error surfaces once the queue is empty. Stranded, the rest
    would land after some later write's text, or never."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []
    state: dict = {"armed": False, "wrap": None}

    class Below:
        def write(self, text):
            if text == "boom":
                raise ValueError("the deferred write fails")
            if state["armed"]:
                state["armed"] = False
                state["wrap"].write("boom")
                state["wrap"].write("::after\n")
                state["wrap"].write("X")
            written.append(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    state["wrap"] = wrap
    state["armed"] = True
    with pytest.raises(ValueError, match="the deferred write fails"):
        wrap.write("abc")

    assert wrap._pending == [], wrap._pending
    assert "".join(written) == "abc::after\nX", written
    _assert_no_command("".join(written))


@pytest.mark.unit
def test_the_outer_writes_error_is_the_one_its_caller_sees():
    """When the outer text's own write raises and a deferred write's landing
    raises too, the caller gets the outer error: that is the write it made.
    The other deferred writes still drain."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []
    state: dict = {"armed": False, "wrap": None}

    class Below:
        def write(self, text):
            if state["armed"]:
                state["armed"] = False
                state["wrap"].write("boom")
                state["wrap"].write("note\n")
                raise OSError("the outer write fails")
            if text == "boom":
                raise ValueError("the deferred write fails")
            written.append(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    state["wrap"] = wrap
    state["armed"] = True
    with pytest.raises(OSError, match="the outer write fails"):
        wrap.write("abc")

    assert wrap._pending == [], wrap._pending
    assert "".join(written) == "note\n", written


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.parametrize("side", ["text", "bytes"])
@pytest.mark.unit
def test_a_signal_handlers_write_while_a_write_is_checked_is_checked(side, monkeypatch):
    """A signal can run its handler while an outer write is still checking its
    text, before any of it reaches the stream. The handler's write is deferred,
    so the outer text lands at the state its check read, and the handler's line
    lands after it. The signal is raised from inside the check's own line
    split."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.write("note\n")
    )
    try:
        sys.stderr.write("prefix")
        SplitThatSignals.armed = True
        if side == "text":
            sys.stderr.write("::add-mask::CANWINDOW\n")
        else:
            sys.stderr.buffer.write(b"::add-mask::CANWINDOW\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = raw.getvalue().decode("utf-8")
    # The handler's line lands after the outer text, whose "::" stays on the
    # mid-line position its check read.
    assert text == "prefix::add-mask::CANWINDOW\nnote\n", text
    _assert_no_command(text)


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.parametrize("side", ["text", "bytes"])
@pytest.mark.unit
def test_a_signal_handlers_write_before_the_check_reads_the_line_state(
    side, monkeypatch
):
    """A signal can run its handler after a write has started but before its
    check reads the line state: the handler's write is deferred, so the state
    the check reads is the one the handler found, and the handler's line lands
    after the outer text. The signal is raised from the terminal probe, the
    first thing a started write runs."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    is_terminal = css._is_terminal

    class ProbeThatSignals:
        armed = False

        def __call__(self, stream):
            if ProbeThatSignals.armed:
                ProbeThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return is_terminal(stream)

    monkeypatch.setattr(css, "_is_terminal", ProbeThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.write("note\n")
    )
    try:
        sys.stderr.write("prefix")
        ProbeThatSignals.armed = True
        if side == "text":
            sys.stderr.write("::add-mask::CANBEFORE\n")
        else:
            sys.stderr.buffer.write(b"::add-mask::CANBEFORE\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = raw.getvalue().decode("utf-8")
    # The handler's line lands after the outer text, whose "::" stays on the
    # mid-line position its check read.
    assert text == "prefix::add-mask::CANBEFORE\nnote\n", text
    _assert_no_command(text)


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_signal_handlers_write_during_a_byte_writes_encode_is_checked(monkeypatch):
    """A byte write encodes its checked text back to bytes before they reach
    the stream, so a signal there runs its handler after the check has read
    the line state. The handler's write is deferred, so the outer bytes land
    at the state their check read, and the handler's line lands after them.
    The signal is raised from the encode of the checked text."""
    import automated_security_helper.utils.command_safe_stream as css

    class EncodeThatSignals(str):
        __slots__ = ()
        armed = False

        def encode(self, *args, **kwargs):
            if EncodeThatSignals.armed:
                EncodeThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return str(self).encode(*args, **kwargs)

    real_safe = css.CommandSafeStream._safe

    def safe(self, text, at_line_start):
        checked, end = real_safe(self, text, at_line_start)
        return EncodeThatSignals(checked), end

    monkeypatch.setattr(css.CommandSafeStream, "_safe", safe)
    raw = io.BytesIO()
    below = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    wrap = css.CommandSafeStream(lambda: below, check_buffer=True)
    previous = signal.signal(signal.SIGUSR1, lambda signum, frame: wrap.write("note\n"))
    try:
        wrap.write("prefix")
        EncodeThatSignals.armed = True
        wrap.buffer.write(b"::add-mask::CANENC\n")
        wrap.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = raw.getvalue().decode("utf-8")
    # The handler's line lands after the outer bytes, whose "::" stays on the
    # mid-line position its check read.
    assert text == "prefix::add-mask::CANENC\nnote\n", text
    _assert_no_command(text)


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_storm_of_signal_handlers_writes_lands_every_line_checked_once(monkeypatch):
    """A handler's write arriving during every check must not keep the stream
    checking or recursing for as long as signals come: each handler write is
    deferred, drained in turn, and checked once, and a signal during a drained
    line's own check only defers one more. 200 signals are raised, one per
    checked line, so a drain with no bound still returns, and every deferred
    line lands. The outer line is checked exactly once."""
    import automated_security_helper.utils.command_safe_stream as css

    raw = io.BytesIO()
    below = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    wrap = css.CommandSafeStream(lambda: below, check_buffer=True)
    line_break = css._LINE_BREAK
    state = {"left": 0, "outer_checks": 0}

    class SplitThatSignals:
        def split(self, text):
            if "CANSTORM" in text:
                state["outer_checks"] += 1
            if state["left"] > 0:
                state["left"] -= 1
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(signal.SIGUSR1, lambda signum, frame: wrap.write("note\n"))
    try:
        wrap.write("prefix")
        state["left"] = 200
        wrap.write("::add-mask::CANSTORM\n")
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = raw.getvalue().decode("utf-8")
    # The control: the outer line and every handler line landed.
    assert "CANSTORM" in text, text
    assert text.count("note\n") == 200, text.count("note\n")
    _assert_no_command(text)
    assert state["outer_checks"] == 1, state["outer_checks"]


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.parametrize("side", ["text", "bytes"])
@pytest.mark.unit
def test_the_write_after_a_signal_handlers_line_landed_last_starts_a_line(side):
    """A signal that arrives during the write call runs its handler right after
    the outer text has reached the stream. The handler's line is then the
    stream's tail, so the next write starts a line: the outer write must not
    commit the line state its own text ended on."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    written: list = []
    armed = [False]

    def landed(text: str) -> None:
        written.append(text)
        if armed[0]:
            armed[0] = False
            signal.raise_signal(signal.SIGUSR1)

    class BelowBuffer:
        def write(self, data):
            landed(bytes(data).decode("utf-8", "surrogateescape"))
            return len(data)

        def flush(self):
            pass

    class Below:
        buffer = BelowBuffer()

        def write(self, text):
            landed(text)
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below, check_buffer=True)
    previous = signal.signal(signal.SIGUSR1, lambda signum, frame: wrap.write("note\n"))
    try:
        armed[0] = True
        if side == "text":
            wrap.write("abc")
        else:
            wrap.buffer.write(b"abc")
        wrap.write("::add-mask::CANAFTER\n")
    finally:
        signal.signal(signal.SIGUSR1, previous)

    text = "".join(written)
    # The control: the handler's line landed right after the outer text.
    assert "abcnote\n" in text and "CANAFTER" in text, text
    _assert_no_command(text)


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_signal_handlers_byte_write_leaves_a_byte_writes_held_tail_in_place(
    monkeypatch,
):
    """The byte-write form of the held-tail case: a signal handler's own
    byte write, while an outer byte write that holds a character's first
    bytes is still being checked, must not take that tail as the start of
    its own bytes. The handler's bytes are deferred and land whole after the
    outer text; the held byte stays with the character's rest, written
    next."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.buffer.write(b"note\n")
    )
    try:
        SplitThatSignals.armed = True
        sys.stderr.buffer.write(b"hello\xc3")
        sys.stderr.buffer.write(b"\xa9\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    assert raw.getvalue() == b"hellonote\n\xc3\xa9\n", raw.getvalue()


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_nested_byte_write_keeps_a_split_character_whole(monkeypatch):
    """A nested byte write between an outer byte write's decode and its
    landing leaves the outer write's split multi-byte character whole, and
    the nested bytes land whole. The deferred ordering is the pinned design:
    the nested piece is queued and lands after the outer write's decoded
    text, while the split character's held bytes land once its rest arrives,
    so the character's bytes stay contiguous after the nested piece."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.buffer.write(b"note\n")
    )
    try:
        SplitThatSignals.armed = True
        sys.stderr.buffer.write(b"hello\xc3")
        sys.stderr.buffer.write(b"\xa9\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    written = raw.getvalue()
    # The split character's two bytes are contiguous: the nested piece sits
    # between the outer write's decoded text and the character, never inside it.
    assert b"\xc3\xa9\n" in written, written
    assert written == b"hellonote\n\xc3\xa9\n", written


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_signal_handlers_write_leaves_a_byte_writes_held_tail_in_place(monkeypatch):
    """A byte write that ends inside a character holds the character's first
    bytes. A signal handler's text write while that byte write is still being
    checked must leave the tail held: emitted around its deferred landing, the
    tail would be cut off from the character's rest, written next."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.write("note\n")
    )
    try:
        SplitThatSignals.armed = True
        sys.stderr.buffer.write(b"hello\xc3")
        sys.stderr.buffer.write(b"\xa9\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    # The handler's line lands after the outer text, as any deferred write
    # does; the held byte stays with the character's rest.
    assert raw.getvalue() == b"hellonote\n\xc3\xa9\n", raw.getvalue()


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 here")
@pytest.mark.unit
def test_a_deferred_byte_write_leaves_no_tail_in_the_shared_decoder(monkeypatch):
    """A deferred byte write that ends inside a character rides those bytes
    through as they are, decoded on their own: it must neither take the tail
    the interrupted write holds nor leave a tail of its own in the shared
    decoder, whose held bytes belong to the ordinary byte stream."""
    import automated_security_helper.utils.command_safe_stream as css
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()
    line_break = css._LINE_BREAK

    class SplitThatSignals:
        armed = False

        def split(self, text):
            if SplitThatSignals.armed:
                SplitThatSignals.armed = False
                signal.raise_signal(signal.SIGUSR1)
            return line_break.split(text)

    monkeypatch.setattr(css, "_LINE_BREAK", SplitThatSignals())
    previous = signal.signal(
        signal.SIGUSR1, lambda signum, frame: sys.stderr.buffer.write(b"ok\xe2")
    )
    try:
        SplitThatSignals.armed = True
        sys.stderr.buffer.write(b"hi\xc3")
        sys.stderr.buffer.write(b"\xa9\n")
        sys.stderr.flush()
    finally:
        signal.signal(signal.SIGUSR1, previous)

    # The deferred b"ok\xe2" lands as it was, after the outer text; the
    # outer write's held byte still completes with the character's rest.
    assert raw.getvalue() == b"hiok\xe2\xc3\xa9\n", raw.getvalue()


@pytest.mark.unit
def test_the_wrap_of_a_stream_with_no_buffer_has_none(monkeypatch):
    """A probe like click's getattr(stream, "buffer", None) falls back to text
    on a stream with no buffer (a StringIO, an IDE console), and must do the
    same through the wrap: a view handed out anyway would pass the probe and
    raise from its first write instead. The view the wrap keeps for its own
    use is closed by the finalizer when the wrap is dropped, and that close's
    flush stays quiet about the missing buffer."""
    import gc

    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    target = io.StringIO()
    wrap = CommandSafeStream(lambda: target, check_buffer=True)

    assert getattr(wrap, "buffer", None) is None

    # Garbage from before this cell is collected first, so what the hook sees
    # comes from this wrap and its view only.
    gc.collect()
    unraisable: list = []
    monkeypatch.setattr(sys, "unraisablehook", unraisable.append)
    del wrap
    gc.collect()
    assert unraisable == [], [u.exc_value for u in unraisable]


@pytest.mark.parametrize("data", [5, [1, 2]], ids=["int", "list"])
@pytest.mark.unit
def test_the_checked_buffer_rejects_what_a_buffered_writer_rejects(data, monkeypatch):
    """bytes(5) is five NUL bytes and bytes([1, 2]) two bytes, but a buffered
    writer raises TypeError for both: the view keeps that contract, so a wrong
    write fails the same with and without the wrap, and writes nothing."""
    from automated_security_helper.utils.log import check_commands_of_stderr

    raw = _stream_in_place(monkeypatch, "stderr", "utf-8")
    check_commands_of_stderr()

    with pytest.raises(TypeError):
        sys.stderr.buffer.write(data)

    assert raw.getvalue() == b"", raw.getvalue()


@pytest.mark.unit
def test_closing_the_view_writes_the_bytes_it_holds_to_a_live_target():
    """close flushes first, as any buffered file's close does: bytes a byte
    write left held reach a target that is still open, instead of being
    dropped with the view."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    raw = io.BytesIO()
    target = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    wrap = CommandSafeStream(lambda: target, check_buffer=True)
    view = wrap.buffer
    view.write(b"caf\xc3")

    view.close()

    assert view.closed
    assert raw.getvalue() == b"caf\xc3", raw.getvalue()


@pytest.mark.unit
def test_the_view_is_quiet_about_a_target_detached_under_it():
    """The Windows UTF-8 fallback detaches the stream it replaces, and a reader
    of the old wrap's view can still flush or close it afterwards: both stay
    quiet, as they do on a target already closed."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    raw = io.BytesIO()
    target = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    wrap = CommandSafeStream(lambda: target, check_buffer=True)
    view = wrap.buffer
    view.write(b"caf\xc3")
    target.detach()

    view.flush()
    view.close()

    assert view.closed


@pytest.mark.unit
def test_retargeted_writes_held_bytes_and_checks_through_the_new_target():
    """retargeted puts what the replacement makes of the old target under a new
    wrap with the same buffer rule: bytes the old wrap's buffer held are
    written to the old target first, so they are not dropped with it, and the
    new wrap checks text and bytes as the old one did."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    old_raw = io.BytesIO()
    old = io.TextIOWrapper(old_raw, encoding="utf-8", write_through=True)
    wrap = CommandSafeStream(lambda: old, check_buffer=True)
    wrap.buffer.write(b"caf\xc3")
    new_raw = io.BytesIO()
    seen: list = []

    def replace(target):
        seen.append(target)
        return io.TextIOWrapper(new_raw, encoding="utf-8", write_through=True)

    new_wrap = wrap.retargeted(replace)
    new_wrap.write("note\n::add-mask::CANSWAP\n")
    new_wrap.buffer.write(b"note\n::add-mask::CANSWAP2\n")
    new_wrap.flush()

    assert seen == [old]
    assert old_raw.getvalue() == b"caf\xc3", old_raw.getvalue()
    text = new_raw.getvalue().decode("utf-8")
    # The control: both writes reached the new stream.
    assert "CANSWAP" in text and "CANSWAP2" in text, text
    _assert_no_command(text)


@pytest.mark.unit
def test_retargeted_replaces_the_target_only_after_a_write_in_flight_lands():
    """The replacement can detach the old target, so it runs under the wrap's
    lock: a write in flight on another thread lands on the old stream first,
    never after the detach."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    order: list = []
    in_write = threading.Event()
    release = threading.Event()

    class Below:
        def write(self, text):
            in_write.set()
            release.wait(10)
            order.append(("landed", text))
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    writer = threading.Thread(target=lambda: wrap.write("inflight\n"))
    writer.start()
    assert in_write.wait(10)

    def replace(target):
        order.append(("replaced", target))
        return target

    swapper = threading.Thread(target=lambda: wrap.retargeted(replace))
    swapper.start()
    swapper.join(1)
    waited_for_the_write = swapper.is_alive()
    release.set()
    writer.join(10)
    swapper.join(10)

    assert waited_for_the_write, order
    assert order == [("landed", "inflight\n"), ("replaced", below)], order


@pytest.mark.unit
def test_retargeted_holds_the_lock_while_the_replacement_runs():
    """The lock is held across the replacement, not only the held-bytes emit
    before it: a write started on another thread while the replacement runs
    waits for retargeted to return, so it never lands on a target being
    detached."""
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    order: list = []

    class Below:
        def write(self, text):
            order.append(("landed", text))
            return len(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    below = Below()
    wrap = CommandSafeStream(lambda: below)
    writers: list = []

    def replace(target):
        writer = threading.Thread(target=lambda: wrap.write("between\n"))
        writer.start()
        writer.join(0.5)
        order.append(("replaced", "writer waiting" if writer.is_alive() else "done"))
        writers.append(writer)
        return target

    wrap.retargeted(replace)
    writers[0].join(10)

    assert order == [("replaced", "writer waiting"), ("landed", "between\n")], order


class _CannotReconfigure(io.TextIOWrapper):
    def reconfigure(self, *args, **kwargs):
        raise OSError("this stream cannot be reconfigured")


@pytest.mark.unit
def test_the_windows_utf8_fallback_keeps_both_streams_checked(monkeypatch):
    """configure_windows_safe_logging, on a Windows console whose code page is
    cp1252, cannot reconfigure the streams and puts a UTF-8 writer on each one's
    buffer in its place: a wrap of each, as the server's start leaves them."""
    import automated_security_helper.utils.log as ash_log
    from automated_security_helper.utils.command_safe_stream import CommandSafeStream

    raws = {}
    for name in ("stdout", "stderr"):
        raws[name] = io.BytesIO()
        monkeypatch.setattr(
            sys,
            name,
            _CannotReconfigure(raws[name], encoding="cp1252", write_through=True),
        )
    ash_log.check_commands_of_stdout()
    ash_log.check_commands_of_stderr()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("CI", "1")
    # The process's locale and environment are not this test's to change.
    monkeypatch.setattr(locale, "setlocale", lambda *args, **kwargs: "C")
    monkeypatch.setattr(ash_log, "setdefault_environ", lambda *args, **kwargs: None)

    ash_log.configure_windows_safe_logging()

    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        assert isinstance(stream, CommandSafeStream), (name, type(stream))
        stream.write("note\n::add-mask::CANWIN\n")
        stream.flush()
        text = raws[name].getvalue().decode("utf-8")
        # The control: the line was written to this stream's buffer.
        assert "CANWIN" in text, (name, text)
        _assert_no_command(text)


@pytest.mark.unit
def test_the_windows_utf8_fallback_writes_the_bytes_stderr_held(monkeypatch):
    """A byte write that ended inside a character, before the fallback replaced
    stderr, has its held bytes written ahead of what follows, not dropped."""
    import automated_security_helper.utils.log as ash_log

    raw = io.BytesIO()
    monkeypatch.setattr(
        sys,
        "stderr",
        _CannotReconfigure(raw, encoding="cp1252", write_through=True),
    )
    monkeypatch.setattr(
        sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    )
    ash_log.check_commands_of_stderr()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("CI", "1")
    # The process's locale and environment are not this test's to change.
    monkeypatch.setattr(locale, "setlocale", lambda *args, **kwargs: "C")
    monkeypatch.setattr(ash_log, "setdefault_environ", lambda *args, **kwargs: None)

    sys.stderr.buffer.write(b"caf\xc3")
    ash_log.configure_windows_safe_logging()
    sys.stderr.buffer.write(b"\xa9\n")
    sys.stderr.flush()

    assert raw.getvalue() == b"caf\xc3\xa9\n", raw.getvalue()


@pytest.mark.unit
def test_the_windows_utf8_fallback_keeps_stderrs_buffer_checked(monkeypatch):
    """The writer the fallback puts in stderr's place still hands out a checked
    buffer, so click's own writer and a direct byte write stay checked there."""
    import automated_security_helper.utils.log as ash_log

    raw = io.BytesIO()
    monkeypatch.setattr(
        sys,
        "stderr",
        _CannotReconfigure(raw, encoding="cp1252", write_through=True),
    )
    monkeypatch.setattr(
        sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    )
    ash_log.check_commands_of_stderr()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("CI", "1")
    # The process's locale and environment are not this test's to change.
    monkeypatch.setattr(locale, "setlocale", lambda *args, **kwargs: "C")
    monkeypatch.setattr(ash_log, "setdefault_environ", lambda *args, **kwargs: None)

    ash_log.configure_windows_safe_logging()
    sys.stderr.buffer.write(b"note\n::add-mask::CANWINBUF\n")
    sys.stderr.flush()

    text = raw.getvalue().decode("utf-8")
    # The control: the bytes reached this stream.
    assert "CANWINBUF" in text, text
    _assert_no_command(text)
