# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The console-script floor reports whole, through the hook the environment set.

A reattached stream follows PYTHONIOENCODING; the raw writer finishes a short
write, hands a failed descriptor's remainder on, skips a descriptor that was
closed at start and flushes stdout first; an installed excepthook is called
without a stderr, and the hook typer chained to is called on typer's standard
path; a broken ``__str__`` does not break the floor; a shown stream flushes a
prompt and its cleanup never replaces the hook's outcome; a Ctrl-C is not
swallowed; a sub-app run as a module exits as the root group does.
"""

from __future__ import annotations

import io
import os
import sys

import pytest
import typer
from typer import core as typer_core

from automated_security_helper.cli import entrypoint
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit


# --- the reattached stream's codec ---


@pytest.fixture
def pipe_fd():
    read_end, write_end = os.pipe()
    yield write_end
    for fd in (read_end, write_end):
        try:
            os.close(fd)
        except OSError:
            pass


def test_a_reattached_stream_follows_pythonioencoding(monkeypatch, pipe_fd):
    """The stream was opened with the locale's codec whatever the environment
    asked for, so a repaired channel could be written in another encoding."""
    monkeypatch.setenv("PYTHONIOENCODING", "latin-1:strict")

    stream = entrypoint._reattach(pipe_fd)

    assert stream is not None
    assert stream.encoding == "latin-1"
    assert stream.errors == "strict"
    stream.detach()


def test_the_error_handler_stays_backslashreplace_when_none_is_asked(
    monkeypatch, pipe_fd
):
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")

    stream = entrypoint._reattach(pipe_fd)

    assert stream is not None
    assert stream.encoding == "utf-8"
    assert stream.errors == "backslashreplace"
    stream.detach()


def test_a_codec_python_does_not_have_leaves_the_stream_unrepaired(
    monkeypatch, pipe_fd
):
    monkeypatch.setenv("PYTHONIOENCODING", "no-such-codec-zz")

    assert entrypoint._reattach(pipe_fd) is None


# --- the raw writer ---


class _Writes:
    """A stand-in for os.write: *limit* bytes per call, failing the descriptors
    in *broken* after *broken_after* bytes went through."""

    def __init__(self, limit: int, broken: dict[int, int] | None = None):
        self.limit = limit
        self.broken = broken or {}
        self.written: dict[int, bytes] = {}

    def __call__(self, fd: int, payload: bytes) -> int:
        so_far = self.written.get(fd, b"")
        if fd in self.broken and len(so_far) >= self.broken[fd]:
            raise OSError(32, "Broken pipe")
        chunk = payload[: self.limit]
        self.written[fd] = so_far + chunk
        return len(chunk)


def test_a_short_write_is_completed(monkeypatch):
    """The count os.write returned was never read, so a pipe that took part
    of the report ended it there."""
    writes = _Writes(limit=5)
    monkeypatch.setattr(entrypoint.os, "write", writes)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())

    assert entrypoint._write_raw("ash: fatal error: the whole report\n") is True
    assert writes.written == {2: b"ash: fatal error: the whole report\n"}


def test_a_descriptor_that_fails_part_way_hands_the_rest_on(monkeypatch):
    """The next descriptor used to get the whole text again, so a report
    stderr took half of was written one and a half times."""
    writes = _Writes(limit=4, broken={2: 8})
    monkeypatch.setattr(entrypoint.os, "write", writes)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    assert entrypoint._write_raw("stderr-1stdout-2") is True
    assert writes.written[2] == b"stderr-1"
    assert writes.written[1] == b"stdout-2"


def test_a_descriptor_that_takes_nothing_is_handed_on(monkeypatch):
    """A descriptor whose os.write returned 0 without raising left the payload
    whole on every turn, and the raw floor never returned."""
    writes = _Writes(limit=100)
    turns: list[int] = []

    def write(fd: int, payload: bytes) -> int:
        turns.append(fd)
        if len(turns) > 50:
            raise AssertionError("the raw floor is spinning on descriptor 2")
        return 0 if fd == 2 else writes(fd, payload)

    monkeypatch.setattr(entrypoint.os, "write", write)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    assert entrypoint._write_raw("report\n") is True
    assert turns == [2, 1]
    assert writes.written == {1: b"report\n"}


def test_a_full_pipe_is_waited_for_and_the_line_is_written_whole(monkeypatch):
    """A full non-blocking pipe is not a broken descriptor. It raised
    BlockingIOError, the writer moved on to the next descriptor, and the report
    was handed off in the middle of a line."""
    calls: list[tuple[int, bytes]] = []
    waits: list[int] = []

    def write(fd, payload):
        calls.append((fd, bytes(payload)))
        if len(calls) == 1:
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return len(payload)

    def drained(fd, seconds):
        waits.append(fd)
        return True

    monkeypatch.setattr(entrypoint.os, "write", write)
    monkeypatch.setattr(entrypoint, "_wait_writable", drained)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    assert entrypoint._write_raw("one whole line\n") is True

    assert calls == [(2, b"one whole line\n"), (2, b"one whole line\n")], calls
    assert waits == [2], waits


def test_a_pipe_that_stays_full_hands_the_report_on_from_the_last_whole_line(
    monkeypatch,
):
    """After the wait, descriptor 1 gets the report from the start of the line
    stderr took only part of, under a line that says it continues there, so no
    line is read cut in two."""
    written: dict[int, bytes] = {}

    def write(fd, payload):
        so_far = written.get(fd, b"")
        if fd == 2 and len(so_far) >= 15:
            raise BlockingIOError(11, "Resource temporarily unavailable")
        chunk = bytes(payload[:15])
        written[fd] = so_far + chunk
        return len(chunk)

    monkeypatch.setattr(entrypoint.os, "write", write)
    monkeypatch.setattr(entrypoint, "_wait_writable", lambda fd, seconds: False)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    assert entrypoint._write_raw("first line\nsecond line\n") is True

    assert written[2] == b"first line\nseco", written
    announcement, _, rest = written[1].partition(b"\n")
    assert announcement.startswith(entrypoint._BANNER.encode()), announcement
    assert rest == b"second line\n", rest


def test_a_descriptor_closed_at_start_is_never_written(monkeypatch):
    """Found closed by ensure_std_streams, descriptor 2 can since have been
    given to a file the run opened; the report must not land in it."""
    writes = _Writes(limit=100)
    monkeypatch.setattr(entrypoint.os, "write", writes)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", {2})
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    assert entrypoint._write_raw("report\n") is True
    assert 2 not in writes.written
    assert writes.written[1] == b"report\n"


def test_stdout_is_flushed_before_the_raw_write_to_descriptor_1(monkeypatch):
    order: list[str] = []

    class Stdout(io.StringIO):
        def flush(self):
            order.append("flush")
            super().flush()

    def write(fd, payload):
        if fd == 2:
            raise OSError(9, "Bad file descriptor")
        order.append("write")
        return len(payload)

    monkeypatch.setattr(entrypoint.os, "write", write)
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(sys, "stdout", Stdout())

    assert entrypoint._write_raw("report\n") is True
    assert order == ["flush", "write"]


def test_ensure_std_streams_records_a_descriptor_it_could_not_open(monkeypatch):
    """Recorded because it is closed. The descriptor is read as closed by a
    stand-in here, and the null-device hold is stood in for too: the real
    descriptor 2 is open, and holding it would replace the test runner's own."""
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(entrypoint, "_RESERVED_DESCRIPTORS", set())
    monkeypatch.setattr(entrypoint, "_reattach", lambda fd: None)
    monkeypatch.setattr(entrypoint, "_descriptor_is_closed", lambda fd: fd == 2)
    monkeypatch.setattr(entrypoint, "_reserve_descriptor", lambda fd: True)
    monkeypatch.setattr(sys, "stderr", None)

    assert entrypoint.ensure_std_streams() == ()
    assert entrypoint._CLOSED_AT_START == {2}


# --- the installed hook ---


def _raised() -> RuntimeError:
    try:
        raise RuntimeError("boom")
    except RuntimeError as error:
        return error


def test_an_installed_hook_is_called_when_there_is_no_stderr(monkeypatch):
    """The call was gated on a stderr object, so a crash reporter was never
    called on a console-less host, where it is needed most. Called there, a hook
    that reports to stderr alone (the interpreter's printer, which a reporter
    chains to, writes nothing when sys.stderr is None) reported to nothing, so
    the hook's stderr is a shown stream onto stdout."""
    calls: list = []

    def hook(exc_type, exc, tb):
        calls.append(exc)
        # Through the stream object, as the interpreter's printer writes: a
        # print(file=sys.stderr) falls back to stdout on its own when it is None.
        sys.stderr.write(f"::reporter:: saw {exc_type.__name__}\n")

    monkeypatch.setattr(sys, "excepthook", hook)
    monkeypatch.setattr(sys, "stderr", None)
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    error = _raised()

    entrypoint._report_failure(error)

    assert calls == [error]
    assert "saw RuntimeError" in out.getvalue()
    # Once: the hook's report is the report, and ASH's floor adds none.
    assert entrypoint._BANNER not in out.getvalue()


def test_the_floor_reports_after_a_hook_when_no_stream_exists(monkeypatch):
    """With neither stream the hook is still called, and its report reached
    nothing a reader has; ASH's own report then goes to the raw descriptors."""
    raw: list[str] = []
    monkeypatch.setattr(entrypoint, "_write_raw", lambda text: raw.append(text) or True)
    calls: list = []
    monkeypatch.setattr(sys, "excepthook", lambda *args: calls.append(args[1]))
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(sys, "stdout", None)
    error = _raised()

    entrypoint._report_failure(error)

    assert calls == [error]
    assert len(raw) == 1 and "RuntimeError: boom" in raw[0]


@pytest.mark.parametrize(
    ("variable", "pretty"),
    [
        ("TYPER_STANDARD_TRACEBACK", True),
        ("_TYPER_STANDARD_TRACEBACK", True),
        (None, False),
    ],
    ids=["the variable", "the older variable", "pretty traceback off"],
)
def test_typers_chained_hook_is_called_on_the_standard_traceback_path(
    monkeypatch, variable, pretty
):
    """typer's hook, on its standard path, calls the hook installed before typer
    was imported. ASH reports in typer's place, and dropped that call. Each case
    changes one input from the pretty-path test below, which tags the exception
    with a pretty config and sets no variable: the variable alone (either
    spelling), or the config's switch alone."""
    import typer.main
    from typer.models import DeveloperExceptionConfig

    calls: list = []
    reports: list = []
    monkeypatch.setattr(typer.main, "_original_except_hook", lambda *a: calls.append(a))
    monkeypatch.setattr(sys, "excepthook", typer.main.except_hook)
    monkeypatch.delenv("TYPER_STANDARD_TRACEBACK", raising=False)
    monkeypatch.delenv("_TYPER_STANDARD_TRACEBACK", raising=False)
    if variable is not None:
        monkeypatch.setenv(variable, "1")
    monkeypatch.setattr(entrypoint, "_ash_traceback", lambda *a: reports.append(a))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    error = _raised()
    setattr(
        error,
        typer.main._typer_developer_exception_attr_name,
        DeveloperExceptionConfig(
            pretty_exceptions_enable=pretty,
            pretty_exceptions_show_locals=False,
            pretty_exceptions_short=True,
        ),
    )

    entrypoint._report_failure(error)

    assert [call[1] for call in calls] == [error]
    assert reports == []


def test_typers_chained_hook_is_left_alone_on_the_pretty_path(monkeypatch):
    """On its pretty path typer prints its own frame and chains to nothing, so
    neither does ASH's report in its place."""
    import typer.main
    from typer.models import DeveloperExceptionConfig

    calls: list = []
    reports: list = []
    monkeypatch.setattr(typer.main, "_original_except_hook", lambda *a: calls.append(a))
    monkeypatch.setattr(sys, "excepthook", typer.main.except_hook)
    monkeypatch.delenv("TYPER_STANDARD_TRACEBACK", raising=False)
    monkeypatch.delenv("_TYPER_STANDARD_TRACEBACK", raising=False)
    monkeypatch.setattr(entrypoint, "_ash_traceback", lambda *a: reports.append(a))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    error = _raised()
    setattr(
        error,
        typer.main._typer_developer_exception_attr_name,
        DeveloperExceptionConfig(
            pretty_exceptions_enable=True,
            pretty_exceptions_show_locals=False,
            pretty_exceptions_short=True,
        ),
    )

    entrypoint._report_failure(error)

    assert calls == []
    assert [report[1] for report in reports] == [error]


def test_a_flushed_line_start_colon_is_shown_with_its_line():
    """Each flushed piece was shown on its own, so ":" then a flush then
    ":warning::x" reached the stream as "::warning::x" at line start, whole."""
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write(":")
    shown.flush()
    assert real.getvalue() == ""
    shown.write(":warning::x\n")

    assert real.getvalue() == str(shown_not_obeyed("::warning::x\n"))
    assert real.getvalue() != "::warning::x\n"


def test_a_flushed_line_start_hash_is_ended_by_end():
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write("#")
    shown.flush()
    assert real.getvalue() == ""
    shown.end()

    assert real.getvalue() == str(shown_not_obeyed("#\n"))


@pytest.mark.parametrize(
    ("front", "rest"),
    [
        ("##vso", "[task.complete result=Succeeded]x\n"),
        ("##teamcity", "[message text='x']\n"),
        ("::wa", "rn::x\n"),
        ("  ##vso", "[task.complete result=Succeeded]x\n"),
        ("done ##vso", "[task.complete result=Succeeded]x\n"),
        ("path: ##teamcity", "[message text='x']\n"),
        ("done x##vso", "[task.complete result=Succeeded]x\n"),
        ("x#", "#vso[task.complete result=Succeeded]x\n"),
        ("path/##teamcity", "[message text='x']\n"),
    ],
)
def test_a_flushed_front_of_a_command_name_is_kept_for_the_rest_of_its_line(
    front, rest
):
    """Only a piece made of colons and hashes was kept. "##vso" is no command on
    its own, so a flush wrote it, and the "[...]" written after finished a
    command on the reader's line that was never shown as one. The reader's
    pattern has no word boundary, so a front glued to the text before it
    ("done x##vso", "x#" before "#vso[") is kept the same."""
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write(front)
    shown.flush()
    assert real.getvalue() == "", real.getvalue()
    shown.write(rest)

    assert real.getvalue() == str(shown_not_obeyed(front + rest))
    assert "##vso[" not in real.getvalue()
    assert "##teamcity[" not in real.getvalue()


def test_a_flushed_prompt_that_starts_with_a_hash_or_a_colon_is_still_written():
    """The control: a piece with a blank in it is no command's front, and a hook
    waiting for an answer needs its prompt; so does a colon in the middle of a
    line."""
    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write("# Send the report? [y/N] ")
    shown.flush()
    assert real.getvalue() == "# Send the report? [y/N] "
    shown.write("y\n")
    shown.write("see ")
    shown.flush()
    shown.write(":")
    shown.flush()

    assert real.getvalue().endswith("see :"), real.getvalue()


def test_a_front_in_the_middle_of_a_line_is_kept_after_an_earlier_flush():
    """The line was already started by an earlier flush, so it is not at its
    start, and the front of a command name in it is still kept until the rest
    of the line arrives."""
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write("done ")
    shown.flush()
    shown.write("##vso")
    shown.flush()
    assert real.getvalue() == "done ", real.getvalue()
    shown.write("[task.complete result=Succeeded]x\n")

    assert real.getvalue() == "done " + str(
        shown_not_obeyed("##vso[task.complete result=Succeeded]x\n")
    )
    assert "##vso[" not in real.getvalue()


@pytest.mark.parametrize("piece", ["build #12", "see ## ", "ok #1a", "x#vso"])
def test_a_flushed_piece_that_is_no_front_of_a_name_is_still_written(piece):
    """The control: a last word that is not hash marks and letters, a piece
    that ends in a blank, and one mark followed by letters glued to a word
    ("x#vso" cannot become a `##name[` form) are written at once. A lone "#"
    ending a piece is a front (the next write may be "#vso["), so it is kept
    and is not in this list."""
    real = io.StringIO()
    shown = entrypoint._ShownLines(real)

    shown.write(piece)
    shown.flush()

    assert real.getvalue() == piece, real.getvalue()


def test_an_exception_whose_text_cannot_be_read_is_still_reported(monkeypatch):
    """The floor's own line formatted str(exc) outside any handler."""

    class Unspeakable(RuntimeError):
        def __str__(self):
            raise ValueError("no text")

    raw: list[str] = []
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(entrypoint, "_write_raw", lambda text: raw.append(text) or True)

    entrypoint._report_failure(Unspeakable())

    assert len(raw) == 1
    assert raw[0].startswith("ash: fatal error: Unspeakable: <Unspeakable")


# --- the shown streams ---


def test_a_flush_writes_the_prompt_a_hook_left_unended():
    sink = io.StringIO()
    shown = entrypoint._ShownLines(sink)

    shown.write("Send the report? [y/N] ")
    shown.flush()

    assert sink.getvalue() == "Send the report? [y/N] "
    shown.end()
    assert sink.getvalue() == "Send the report? [y/N] \n"


def test_the_cleanup_of_the_shown_streams_never_replaces_the_hooks_exit(monkeypatch):
    """A failing flush of the real stdout replaced a hook's sys.exit code with
    its own error, printed the report a second time, and left stderr's held
    line unended."""

    class BrokenFlush(io.StringIO):
        def flush(self):
            raise OSError(32, "Broken pipe")

    err = io.StringIO()
    monkeypatch.setattr(sys, "stdout", BrokenFlush())
    monkeypatch.setattr(sys, "stderr", err)

    def hook(exc_type, exc, tb):
        sys.stdout.write("partial")
        sys.stderr.write("told")
        raise SystemExit(7)

    with pytest.raises(SystemExit) as exit_info:
        entrypoint._call_shown(hook, _raised())

    assert exit_info.value.code == 7
    assert err.getvalue() == "told\n"


def test_the_hook_runs_with_color_turned_off_and_the_environment_put_back(
    monkeypatch,
):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("PYTHON_COLORS", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    seen: dict = {}

    def hook(exc_type, exc, tb):
        seen.update(
            {
                name: os.environ.get(name)
                for name in ("FORCE_COLOR", "PYTHON_COLORS", "NO_COLOR")
            }
        )

    entrypoint._call_shown(hook, _raised())

    assert seen == {"FORCE_COLOR": None, "PYTHON_COLORS": "0", "NO_COLOR": "1"}
    assert os.environ["FORCE_COLOR"] == "1"
    assert os.environ["PYTHON_COLORS"] == "1"
    assert "NO_COLOR" not in os.environ


# --- interrupts and the emit ---


def test_shown_lets_an_interrupt_through(monkeypatch):
    from automated_security_helper.utils import terminal_text

    def interrupted(text):
        raise KeyboardInterrupt

    monkeypatch.setattr(terminal_text, "shown_not_obeyed", interrupted)

    with pytest.raises(KeyboardInterrupt):
        entrypoint._shown("text")


def test_emit_lets_an_interrupt_through_and_writes_nothing_raw(monkeypatch):
    raw: list[str] = []
    monkeypatch.setattr(entrypoint, "_write_raw", lambda text: raw.append(text) or True)

    class Interrupting(io.StringIO):
        def write(self, text):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        entrypoint._emit("text", Interrupting())
    assert raw == []


def test_emit_does_not_write_the_text_again_after_a_failed_flush(monkeypatch):
    """Written, then flushed in one try: a flush that failed after the write
    succeeded fell to the raw writer with the whole text."""
    raw: list[str] = []
    monkeypatch.setattr(entrypoint, "_write_raw", lambda text: raw.append(text) or True)

    class BrokenFlush(io.StringIO):
        def flush(self):
            raise OSError(32, "Broken pipe")

    stream = BrokenFlush()
    entrypoint._emit("text", stream)

    assert stream.getvalue() == "text"
    assert raw == []


def test_a_failed_write_still_falls_to_the_raw_writer(monkeypatch):
    raw: list[str] = []
    monkeypatch.setattr(entrypoint, "_write_raw", lambda text: raw.append(text) or True)

    class BrokenWrite(io.StringIO):
        def write(self, text):
            raise OSError(9, "Bad file descriptor")

    entrypoint._emit("text", BrokenWrite())

    assert raw == ["text"]


def test_suppressed_paths_are_shown_as_the_frames_file_names_are():
    """Rich leaves a frame's source out when its file name starts with a
    suppressed path; the file names are shown, so the paths must be too."""
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    install = "C:\\x64\\typer"
    frame = install + "\\main.py"

    [shown_install] = entrypoint._shown_suppress([install])

    assert shown_install != install
    assert str(shown_not_obeyed(frame)).startswith(shown_install)


# --- a sub-app run as a module ---


def _demo_app() -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def run(count: int = typer.Option(1, "--count"), code: int = 0):
        if code:
            raise typer.Exit(code)

    return app


def test_a_usage_error_under_a_module_app_exits_with_ashs_usage_code(
    monkeypatch, capsys
):
    """Run as its own app, the sub-app exited 2, ASH's code for actionable
    findings, and printed the token as given."""
    monkeypatch.setattr(sys, "argv", ["prog", "--count", "x\x1b[31m"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_demo_app())

    assert exit_info.value.code == ASH_EXIT_USAGE_ERROR
    output = capsys.readouterr()
    assert "Error:" in output.out + output.err
    assert "\x1b[31m" not in output.out + output.err


def test_a_commands_exit_code_passes_through_a_module_app(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--code", "3"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_demo_app())

    assert exit_info.value.code == 3


def test_a_module_app_that_returns_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_demo_app())

    assert exit_info.value.code == 0


def _raising_app(error: BaseException) -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def run():
        raise error

    return app


def test_an_aborted_command_under_a_module_app_exits_1_with_one_word(
    monkeypatch, capsys
):
    """The `except Abort` branch depends on a name typer exports, and no test
    reached it: an Abort exits 1 with "Aborted!", as click's own handling
    does."""
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_raising_app(typer.Abort()))

    assert exit_info.value.code == 1
    assert "Aborted!" in capsys.readouterr().err


def test_an_interrupted_command_under_a_module_app_exits_130_silently(
    monkeypatch, capsys
):
    """typer's own main turns a KeyboardInterrupt into Exit(130) outside
    standalone mode, so the interrupt comes back as a code and the branch exits
    with it; nothing is printed, as for a Ctrl-C anywhere else in the CLI."""
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_raising_app(KeyboardInterrupt()))

    assert exit_info.value.code == 130
    output = capsys.readouterr()
    assert output.out + output.err == ""


def _app_that_shows_its_help_without_arguments(**options) -> typer.Typer:
    app = typer.Typer(**options)

    @app.command(no_args_is_help=True)
    def run():
        raise AssertionError("the command is not reached when the help is shown")

    return app


def test_an_app_in_plain_markup_mode_gets_its_help_on_stderr_under_a_module_app(
    monkeypatch, capsys
):
    """In the plain markup mode typer prints nothing itself: the help is the
    message of NoArgsIsHelpError, so the branch writes it to stderr, as the
    class's own show() does, and exits with ASH's usage code, as the root
    group does."""
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(
            _app_that_shows_its_help_without_arguments(rich_markup_mode=None)
        )

    assert exit_info.value.code == ASH_EXIT_USAGE_ERROR
    output = capsys.readouterr()
    assert "Usage" in output.err, output
    assert "Usage" not in output.out, output


@pytest.mark.skipif(
    typer_core.DEFAULT_MARKUP_MODE is None,
    reason="without rich, typer's default markup mode is the plain one",
)
def test_an_app_in_the_default_markup_mode_gets_its_help_once_under_a_module_app(
    monkeypatch, capsys
):
    """In typer's default Rich mode the help is printed to stdout while the
    error is built and the error's message is empty, so the branch writes
    nothing: no blank line follows a help that was already shown."""
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(_app_that_shows_its_help_without_arguments())

    assert exit_info.value.code == ASH_EXIT_USAGE_ERROR
    output = capsys.readouterr()
    assert output.out.count("Usage") == 1, output
    assert output.err == "", output


def test_a_commands_click_error_under_a_module_app_is_one_line(monkeypatch, capsys):
    """Outside standalone mode click raises a command's ClickException to the
    caller; only usage errors were caught, so a FileError or a command's own
    ClickException became a full traceback where standalone mode printed one
    "Error:" line and exited with the exception's code."""
    from typer._click.exceptions import ClickException

    app = typer.Typer()

    @app.command()
    def run():
        raise ClickException("the input \x1b[31mcannot\x1b[0m be read")

    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as exit_info:
        entrypoint.run_module_app(app)

    assert exit_info.value.code == 1
    output = capsys.readouterr()
    assert "Error: the input" in output.err
    assert "Traceback" not in output.out + output.err
    assert entrypoint._BANNER not in output.out + output.err
    assert "\x1b[31m" not in output.out + output.err
