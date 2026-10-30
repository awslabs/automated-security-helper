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
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    monkeypatch.setattr(entrypoint, "_reattach", lambda fd: None)
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


def test_typers_chained_hook_is_called_on_the_standard_traceback_path(monkeypatch):
    """typer's hook, on its standard path, calls the hook installed before typer
    was imported. ASH reports in typer's place, and dropped that call."""
    import typer.main

    calls: list = []
    reports: list = []
    monkeypatch.setattr(typer.main, "_original_except_hook", lambda *a: calls.append(a))
    monkeypatch.setattr(sys, "excepthook", typer.main.except_hook)
    monkeypatch.setenv("TYPER_STANDARD_TRACEBACK", "1")
    monkeypatch.setattr(entrypoint, "_ash_traceback", lambda *a: reports.append(a))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    error = _raised()

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
