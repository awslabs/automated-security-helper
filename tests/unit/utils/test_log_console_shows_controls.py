# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The console log shows the terminal controls a message carries instead of obeying them.

Log messages quote text from the scanned repository, a results file or a tool:
paths, keys, exception text. Written to the console as is, an OSC 8 sequence
there would plant a hyperlink, OSC 52 would set the clipboard, a carriage return
or CSI 2K would overwrite the line before it, and a newline followed by "::"
would start a line GitHub Actions reads as a workflow command ("::error ...",
"::add-mask::", "::stop-commands::"), since the runner trims leading whitespace
first. A results file whose stored plugin options hold such a key logs "The
configuration stored in these results has an unknown key '<key>'" with the key's
controls shown as escapes.

The console handler and the live panel write C0 controls other than tab and
newline (a carriage return only before a newline), DEL and C1 as \\xNN, as ash
report shows them on a terminal, and the first colon of a line that starts with
"::" as \\x3a. ash.log, which is read in terminals and printed in CI logs too,
writes each message and traceback the same way.
"""

from __future__ import annotations

import builtins
import itertools
import logging
import re
import subprocess
import sys

import pytest
from rich.console import Console

from automated_security_helper.utils.log import MARKUP, escape_markup, get_logger
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)
from tests.utils.helpers import checkout_env

_names = itertools.count()

#: Text a terminal or a CI runner acts on, and what the console shows for it.
OBEYED = [
    pytest.param(
        "a\x1b]8;;https://example.com\x1b\\b\x1b]8;;\x1b\\c", "\\x1b]8;;", id="osc8"
    ),
    pytest.param("a\x1b]52;c;ZXZpbA==\x07b", "\\x1b]52;c;ZXZpbA==\\x07", id="osc52"),
    pytest.param("a\x1b[2Kb", "\\x1b[2K", id="csi"),
    pytest.param("a\x9b2Kb", "\\x9b2K", id="c1-csi"),
    pytest.param("a\rb", "a\\x0db", id="carriage-return"),
    pytest.param("a\x7fb\x08c", "a\\x7fb\\x08c", id="del-and-backspace"),
    pytest.param("a\N{RIGHT-TO-LEFT OVERRIDE}b", "a\\u202eb", id="bidi-override"),
    pytest.param("a\N{ZERO WIDTH SPACE}b", "a\\u200bb", id="zero-width-space"),
    pytest.param("a\N{LINE SEPARATOR}b", "a\\u2028b", id="line-separator"),
    pytest.param("a\N{PARAGRAPH SEPARATOR}b", "a\\u2029b", id="paragraph-separator"),
    # Text that reads as an escape has its backslash doubled, so it cannot pass
    # for a control that was shown.
    pytest.param("C:\\x1b\\out", "C:\\\\x1b\\out", id="escape-lookalike"),
    # So does a Windows path segment that reads as one, as on a runner's
    # ...\Python\3.12.0\x64\Lib\: by design, the rule can't tell it from text.
    pytest.param(
        "C:\\Python\\x64\\Lib\\a.py", "C:\\Python\\\\x64\\Lib\\a.py", id="windows-x64"
    ),
]

#: Lines a CI runner reads as a workflow command.
COMMANDS = [
    pytest.param("key '\n::error title=x::pwned'", id="newline"),
    pytest.param("see ##[add-mask]pwned", id="legacy-command"),
    pytest.param("see ##vso[task.setvariable variable=x]pwned", id="azure-command"),
    pytest.param("key '\n   ::add-mask::pwned'", id="indented"),
    pytest.param("key '\n  ::stop-commands::pwned'", id="unicode-space"),
    pytest.param("key '\r\n::error::pwned'", id="crlf"),
    pytest.param("::error::pwned", id="first-line"),
]

#: Output a CI runner would read as a command: a line starting, after whitespace,
#: with "::" (GitHub Actions), or "##[" / "##vso[" anywhere in a line (the
#: runner's legacy form and Azure Pipelines'). A bare "##" is none.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)


@pytest.fixture
def console_logger(request, capsys, monkeypatch):
    """A logger built by get_logger, writing its console records to captured stdout.

    ASH_LOG_TO_STDERR sends get_logger's console to stderr, and the mcp command
    sets it process-wide, so a test that ran it earlier in the worker would leave
    this one reading an empty stdout. With the "windows-ci" param, the logger is
    built as on a Windows CI runner, where WindowsSafeFilter is on.
    """
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    if getattr(request, "param", "native") == "windows-ci":
        from automated_security_helper.utils import log
        from tests.utils.windows_console import windows_logging_kept_in_the_test

        monkeypatch.setattr(log.platform, "system", lambda: "Windows")
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        windows_logging_kept_in_the_test(monkeypatch)
    logger = get_logger(
        name=f"ash-controls-test-{next(_names)}",
        level=5,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    capsys.readouterr()
    yield logger
    logger.handlers = []


@pytest.mark.unit
def test_a_path_with_a_lone_surrogate_is_logged_once(tmp_path, monkeypatch):
    """A name read from bytes that are not UTF-8 holds a lone surrogate
    (os.fsdecode, a tar member read with surrogateescape). Logged as it is, it is
    shown once, as its escape, on a console that encodes strictly and in ash.log:
    neither drops the line, and neither shows the backslash twice."""
    import io

    path = "src/secr" + chr(0xDCE9) + "t.py"
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    name = f"ash-surrogate-test-{next(_names)}"
    logger = get_logger(
        name=name,
        level=logging.INFO,
        output_dir=tmp_path,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    try:
        logger.warning("cannot read %s", path)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []
    stream.flush()
    console = stream.buffer.getvalue().decode("utf-8")
    ash_log = (tmp_path / f"{name}.log").read_text(encoding="utf-8")

    for written in (console, ash_log):
        assert written.count("src/secr\\udce9t.py") == 1, ascii(written)
        assert "\\\\udce9" not in written, ascii(written)


@pytest.mark.unit
@pytest.mark.parametrize("console_logger", ["native", "windows-ci"], indirect=True)
@pytest.mark.parametrize("text, shown", OBEYED)
def test_the_console_shows_a_control_sequence(console_logger, capsys, text, shown):
    """On Windows CI too: WindowsSafeFilter shows the message first and writes
    what is still outside ASCII as its escape, so a C1 sequence or a format
    character reaches the console as the same escape the native console shows
    (it used to be dropped, which hid it and mangled the text around it)."""
    console_logger.warning(f"unknown key '{text}'")

    out = capsys.readouterr().out
    assert shown in out, repr(out)
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", out), repr(out)


@pytest.mark.unit
@pytest.mark.parametrize("console_logger", ["native", "windows-ci"], indirect=True)
@pytest.mark.parametrize("text", COMMANDS)
def test_no_line_of_the_console_is_a_workflow_command(console_logger, capsys, text):
    """On Windows CI too, where WindowsSafeFilter leaves an all-ASCII message as
    it was logged: the console's own show breaks the command."""
    console_logger.warning(text)

    out = capsys.readouterr().out
    assert not _COMMAND_LINE.search(out), repr(out)
    assert "\\x3a:" in out or "\\x23" in out, repr(out)


@pytest.mark.unit
def test_tab_and_newline_lay_out_a_message(console_logger, capsys):
    console_logger.info("first line\nsecond\tline")

    out = capsys.readouterr().out
    assert "\\x0a" not in out and "\\x09" not in out, repr(out)
    assert "first line" in out and "second" in out, repr(out)


@pytest.mark.unit
def test_a_message_that_asks_for_markup_shows_controls_too(console_logger, capsys):
    key = escape_markup("a\x1b[2Kb")
    console_logger.info(f"[bold]Key[/bold] {key}", extra=MARKUP)

    out = capsys.readouterr().out
    assert "Key a\\x1b[2Kb" in out, repr(out)


@pytest.mark.unit
@pytest.mark.parametrize("text, shown", OBEYED)
def test_the_live_panel_shows_a_control_sequence(text, shown):
    panel = RichLogPanel(max_lines=5)
    handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(f"ash-controls-panel-{next(_names)}")
    logger.propagate = False
    logger.addHandler(handler)

    logger.info(f"unknown key '{text}'")

    console = Console(record=True, width=200, color_system=None)
    console.print(panel)
    rendered = console.export_text()
    assert shown in rendered, repr(rendered)


@pytest.mark.unit
@pytest.mark.parametrize("text", COMMANDS)
def test_no_line_of_the_live_panel_is_a_workflow_command(text):
    """The panel breaks a command in the message itself, as the console handler does.

    A message's second line is indented by the level column, and the runner trims
    that. The panel is rendered on a plain Console, not one from ash_console, so
    the factory stream's own check (utils/console.py) cannot stand in for the
    panel's.
    """
    panel = RichLogPanel(max_lines=5)
    handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(f"ash-commands-panel-{next(_names)}")
    logger.propagate = False
    logger.addHandler(handler)

    logger.warning(text)

    console = Console(record=True, width=200, color_system=None)
    console.print(panel)
    rendered = console.export_text()
    assert not _COMMAND_LINE.search(rendered), repr(rendered)
    assert "\\x3a:" in rendered or "\\x23" in rendered, repr(rendered)


#: Text that reaches a traceback from outside ASH's code: an error's message names
#: a repository path or quotes a tool's output.
HOSTILE = "m\x1b]8;;https://example.com\x1b\\L\x1b]8;;\x1b\\ \x9b2K \x7f \x1b[2K\n::error title=t::x"


@pytest.fixture
def traceback_logger(capsys, monkeypatch):
    """get_logger's console as a scan builds it: Rich renders exc_info as a traceback."""
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name=f"ash-controls-tb-{next(_names)}",
        level=5,
        show_progress=False,
        use_color=False,
        simple_format=False,
    )
    capsys.readouterr()
    yield logger
    logger.handlers = []


def _raise_from(filename: str, message: str) -> None:
    code = compile("def boom(m):\n    raise RuntimeError(m)\n", filename, "exec")
    namespace: dict = {}
    exec(code, namespace)  # nosec B102 - fixed source, to give the frame a file name
    namespace["boom"](message)


#: Exception notes and groups are Python 3.11's; ASH supports 3.10. The two
#: helpers below skip the case themselves on 3.10. pytest.skip raises a
#: BaseException, so the caller's "except Exception" does not swallow it.
def _noted() -> None:
    error = RuntimeError("plain")
    if sys.version_info >= (3, 11):
        error.add_note(HOSTILE)
    else:
        pytest.skip("notes need Python 3.11")
    raise error


def _chained() -> None:
    try:
        raise OSError(HOSTILE)
    except OSError as cause:
        raise RuntimeError("could not read the file") from cause


def _syntax_error() -> None:
    """A SyntaxError, whose line Rich shows on its own."""
    compile("value = (\x1b]8;;x\x1b\\ \x9b2K\n", "rules\x1b[2K.py", "exec")


def _grouped() -> None:
    if sys.version_info >= (3, 11):
        # Looked up by name: the linter's 3.10 target does not know the builtin.
        group = getattr(builtins, "ExceptionGroup")
    else:
        pytest.skip("exception groups need Python 3.11")
    raise group("two scanners failed", [RuntimeError(HOSTILE), OSError("b")])


def _source_named(tmp_path) -> None:
    """A frame whose file exists, so Rich shows its name and its source."""
    path = tmp_path / "pkg\x1b]8;;x\x1b\\f\x9b2K.py"
    path.write_text("def boom(m):\n    raise RuntimeError(m)\n", encoding="utf-8")
    _raise_from(str(path), "plain")


@pytest.mark.unit
@pytest.mark.parametrize(
    "raise_it",
    [
        pytest.param(lambda tmp_path: _raise_from("app.py", HOSTILE), id="message"),
        pytest.param(lambda tmp_path: _noted(), id="note"),
        pytest.param(lambda tmp_path: _chained(), id="cause"),
        pytest.param(lambda tmp_path: _syntax_error(), id="syntax-error"),
        pytest.param(lambda tmp_path: _grouped(), id="exception-group"),
        pytest.param(_source_named, id="file-name"),
    ],
)
def test_a_traceback_shows_what_the_error_carries(
    traceback_logger, capsys, tmp_path, raise_it
):
    """rich_tracebacks renders exc_info itself, apart from the message.

    With logger.exception("case <name>"), the exception's text and its notes
    reach the console with OSC 8, CSI 2K, C1 CSI and DEL shown as escapes, and no
    line after the message's newline starts a workflow command.
    """
    try:
        raise_it(tmp_path)
    except Exception:  # noqa: BLE001 - the test logs whatever was raised
        traceback_logger.exception("the scan failed")

    out = capsys.readouterr().out
    assert "Traceback" in out, out
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", out), repr(out)
    assert not _COMMAND_LINE.search(out), repr(out)


@pytest.mark.unit
def test_a_traceback_names_the_error(traceback_logger, capsys):
    try:
        _raise_from("app.py", "could not read pkgs/a[/x]/b")
    except RuntimeError:
        traceback_logger.exception("the scan failed")

    out = " ".join(capsys.readouterr().out.split())
    assert "RuntimeError: could not read pkgs/a[/x]/b" in out, out


#: ESC, BEL, a bare carriage return, an OSC 8 link and a line-start "::error".
FILE_HOSTILE = (
    "a\x1b[2Kb \x07 c\rd "
    "\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\ e\n::error title=x::pwned"
)
#: A raw control a file shown in a terminal or a CI log acts on (tab and newline
#: lay text out).
_RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _ash_log(tmp_path, log) -> str:
    """What *log* writes to ash.log, the tabular log file, under *tmp_path*."""
    name = f"ash-controls-file-{next(_names)}"
    logger = get_logger(
        name=name,
        level=logging.INFO,
        output_dir=tmp_path,
        show_progress=False,
        use_color=False,
        simple_format=False,
    )
    try:
        log(logger)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []
    # Its bytes: reading it as text would turn a bare carriage return into "\n".
    return (tmp_path / f"{name}.log").read_bytes().decode("utf-8")


@pytest.mark.unit
def test_the_log_file_shows_a_messages_controls_once(tmp_path):
    """ash.log is read in a terminal and printed in CI logs, so it shows what a
    message carries as the console does: each control escaped once, CI commands
    broken."""
    written = _ash_log(
        tmp_path, lambda logger: logger.warning("unknown key %s", FILE_HOSTILE)
    )

    assert not _RAW_CONTROL.search(written), repr(written)
    assert not _COMMAND_LINE.search(written), repr(written)
    for shown in ("\\x1b[2K", "\\x07", "c\\x0dd", "\\x1b]8;;", "\\x3a:error title"):
        assert shown in written, (shown, written)
    assert "\\\\x" not in written, repr(written)


#: Characters the console and ash.log printed raw: format characters (zero-width
#: space, non-joiner, joiner, word joiner, invisible plus, byte order mark), the
#: line and paragraph separators, which some log viewers take as line breaks, a
#: private-use character and two noncharacters.
_UNSHOWN = [0x200B, 0x200C, 0x200D, 0x2060, 0x2064, 0xFEFF, 0x2028, 0x2029]
_UNSHOWN += [0xE000, 0xFFFE, 0xFDD0]


@pytest.mark.unit
@pytest.mark.parametrize("code", _UNSHOWN, ids=lambda code: "u%04x" % code)
def test_the_console_and_the_log_file_show_it_once(tmp_path, capsys, monkeypatch, code):
    """One set for every sink: the console and ash.log, the same escape, once.

    The mcp command sets ASH_LOG_TO_STDERR for the whole process, which sends the
    console to stderr, so a test that ran it earlier in the worker emptied stdout.
    """
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    message = f"key a{chr(code)}b"
    shown = "key a\\u%04xb" % code

    written = _ash_log(tmp_path, lambda logger: logger.warning(message))
    out = " ".join(capsys.readouterr().out.split())

    assert chr(code) not in written and shown in written, repr(written)
    assert chr(code) not in out and shown in out, repr(out)
    assert "\\\\u" not in written + out, repr(written + out)


#: A file name read from a byte that is not UTF-8: os.fsdecode gives it as a lone
#: surrogate, which a UTF-8 stream cannot encode.
_UNDECODABLE = "out" + chr(0xDC80) + "dir"


@pytest.mark.unit
def test_a_lone_surrogate_is_shown_in_both_log_files(tmp_path):
    """ash.log could not encode it, so the whole record was dropped with a
    "--- Logging error ---" report. The JSONL log keeps the text, as JSON's own
    escape."""
    import json

    name = f"ash-controls-cs-{next(_names)}"
    logger = get_logger(
        name=name,
        level=logging.INFO,
        output_dir=tmp_path,
        log_format="BOTH",
        show_progress=False,
        use_color=False,
    )
    try:
        logger.warning("Cannot read %s", _UNDECODABLE)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []

    tabular = (tmp_path / f"{name}.log").read_bytes().decode("utf-8")
    assert "Cannot read out\\udc80dir" in tabular, repr(tabular)
    records = [
        json.loads(line)
        for line in (tmp_path / f"{name}.log.jsonl").read_text("utf-8").splitlines()
    ]
    assert [r["message"] for r in records] == [f"Cannot read {_UNDECODABLE}"]


@pytest.mark.unit
@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
def test_a_lone_surrogate_on_the_console_is_shown_once(monkeypatch, errors):
    """On a strict stdout and on a lenient one, the record is written with the
    byte shown once as its escape."""
    import io

    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors=errors)
    monkeypatch.setattr(sys, "stdout", stream)
    logger = get_logger(
        name=f"ash-controls-cs-console-{next(_names)}",
        level=logging.INFO,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    try:
        logger.warning("Cannot read %s", _UNDECODABLE)
        stream.flush()
    finally:
        logger.handlers = []

    written = stream.buffer.getvalue()
    assert b"Cannot read out\\udc80dir" in written, written
    assert b"\x80" not in written, written


@pytest.mark.unit
def test_the_log_file_shows_a_markup_records_values_once(tmp_path):
    """A MARKUP record's values were shown by escape_markup already; the file writes
    its text without the tags and does not show them a second time."""
    written = _ash_log(
        tmp_path,
        lambda logger: logger.warning(
            f"[bold]key[/bold] {escape_markup(FILE_HOSTILE)}", extra=MARKUP
        ),
    )

    assert "key " in written and "[bold]" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert not _COMMAND_LINE.search(written), repr(written)
    assert "\\x1b[2K" in written and "\\\\x" not in written, repr(written)


@pytest.mark.unit
def test_the_log_file_shows_a_tracebacks_controls(tmp_path, monkeypatch):
    """The exception's text in ash.log, as on the console."""
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)

    def log(logger):
        try:
            _raise_from("app.py", HOSTILE)
        except RuntimeError:
            logger.exception("the scan failed")

    written = _ash_log(tmp_path, log)

    assert "RuntimeError" in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert not _COMMAND_LINE.search(written), repr(written)


@pytest.mark.unit
def test_a_traceback_ash_log_formatted_first_is_shown_once_by_the_live_panel(
    tmp_path,
):
    """logging caches a record's formatted traceback on the record (exc_text), and
    the next handler's formatter uses the cached text. ash.log's formatter shows
    the traceback, so a record it formatted first carried shown text to the live
    panel, which showed it again: ESC as the text "\\\\x1b". TextFileFormatter puts
    the record's own cache back after it formats."""
    from automated_security_helper.utils.log import LogFileHandler, TextFileFormatter

    file_handler = LogFileHandler((tmp_path / "ash.log").as_posix())
    file_handler.setFormatter(TextFileFormatter("%(message)s"))
    panel = RichLogPanel(max_lines=40)
    panel_handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    panel_handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(f"ash-controls-cache-{next(_names)}")
    logger.propagate = False
    logger.handlers = [file_handler, panel_handler]
    # Built at run time: the traceback quotes this line, and an escape written in
    # the source would read there as text, shown with its backslash doubled.
    message = "boom" + chr(0x1B) + "[31m red"
    try:
        try:
            _raise_from("app.py", message)
        except RuntimeError:
            logger.exception("the scan failed")
    finally:
        logger.handlers = []
        file_handler.close()

    console = Console(record=True, width=400, color_system=None)
    console.print(panel)
    rendered = console.export_text()
    written = (tmp_path / "ash.log").read_bytes().decode("utf-8")
    for text in (rendered, written):
        assert "boom\\x1b[31m red" in text, text
        assert "\\\\x1b" not in text and "\x1b" not in text, text


@pytest.mark.unit
def test_a_record_carrying_only_cached_traceback_text_keeps_it(tmp_path):
    """A filter can render a record's traceback itself, setting exc_text and
    dropping exc_info. ash.log writes that cached text, shown: the formatter's
    own rendering is only for a record that still carries exc_info."""
    from automated_security_helper.utils.log import LogFileHandler, TextFileFormatter

    file_handler = LogFileHandler((tmp_path / "ash.log").as_posix())
    file_handler.setFormatter(TextFileFormatter("%(message)s"))
    record = logging.LogRecord(
        "ash-exc-text-only", logging.ERROR, "app.py", 1, "the scan failed", None, None
    )
    record.exc_text = (
        "Traceback (most recent call last):\nRuntimeError: boom" + chr(0x1B) + "[31m"
    )
    try:
        file_handler.emit(record)
    finally:
        file_handler.close()

    written = (tmp_path / "ash.log").read_bytes().decode("utf-8")
    assert "the scan failed" in written, repr(written)
    assert "RuntimeError: boom\\x1b[31m" in written, repr(written)
    assert chr(0x1B) not in written, repr(written)


#: A configuration file name a warning quotes before the logger is set up: the
#: extends base of a repository's config.
_EARLY_NAME = "b\x1b]52;c;ZXZpbA==\x07\n::add-mask::hidden.yaml"

#: A fresh process that logs to ASH's logger without get_logger having run.
_FRESH_PROCESS = """
import logging, sys
case = sys.argv[1]
name = {name!r}
if case == "made-before-the-import":
    # A logger under "ash" made before utils/log.py set its logger class.
    early = logging.getLogger("ash.early")
from automated_security_helper.utils.log import ASH_LOGGER
if case == "made-before-the-import":
    early.warning("Cannot read the configuration %s", name)
elif case == "another-logger-class":
    # A library that sets its own logger class after ASH's.
    logging.setLoggerClass(logging.Logger)
    logging.getLogger("ash.library").warning("Cannot read the configuration %s", name)
elif case == "not-ash":
    logging.getLogger("other").warning("plain %s", "text")
elif case == "warning":
    ASH_LOGGER.warning("Cannot read the configuration %s", name)
elif case == "exception":
    try:
        raise RuntimeError(name)
    except RuntimeError:
        ASH_LOGGER.exception("Cannot read the configuration")
elif case == "with-a-handler":
    ASH_LOGGER.addHandler(logging.NullHandler())
    ASH_LOGGER.warning("Cannot read the configuration %s", name)
elif case == "after-reset":
    # What the ash command does first (cli/entrypoint.py runs run_app).
    from automated_security_helper.cli.main import reset_logging_config

    reset_logging_config()
    ASH_LOGGER.warning("Cannot read the configuration %s", name)
elif case == "child-without-propagation":
    child = logging.getLogger("ash.solo")
    child.propagate = False
    child.warning("Cannot read the configuration %s", name)
elif case == "reloaded":
    import importlib

    from automated_security_helper.utils import log

    importlib.reload(log)
    log.ASH_LOGGER.warning("Cannot read the configuration %s", name)
elif case == "child-with-a-handler":
    child = logging.getLogger("ash.own")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("child: %(message)s"))
    child.addHandler(handler)
    child.warning("plain")
"""


def _fresh_process_stderr(case: str) -> str:
    proc = subprocess.run(  # nosec B603 - this interpreter, fixed code
        [sys.executable, "-c", _FRESH_PROCESS.format(name=_EARLY_NAME), case],
        env=checkout_env(),
        capture_output=True,
        timeout=120,
    )
    # Its bytes: text mode would turn a bare carriage return into "\n".
    stderr = proc.stderr.decode("utf-8")
    assert proc.returncode == 0, stderr
    return stderr


@pytest.mark.integration
@pytest.mark.parametrize("case", ["warning", "exception"])
def test_a_warning_logged_before_the_logger_is_set_up_is_shown(case):
    """Until get_logger runs, ASH's logger has no handler, so a warning logged then
    goes to a stand-in for logging's last resort. A process that loads a
    configuration first (the MCP server's get_config does) logs a repository's
    file name through it, with its OSC 52 sequence shown and its "::add-mask::"
    broken: the stand-in shows each control and breaks each command, as the
    console does."""
    stderr = _fresh_process_stderr(case)

    assert "add-mask" in stderr, repr(stderr)
    assert not _RAW_CONTROL.search(stderr), repr(stderr)
    assert not _COMMAND_LINE.search(stderr), repr(stderr)
    assert "\\x1b]52;c;ZXZpbA==\\x07" in stderr and "\\\\x" not in stderr, repr(stderr)


@pytest.mark.integration
def test_the_stand_in_steps_aside_once_the_logger_has_a_handler():
    """As logging's last resort does: any handler of the logger's own replaces it."""
    assert _fresh_process_stderr("with-a-handler") == ""


@pytest.mark.integration
@pytest.mark.parametrize(
    "case", ["after-reset", "child-without-propagation", "reloaded"]
)
def test_a_warning_no_handler_takes_is_shown_once_however_it_got_there(case):
    """The ash command clears every handler of ASH's logger before a command runs
    (cli/main.py's reset_logging_config). The stand-in is not a handler a clear
    removes: a record no handler takes goes to it, as to logging's last resort,
    so a warning from an MCP server's get_config is still shown. A logger under
    "ash" that does not propagate, and a reload of utils/log.py, reach it too."""
    stderr = _fresh_process_stderr(case)

    assert stderr.count("add-mask") == 1, repr(stderr)
    assert not _RAW_CONTROL.search(stderr), repr(stderr)
    assert not _COMMAND_LINE.search(stderr), repr(stderr)


@pytest.mark.integration
@pytest.mark.parametrize("case", ["made-before-the-import", "another-logger-class"])
def test_a_warning_of_an_ash_logger_of_another_class_is_shown(case):
    """A stand-in run only through ASH's logger class would miss a logger under
    "ash" made before utils/log.py set it, or after a library set its own: those
    would go to logging's last resort and write the file name raw. logging's last
    resort hands every record of "ash" and the loggers under it to the stand-in."""
    stderr = _fresh_process_stderr(case)

    assert stderr.count("add-mask") == 1, repr(stderr)
    assert not _RAW_CONTROL.search(stderr), repr(stderr)
    assert not _COMMAND_LINE.search(stderr), repr(stderr)


@pytest.mark.integration
def test_any_other_logger_keeps_logging_last_resort():
    assert _fresh_process_stderr("not-ash") == "plain text\n"


@pytest.mark.integration
def test_a_child_logger_with_its_own_handler_is_printed_once():
    """Its own handler takes the record, so the stand-in does not write it too."""
    assert _fresh_process_stderr("child-with-a-handler") == "child: plain\n"
