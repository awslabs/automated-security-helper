# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A log message is text unless the call asks for Rich markup.

Most log messages carry text ASH does not control: paths from the scanned
repository, exception text, tool output. Read as Rich markup, a closing tag such as
``[/x]`` raises MarkupError, which neither RichHandler.emit nor
logging.Handler.handle catches, and an opening one such as ``[bold]`` or
``[link=...]`` is swallowed as a style.

Markup is off at both sinks, the console handler and the live progress panel, and a
call that styles its own message asks for it with ``extra=MARKUP`` and escapes what
it interpolates. ``NO_MARKUP`` and ``escape_markup`` keep working.
"""

from __future__ import annotations

import ast
import itertools
import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from rich.text import Text

from automated_security_helper.utils.log import (
    MARKUP,
    NO_MARKUP,
    escape_markup,
    get_logger,
)
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)

#: Text Rich reads as markup: a closing tag with no opener (raises), an opening
#: style tag, a whole style tag around a word, and a link (all three silently
#: removed).
OPERATOR_TEXT = [
    "file a[/x] b",
    "file c[bold]d",
    "file h [bold]x[/bold] i",
    "file e[link=https://example.com]f[/link] g",
]

_names = itertools.count()


@pytest.fixture
def console_logger(capsys, monkeypatch):
    """A logger built by get_logger, writing its console records to captured stdout.

    ASH_LOG_TO_STDERR sends get_logger's console to stderr, and the mcp command
    sets it process-wide, so a test that ran it earlier in the worker would leave
    this one reading an empty stdout.
    """
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name=f"ash-markup-test-{next(_names)}",
        level=5,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    capsys.readouterr()
    yield logger
    logger.handlers = []


def _logged(capsys) -> str:
    return " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("text", OPERATOR_TEXT)
@pytest.mark.parametrize(
    "emit",
    [
        pytest.param(lambda log, text: log.trace(text), id="trace"),
        pytest.param(lambda log, text: log.debug(text), id="debug"),
        pytest.param(lambda log, text: log.verbose(text), id="verbose"),
        pytest.param(lambda log, text: log.info(text), id="info"),
        pytest.param(lambda log, text: log.warning(text), id="warning"),
        pytest.param(lambda log, text: log.error(text), id="error"),
        pytest.param(lambda log, text: log.critical(text), id="critical"),
        pytest.param(lambda log, text: log.log(logging.INFO, text), id="log"),
        pytest.param(lambda log, text: log.info("%s", text), id="info-with-args"),
        pytest.param(
            lambda log, text: log.info(RuntimeError(text)), id="exception-object"
        ),
    ],
)
def test_the_console_prints_operator_text_as_given(console_logger, capsys, emit, text):
    emit(console_logger, text)

    assert text in _logged(capsys)


@pytest.mark.parametrize("text", OPERATOR_TEXT)
def test_logger_exception_prints_the_exception_text_as_given(
    console_logger, capsys, text
):
    """run_ash_scan logs a scan's exception with logger.exception(e)."""
    try:
        raise RuntimeError(text)
    except RuntimeError as error:
        console_logger.exception(error)

    assert text in _logged(capsys)


def test_a_call_that_asks_for_markup_gets_it(console_logger, capsys):
    console_logger.info(
        f"[bold]Styled[/bold] then {escape_markup('a[/x] b')}", extra=MARKUP
    )

    assert "Styled then a[/x] b" in _logged(capsys)


def test_no_markup_still_works(console_logger, capsys):
    console_logger.info("file a[/x] b", extra=NO_MARKUP)

    assert "file a[/x] b" in _logged(capsys)


#: Values whose backslashes Rich reads: trailing ones, and ones before a tag.
_BACKSLASH_VALUES = [
    "C:\\temp\\",
    "a\\\\",
    "a\\\\\\",
    "p[/x]\\",
    "q\\[/x]",
    "r\\\\[bold]",
]

#: Where an escaped value sits in a styled message: at the end, before a closing
#: tag, and right before an opening one.
_TEMPLATES = [
    "{}",
    "[red]{}[/red]",
    "[red]{}[/red] then [bold]b[/bold]",
    "{}[bold]b[/bold]",
]


@pytest.mark.parametrize("value", _BACKSLASH_VALUES)
@pytest.mark.parametrize("template", _TEMPLATES)
def test_an_escaped_value_renders_as_given_wherever_it_sits(template, value):
    """rich.markup.escape doubles a single trailing backslash and leaves two or more.

    At the end of a message the doubled one shows. Before a tag, two lose one, and
    three escape the tag: a closing tag is printed and its style left open, and an
    opening one leaves its closing tag with nothing to close, which raises.
    """
    expected = template
    for tag in ("[red]", "[/red]", "[bold]", "[/bold]"):
        expected = expected.replace(tag, "")
    expected = expected.format(value)

    assert Text.from_markup(template.format(escape_markup(value))).plain == expected


def test_only_escape_markup_calls_rich_escape():
    """A module importing rich.markup.escape gets the trailing-backslash cases above.

    Counted however the module reaches it: ``from rich.markup import escape`` (or
    ``*``) under any name, or ``.escape`` read off rich.markup, whether that is
    bound as ``rich.markup``, by ``import rich.markup as m``, or by ``from rich
    import markup [as m]``.
    """
    package = Path(__file__).resolve().parents[3] / "automated_security_helper"
    importers = []
    for source in sorted(package.rglob("*.py")):
        if source == package / "utils" / "log.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        markup_module = {"rich.markup", "markup"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                markup_module.update(
                    alias.asname
                    for alias in node.names
                    if alias.name == "rich.markup" and alias.asname
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "rich":
                markup_module.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "markup"
                )
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "rich.markup":
                if any(alias.name in {"escape", "*"} for alias in node.names):
                    importers.append(f"{source.relative_to(package)}:{node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr == "escape":
                if ast.unparse(node.value) in markup_module:
                    importers.append(f"{source.relative_to(package)}:{node.lineno}")

    assert importers == [], importers


@pytest.mark.parametrize("text", OPERATOR_TEXT)
def test_plugin_log_prints_the_plugin_message_as_given(
    console_logger, capsys, monkeypatch, text
):
    """_plugin_log styles its prefix; the message is a scanner's, often a path."""
    import contextlib

    from automated_security_helper.base import plugin_base

    monkeypatch.setattr(plugin_base, "ASH_LOGGER", console_logger)
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="npm-audit"), errors=[], output=[]
    )
    plugin.environment_values_shown = contextlib.nullcontext

    plugin_base.PluginBase._plugin_log(
        plugin, f"Target directory {text} is empty", level=logging.INFO
    )

    logged = _logged(capsys)
    assert f"(npm-audit @ source) Target directory {text} is empty" in logged


def test_plugin_log_prints_a_trailing_backslash_once(
    console_logger, capsys, monkeypatch
):
    """The escaped message ends the styled line, where Rich showed a doubled backslash."""
    from automated_security_helper.base import plugin_base

    monkeypatch.setattr(plugin_base, "ASH_LOGGER", console_logger)
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="npm-audit"), errors=[], output=[]
    )

    plugin_base.PluginBase._plugin_log(
        plugin, "Target directory is C:\\temp\\", level=logging.INFO
    )

    logged = _logged(capsys)
    assert logged.endswith("Target directory is C:\\temp\\"), logged


@pytest.mark.parametrize(
    "message",
    [
        "Installing bandit[sarif,toml]>=1.7.0",
        "Target directory /repo/[/x]/src is empty",
        "Writing to C:\\out\\",
    ],
)
def test_the_log_files_get_a_plugin_message_as_its_text(tmp_path, monkeypatch, message):
    """_plugin_log logs markup, and the file handlers wrote it as markup.

    ash.log and the JSONL file held
    'Installing bandit\\[sarif,toml]>=1.7.0' and 'Writing to C:\\out\\\\[none][/none]',
    with the [yellow] and [magenta] tags of the prefix.
    """
    import json

    from automated_security_helper.base import plugin_base

    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name=f"ash-markup-files-{next(_names)}",
        level=logging.INFO,
        output_dir=tmp_path,
        log_format="BOTH",
        show_progress=True,
        use_color=False,
    )
    monkeypatch.setattr(plugin_base, "ASH_LOGGER", logger)
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="npm-audit"), errors=[], output=[]
    )
    try:
        plugin_base.PluginBase._plugin_log(
            plugin, message, target_type="source", level=logging.INFO
        )
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []

    tabular = (tmp_path / f"{logger.name}.log").read_text(encoding="utf-8")
    records = [
        json.loads(line)
        for line in (tmp_path / f"{logger.name}.log.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    expected = f"(npm-audit @ source)\t{message}"
    assert expected in tabular, tabular
    assert expected in [record["message"] for record in records], records
    for written in (tabular, json.dumps(records)):
        assert "[yellow]" not in written and "\\[" not in written, written


@pytest.mark.parametrize("text", OPERATOR_TEXT)
def test_the_live_panel_prints_operator_text_as_given(text):
    panel = RichLogPanel(max_lines=5)
    handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(f"ash-markup-panel-{next(_names)}")
    logger.propagate = False
    logger.addHandler(handler)

    logger.info(text)
    logger.info("[bold]Styled[/bold] line", extra=MARKUP)

    console = Console(record=True, width=200, color_system=None)
    console.print(panel)
    rendered = console.export_text()
    assert text in rendered, rendered
    assert "Styled line" in rendered and "[bold]Styled" not in rendered, rendered


def test_a_failing_scanner_whose_error_names_a_bracketed_path_is_reported(
    console_logger, capsys, monkeypatch, tmp_path
):
    """The executor logs a scanner's stack trace and error text, which name its target.

    Measured with npm-audit on pkgs/[/x]/package-lock.json and an audit response that
    did not parse: MarkupError escaped run_sequential and the scan ended in a
    traceback instead of an ERROR row for the scanner.
    """
    from unittest.mock import MagicMock

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.utils import log

    class _Config(ScannerPluginConfigBase):
        name: str = "brackets"

    class _FailingScanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type=None, *_args, **_kwargs):
            raise RuntimeError(
                "could not parse the audit of pkgs/[/x]/package-lock.json: "
                "<html>[/proxy] error</html>"
            )

    source = tmp_path / "source"
    (source / "pkgs" / "[" / "x]").mkdir(parents=True)
    (tmp_path / "output").mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )
    monkeypatch.setattr(log.ASH_LOGGER, "handlers", list(console_logger.handlers))
    monkeypatch.setattr(log.ASH_LOGGER, "level", 5)
    monkeypatch.setattr(
        scanner_executor.ASH_LOGGER, "handlers", log.ASH_LOGGER.handlers
    )
    executor = scanner_executor.ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    (container,) = executor._execute_scanner(
        "brackets",
        _FailingScanner(config=_Config(), context=context),
        [{"path": source / "pkgs" / "[" / "x]", "type": "source"}],
    )

    assert container.status == ScannerStatus.ERROR
    assert "pkgs/[/x]/package-lock.json" in _logged(capsys)


@pytest.mark.parametrize("text", OPERATOR_TEXT)
def test_an_unreadable_file_under_a_bracketed_directory_is_skipped_and_logged(
    console_logger, capsys, monkeypatch, tmp_path, text
):
    """Reading inline suppressions logs the file it could not read, at DEBUG.

    A scan of a directory named "[/x]" raised MarkupError out of that log call,
    and the scan died with it.
    """
    from automated_security_helper.utils import log, suppression_matcher

    monkeypatch.setattr(log.ASH_LOGGER, "handlers", list(console_logger.handlers))
    monkeypatch.setattr(log.ASH_LOGGER, "level", 5)
    missing = tmp_path / text / "app.py"

    assert suppression_matcher.find_inline_suppressions(missing) == []
    # The long path wraps at the console width; compare without whitespace.
    logged = "".join(capsys.readouterr().out.split())
    assert "".join(f"Could not read {missing}".split()) in logged, logged


#: Fields a progress description may interpolate unescaped: plugin names, which a
#: plugin config's name pattern (^[a-zA-Z][\w-]+$) or a class name keeps to letters,
#: digits, "_" and "-", and counts.
_NAME_FIELDS = {"scanner_name", "plugin_name", "display_name"}
_COUNT_FIELDS = {
    "completed",
    "completed_count",
    "total",
    "total_converters",
    "total_reporters",
}

#: Calls whose arguments become a progress task's description, by position and by
#: keyword. add_summary and add_summary_row build a summary task's description
#: from their status and details.
_DESCRIPTION_SINKS = {
    "add_task": ({1}, {"description"}),
    "update_task": (set(), {"description"}),
    "add_summary": ({0, 1}, {"status", "details"}),
    "add_summary_row": ({0, 1, 2}, {"phase", "status", "details"}),
}


def _a_count(node) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _COUNT_FIELDS
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int)
    if isinstance(node, ast.Call):
        return getattr(node.func, "id", "") == "len"
    if isinstance(node, ast.BinOp):
        return _a_count(node.left) and _a_count(node.right)
    return False


def _vetted_description(node) -> bool:
    """A string constant, or an f-string of names, counts and escape_markup calls."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if not isinstance(node, ast.JoinedStr):
        return False
    for part in node.values:
        if not isinstance(part, ast.FormattedValue):
            continue
        value = part.value
        if isinstance(value, ast.Name) and value.id in _NAME_FIELDS:
            continue
        if isinstance(value, ast.Call) and getattr(value.func, "id", "") == (
            "escape_markup"
        ):
            continue
        if not _a_count(value):
            return False
    return True


def test_progress_descriptions_escape_what_they_quote():
    """The progress bar's TextColumn reads each task description as markup.

    A description quoting an exception's text or a report file name raised
    MarkupError in the live display for "[/x]", as a log line did. Every argument
    the package passes as a description is held to a string constant or an f-string
    that interpolates only a name, a count or escape_markup(...); a concatenation, a
    variable or any other call is flagged. The sinks' own bodies are skipped: they
    pass on what their callers gave, and the callers are checked.
    """
    package = Path(__file__).resolve().parents[3] / "automated_security_helper"
    unvetted = []
    for source in sorted(package.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        forwarding = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in _DESCRIPTION_SINKS:
                    forwarding.update(id(child) for child in ast.walk(node))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or id(node) in forwarding:
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name not in _DESCRIPTION_SINKS:
                continue
            positions, keywords = _DESCRIPTION_SINKS[name]
            values = [arg for i, arg in enumerate(node.args) if i in positions]
            values += [kw.value for kw in node.keywords if kw.arg in keywords]
            unvetted += [
                f"{source.relative_to(package)}:{value.lineno}: {ast.unparse(value)}"
                for value in values
                if not _vetted_description(value)
            ]

    assert unvetted == [], unvetted


def test_the_live_display_prints_operator_text_and_stops(monkeypatch):
    """The real LiveProgressDisplay, as a scan runs it, with npm-audit's INFO record.

    Its panel read every record as markup: a "[/x]" directory raised MarkupError
    in the refresh, which the refresh thread does not survive, and in stop().
    """
    from automated_security_helper.core.progress import LiveProgressDisplay
    from automated_security_helper.utils import log

    monkeypatch.setattr(log.ASH_LOGGER, "level", logging.DEBUG)
    monkeypatch.setattr(log.ASH_LOGGER, "handlers", [])
    # Rich treats a TERM=dumb or TERM=unknown terminal as not interactive, and a
    # Live display there renders only once, at stop: the cell names its terminal.
    monkeypatch.setenv("TERM", "xterm-256color")
    display = LiveProgressDisplay(show_progress=True, max_log_lines=len(OPERATOR_TEXT))
    # A terminal, so each refresh renders, as the refresh thread does on one.
    display.console = Console(
        record=True, width=200, height=40, color_system=None, force_terminal=True
    )
    display.start()
    try:
        for text in OPERATOR_TEXT:
            log.ASH_LOGGER.info(
                f"(npm-audit @ source) Target directory {text} is empty"
            )
        display.live.refresh()
        log.ASH_LOGGER.info("a later line, which scrolls the first one out")
        display.live.refresh()
    finally:
        display.stop()

    rendered = display.console.export_text()
    for text in OPERATOR_TEXT:
        assert f"Target directory {text} is empty" in rendered, rendered


def test_a_missing_scan_target_is_reported_in_text(tmp_path):
    """The error is logged and printed as text, so markup in it showed as tags."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.exceptions import ScannerError

    class _Config(ScannerPluginConfigBase):
        name: str = "brackets"

    class _Scanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type=None, *_args, **_kwargs):
            raise NotImplementedError

    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )
    scanner = _Scanner(config=_Config(), context=context)
    with pytest.raises(ScannerError) as caught:
        scanner._pre_scan(target=tmp_path / "a[/x]", target_type="source")

    message = str(caught.value)
    assert message.startswith("(brackets @ source) Target "), message
    assert message.endswith("a[/x] does not exist!"), message


def test_an_expired_entry_whose_name_reads_as_markup_is_logged_as_text(
    tmp_path, capsys, monkeypatch
):
    """A suppression's rule id and an ignore path come from the repository's
    configuration. Read as markup, an expired one named "R[/x]" raised MarkupError
    out of the matcher's debug line, and the scan applying it failed with it and
    lost its results. Each line the matcher and the expiry warning log about one
    is text, on the console and in ash.log, at the level --debug sets."""
    from automated_security_helper.models.core import (
        AshSuppression,
        IgnorePathWithReason,
    )
    from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
        suppression_expiration_checker,
    )
    from automated_security_helper.utils import suppression_matcher

    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name=f"ash-markup-expired-{next(_names)}",
        level=logging.DEBUG,
        file_log_level=logging.DEBUG,
        output_dir=tmp_path,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    monkeypatch.setattr(suppression_matcher, "ASH_LOGGER", logger)
    monkeypatch.setattr(suppression_expiration_checker, "ASH_LOGGER", logger)
    capsys.readouterr()
    suppression = AshSuppression(
        rule_id="R[/x]", path="src/*", reason="probe", expiration="2020-01-01"
    )
    ignore_path = IgnorePathWithReason(
        path="R[/x]", reason="probe", expiration="2020-01-01"
    )
    try:
        # An expired suppression is passed over before the finding is looked at.
        assert suppression_matcher.should_suppress_finding(object(), [suppression]) == (
            False,
            None,
        )
        assert suppression_matcher.active_ignore_paths([ignore_path]) == []
        # Each list of ignore-path entries comes with the subject that names it
        # and its location.
        suppression_expiration_checker._warn_about_expired_entries(
            [("Ignore path", [ignore_path], "global_settings.ignore_paths")],
            [suppression],
        )
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []

    console = _logged(capsys)
    written = " ".join(
        (tmp_path / f"{logger.name}.log").read_text(encoding="utf-8").split()
    )
    # The matcher's debug lines name each entry by its location; the expiry
    # warning names the rule id and the path, which read as markup.
    for line in (
        "global_settings.suppressions[0] has expired",
        "global_settings.ignore_paths[0] has expired",
        "Ignore path 'R[/x]' expired on 2020-01-01",
        "Suppression of rule 'R[/x]' for 'src/*' expired on 2020-01-01",
    ):
        assert line in console, (line, console)
        assert line in written, (line, written)


#: A Rich style or link tag, as a message written for a markup sink carries it.
_STYLE_TAG = re.compile(
    r"\[/?(?:bold|italic|dim|underline|red|green|yellow|blue|magenta|cyan|white"
    r"|black|link)\b[^\]]*\]"
)


def test_no_raised_message_is_markup():
    """An exception's text is logged and printed as text, so it carries no tags."""
    package = Path(__file__).resolve().parents[3] / "automated_security_helper"
    tagged = set()
    for source in sorted(package.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Raise) or node.exc is None:
                continue
            for part in ast.walk(node.exc):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if _STYLE_TAG.search(part.value):
                        tagged.add(f"{source.relative_to(package)}:{node.lineno}")

    assert sorted(tagged) == [], sorted(tagged)
