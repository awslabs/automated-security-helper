import contextvars
import json
import logging
import os
import platform
import re
import sys
import threading
import time
import traceback
import uuid
from contextlib import contextmanager
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    Literal,
    Optional,
    Set,
    TextIO,
    Tuple,
)
from rich.errors import MarkupError
from rich.logging import RichHandler
from rich.theme import Theme
from pathlib import Path
from automated_security_helper.utils.console import ash_console, check_commands_of

# Re-exported: the factory lived here first, and callers reached it as this
# module's. Its home is utils/threads.py, which says why.
from automated_security_helper.utils.threads import ash_thread as ash_thread
from automated_security_helper.utils.process_env import setdefault_environ
from automated_security_helper.utils.terminal_text import (
    ShownText,
    commands_broken,
    escape_for,
    is_shown_as_escape,
    raw_controls_shown,
    shown_in_ascii,
    shown_not_obeyed,
    shown_on_one_line,
)


#: The frames a level method of ASHLogger (verbose, trace, the ones
#: addLoggingLevel installs) adds to the stacklevel a caller asked for, so a
#: record names the caller's file and line rather than the wrapper's. One on
#: Python 3.11 and later, where findCaller starts at its own frame and counts
#: outward past logging's own frames only, so the wrapper's frame is the one the
#: extra step skips; none before 3.11, where findCaller started three frames up,
#: at the wrapper itself, and stepped back once on its own, so the extra step
#: named the caller's caller there.
_WRAPPER_FRAME = 1 if sys.version_info >= (3, 11) else 0


def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Adapted from: https://stackoverflow.com/a/35804945

    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5
    """
    if not methodName:
        methodName = levelName.lower()

    # Guard against duplicate registration (e.g. module re-import). When the
    # attribute is there but the NAME is not registered (another library set
    # logging.TRACE as a bare attribute), the name is registered at the number
    # the attribute carries: get_logger reads the level's name, and an
    # unregistered one read as "Level 5". A name that is already registered is
    # left where it is, whatever number this call asked for: registering it at
    # the new number re-pointed the name for the whole process, so a second
    # addLoggingLevel("TRACE", 99) made every logger get_logger pins to TRACE
    # take level 99 and every file handler stay empty.
    if hasattr(logging, levelName):
        existing = getattr(logging, levelName)
        if isinstance(existing, int) and not isinstance(
            logging.getLevelName(levelName), int
        ):
            logging.addLevelName(existing, levelName)
        return
    if hasattr(logging, methodName):
        return
    if hasattr(logging.getLoggerClass(), methodName):
        return

    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            # The caller's frame, not this wrapper's (see _WRAPPER_FRAME).
            kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + _WRAPPER_FRAME
            self._log(levelNum, message, args, **kwargs)

    def logToRoot(message, *args, **kwargs):
        # The root logger is the point of this function, not an oversight.
        # `setattr(logging, methodName, logToRoot)` below publishes it as
        # `logging.trace()` / `logging.verbose()` -- the module-level convenience
        # form that mirrors stdlib `logging.info()`, which is also a root-logger
        # call. Both spellings are in this function's docstring (`logging.trace('so
        # did this')`). Pointing this at a named logger would make
        # `logging.trace()` write somewhere its stdlib counterparts do not, which
        # is the opposite of the recipe's contract. Per-logger use goes through
        # `logForLevel`, set on the logger class just above.
        logging.log(levelNum, message, *args, **kwargs)  # noqa: LOG015

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)


addLoggingLevel("TRACE", 5)
addLoggingLevel("VERBOSE", 15)

VERBOSE_LEVEL: int = logging._nameToLevel.get("VERBOSE", 15)  # type: ignore[attr-defined]
TRACE_LEVEL: int = logging._nameToLevel.get("TRACE", 5)  # type: ignore[attr-defined]


class ASHLogger(logging.Logger):
    """Logger subclass that adds verbose() and trace() as first-class methods."""

    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name=name, level=level)

    # The wrapper's frame added to the stacklevel where findCaller counts it
    # (_WRAPPER_FRAME): without it the record's file and line were this
    # method's, not the caller's, on Python 3.11 and later; with it on every
    # version they were the caller's caller before 3.11.
    def verbose(self, msg, *args, **kws):
        if self.isEnabledFor(VERBOSE_LEVEL):
            kws["stacklevel"] = kws.get("stacklevel", 1) + _WRAPPER_FRAME
            self._log(VERBOSE_LEVEL, msg, args, **kws)

    def trace(self, msg, *args, **kws):
        if self.isEnabledFor(TRACE_LEVEL):
            kws["stacklevel"] = kws.get("stacklevel", 1) + _WRAPPER_FRAME
            self._log(TRACE_LEVEL, msg, args, **kws)

    def callHandlers(self, record: logging.LogRecord) -> None:
        """logging's, but for ASH's loggers a record no handler takes is shown.

        logging passes a record that finds no handler on its way up to
        logging.lastResort, which writes it to stderr as given. For "ash" and the
        loggers under it, :data:`_LAST_RESORT` takes it instead, so its controls
        are shown and its commands broken. The walk is logging's own: any handler
        on the way, of the logger or a parent it propagates to, takes the record
        and no last resort runs. Being no handler of the logger's, the stand-in
        is not removed when something clears the handlers (the ash command does,
        cli/main.py's reset_logging_config), and a reload of this module does not
        add a second one. Every other logger keeps logging's last resort.

        A handler of another run's (run_log_scope) counts as none: when every
        handler on the way belongs to a run that does not take the record
        (:func:`_run_takes`), the record has nowhere to go but the last resort.
        That is a record of no run's while the MCP server runs scans, which no
        session's ash.log takes, and the server has no handler of its own on
        "ash": it is shown on stderr, as it is when no scan runs.
        """
        if self.name != "ash" and not self.name.startswith("ash."):
            super().callHandlers(record)
            return
        homed = False
        current = _RUN_LOG_SCOPE.get()
        logger: Optional[logging.Logger] = self
        while logger is not None:
            # A copy of the list: another run's setup or close removes handlers
            # while this record walks them, and a removal from the live list
            # under the walk skips the handler after it, this run's own included.
            for handler in list(logger.handlers):
                scope = getattr(handler, _RUN_SCOPE_ATTR, None)
                if scope is None or _run_takes(scope, current):
                    homed = True
                if record.levelno >= handler.level:
                    handler.handle(record)
            logger = logger.parent if logger.propagate else None
        if not homed and record.levelno >= _LAST_RESORT.level:
            _LAST_RESORT.handle(record)


def delivers(logger: logging.Logger, level: int) -> bool:
    """Whether a record at ``level`` that ``logger`` handles reaches a handler.

    The walk :meth:`ASHLogger.callHandlers` makes, asked before a record
    exists: a handler of the logger, or of a parent it propagates to, whose
    level admits ``level`` -- counting, for ASH's loggers, only handlers that
    would TAKE the record. A handler scoped to another run drops what it is
    handed (_RunScopedFilter), so it is no delivery and no home: a record no
    counted handler exists for goes to the last resort, exactly when
    callHandlers runs it. A counted handler whose level refuses the record is
    still its home (the last resort stays out), so the answer is False then.
    The logger's own level is not part of it: a record logged through ``_log``
    (``PluginBase._plugin_log`` does) skips that check, so the handlers'
    levels decide delivery. For work done only to build such a record -- a
    DEBUG dump of a whole config -- this is the predicate that skips the work
    exactly when nothing would receive it. Other filters are not consulted,
    so the answer can only err toward doing the work.
    """
    if logger.disabled:
        return False
    ash = logger.name == "ash" or logger.name.startswith("ash.")
    current_scope = _RUN_LOG_SCOPE.get() if ash else None
    homed = False
    current: Optional[logging.Logger] = logger
    while current is not None:
        for handler in current.handlers:
            if ash:
                scope = getattr(handler, _RUN_SCOPE_ATTR, None)
                if scope is not None and not _run_takes(scope, current_scope):
                    continue
            homed = True
            if level >= handler.level:
                return True
        current = current.parent if current.propagate else None
    if homed:
        return False
    if ash:
        return level >= _LAST_RESORT.level
    # The handler logging's last resort hands the record to: the router this
    # module installs sits at NOTSET and gates per branch, so its own level
    # answered True for every level; the fallback behind it holds the gate.
    last_resort = logging.lastResort
    if last_resort is None:
        return False
    fallback = getattr(last_resort, "fallback", last_resort)
    return level >= fallback.level


logging.setLoggerClass(ASHLogger)


def adopt_early_ash_loggers() -> None:
    """Make every plain logger under "ash" made before this module an ASHLogger.

    logging builds a logger with the class set at the moment it is first asked
    for, so ``logging.getLogger("ash")`` run by a module imported before this one
    (utils.severity_ladder takes the logger by name at import, and core.constants
    imports it first in every CLI process) made a plain ``logging.Logger`` that
    every later ``getLogger("ash")`` returns: ``isinstance(ASH_LOGGER, ASHLogger)``
    was False, and :meth:`ASHLogger.callHandlers`, the run-scoped last-resort
    walk, never ran for ASH's records. ``ASHLogger`` adds methods and no state, so
    such a logger is given this class in place, which keeps its handlers,
    filters, level and children. A ``Logger`` subclass another library made is
    not touched. Run at import and at every :func:`get_logger`.
    """
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if type(logger) is not logging.Logger:
            continue
        if name == "ash" or name.startswith("ash."):
            logger.__class__ = ASHLogger


# The console handler below, and the live progress panel in rich_log_handler.py,
# print a log message as text. Markup is opt-in per call, with MARKUP.
#
# With markup=True, Rich would parse "[...]" in every message, and most messages
# carry text ASH does not control: repository paths, exception text, subprocess
# output, command lines. Two shapes would do harm, and only one loudly:
#
#   * "[/bin/bash -c]" -- body starts with "/", so Rich reads a closing tag with
#     no opener and raises MarkupError. RichHandler.emit does not catch it and
#     neither does logging.Handler.handle, so the exception would leave the
#     logging call and replace whatever was running (`ash merge --output-dir
#     'out[/x]'` would exit 1 without its reports), and `logger.exception(e)` on
#     such an error would raise again from the handler meant to report it.
#   * "[node_modules]" -- body starts with a lowercase letter, so Rich reads an
#     opening tag, consumes it as a style name and drops it. Nothing raises;
#     "semgrep --exclude [node_modules]" would log as "semgrep --exclude".
#
# Escaping every interpolated value at every call site is the alternative, and a
# fragile one: a new call site that forgot would be a new crash, and an
# escaped value reaches the JSONL and tabular file handlers with a literal
# backslash in it. Off at the sink, the default is right without the call site
# doing anything.
#
# Rich's tag pattern is \[([a-z#/@][^[]*?)], so only those four leading
# characters matter -- "[0]", "[B404]" and a Python argv repr are inert either way.
MARKUP: Dict[str, bool] = {"markup": True}
"""``extra`` for a log call whose message is Rich markup: it styles part of itself.

``RichHandler.render_message`` reads ``getattr(record, "markup", self.markup)``,
so this turns markup on for one record, and the live panel reads the same
attribute. Every value interpolated into such a message has to go through
:func:`escape_markup`, or a bracket in it is read as a tag again. Keep the styled
calls few: the file handlers receive the message string as written, tags and
escapes included.
"""

NO_MARKUP: Dict[str, bool] = {"markup": False}
"""``extra`` that keeps one record's message as text.

That is the handlers' default, so this changes nothing; it keeps the calls that
pass it valid, and keeps a message text even if the default is ever changed.
"""


def escape_markup(value: object, *, one_line: bool = False) -> str:
    """Neutralize Rich markup in *value* so it renders as the text it is.

    For a log message logged with :data:`MARKUP`, and for ``rich.print``, which
    reads every string as markup: escape the untrusted value only. Escaping the
    whole message would print the styling tags literally instead of applying them.
    A message logged without MARKUP is text, so escaping a value in it prints the
    backslash.

    The value goes through utils/terminal_text.py's shown_not_obeyed first, so its
    terminal controls print as escapes and its CI commands are broken: every
    markup sink prints to a terminal or a CI log. The log file handlers receive a
    MARKUP record's text with those escapes in it.

    The result renders as *value* wherever it sits in the message. Rich reads
    backslashes only before a tag, two for each literal one, so ``escape`` alone
    shows a single trailing backslash twice at the end of a message, and before a
    tag loses one of two trailing backslashes or, with three, escapes the tag. Here
    trailing backslashes are doubled and end on an empty style of their own.

    A value that is a ShownText (utils/terminal_text.py) was shown already, and is
    only escaped for Rich. With ``one_line`` the value is shown as
    shown_on_one_line shows it, its newlines and tabs as escapes too, for a value
    in a message that is one line: a path a refusal names.

    Rich also replaces each emoji code (``:warning:``, ``:lock:``) in a segment of
    text between tags, which the escape leaves alone, so each code in the escaped
    value is split across two segments by an empty ``[none][/none]`` after its
    first colon (:func:`_emoji_codes_split`): it shows as written, and an emoji
    code in the message's own markup renders. The tag follows a colon, so no
    backslash of the escape stands before it. A tag-shaped value holding a colon
    (``[a:b:]``) is opened rather than escaped, its ``[`` followed by an empty
    style, so Rich reads no tag there and a code in it is split like any other: a
    break inside an escaped tag would have ended the tag and shown the escape's
    backslash, and leaving the code whole rendered it as an emoji. A value
    holding a colon is also closed off at both ends by an empty style, so a code
    it forms with the message's text beside it (``:lock`` against ``: done``)
    does not render as an emoji.
    """
    # Shown, not obeyed, first: every markup sink (rich.print, a progress
    # description, a MARKUP log record) prints the value to a terminal or a CI log,
    # so its controls are written as escapes and its CI commands broken here once.
    # str() of a ShownText is plain text, which would be shown a second time.
    # Each escaper is called by its own name: the shown-twice guard reads calls,
    # and through an alias it read this function, and everything built on it, as
    # one that never shows, so a real double show behind it went unseen.
    if one_line:
        text = shown_on_one_line(value if isinstance(value, ShownText) else str(value))
    else:
        text = shown_not_obeyed(value if isinstance(value, ShownText) else str(value))
    return _escaped_for_rich(text)


#: An emoji code as Rich reads one (rich/_emoji_replace.py), which Rich replaces
#: in each segment of text between markup tags.
_EMOJI_CODE = re.compile(r"(:(\S*?)(?:(?:\-)(emoji|text))?:)")

#: An empty style, which renders as nothing and ends a text segment.
_SEGMENT_BREAK = "[none][/none]"


#: A tag Rich's escape wrote a backslash before, in escaped text, with the run
#: of backslashes the escape doubled in front of it: the added backslash counts
#: only while the tag behind it is whole.
_ESCAPED_TAG = re.compile(r"(\\*)\\(\[[a-z#/@][^[]*?\])")


def _opened_if_it_holds_a_colon(match: "re.Match[str]") -> str:
    """The escaped tag *match* opened when a colon sits inside it.

    A colon inside the tag can start an emoji code, whole inside the tag
    (``[a:b:]``) or ending after it (``[a:b]:c``), and the split after that colon
    would end the tag. So the tag's ``[`` is followed by an empty style instead:
    Rich reads no tag there (a ``[`` right before another ``[`` starts none) and
    the escape's own backslash is not needed. The backslashes the escape doubled
    in front of the tag stay, and an empty style follows them: Rich halves an
    even run of backslashes in front of a tag and prints the other half, which
    gives the value's own backslashes back. Left in front of the opened ``[``
    instead, they are read as text, and Rich turns the last ``\\[`` of that text
    into ``[``, so a value with a backslash before the tag rendered one short.
    A tag holding no colon is returned as it was.
    """
    doubled, tag = match.group(1), match.group(2)
    if ":" not in tag:
        return match.group(0)
    if not doubled:
        return "[" + _SEGMENT_BREAK + tag[1:]
    return doubled + _SEGMENT_BREAK + "[" + _SEGMENT_BREAK + tag[1:]


def _emoji_codes_split(text: str) -> str:
    """``text`` with ``[none][/none]`` after the first colon of each emoji code.

    Each search starts just after the colon the last break followed, so a code
    that overlaps the one before it (the ``:lock:`` of ``:x:lock:``) is split too:
    no segment of the result holds two colons with a code between them. An
    escaped tag holding a colon is opened first (:func:`_opened_if_it_holds_a_colon`),
    so a break after that colon ends no tag and no code is left whole: a code
    left whole in one segment rendered as its emoji, and a break inside an
    escaped tag showed the escape's backslash.
    """
    text = _ESCAPED_TAG.sub(_opened_if_it_holds_a_colon, text)
    pieces = []
    start = 0
    search_from = 0
    while True:
        code = _EMOJI_CODE.search(text, search_from)
        if code is None:
            break
        cut = code.start() + 1
        pieces.append(text[start:cut])
        pieces.append(_SEGMENT_BREAK)
        start = cut
        search_from = cut
    pieces.append(text[start:])
    return "".join(pieces)


def _escaped_for_rich(text: str) -> str:
    """*text*, already shown, escaped so a markup sink renders it as itself.

    The escaping half of :func:`escape_markup`: Rich's escape, trailing
    backslashes doubled and ended on an empty style, and each emoji code split
    across two segments. For text that was shown already (escape_markup's own
    shown value, or the Windows filter's fallback, whose text is the ASCII form
    of a message whose values were shown when they were escaped), so showing it
    here would print each control's escape twice.
    """
    from rich.markup import escape

    body = text.rstrip("\\")
    trailing = len(text) - len(body)
    if not trailing:
        escaped = _emoji_codes_split(escape(text))
    else:
        escaped = _emoji_codes_split(escape(body) + "\\" * (2 * trailing))
    if ":" in text:
        # Closed off at both ends, so no emoji code forms across the value's
        # edge with the message's own text.
        escaped = f"{_SEGMENT_BREAK}{escaped}{_SEGMENT_BREAK}"
    if trailing:
        escaped += _SEGMENT_BREAK
    return escaped


def console_text(record: logging.LogRecord, message: str) -> str:
    """*message* as the console and the live panel print it.

    The console is a terminal or a CI log, so its text goes through
    utils/terminal_text.py's shown_not_obeyed: controls as escapes, CI commands
    broken. A record logged with MARKUP had its values shown that way by
    escape_markup already, so only raw controls and commands are handled there; a
    second full pass would double the backslashes of those escapes. ash.log, the
    tabular log file, writes its text the same way (TextFileFormatter); the JSONL
    log keeps it as written, in JSON's own escapes.

    A record whose message is a ShownText (utils/terminal_text.py's
    shown_not_obeyed or shown_on_one_line made it, or WindowsSafeFilter's
    shown_in_ascii put it in ASCII) and that has no arguments is
    written as it is, for the same reason: a call site showed it, its values
    included. With arguments, the logger put them in as given, so the whole
    message is shown; and a *message* the handler's format added to is shown too,
    except a traceback or a stack the formatter wrote on the lines after it
    (exc_info, stack_info), which is shown on its own, the message passed on.
    """
    if getattr(record, "markup", False):
        return raw_controls_shown(message)
    if isinstance(record.msg, ShownText) and not record.args:
        if message == record.msg:
            return message
        after = message[len(record.msg) :]
        if message.startswith(record.msg) and after.startswith("\n"):
            return record.msg + shown_not_obeyed(after)
    return shown_not_obeyed(message)


def _show_trace(trace) -> None:
    """Pass the text a Rich traceback quotes through :func:`shown_not_obeyed`, in place.

    With rich_tracebacks, RichHandler renders exc_info itself, apart from the
    message: the exception's text, its notes, a SyntaxError's line, and each
    frame's file name, where an error raised over a repository path or a tool's
    output put its controls on the console raw. Locals are reprs, which show
    controls already, and the source lines are the code that ran.

    A frame's file name is the one Rich reads the source lines from, so it is
    rewritten only when it holds something that must be shown (a control, a
    command form): shown whatever it held, a Windows path with a segment that
    reads as an escape (``...\\x64\\...``) had its backslash doubled, Rich found
    no file of that name, and the frame lost its source lines.
    """
    for stack in trace.stacks:
        stack.exc_type = shown_not_obeyed(stack.exc_type)
        stack.exc_value = shown_not_obeyed(stack.exc_value)
        stack.notes = [shown_not_obeyed(note) for note in stack.notes]
        error = stack.syntax_error
        if error is not None:
            error.filename = _shown_file_name(error.filename)
            error.line = shown_not_obeyed(error.line)
            error.msg = shown_not_obeyed(error.msg)
            error.notes = [shown_not_obeyed(note) for note in error.notes]
        for frame in stack.frames:
            frame.filename = _shown_file_name(frame.filename)
            frame.name = shown_not_obeyed(frame.name)
            frame.line = shown_not_obeyed(frame.line)
        for group_trace in stack.exceptions:
            _show_trace(group_trace)


def _shown_file_name(filename: str) -> str:
    """*filename* as given when nothing in it must be shown, else shown."""
    if not isinstance(filename, str):
        return filename
    if any(is_shown_as_escape(character) for character in filename):
        return shown_not_obeyed(filename)
    if commands_broken(filename) != filename:
        return shown_not_obeyed(filename)
    return filename


class ShownHandlerErrors:
    """For each of ASH's log handlers: a record it fails to write is reported shown.

    When a handler cannot write a record (an argument raises as it is formatted,
    a MARKUP message does not parse, the stream fails), logging.Handler.handleError
    prints the error's traceback and the record's arguments to stderr as given,
    and both can quote a repository path, a tool's output or an error from either.
    Here the traceback, and the file and line that logged the record, go through
    :func:`shown_not_obeyed` instead. The message and its arguments are left out,
    since making their text may be what failed. logging.raiseExceptions still
    turns the report off.
    """

    def handleError(self, record: logging.LogRecord) -> None:
        self._report_error(record, traceback.format_exc())

    def _report_error(self, record: logging.LogRecord, trace: str) -> None:
        """Write *trace*, raw text, and where the record was logged, shown once."""
        if not (logging.raiseExceptions and sys.stderr):
            return
        report = (
            "--- Logging error ---\n"
            + trace
            + f"Logged from file {record.filename}, line {record.lineno}\n"
        )
        try:
            sys.stderr.write(shown_not_obeyed(report))
        except OSError:
            pass


def _raw_markup_trace(error: MarkupError, record: logging.LogRecord) -> str:
    """*error*'s traceback, its message as Rich gives it for the raw message.

    The console shows a MARKUP message before Rich parses it, so the tag Rich's
    error quotes holds the escapes the console wrote, and the report would show
    them a second time: ESC as the text "\\x1b". Parsed raw, the message gives the
    same error quoting the tag itself, which the report shows once. When the raw
    message does not fail the same way, the error is reported as it was raised.
    """
    from rich.text import Text

    trace = traceback.TracebackException.from_exception(error)
    whole = "".join(trace.format())
    shown_message = "".join(trace.format_exception_only())
    try:
        Text.from_markup(record.getMessage())
    except MarkupError as raw_error:
        if whole.endswith(shown_message):
            raw_message = "".join(
                traceback.format_exception_only(type(raw_error), raw_error)
            )
            return whole[: len(whole) - len(shown_message)] + raw_message
    except Exception:  # nosec B110 - the error is reported as raised, below
        pass
    return whole


class ConsoleHandler(ShownHandlerErrors, RichHandler):
    """The console's RichHandler: each message, and each traceback, as text shown.

    Both go through :func:`shown_not_obeyed`. ash.log's formatter applies the same
    rule (TextFileFormatter); the JSONL formatter keeps the record as written.
    """

    def emit(self, record: logging.LogRecord) -> None:
        # Rich's emit formats the record and renders its markup outside its own
        # try, which covers only the print: an argument whose text raises, or a
        # MARKUP message that does not parse, escaped the log call, and the
        # default excepthook wrote its text as given. Reported as logging's own
        # handlers report a failure, through ShownHandlerErrors.
        try:
            super().emit(record)
        except RecursionError:
            raise
        except MarkupError as error:
            # Rich parsed the message after it was shown: reported with the tag as
            # the raw message holds it, so the report shows it once.
            self._report_error(record, _raw_markup_trace(error, record))
        except Exception:
            self.handleError(record)

    def render_message(self, record: logging.LogRecord, message: str):
        markup = getattr(record, "markup", self.markup)
        if markup:
            # Without rich_tracebacks the formatter appends the traceback and
            # the stack after the message; neither is markup, so only the
            # message is read as markup and the rest is appended as text.
            own = record.getMessage()
            if message.startswith(own) and len(message) > len(own):
                rendered = super().render_message(record, console_text(record, own))
                rendered.append(str(shown_not_obeyed(message[len(own) :])))
                return rendered
        return super().render_message(record, console_text(record, message))

    def render(self, *, record: logging.LogRecord, traceback, message_renderable):
        if traceback is not None:
            _show_trace(traceback.trace)
        return super().render(
            record=record, traceback=traceback, message_renderable=message_renderable
        )


# Variables a CI runner sets, any value counting: GitHub Actions, Azure
# Pipelines, TeamCity, Jenkins, CodeBuild, GitLab CI, Buildkite, CircleCI,
# Travis CI, AppVeyor, Bitbucket Pipelines and Bamboo, which can set one of these
# alone. And the CI most of the others set, to "true" or to their own word ("1"
# on Vercel), counting unless it is empty, "0" or "false". The one list for the
# locals rule and for the Windows console checks below.
_CI_RUNNER_MARKERS = (
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "AZURE_PIPELINES",
    "TEAMCITY_VERSION",
    "JENKINS_URL",
    "CODEBUILD_BUILD_ID",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "APPVEYOR",
    "BITBUCKET_BUILD_NUMBER",
    "bamboo_buildKey",
)
_CI_OFF = ("", "0", "false")

SHOW_LOCALS_IGNORED = (
    "ASH_DEBUG_SHOW_LOCALS is set but ignored: a CI runner was detected, and the "
    "local variables a traceback shows can include secrets from the config and "
    "the environment, which a CI log would show to everyone who can read it."
)

# The warning above is logged once a process, by the first get_logger call.
_locals_warning_logged = False


def _on_a_ci_runner() -> bool:
    if any(name in os.environ for name in _CI_RUNNER_MARKERS):
        return True
    return os.environ.get("CI", "").strip().casefold() not in _CI_OFF


#: The variable's spelling for callers that must NAME it without reading it
#: (the container pass-through exclusion list imports this constant instead of
#: spelling it again). The read below spells it literally on purpose: the
#: docs-freshness gate resolves environment names by walking the AST for
#: literal lookup keys, and a constant-keyed read would drop the name from the
#: reachable set while the CLI reference still tabulates it. Keep the constant
#: and the read adjacent so a rename changes both or neither.
SHOW_LOCALS_VARIABLE = "ASH_DEBUG_SHOW_LOCALS"


def _show_locals_requested() -> bool:
    return os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper() in [
        "YES",
        "1",
        "TRUE",
    ]


def show_debug_locals() -> bool:
    """Whether a traceback shows each frame's local variables.

    ASH_DEBUG_SHOW_LOCALS asks for them, for a maintainer debugging on their
    own machine. They can hold secrets from the config and the environment, so
    on a CI runner, whose log others read, the request is ignored and
    ``get_logger`` logs SHOW_LOCALS_IGNORED. The one rule for the console log
    handler and for every typer app's handler of an uncaught error.
    """
    return _show_locals_requested() and not _on_a_ci_runner()


#: Characters ASH's own messages emit that a narrow console code page cannot
#: encode: the console-encoding checks below try to encode these.
_EMOJI_PROBE = "✅🔴⚠️"


def _console_cannot_encode(encoding: Optional[str]) -> bool:
    """Whether a console with *encoding* cannot write ASH's own emoji.

    Tried by encoding, rather than read off a fixed list of code pages: the
    list named five (cp1252, cp850, cp437, ascii and a spelling of the first)
    and left every other narrow code page (cp1251, cp932, cp936, cp949,
    cp1250) as it was, where the same write failed. A stream that names no
    encoding is read as UTF-8, as before.
    """
    try:
        _EMOJI_PROBE.encode(encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return True
    return False


def _detect_encoding_issues() -> bool:
    """Return True if running on Windows with an encoding that cannot represent Unicode."""
    if platform.system().lower() != "windows":
        return False

    # By value, as every other CI read here: CI set to "", "0" or "false" is
    # no runner (_on_a_ci_runner), where presence alone counted it as one.
    is_ci = _on_a_ci_runner()

    try:
        console_encoding = sys.stdout.encoding
    except (AttributeError, TypeError):
        return True

    return is_ci or _console_cannot_encode(console_encoding)


def _get_default_emoji_fallback_map() -> Dict[str, str]:
    """Get the default emoji fallback mapping for Windows."""
    return {
        "✅": "[OK]",
        "🔴": "[ERROR]",
        "⚠️": "[WARNING]",
        "🚀": "[INFO]",
        "📁": "[FOLDER]",
        "📄": "[FILE]",
        "🔍": "[SEARCH]",
        "💾": "[SAVE]",
        "🔧": "[CONFIG]",
        "📊": "[STATS]",
        "🎯": "[TARGET]",
        "⏱️": "[TIME]",
        "🔒": "[SECURE]",
        "🔓": "[INSECURE]",
        "📝": "[NOTE]",
        "❌": "[FAIL]",
        "✨": "[SUCCESS]",
        "🛡️": "[SECURITY]",
        "🔎": "[SCAN]",
        "📋": "[LIST]",
        "⭐": "[STAR]",
        "🎉": "[CELEBRATE]",
        "🚨": "[ALERT]",
        "💡": "[TIP]",
        "🔄": "[REFRESH]",
        "📈": "[PROGRESS]",
        "🏁": "[FINISH]",
        "🎪": "[DEMO]",
        "🔗": "[LINK]",
        "📦": "[PACKAGE]",
        "🌟": "[FEATURE]",
        "🎨": "[STYLE]",
        "🧪": "[TEST]",
        "🔥": "[HOT]",
        "❄️": "[COLD]",
        "🌈": "[RAINBOW]",
        "🎭": "[MASK]",
        "🎲": "[DICE]",
        "🎮": "[GAME]",
        "🎸": "[MUSIC]",
        "🎤": "[MIC]",
        "🎬": "[MOVIE]",
        # Unicode warning symbol specifically (the one causing the error)
        "⚠": "[WARNING]",
        # Other common Unicode symbols
        "✓": "[CHECK]",  # ✓
        "✗": "[X]",  # ✗
        "→": "->",  # →
        "←": "<-",  # ←
        "↑": "^",  # ↑
        "↓": "v",  # ↓
    }


def _make_message_windows_safe(message: str, emoji_fallback_map: Dict[str, str]) -> str:
    """Convert a message with Unicode characters to a Windows-safe version."""
    safe_message = message
    for unicode_char, ascii_replacement in emoji_fallback_map.items():
        safe_message = safe_message.replace(unicode_char, ascii_replacement)
    return safe_message


#: Set on a record WindowsSafeFilter rewrote: its message and arguments as they
#: were logged. The UTF-8 file sinks write from these (_file_text), so the
#: ASCII rewrite made for a console that cannot encode never reaches a file.
_UNFILTERED_ATTR = "_ash_unfiltered"


class WindowsSafeFilter(logging.Filter):
    """Logging filter that puts a record's text in ASCII on Windows when the
    console's encoding is limited.

    The filter sits on the logger, so every handler sees its rewrite; the
    record keeps what was logged (``_UNFILTERED_ATTR``), and the file handlers'
    formatters write from that, so ash.log and the JSONL file keep the text
    whole. A plain-str message is shown (utils/terminal_text.py) and put in
    ASCII as one ShownText, so nothing is dropped: a character outside ASCII and
    outside the emoji map is written as its escape, where it used to be deleted
    (a path lost its accented letters). A message with arguments is formatted
    first, so the arguments go through the same rule.
    """

    def __init__(self):
        super().__init__()
        self._active = _detect_encoding_issues()
        self._emoji_map = _get_default_emoji_fallback_map()

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._active:
            return True
        if not hasattr(record, _UNFILTERED_ATTR):
            setattr(record, _UNFILTERED_ATTR, (record.msg, record.args))
        if isinstance(record.msg, ShownText):
            # Shown already, so the sinks leave it as it is. Rebuilt as a plain
            # str, it was shown a second time; and a character dropped from it
            # could join "::" into a command (shown_in_ascii says how).
            record.msg = shown_in_ascii(record.msg, self._emoji_map)
        elif isinstance(record.msg, str):
            if getattr(record, "markup", False):
                safe = self._in_ascii(record.msg)
                record.msg = self._markup_in_ascii(record, safe)
            else:
                # Formatted with its arguments, shown once, and put in ASCII
                # with every character kept as text or as its escape. A record
                # whose arguments do not fit its message keeps both and has
                # each put in ASCII on its own. A message the console can
                # already write (ASCII, its arguments in) is left as it was
                # logged: this filter is for what the console cannot encode,
                # the sinks show text themselves, each once, and a handler an
                # application put on the logger gets such a record as written.
                # Shown here, an ASCII message had a backslash run before text
                # that reads as an escape doubled: the JSON "é" of a
                # suggested --config-overrides command came out as "\\u00e9",
                # which the pasted command then read as the text "u00e9".
                folded = self._folded_message(record)
                if folded is None:
                    record.msg = self._in_ascii(record.msg)
                elif not folded.isascii():
                    # Shown for a sink that puts it in ASCII: a backslash run is
                    # doubled only before the text of an escape shown_in_ascii
                    # or shown_not_obeyed writes, so a message that quotes a
                    # path with an accented letter raw and as JSON's escape (the
                    # suggested command above) keeps the escape as logged.
                    record.msg = shown_in_ascii(
                        shown_not_obeyed(folded, lookalikes="ascii"),
                        self._emoji_map,
                    )
                    record.args = ()
        if record.args:
            # The arguments are put into the message when the record is
            # formatted, after this filter: one outside the stream's encoding
            # failed that write and dropped the whole record from the file.
            record.args = self._args_in_ascii(record.args)
        return True

    def _arg_in_ascii(self, value: Any) -> Any:
        if isinstance(value, ShownText):
            return shown_in_ascii(value, self._emoji_map)
        if isinstance(value, str):
            return self._in_ascii(value)
        return value

    def _args_in_ascii(self, args: Any) -> Any:
        """*args*, a record's, with each str in them in ASCII (``_in_ascii``)."""
        if isinstance(args, tuple):
            return tuple(self._arg_in_ascii(value) for value in args)
        if isinstance(args, dict):
            return {key: self._arg_in_ascii(value) for key, value in args.items()}
        return args

    @staticmethod
    def _folded_message(record: logging.LogRecord) -> Optional[str]:
        """The record's message with its arguments put in, or None when they do
        not fit it (the formatting raises); the handlers then report that."""
        try:
            return record.getMessage()
        except Exception:  # noqa: BLE001 -- a message its arguments do not fit
            return None

    def _in_ascii(self, text: str) -> str:
        """*text* in ASCII: the emoji map's replacements, then each character
        still outside ASCII written as its escape (``\\xNN``, ``\\uNNNN``,
        ``\\UNNNNNNNN``). Nothing is dropped: every such character used to be
        deleted, so a path lost its accented letters in the console and, through
        this filter on the logger, in every file sink too."""
        safe = _make_message_windows_safe(text, self._emoji_map)
        if safe.isascii():
            return safe
        return "".join(
            character if character.isascii() else escape_for(character)
            for character in safe
        )

    def _markup_in_ascii(self, record: logging.LogRecord, safe: str) -> str:
        """*safe*, the ASCII form of a markup record's message, if it shows what the
        message showed; otherwise what the message showed, in ASCII, escaped so
        the sinks render it as itself.

        The record's values were escaped for Rich (escape_markup) before this
        rewrite, and a character it replaces or drops can undo that: one dropped
        between a value's own backslash and the escape left two backslashes before
        a tag, which Rich then read as one; an arrow replaced by "v" turned "[↓x]",
        no tag, into "[vx]", one. Either way the line lost its text, or raised
        MarkupError.

        The fallback keeps the record markup. Markup off sent text whose values
        were shown when they were escaped through the console's and ash.log's
        whole-message show, which printed every escape in it twice, while the
        JSONL file held each once.
        """
        from rich.text import Text

        try:
            shown = Text.from_markup(record.msg).plain
        except MarkupError:
            # Not markup to begin with: the sinks write it as they find it.
            return safe
        expected = self._in_ascii(shown)
        try:
            if Text.from_markup(safe).plain == expected:
                return safe
        except MarkupError:
            pass
        return _escaped_for_rich(expected)


def _file_text(record: logging.LogRecord, unfiltered: bool = True) -> str:
    """The message a log file writes for *record*: a MARKUP record as its text.

    A MARKUP message styles part of itself with tags and has its values escaped
    for Rich (escape_markup), so written as is a file got "[yellow]npm-audit[/yellow]"
    and "bandit\\[sarif,toml]". The file gets what the console shows. A message
    that does not parse as markup is written as it is.

    With *unfiltered*, a record WindowsSafeFilter rewrote is written as it was
    logged (``_UNFILTERED_ATTR``): the files are UTF-8, and the rewrite is for
    a console that cannot encode. The last resort, which writes to that
    console, passes False.
    """
    message = _logged_message(record) if unfiltered else record.getMessage()
    if not getattr(record, "markup", False):
        return message
    from rich.errors import MarkupError
    from rich.text import Text

    try:
        return Text.from_markup(message).plain
    except MarkupError:
        return message


def _logged_message(record: logging.LogRecord) -> str:
    """The record's message as it was logged, before any filter rewrote it.

    ``record.getMessage()`` over the message and arguments WindowsSafeFilter
    saved (``_UNFILTERED_ATTR``), else the record's own. A ShownText logged
    with no arguments is returned as it is, so a sink shows it once.
    """
    unfiltered = getattr(record, _UNFILTERED_ATTR, None)
    if unfiltered is None:
        return record.getMessage()
    msg, args = unfiltered
    if not args:
        return msg if isinstance(msg, str) else str(msg)
    return str(msg) % args


class TextFileFormatter(logging.Formatter):
    """The tabular log file's formatter: each message and traceback shown, not obeyed.

    ash.log is read in a terminal and printed in CI logs, so its text goes through
    the console's rule (:func:`console_text`): controls as escapes, CI commands
    broken, each once. A MARKUP record is written as its text, without the tags;
    its values were shown by escape_markup already, so only the raw controls and
    commands left in it are handled. The traceback is formatted here rather than
    taken from the record, where another handler may have cached its raw text.
    A record WindowsSafeFilter put in ASCII is written as it was logged, unless
    *unfiltered* is False (the last resort, which writes to that console).
    """

    def __init__(self, *args: Any, unfiltered: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._unfiltered = unfiltered

    def format(self, record: logging.LogRecord) -> str:
        cached = record.exc_text
        stack = record.stack_info
        cached_only = bool(cached) and not record.exc_info
        record.exc_text = None
        if cached_only:
            # The stack block is written below, after the traceback, in the
            # order logging writes them; left to the base format here it came
            # first, and the cached traceback landed after it.
            record.stack_info = None
        try:
            formatted = super().format(record)
        finally:
            record.exc_text = cached
            record.stack_info = stack
        if cached_only:
            # A record carrying only the cached text has no exc_info to format
            # it from again: a filter rendered the traceback itself and dropped
            # exc_info. The cache is kept, shown, where logging.Formatter.format
            # would have appended it.
            if formatted[-1:] != "\n":
                formatted += "\n"
            formatted += str(shown_not_obeyed(cached))
            if stack:
                if formatted[-1:] != "\n":
                    formatted += "\n"
                formatted += self.formatStack(stack)
        return formatted

    def formatMessage(self, record: logging.LogRecord) -> str:
        record.message = console_text(record, _file_text(record, self._unfiltered))
        return super().formatMessage(record)

    def formatException(self, ei) -> str:
        return shown_not_obeyed(super().formatException(ei))

    def formatStack(self, stack_info: str) -> str:
        return shown_not_obeyed(super().formatStack(stack_info))


class CommandSafeFormatter(TextFileFormatter):
    """A formatter for a handler an application puts on the ``ash`` logger.

    ASH keeps such a handler, and it gets ASH's records as written: a file name
    or a tool's output from the scanned repository in them, a line that starts
    with "::" or a "##vso[" among them. Given this formatter, the handler writes
    each record as ASH's own console and log file do: control characters as
    escapes, CI command lines broken, and a record's Rich markup as its text.
    It takes logging.Formatter's arguments::

        handler.setFormatter(CommandSafeFormatter("%(levelname)s %(message)s"))
    """

    def format(self, record: logging.LogRecord) -> str:
        # The format string's own text stands right against the message, so the
        # two together can form a command neither holds alone (":%(message)s"
        # against ":add-mask::X"). The whole formatted line is checked; a line
        # already broken holds no command form to break again.
        from automated_security_helper.utils.terminal_text import commands_broken

        return commands_broken(super().format(record))


class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.

    @param dict fmt_dict: Key: logging format attribute pairs. Defaults to {"message": "message"}.
    @param str time_format: time.strftime() format string. Default: "%Y-%m-%dT%H:%M:%S"
    @param str msec_format: Microsecond formatting. Appended at the end. Default: "%s.%03dZ"
    """

    def __init__(
        self,
        fmt_dict: dict | None = None,
        time_format: str = "%Y-%m-%dT%H:%M:%S",
        msec_format: str = "%s.%03dZ",
    ):
        self.fmt_dict = fmt_dict if fmt_dict is not None else {"message": "message"}
        self.default_time_format = time_format
        self.default_msec_format = msec_format
        self.datefmt = None
        # The default msec format ends the timestamp with "Z", UTC's designator,
        # so the time it is put on is UTC: logging.Formatter's own converter is
        # time.localtime, which wrote the local wall-clock time under that "Z".
        self.converter = time.gmtime

    def usesTime(self) -> bool:
        """
        Overwritten to look for the attribute in the format dict values instead of the fmt string.
        """
        return "asctime" in self.fmt_dict.values()

    def formatMessage(self, record) -> dict:
        """
        Overwritten to return a dictionary of the relevant LogRecord attributes instead of a string.
        KeyError is raised if an unknown attribute is provided in the fmt_dict.
        """
        return {
            fmt_key: record.__dict__[fmt_val]
            for fmt_key, fmt_val in self.fmt_dict.items()
        }

    def format(self, record) -> str:
        """
        Mostly the same as the parent's class method, the difference being that a dict is manipulated and dumped as JSON
        instead of a string.
        """
        # A MARKUP record as its text, as TextFileFormatter writes it.
        record.message = _file_text(record)

        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)

        message_dict = self.formatMessage(record)

        if record.exc_info:
            # Cache the traceback text to avoid converting it multiple times
            # (it's constant anyway)
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)

        if record.exc_text:
            message_dict["exc_info"] = record.exc_text

        if record.stack_info:
            message_dict["stack_info"] = self.formatStack(record.stack_info)

        # A CI step may print the file, so a "##name[" in a message is written with
        # JSON's escape for its "#"; the line still parses to the same record.
        from automated_security_helper.utils.command_safe_stream import (
            json_commands_broken,
        )

        return json_commands_broken(json.dumps(message_dict, default=str))


# Whether configure_windows_safe_logging has made its one attempt at the process
# locale, and the lock that makes the attempt once even when several threads
# reach it together.
_locale_step_done = False
_LOCALE_STEP_LOCK = threading.Lock()


def configure_windows_safe_logging():
    """Reconfigure stdout/stderr to UTF-8 on Windows consoles that cannot encode.

    This coexists with _make_message_windows_safe, which substitutes ASCII for
    emoji in log records. That covers the logging path only. Direct console writes
    -- typer.secho, typer.echo, print -- bypass the logger entirely, and several
    carry emoji: cli/config.py, cli/main.py and interactions/run_ash_scan.py hold
    18 such characters between them, six of which cp1252 cannot represent.

    On a Windows runner those writes raise UnicodeEncodeError. The failure is
    self-compounding: cli/config.py's validation handler reports errors with
    typer.secho(f"\u274c ..."), so an encoding error inside validation makes the
    handler raise a second encoding error while reporting the first, and the
    process exits 1 with a traceback rather than a message.

    Narrowly gated: returns immediately unless the platform is Windows and either
    CI is detected or the console encoding cannot represent the characters ASH
    emits, so it is a no-op on Linux and macOS.

    The process locale is set on the first call that gets past that gate, and not
    again; the streams are reconfigured on each call, for the streams of the moment.
    """
    global _locale_step_done

    if platform.system().lower() != "windows":
        return

    # Check if we're in a CI environment where encoding might be problematic,
    # by value as _detect_encoding_issues reads it (CI=false is no runner).
    is_ci = _on_a_ci_runner()

    # Check console encoding: whether it can write ASH's own emoji, rather than
    # a fixed list of code pages (_console_cannot_encode).
    try:
        has_encoding_issues = _console_cannot_encode(sys.stdout.encoding)
    except (AttributeError, TypeError):
        has_encoding_issues = True

    if not (is_ci or has_encoding_issues):
        return

    # Try to set UTF-8 encoding for stdout/stderr on Windows
    try:
        import locale

        # Try to set console to UTF-8 if possible
        if (
            sys.stdout
            and hasattr(sys.stdout, "reconfigure")
            and sys.stderr
            and hasattr(sys.stderr, "reconfigure")
        ):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError, ValueError):
                # Fallback: wrap stdout/stderr with UTF-8 codec. ValueError is
                # a closed or detached stream's answer to reconfigure and to
                # detach, which get_logger must not raise for.
                try:
                    sys.stdout = _utf8_writer_in_place_of(sys.stdout)
                    sys.stderr = _utf8_writer_in_place_of(sys.stderr)
                except (AttributeError, OSError, ValueError):
                    pass

        # Set locale to UTF-8 if possible, once a process: the locale is the
        # process's, setlocale is not safe to call from several threads at once,
        # and get_logger runs this for every logger it sets up, MCP scan threads
        # included. A second call would set what the first has set.
        with _LOCALE_STEP_LOCK:
            if not _locale_step_done:
                try:
                    locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
                except locale.Error:
                    try:
                        locale.setlocale(locale.LC_ALL, "C.UTF-8")
                    except locale.Error:
                        pass  # Keep default locale
                _locale_step_done = True

        # Set environment variable for subprocess encoding. Under the shared
        # environment lock: get_logger runs this from MCP scan threads too.
        setdefault_environ("PYTHONIOENCODING", "utf-8:replace")

    except ImportError:
        pass  # locale not available


def _utf8_writer_in_place_of(stream: Any) -> Any:
    """A UTF-8 writer on *stream*'s binary buffer, which configure_windows_safe_logging
    puts in *stream*'s place: the stream is detached from its buffer, and is not
    usable after this. In MCP server mode the stream is a CommandSafeStream
    (check_commands_of_stderr), whose retargeted puts the writer that replaced
    the stream it wraps under a new wrap with the same buffer rule, so its text
    still goes through the CI-command check and stderr's buffer stays checked;
    bytes the old wrap held and the detach stay under the wrap's lock there. The
    writer is a text layer with a ``buffer``, which that needs; write_through,
    as the codec writer it replaced wrote.
    """
    import io

    from automated_security_helper.utils.command_safe_stream import (
        CommandSafeStream,
    )

    if isinstance(stream, CommandSafeStream):
        return stream.retargeted(_utf8_writer_in_place_of)
    return io.TextIOWrapper(
        stream.detach(), encoding="utf-8", errors="replace", write_through=True
    )


#: Set on each handler ASH adds to a logger (get_logger's, the live progress
#: display's). Only a handler that has it is replaced or removed: "ash" is one
#: logger for the whole process, and an application that embeds ASH may have put
#: its own handler on it, which stays.
_ADDED_BY_ASH = "_added_by_ash"


def ash_handler(handler: logging.Handler) -> logging.Handler:
    """*handler*, marked as one ASH added, so remove_ash_handlers can take it off."""
    setattr(handler, _ADDED_BY_ASH, True)
    return handler


def added_by_ash(handler: logging.Handler) -> bool:
    """Whether ASH added *handler* (ash_handler)."""
    return bool(getattr(handler, _ADDED_BY_ASH, False))


def remove_ash_handlers(logger: logging.Logger) -> None:
    """Take the handlers ASH added (ash_handler) off *logger*, and no other.

    A handler another run owns stays: "ash" is one logger for the whole
    process, and the MCP server runs scans in it concurrently, so a scan's
    setup must not strip a running scan's handlers mid-run. A handler is
    another run's while its scope (run_log_scope) is active and is not the
    caller's own; a run's own handlers, and handlers added with no scope, are
    replaced as before.
    """
    current = _RUN_LOG_SCOPE.get()
    # One copy of the list, taken whole: a comprehension read the list while
    # another run's setup or close removed from it, which skipped a handler.
    for handler in list(logger.handlers):
        if not added_by_ash(handler):
            continue
        scope = getattr(handler, _RUN_SCOPE_ATTR, None)
        if scope is not None and scope != current and scope in _ACTIVE_RUN_LOG_SCOPES:
            continue
        logger.removeHandler(handler)


#: Set on each handler get_logger adds while a run's log scope is active, to the
#: scope. Such a handler takes only its own run's records, is not replaced by
#: another run's setup, and is detached when its run ends.
_RUN_SCOPE_ATTR = "_ash_run_log_scope"

#: The log scope of the current context's run: each scan is one run. Follows the
#: run into its scanner workers (scanner_executor wraps each task with
#: contextvars.copy_context().run) and into any thread or task started with a
#: copied context (:func:`ash_thread`). None outside a run, and in threads a run
#: started without copying its context: such a record belongs to no single run
#: (:func:`_run_takes` says where it goes).
_RUN_LOG_SCOPE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "ash_run_log_scope", default=None
)

#: The scopes of the runs that have begun and not ended. remove_ash_handlers
#: keeps another run's handlers only while its scope is here, so a run that
#: ended without detaching (a crashed thread) does not pin its handlers forever.
_ACTIVE_RUN_LOG_SCOPES: Set[str] = set()

#: The active scopes a host opened for the runs it starts (open_run_log_scope):
#: the MCP server's scans, each a session's. A CLI run's own scope
#: (begin_run_log_scope with none open) is not here.
_HOSTED_RUN_LOG_SCOPES: Set[str] = set()


def _run_takes(scope: str, current: Optional[str]) -> bool:
    """Whether a handler of run *scope* takes a record logged in run *current*.

    Its own run's records, and no other run's. A record of no run's (*current*
    None: logged outside every run, or from a thread started without the
    run's context) only while no host runs a run (_HOSTED_RUN_LOG_SCOPES):
    while the MCP server runs scans nothing says whose such a record is, so no
    session's ash.log takes it, and it goes to the handlers of no run's or the
    last resort (ASHLogger.callHandlers). A CLI run is the process's only run,
    and takes such a record as it always did.

    A retired run takes nothing. Its handlers come off the logger when it
    closes, but a thread still in its context can add one afterwards, and no
    close is coming for that orphan: left live, it would take the server's own
    lines and count as their home, keeping them from the last resort.
    """
    if scope not in _ACTIVE_RUN_LOG_SCOPES:
        return False
    if current is None:
        return not _HOSTED_RUN_LOG_SCOPES
    return current == scope


class _RunScopedFilter(logging.Filter):
    """Accepts the records this handler's run takes (:func:`_run_takes`).

    The filter sits on the handler, not the logger, so a walk of the logger's
    handlers (a dump gate deciding whether a record would be delivered) sees
    both the handler and the answer it would give.
    """

    def __init__(self, scope: str) -> None:
        super().__init__()
        self._scope = scope

    def filter(self, record: logging.LogRecord) -> bool:
        return _run_takes(self._scope, _RUN_LOG_SCOPE.get())


def run_handler(handler: logging.Handler) -> logging.Handler:
    """*handler* as ASH adds one during a run: marked as ASH's (ash_handler)
    and, inside a run (run_log_scope), the run's own.

    A run's own handler takes only the records its run takes (_run_takes),
    stays through another run's setup (remove_ash_handlers), and comes off the
    logger when the run ends (close_run_log_scope). Every handler ASH puts on
    "ash" for a run goes through here, the log files and the console as much
    as the live display's panel: a handler of no run's would take every
    session's lines while the MCP server runs scans. Outside a run it is only
    marked, as before.
    """
    scope = _RUN_LOG_SCOPE.get()
    if scope is not None:
        setattr(handler, _RUN_SCOPE_ATTR, scope)
        handler.addFilter(_RunScopedFilter(scope))
    return ash_handler(handler)


def current_run_log_scope() -> Optional[str]:
    """This context's run log scope, or None outside every run."""
    return _RUN_LOG_SCOPE.get()


def _open_scope(hosted: bool) -> Tuple[str, contextvars.Token]:
    scope = uuid.uuid4().hex
    token = _RUN_LOG_SCOPE.set(scope)
    _ACTIVE_RUN_LOG_SCOPES.add(scope)
    if hosted:
        _HOSTED_RUN_LOG_SCOPES.add(scope)
    return scope, token


def open_run_log_scope() -> Tuple[str, contextvars.Token]:
    """Open a new log scope in this context, inside any existing one.

    Everything the run logs from this context, and from contexts copied from
    it, goes only to the log files the run sets up (get_logger with this scope
    active), and those files take no other run's lines. For the caller that
    STARTS runs, a host: the MCP tools open one per scan, before registering
    it, and two scans started from one context must not share, so an existing
    scope is shadowed, not joined. While a scope opened here is active, a
    record of no run's goes to no run's handlers (:func:`_run_takes`). The tool
    hands the scope to the runner task it starts (which inherits this context)
    and puts its own context back with :func:`disown_run_log_scope`; a run it
    could not start is closed with :func:`end_run_log_scope`.
    """
    return _open_scope(hosted=True)


def begin_run_log_scope() -> Tuple[Optional[str], Optional[contextvars.Token]]:
    """The context's scope, joined, or a new one: for the run's own entry.

    A context already inside a scope gets ``(that scope, None)``, and the
    owner ends it: the MCP runner joins the scope its tool opened, and
    run_ash_scan inside the runner joins rather than nests. A context with
    none (a CLI run) gets a new scope of its own with its token, ended with
    :func:`end_run_log_scope` when the run returns.
    """
    existing = _RUN_LOG_SCOPE.get()
    if existing is not None:
        return existing, None
    return _open_scope(hosted=False)


def disown_run_log_scope(token: contextvars.Token) -> None:
    """Take an open scope out of this context and leave it active.

    For the tool that started a run: the runner task it created inherited the
    scope, and the run's writers close it when the last of them is done
    (:func:`release_run_log_scope`). The tool's own context goes back to
    whatever it held, so the next run started from it gets a scope of its own.
    """
    _RUN_LOG_SCOPE.reset(token)


def close_run_log_scope(scope: Optional[str]) -> None:
    """Close a run's log scope: detach its handlers and retire the scope.

    The handlers are detached from "ash" and closed here, not left for the
    next setup to replace, so a finished run's ash.log takes no later run's
    lines. By scope value, with no context to reset: an MCP scan's scope was
    opened in the tool's context and is closed by whichever of the scan's
    writers lets go of it last (:func:`release_run_log_scope`), after the
    run's last lines. None is a no-op, for a caller that never had a scope.
    """
    if scope is None:
        return
    logger = logging.getLogger("ash")
    for handler in list(logger.handlers):
        if getattr(handler, _RUN_SCOPE_ATTR, None) != scope:
            continue
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001 - closing a finished run's handler
            pass
    _ACTIVE_RUN_LOG_SCOPES.discard(scope)
    _HOSTED_RUN_LOG_SCOPES.discard(scope)
    with _RUN_LOG_SCOPE_HOLDS_LOCK:
        _RUN_LOG_SCOPE_HOLDS.pop(scope, None)


#: How many holders each held scope has left (hold_run_log_scope).
_RUN_LOG_SCOPE_HOLDS: Dict[str, int] = {}
_RUN_LOG_SCOPE_HOLDS_LOCK = threading.Lock()


def hold_run_log_scope(scope: Optional[str]) -> None:
    """Count one more holder of *scope*: something that still writes to it.

    For a run whose writers end in no fixed order, as an MCP scan's task and
    the thread its scan runs on do: a cancelled task ends at once while its
    thread runs on until the scan stops, and the thread's last lines are the
    run's. Each writer holds the scope and lets go with
    :func:`release_run_log_scope`, and the last one to let go closes it. None
    is a no-op.
    """
    if scope is None:
        return
    with _RUN_LOG_SCOPE_HOLDS_LOCK:
        _RUN_LOG_SCOPE_HOLDS[scope] = _RUN_LOG_SCOPE_HOLDS.get(scope, 0) + 1


def release_run_log_scope(scope: Optional[str]) -> None:
    """One holder of *scope* is done with it; the last one closes it
    (:func:`close_run_log_scope`). None is a no-op.

    A release with no matching hold is logged and ignored: closing on it would
    tear down a live scope the real holders still log under, retiring the run's
    handlers mid-run, and a double release is a caller's bug, never the run's
    end.
    """
    if scope is None:
        return
    with _RUN_LOG_SCOPE_HOLDS_LOCK:
        held = _RUN_LOG_SCOPE_HOLDS.get(scope)
        if held is None:
            unmatched = True
        elif held > 1:
            _RUN_LOG_SCOPE_HOLDS[scope] = held - 1
            return
        else:
            unmatched = False
            _RUN_LOG_SCOPE_HOLDS.pop(scope, None)
    if unmatched:
        ASH_LOGGER.debug(
            "release_run_log_scope(%s): no matching hold; the scope stays open",
            scope,
        )
        return
    close_run_log_scope(scope)


def end_run_log_scope(scope: Optional[str], token: Optional[contextvars.Token]) -> None:
    """:func:`close_run_log_scope`, and this context's variable put back.

    With ``token`` None (the scope was joined, not opened) this does nothing;
    the owner closes it.
    """
    if token is None:
        return
    close_run_log_scope(scope)
    _RUN_LOG_SCOPE.reset(token)


@contextmanager
def run_log_scope() -> Iterator[None]:
    """:func:`begin_run_log_scope` around a block, for the run's entry point."""
    scope, token = begin_run_log_scope()
    try:
        yield
    finally:
        end_run_log_scope(scope, token)


def route_library_handlers_through_command_check() -> None:
    """Have each logging handler ASH did not add, that writes to the process's
    stdout or stderr, write through ASH's CI-command check.

    A library configures handlers of its own: ``MCPServer()`` puts the MCP SDK's
    RichHandler on the root logger, and uvicorn its stream handlers on its loggers.
    They write the text they are given as it is, and on the MCP server that text
    holds what a client sent, a tool name among it. On a stream a CI step reads,
    "##vso[" in it, or a line starting "::", is a command to the runner. Each such
    handler's stream is wrapped in CommandSafeStream: a StreamHandler's own, and
    the one under a RichHandler's console, which keeps the width, color and theme
    the library gave it.

    Handlers ASH added (ash_handler) write through ASH's consoles already and are
    left alone, as is a handler writing anywhere else (a file, a buffer), and one
    whose stream is checked already: a handler built after the server's start
    wrapped sys.stderr and sys.stdout holds a CommandSafeStream itself, and a
    second wrap would repeat the check with a line state of its own. Only the
    handlers there when this is called are routed, so it is called after each
    library has configured its logging. A second call changes nothing.
    """
    from automated_security_helper.utils.command_safe_stream import (
        CommandSafeStream,
    )

    std_streams = [
        stream
        for stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__)
        if stream is not None
    ]

    def is_std(stream) -> bool:
        return any(stream is std for std in std_streams)

    loggers = [logging.getLogger()] + [
        logger
        for logger in list(logging.root.manager.loggerDict.values())
        if isinstance(logger, logging.Logger)
    ]
    for logger in loggers:
        for handler in list(logger.handlers):
            if added_by_ash(handler):
                continue
            if isinstance(handler, RichHandler):
                if is_std(handler.console.file):
                    check_commands_of(handler.console)
            elif isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                stream = handler.stream
                if is_std(stream) and not isinstance(stream, CommandSafeStream):
                    handler.setStream(
                        CommandSafeStream(_returning(stream))  # type: ignore[arg-type]
                    )


def _returning(stream: TextIO) -> Callable[[], TextIO]:
    """A target for CommandSafeStream that is always *stream*."""
    return lambda: stream


def _encode_as_utf8_if_ascii(stream: Any) -> None:
    """Set *stream*'s encoding to UTF-8 when it is ASCII, keeping its errors.

    click's echo, and typer's, finds a stream whose encoding is ASCII
    misconfigured and writes UTF-8 to the stream's binary buffer through a
    writer of its own, below any wrap of the text stream. Text that encoded
    under ASCII encodes to the same bytes under UTF-8, so only text that ASCII
    could not encode is written differently. For the stdout wrap, whose buffer
    is handed on as it is; the stderr wrap checks its buffer instead and leaves
    the encoding alone. A stream that cannot be reconfigured is left as it is,
    and click's echo then writes past the check.
    """
    import codecs

    encoding = getattr(stream, "encoding", None)
    reconfigure = getattr(stream, "reconfigure", None)
    if not isinstance(encoding, str) or reconfigure is None:
        return
    try:
        if codecs.lookup(encoding).name != "ascii":
            return
        reconfigure(encoding="utf-8", errors=getattr(stream, "errors", None))
    except (LookupError, OSError, ValueError):
        pass


def _check_commands_of_std(name: str) -> None:
    """Have Python's writes to ``sys.<name>``, ``"stderr"`` or ``"stdout"``,
    go through the CI-command check.

    An ``os.write`` on the stream's fd, and a child process that inherits the
    fd, reach it as they are. So do bytes written to ``sys.stdout.buffer``,
    which carries the MCP SDK's JSON-RPC frames, where an inserted escape would
    corrupt a frame; a stdout stream whose encoding is ASCII is set to UTF-8
    first (_encode_as_utf8_if_ascii), so that click and typer, which replace a
    stream they find misconfigured with a writer of their own on its buffer,
    write through the wrap. On stderr it is the other way around: the stream's
    encoding is left as it is, so what a non-UTF-8 console shows for a write
    does not change, and the wrap's ``buffer`` checks the bytes themselves
    (CommandSafeBuffer), click's own writer's among them, under the same lock
    and line state, changing no byte outside an inserted escape.

    The wrap holds the stream that was ``sys.<name>`` when it ran: a dynamic
    lookup would find the wrap itself. It reports that stream's encoding,
    errors, isatty and buffer, so a reader of it (Rich, click, the MCP SDK)
    sees the stream it wraps. Code that replaces the stream afterwards
    (``contextlib.redirect_stderr``, a capturing test) replaces the wrap whole,
    as it would any stream. A second call changes nothing, and a handler whose
    stream the routing wrapped writes byte-identically through both, because
    an escaped line holds no command form to break again.

    A process with no such stream (pythonw, or a start whose fd was closed,
    which ensure_std_streams leaves None) has nothing to wrap, and is left so,
    where a wrap around None would raise on each write. Python's sinks then skip
    stderr, and ``print(file=None)`` writes to ``sys.stdout`` instead.
    """
    from automated_security_helper.utils.command_safe_stream import (
        CommandSafeStream,
    )

    stream = getattr(sys, name)
    if stream is None or isinstance(stream, CommandSafeStream):
        return
    if name == "stdout":
        _encode_as_utf8_if_ascii(stream)
    setattr(
        sys, name, CommandSafeStream(_returning(stream), check_buffer=name == "stderr")
    )


def check_commands_of_stderr() -> None:
    """Have Python's writes to ``sys.stderr``, text and bytes, go through the
    CI-command check.

    For MCP server mode, where sinks that are not logging handlers write to
    ``sys.stderr`` as given: ``logging.lastResort`` for a library logger with no
    handler, ``warnings.showwarning``, and the thread and sys excepthooks.
    ``route_library_handlers_through_command_check`` routes only the handlers
    that are there when it runs, so those sinks write raw without this.
    run_mcp_server and cli/mcp's _run_uvicorn call it as the server starts, not
    the server module's import, so a program that imports the module keeps its
    own stream. The rules and the limits are :func:`_check_commands_of_std`'s.
    """
    _check_commands_of_std("stderr")


def check_commands_of_stdout() -> None:
    """Have Python's text writes to ``sys.stdout`` go through the CI-command check.

    For MCP server mode, called where :func:`check_commands_of_stderr` is. While
    the stdio server serves, the MCP SDK writes its frames through a private
    copy of fd 1 and points fd 1 at stderr, so a raw ``sys.stdout`` write (a
    print, a library writing to stdout) lands on stderr, which a CI step reads.
    Over HTTP stdout is the console, read the same way.

    The frames never pass through ``sys.stdout``: the SDK finds fd 1 through
    ``sys.stdout.buffer``, which the wrap hands on, and writes either to its own
    copy of fd 1 or to that binary buffer. The rules and the limits are
    :func:`_check_commands_of_std`'s.
    """
    _check_commands_of_std("stdout")


class LogFileHandler(ShownHandlerErrors, logging.FileHandler):
    """A FileHandler that opens its file as ``fs_guard.open_for_write`` does.

    A record it cannot write is reported shown (:class:`ShownHandlerErrors`), as
    every one of ASH's log handlers reports one.

    Appending, since get_logger has already truncated the file when asked to. A link
    at the file name, or a file another name refers to, raises instead of being
    opened: the directory holding the file is guarded for each open, whether or not
    it is still a registered root, and below a registered output directory every
    component under it is checked too.

    The handler registers the directory holding its file (the output directory) as
    a guarded root while it is open, so ASH's other writes there refuse a link for
    as long as it logs there, and releases it in close().
    """

    def __init__(self, filename: str, *args, **kwargs) -> None:
        # UTF-8 unless the caller chose an encoding. FileHandler's own default,
        # None, is the locale's encoding, under which a record holding a
        # character outside the ANSI code page was dropped from the file on
        # Windows; and since Python 3.10 FileHandler records that default on
        # self.encoding as the name "locale", so a fallback read at the open
        # ("self.encoding or 'utf-8'") found a name there and opened the file
        # in the locale's encoding all the same. The default is chosen here,
        # before FileHandler reads it. The files are read back as UTF-8.
        if len(args) >= 2:
            if args[1] is None:
                args = (args[0], "utf-8", *args[2:])
        elif kwargs.get("encoding") is None:
            kwargs["encoding"] = "utf-8"
        # Imported here, not at the top: fs_guard imports this module for
        # ASH_LOGGER. Do not hoist.
        from automated_security_helper.utils.sandbox import fs_guard

        self._root: Path | None = fs_guard.register_writable_root(Path(filename).parent)
        try:
            super().__init__(filename, *args, **kwargs)
        except BaseException:
            self._release_root()
            raise

    def _release_root(self) -> None:
        # Not at the top: fs_guard imports this module. Do not hoist.
        from automated_security_helper.utils.sandbox import fs_guard

        # Under the handler's own lock: two close() calls at once each read the
        # root before either cleared it, and the counted registration was
        # released twice. The lock may not exist yet: FileHandler opens its file
        # before the base class makes the lock, so a refused open raises from
        # __init__ with no lock, and reading self.lock there replaced the refusal
        # with an AttributeError and left the root registered. Nothing else can
        # reach a handler that has not been constructed, so no lock is needed then.
        lock = getattr(self, "lock", None)
        if lock is None:
            root, self._root = self._root, None
        else:
            with lock:
                root, self._root = self._root, None
        if root is not None:
            fs_guard.release_writable_root(root)

    def close(self) -> None:
        """Close the file, and release the directory's registration once."""
        try:
            super().close()
        finally:
            self._release_root()

    def emit(self, record: logging.LogRecord) -> None:
        # Appending, so logging.FileHandler.emit would open the file again for
        # a record that reaches a handler close_run_log_scope has closed (its
        # mode is not "w", the one case the base class refuses), and the
        # reopened file was never closed; a refusal of that open also escaped
        # the logging call. A closed handler takes nothing.
        if self.stream is None and getattr(self, "_closed", False):
            return
        super().emit(record)

    def _open(self):
        # Not at the top: fs_guard imports this module. Do not hoist.
        from automated_security_helper.utils.sandbox import fs_guard

        # The encoding __init__ chose: UTF-8 unless the caller named one. The
        # fallback stays for an encoding set to None after the construction.
        return fs_guard.open_for_write(
            self.baseFilename,
            encoding=self.encoding or "utf-8",
            errors=self.errors,
            append=True,
            root=Path(self.baseFilename).parent,
        )


def get_logger(
    name: str = "ash",
    level: str | int | None = None,
    output_dir: Path | None = None,
    log_format: Literal["JSONL", "TABULAR", "BOTH"] = "TABULAR",
    show_progress: bool = True,
    use_color: bool = True,
    simple_format: bool = False,
    file_log_level: str | int | None = None,
    truncate_log: bool = True,
    use_stderr: bool = False,
) -> "ASHLogger":
    # Make the console able to encode what ASH emits before anything is written.
    configure_windows_safe_logging()

    # Disable propagation to the root logger to prevent duplicate messages
    root_logger = logging.getLogger()
    if root_logger.handlers and name != "":
        logging.getLogger(name).propagate = False

    # A logger made before this module was imported is a plain Logger until it
    # is adopted (adopt_early_ash_loggers); the setup below relies on ASHLogger's
    # verbose() and callHandlers().
    adopt_early_ash_loggers()
    logger: ASHLogger = logging.getLogger(name)  # type: ignore[assignment]

    # Attach the Windows-safe filter if not already present
    if not any(isinstance(f, WindowsSafeFilter) for f in logger.filters):
        logger.addFilter(WindowsSafeFilter())

    # Replace the handlers an earlier call added, so they don't pile up; a handler
    # something else put on the logger stays, and so does a handler a live run
    # owns (remove_ash_handlers). A guarded log-file handler that comes off is
    # closed, which releases the output directory it registered (fs_guard).
    replaced = list(logger.handlers)
    remove_ash_handlers(logger)
    for handler in replaced:
        if isinstance(handler, LogFileHandler) and handler not in logger.handlers:
            handler.close()

    # Inside a run (run_log_scope), the handlers this call adds are the run's
    # own (run_handler): they take only its records, survive another run's
    # setup, and are detached when the run ends.

    # Explicit set the logger level to TRACE/5
    # (root logger sets the lowest level depth for all attached handlers)
    logger.setLevel(logging._nameToLevel.get("TRACE", 5))  # type: ignore[attr-defined]
    level_param = {}
    if level is not None:
        level_param = {"level": level}
    # The process-wide last-resort gate is NOT set here: the MCP server runs
    # get_logger for every hosted scan (cli/mcp_tools.py starts
    # interactions/run_ash_scan.py), so a gate set here would clobber the
    # server's own at the first hosted scan. A process's entry point sets it
    # once (configure_last_resort_level).

    # From the console level asked for, not from the logger's effective level,
    # which the line above has just pinned to TRACE: read there, this was always
    # True and the plain console layout below was never used.
    requested = _coerce_log_level(level) if level is not None else None
    SHOW_DEBUG_INFO = requested is None or logging.getLevelName(requested) != "INFO"
    # The setup's own records ("Log level set to", "Show debug info", the
    # verbose pair) are logged AFTER the handlers attach, at the end of this
    # function: logged here, between remove_ash_handlers above and the
    # addHandler calls below, they are homeless -- no handler takes them -- so
    # a process whose configured gate admits INFO wrote them to stderr for
    # every logger setup, a hosted scan's included.
    # Configure console parameters with Windows-safe settings
    console_base_params = {
        "theme": Theme(
            {
                "logging.level.verbose": "magenta",
                "logging.level.warning": "yellow",
                "logging.level.trace": "green",
            }
        ),
        "highlight": use_color,
        "legacy_windows": platform.system().lower() == "windows",
        "safe_box": platform.system().lower() == "windows",
        # The console reads the process environment, as any Rich console does:
        # built with an empty one it ignored NO_COLOR, FORCE_COLOR, TERM=dumb
        # and COLUMNS, which an operator or a CI job sets for every program.
    }

    # Set color system based on the color preference. "auto" on every platform:
    # Rich detects the color system from the file the console writes to, so on a
    # Windows console it finds the console (legacy_windows above tells it which
    # escapes that console takes) and behind a pipe or a captured stream it finds
    # no terminal and writes plain text. The "windows" color system this branch
    # once named outright was used whatever the file was, so a child ash whose
    # output a test captured wrote escapes around every level name and every
    # highlighted number, on Windows and nowhere else.
    if use_color:
        console_base_params["color_system"] = "auto"
    else:
        console_base_params["color_system"] = None

    # Add width constraint for container environments
    if os.environ.get("ASH_IN_CONTAINER", "NO").upper() in ["YES", "1", "TRUE"]:
        console_base_params["width"] = 150

    # The stdio MCP transport uses stdout as its JSON-RPC channel, and the MCP
    # server runs scans in-process (mcp_tools hands run_ash_scan to
    # loop.run_in_executor, i.e. a thread in the same process). So once a scan
    # starts, every record this handler emits would land inside the JSON-RPC
    # stream and the client fails to parse it -- the reported "Expecting value".
    # Routing the command's own banner to stderr is not enough; the logger is the
    # larger source, and it only attaches once a scan begins.
    #
    # Read from the environment rather than threaded through as a parameter,
    # because the caller that knows (the mcp command) is several layers above the
    # caller that configures logging (run_ash_scan._setup_logger), and the
    # in-process scan inherits the same environment.
    log_to_stderr = use_stderr or os.environ.get("ASH_LOG_TO_STDERR", "NO").upper() in [
        "YES",
        "1",
        "TRUE",
    ]

    custom_console_params = {
        "console": ash_console(stderr=log_to_stderr, **console_base_params)
    }
    show_locals = show_debug_locals()
    if SHOW_DEBUG_INFO:
        handler = ConsoleHandler(
            show_level=not simple_format,
            enable_link_path=not simple_format,
            rich_tracebacks=not simple_format,
            # The source line of each log call: not a value, so not CI-gated.
            show_path=_show_locals_requested(),
            tracebacks_show_locals=show_locals,
            # Text unless the record asks for markup; see MARKUP above.
            markup=False,
            **level_param,
            **custom_console_params,
        )
    else:
        handler = ConsoleHandler(
            show_level=not simple_format,
            enable_link_path=False,
            show_path=False,
            tracebacks_show_locals=show_locals,
            show_time=False,
            rich_tracebacks=not simple_format,
            # Text unless the record asks for markup; see MARKUP above.
            markup=False,
            **level_param,
            **custom_console_params,
        )

    handler.setFormatter(logging.Formatter("%(message)s"))

    # Always add the handler unless show_progress is True
    # (show_progress means we're using a different progress display mechanism)
    if not show_progress:
        logger.addHandler(run_handler(handler))

    if output_dir:
        """Add a file handler for this logger with the specified `name` (and
        store the log file under `output_dir`)."""
        # The log files are opened with the output directory guarded, as ASH's
        # other writes there are: a link at the file name, or a file another name
        # refers to, raises before anything is written (_log_file_handler). That
        # holds whether or not a root is registered; run_ash_scan registers the
        # output directory for the whole run, which guards every write below it.
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        # Determine file log level (default to INFO to avoid huge log files)
        final_file_log_level = (
            file_log_level if file_log_level is not None else logging.INFO
        )

        # Create JSONLines/JSONL file handler for logging to a file
        if log_format in ["JSONL", "BOTH"]:
            jsonl_log_file = Path(output_dir).joinpath(f"{name}.log.jsonl")
            jsonl_file_handler = _log_file_handler(jsonl_log_file, truncate_log)
            jsonl_file_handler.setLevel(final_file_log_level)
            jsonl_file_handler.setFormatter(
                JsonFormatter(
                    {
                        "timestamp": "asctime",
                        "level": "levelname",
                        "filename": "filename",
                        "lineno": "lineno",
                        "message": "message",
                        "loggerName": "name",
                        "processName": "processName",
                        "processID": "process",
                        "threadName": "threadName",
                        "threadID": "thread",
                    }
                )
            )
            logger.addHandler(run_handler(jsonl_file_handler))
            # After the handler is attached, so the record reaches the file it
            # announces instead of going homeless to the last resort.
            logger.verbose("Logging to JSONL file: %s", jsonl_log_file.as_posix())
        # Create tabular file handler for logging to a file
        if log_format in ["TABULAR", "BOTH"]:
            tab_log_file = Path(output_dir).joinpath(f"{name}.log")
            tab_file_handler = _log_file_handler(tab_log_file, truncate_log)
            tab_file_handler.setLevel(final_file_log_level)
            tab_file_handler.setFormatter(
                TextFileFormatter(
                    fmt="%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "
                )
            )
            logger.addHandler(run_handler(tab_file_handler))
            logger.verbose("Logging to tabular file: %s", tab_log_file.as_posix())

    # After the handlers, so these reach the console and the log files instead
    # of going homeless (see the note beside SHOW_DEBUG_INFO above). The level
    # names come from logging.getLevelName, which answers "Level N" for a
    # number no name is registered for; the level-to-name table raised KeyError
    # for one, after the handlers had already been replaced.
    logger._log(
        15,
        msg=f"Log level set to: {logging.getLevelName(level) if isinstance(level, int) else level}",
        args=(),
    )
    logger.verbose("Logger initialized: %s", name)
    logger.verbose(
        "Logger effective level: %s",
        logging.getLevelName(logger.getEffectiveLevel() or 0),
    )
    # Verbose, like the setup records beside it: at INFO this flag echo was
    # never seen anywhere -- it went homeless before the handlers attached --
    # so logging it through the handlers at INFO would put a new line in every
    # CLI run's output. An operator who wants setup detail runs verbose.
    logger.verbose("Show debug info: %s", SHOW_DEBUG_INFO)

    # After the handlers, so the warning reaches the console and the log files.
    global _locals_warning_logged
    if _show_locals_requested() and not show_locals and not _locals_warning_logged:
        _locals_warning_logged = True
        logger.warning(SHOW_LOCALS_IGNORED)

    return logger


def _log_file_handler(path: Path, truncate: bool) -> logging.FileHandler:
    """A handler appending to ``path``, emptied first when ``truncate`` (the default).

    Both opens go through fs_guard.open_for_write below the output directory
    get_logger registered, so a link at the name, or a file another name refers to,
    raises before anything is written; see LogFileHandler.
    """
    # Not at the top: fs_guard imports this module. Do not hoist.
    from automated_security_helper.utils.sandbox import fs_guard

    with fs_guard.open_for_write(path, append=not truncate, root=path.parent):
        pass
    return LogFileHandler(path.as_posix())


def _coerce_log_level(value: str | int) -> Optional[int]:
    """The numeric level *value* names, or None for a name logging has not got.

    A number is ASCII decimal digits only: ``str.isdigit`` admits a superscript
    or a circled digit that ``int()`` refuses, which raised ValueError from the
    environment read at import.
    """
    if isinstance(value, int):
        return value
    name = value.strip().upper()
    if name.isascii() and name.isdecimal():
        return int(name)
    return logging._nameToLevel.get(name)


def _last_resort_level() -> int:
    """The level the last resort takes homeless records at: ASH_LOG_LEVEL when
    the environment names a level, WARNING otherwise.

    This gate cannot come from the "ash" logger's own level: get_logger pins
    that logger at its lowest level so the handlers decide, so reading it would
    pass every record. With no gate at all the stand-in wrote a TRACE-pinned
    logger's whole output to stderr the moment a run's handlers came off. So
    the gate is the configured level, set once at a process's entry point
    (:func:`configure_last_resort_level`) -- never from get_logger, which the
    MCP server runs for every hosted scan.
    """
    value = os.environ.get("ASH_LOG_LEVEL")
    if value:
        level = _coerce_log_level(value)
        if level is not None:
            return level
    return logging.WARNING


class _ShownLastResort(ShownHandlerErrors, logging.StreamHandler):
    """ASH's loggers' stand-in for logging.lastResort (ASHLogger.callHandlers).

    A record no handler takes, before get_logger runs or after something clears
    the handlers, goes to logging's last resort, which writes it to stderr as
    given. The process may already be reading a repository's configuration then
    (the MCP server's tools load one before any logging is set up), so a file
    name with an escape sequence or a line starting "::" reached the terminal or
    the CI log as written. This writes the same records, the same way, but
    through ash.log's formatter: each control shown, each command broken, in the
    traceback too. To the stderr of the moment, at the configured level: the
    "ash" logger itself runs wide open so its handlers decide, so this
    handler's level is the only gate a homeless record meets. The gate is set
    once at a process's entry point (:func:`configure_last_resort_level`),
    from the level the operator asked for there or from ASH_LOG_LEVEL.
    """

    def __init__(self) -> None:
        super().__init__(sys.stderr)
        self.setLevel(_last_resort_level())
        # The console's text: a record WindowsSafeFilter put in ASCII stays so
        # here, since this writes to the console that could not encode it.
        self.setFormatter(TextFileFormatter("%(message)s", unfiltered=False))

    def emit(self, record: logging.LogRecord) -> None:
        # The stream of the moment, as the last resort reads it: a test, or Rich's
        # Live, may have replaced sys.stderr since this was built.
        self.stream = sys.stderr
        super().emit(record)


#: The one stand-in, attached to no logger: ASHLogger.callHandlers hands it a
#: record of "ash" or a logger under it that no handler took.
_LAST_RESORT = _ShownLastResort()


def configure_last_resort_level(level: "str | int | None" = None) -> None:
    """Set the last resort's gate for this process, at its entry point.

    Two entry points call this once, at their start. The MCP server passes its
    log-level option (INFO when not given). ``ash scan`` passes its console
    level (cli/scan.py, ``resolved_console_log_level``: its flags, then
    ASH_DEBUG or ASH_VERBOSE, then INFO; ERROR for quiet and simple unless
    ``--verbose`` or ``--debug`` is also given), so
    homeless records show at the verbosity its console shows. Given none, or a
    name logging does not know (the server's quiet and simple), it reads
    ASH_LOG_LEVEL (WARNING default) when it runs -- at the start, not at
    import, so an environment set after the module loaded still counts.

    Nothing else calls it: a hosted scan's logger setup runs inside the server
    (cli/mcp_tools.py starts interactions/run_ash_scan.py, whose setup runs
    get_logger), so a gate set from there would move the server's process-wide
    gate with every hosted scan.
    """
    resolved = None if level is None else _coerce_log_level(level)
    _LAST_RESORT.setLevel(_last_resort_level() if resolved is None else resolved)
    # The gate is meant to be the only filter a homeless record meets, but a
    # logger whose level was never set takes its parent's (root's WARNING), and
    # that refuses an INFO or DEBUG record before it can reach a gate set below
    # WARNING. get_logger pins the logger low for the same reason; this does it
    # for the records logged before get_logger runs. A level somebody set
    # stays, and so does a gate at or above the level the logger already has.
    if (
        ASH_LOGGER.level == logging.NOTSET
        and _LAST_RESORT.level < ASH_LOGGER.getEffectiveLevel()
    ):
        ASH_LOGGER.setLevel(_LAST_RESORT.level)


class _RoutedLastResort(ShownHandlerErrors, logging.Handler):
    """logging.lastResort, as this module leaves it: "ash"'s records go to the stand-in.

    ASHLogger.callHandlers sends a record no handler took to the stand-in, but a
    logger under "ash" is an ASHLogger only if it was made after this module set
    the logger class and before anything set another (one made before the import
    is adopted, adopt_early_ash_loggers): one made after a library's
    setLoggerClass would reach logging's last resort, which
    writes it as given. logging's last resort is therefore this router: "ash" and
    the loggers under it go to the stand-in, shown; every other logger to the
    last resort logging had. A reload of this module replaces the
    router and keeps the same last resort behind it.
    """

    def __init__(self, fallback: logging.Handler) -> None:
        # NOTSET, so logging's callHandlers hands every homeless record to the
        # routing below, which applies the right gate per branch: the frozen
        # copy of the fallback's level this handler used to carry admitted
        # what a quieter configuration refused and dropped what a more verbose
        # one asked for.
        super().__init__()
        self.fallback = fallback

    def handle(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if record.name == "ash" or record.name.startswith("ash."):
            # The configured gate, read live: the same one the stand-in's own
            # path applies (ASHLogger.callHandlers).
            if record.levelno >= _LAST_RESORT.level:
                return bool(_LAST_RESORT.handle(record))
            return False
        if record.levelno >= self.fallback.level:
            return bool(self.fallback.handle(record))
        return False

    def emit(self, record: logging.LogRecord) -> None:
        self.handle(record)


if logging.lastResort is not None:
    logging.lastResort = _RoutedLastResort(
        getattr(logging.lastResort, "fallback", logging.lastResort)
    )


adopt_early_ash_loggers()
ASH_LOGGER: ASHLogger = logging.getLogger("ash")  # type: ignore[assignment]
ASH_LOGGER.propagate = False
ASH_LOGGER.addFilter(WindowsSafeFilter())
