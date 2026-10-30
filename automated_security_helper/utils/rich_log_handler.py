"""Rich log handler for displaying logs in a Rich live display."""

import logging
import threading
from rich.console import Console, ConsoleOptions, RenderableType
from rich.errors import MarkupError
from rich.highlighter import ReprHighlighter
from rich.text import Text
from rich.table import Table
from collections import deque
from typing import Optional

from automated_security_helper.utils.log import (
    ShownHandlerErrors,
    _raw_markup_trace,
    console_text,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed


class RichLogPanel:
    """A class to store and render log messages for display in a Rich panel."""

    def __init__(self, max_lines: int, use_markup: bool = True):
        """Initialize the log panel.

        Args:
            max_lines: Maximum number of log lines to keep in the buffer
            use_markup: Whether a message logged with ``extra=MARKUP`` (see
                utils/log.py) is read as Rich markup. Every other message is text
                either way, as on the console handler: a table cell given a plain
                string reads it as markup, so a path or exception text holding
                ``[/x]`` raised MarkupError inside the live display, and
                ``[bold]`` vanished.
        """
        self.logs = deque(maxlen=max_lines)
        self.max_lines = max_lines
        self.use_markup = use_markup
        self._highlighter = ReprHighlighter()
        # The deque is appended from the logging threads and copied by the Live
        # refresh thread; a copy taken while an append wraps the deque raised
        # RuntimeError inside the display. Both go under this lock.
        self._lock = threading.Lock()

        # Map log levels to their display names
        self.level_names = {
            logging.CRITICAL: "CRIT",
            logging.ERROR: "ERR ",
            logging.WARNING: "WARN",
            logging.INFO: "INFO",
            15: "VERB",  # VERBOSE
            logging.DEBUG: "DEBG",
            5: "TRAC",  # TRACE
        }

    def add_log(
        self,
        message: str,
        level: int = logging.INFO,
        markup: bool = False,
        plain_tail: str = "",
    ):
        """Add a log message to the panel.

        Args:
            message: The log message
            level: The log level
            markup: Whether the record asked for Rich markup (``extra=MARKUP``)
            plain_tail: Text appended to the message as text whatever ``markup``
                says: the traceback or stack the handler's formatter wrote after
                a MARKUP record's own message, which is not markup and whose
                brackets would otherwise drop the record (MarkupError) or restyle it.
        """
        # Stored as Text, so the table renders it without reading markup in it. The
        # highlighter is the one a printed string gets.
        text = (
            Text.from_markup(message) if markup and self.use_markup else Text(message)
        )
        if plain_tail:
            text.append(plain_tail)
        with self._lock:
            self.logs.append((level, self._highlighter(text)))

    def _level_name(self, level: int) -> str:
        """The four-character label of ``level``: the table's, else logging's
        own name for the level cut to four characters (a custom level's), else
        ``L<n>``. INFO was shown for every level the table did not name, a
        custom level above WARNING among them."""
        known = self.level_names.get(level)
        if known is not None:
            return known
        name = logging.getLevelName(level)
        if name.startswith("Level "):
            return f"L{level}"[:4].ljust(4)
        return name[:4].ljust(4)

    def __rich__(self) -> RenderableType:
        """Make the log panel renderable for Rich, with no height known."""
        return self._table(None)

    def __rich_console__(self, console: Console, options: ConsoleOptions):
        """Render for the height Rich gives the panel (a Layout region's), so
        the newest records are the ones shown: the rows were added oldest-first
        and padded to ``max_lines``, so a region shorter than that cropped the
        newest records off the bottom and showed the oldest instead."""
        yield self._table(options.height)

    def _table(self, height: Optional[int]) -> RenderableType:
        with self._lock:
            log_list = list(self.logs)
        if not log_list:
            return Text("No log messages", style="dim")

        # The rows that fit: every record when the height is not known, else
        # the newest ones the region can hold, one row per record.
        rows = self.max_lines
        if height is not None and 0 < height < rows:
            rows = height
        log_list = log_list[-rows:]

        # Create a table for the logs
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)

        # Add columns for level and message
        table.add_column("Level", style="bold", width=5)
        table.add_column("Message", ratio=1)

        for level, message in log_list:
            level_name = self._level_name(level)

            # Style the level based on severity
            if level >= logging.ERROR:
                level_style = "bold red"
            elif level >= logging.WARNING:
                level_style = "yellow"
            elif level >= logging.INFO:
                level_style = "green"
            elif level >= 15:  # VERBOSE
                level_style = "magenta"
            elif level >= logging.DEBUG:
                level_style = "cyan"
            else:  # TRACE or lower
                level_style = "blue"

            # Add the row to the table - only colorize the level column
            table.add_row(
                f"[{level_style}]{level_name}[/{level_style}]",
                message,  # Text, built in add_log
            )

        # Pad to a fixed height so the panel does not change size as records
        # arrive. The count comes from the snapshot taken above rather than from
        # the table, because add_row mutates only the table: a loop conditioned
        # on len(log_list) would never advance and never return.
        for _ in range(rows - len(log_list)):
            table.add_row("", "")

        return table


class LiveDisplayLogHandler(ShownHandlerErrors, logging.Handler):
    """A log handler that sends log messages to a Rich log panel.

    A record it cannot add is reported as ShownHandlerErrors reports one, and as
    the console handler reports one: the traceback shown, not obeyed, once,
    through logging's own guard (``logging.raiseExceptions`` turns it off, and a
    stderr that fails or is None loses nothing). A MarkupError is reported with
    the tag as the raw message holds it, so the report shows it once; a
    RecursionError is raised as it is.
    """

    def __init__(self, log_panel: RichLogPanel, level: int = logging.INFO):
        """Initialize the handler.

        Args:
            log_panel: The Rich log panel to send messages to
            level: The minimum log level to capture
        """
        super().__init__(level)
        self.log_panel = log_panel

    def emit(self, record: logging.LogRecord):
        """Process a log record by adding it to the log panel.

        Args:
            record: The log record to process
        """
        try:
            markup = getattr(record, "markup", False)
            formatted = self.format(record)
            tail = ""
            if markup:
                # The formatter appends the traceback and the stack after the
                # message; neither is markup, so only the message is read as
                # markup and the rest goes in as text.
                own = record.getMessage()
                if formatted.startswith(own) and len(formatted) > len(own):
                    tail = formatted[len(own) :]
                    formatted = own
            # As the console prints it: terminal controls shown, not obeyed.
            message = console_text(record, formatted)
            self.log_panel.add_log(
                message,
                record.levelno,
                markup=markup,
                plain_tail=str(shown_not_obeyed(tail)) if tail else "",
            )
        except RecursionError:
            raise
        except MarkupError as error:
            self._report_error(record, _raw_markup_trace(error, record))
        except Exception:
            self.handleError(record)
