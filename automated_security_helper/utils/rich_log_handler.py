"""Rich log handler for displaying logs in a Rich live display."""

import logging
from rich.console import RenderableType
from rich.highlighter import ReprHighlighter
from rich.text import Text
from rich.table import Table
from collections import deque
import sys

from automated_security_helper.utils.log import ShownHandlerErrors, console_text
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

    def add_log(self, message: str, level: int = logging.INFO, markup: bool = False):
        """Add a log message to the panel.

        Args:
            message: The log message
            level: The log level
            markup: Whether the record asked for Rich markup (``extra=MARKUP``)
        """
        # Stored as Text, so the table renders it without reading markup in it. The
        # highlighter is the one a printed string gets.
        text = (
            Text.from_markup(message) if markup and self.use_markup else Text(message)
        )
        self.logs.append((level, self._highlighter(text)))

    def __rich__(self) -> RenderableType:
        """Make the log panel renderable for Rich."""
        if not self.logs:
            return Text("No log messages", style="dim")

        # Create a table for the logs
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)

        # Add columns for level and message
        table.add_column("Level", style="bold", width=5)
        table.add_column("Message", ratio=1)

        # Add rows for each log message
        log_list = list(self.logs)

        for level, message in log_list:
            # Get the level display name
            level_name = self.level_names.get(level, "INFO")

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
        for _ in range(self.max_lines - len(log_list)):
            table.add_row("", "")

        return table


class LiveDisplayLogHandler(ShownHandlerErrors, logging.Handler):
    """A log handler that sends log messages to a Rich log panel.

    A record it cannot add is reported as ShownHandlerErrors reports one: the
    traceback shown, not obeyed.
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
            # As the console prints it: terminal controls shown, not obeyed.
            message = console_text(record, self.format(record))
            self.log_panel.add_log(
                message, record.levelno, markup=getattr(record, "markup", False)
            )
        except Exception as e:
            print(
                shown_not_obeyed(f"ERROR in LiveDisplayLogHandler: {e}"),
                file=sys.stderr,
            )
            self.handleError(record)
