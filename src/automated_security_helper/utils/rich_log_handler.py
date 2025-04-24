"""Rich log handler for displaying logs in a Rich live display."""

import logging
from rich.console import RenderableType
from rich.text import Text
from rich.table import Table
from collections import deque
import sys


class RichLogPanel:
    """A class to store and render log messages for display in a Rich panel."""

    def __init__(self, max_lines: int, use_markup: bool = True):
        """Initialize the log panel.

        Args:
            max_lines: Maximum number of log lines to keep in the buffer
            use_markup: Whether to interpret Rich markup in log messages
        """
        self.logs = deque(maxlen=max_lines)
        self.max_lines = max_lines
        self.use_markup = use_markup

        # Map log levels to their display names
        self.level_names = {
            logging.CRITICAL: "CRIT",
            logging.ERROR: "ERROR",
            logging.WARNING: "WARN",
            logging.INFO: "INFO",
            15: "VERBOSE",  # VERBOSE
            logging.DEBUG: "DEBUG",
            5: "TRACE",  # TRACE
        }

    def add_log(self, message: str, level: int = logging.INFO):
        """Add a log message to the panel.

        Args:
            message: The log message
            level: The log level
        """
        # Store the log entry as a tuple of (level, message)
        self.logs.append((level, message))

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
                message,  # No styling applied to message, respects any markup in the message
            )

        # If we have fewer logs than max_lines, add empty rows
        while len(log_list) < self.max_lines:
            table.add_row("", "")

        return table


class LiveDisplayLogHandler(logging.Handler):
    """A log handler that sends log messages to a Rich log panel."""

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
            message = self.format(record)
            self.log_panel.add_log(message, record.levelno)
        except Exception as e:
            print(f"ERROR in LiveDisplayLogHandler: {e}", file=sys.stderr)
            self.handleError(record)
