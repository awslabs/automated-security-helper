import logging
import sys
import time
from typing import TYPE_CHECKING, Any, Literal

from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    ShownHandlerErrors,
    TextFileFormatter,
    run_handler,
)
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed

from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


ExecutionPhaseType = Literal["convert", "scan", "report", "inspect"]


if TYPE_CHECKING:
    # The stub declares StreamHandler generic on every Python version, but the
    # class only accepts a subscript at run time from 3.11 on. A subscripted base
    # in the class statement below would raise TypeError at import on 3.10, so
    # the checker sees the generic and the interpreter sees the plain class.
    _StreamHandlerBase = logging.StreamHandler[Any]
else:
    _StreamHandlerBase = logging.StreamHandler


class _ConsoleSink(ShownHandlerErrors, _StreamHandlerBase):
    """The standard-error sink the display falls back to without a panel.

    A record it cannot write is reported shown (:class:`ShownHandlerErrors`),
    as every other handler ASH puts on its logger reports one: a plain
    StreamHandler printed the failed record's traceback and arguments as given.
    """


class LiveProgressDisplay:
    """Manages a rich live display with a unified task table for ASH execution phases."""

    def __init__(
        self,
        show_progress: bool = True,
        color_system: Literal[
            "auto", "standard", "256", "truecolor", "windows"
        ] = "auto",
        max_log_lines: int = 15,
        verbose: bool = False,
        debug: bool = False,
    ):
        """Initialize the live progress display.

        Args:
            show_progress: Whether to show the progress display
            color_system: Color system to use for the console
            max_log_lines: Maximum number of log lines to show in the log panel
            verbose: Whether to show verbose logs
            debug: Whether to show debug logs
        """
        self.show_progress = show_progress
        self.console = ash_console(color_system=color_system)
        self.verbose = verbose
        self.debug = debug

        # Create a layout with two sections: logs and progress (logs on top)
        self.layout = Layout(name="root")

        # Split the layout vertically with logs on top
        self.layout.split(
            Layout(name="logs", ratio=1), Layout(name="progress", ratio=1)
        )

        # Create a simple progress display
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
        )

        # Create a log panel for displaying log messages
        self.log_panel = RichLogPanel(max_lines=max_log_lines)

        # Set up a log handler to capture logs with appropriate level based on flags.
        # 15 is VERBOSE, and it is the default rather than a level `verbose` raises us
        # to, so that flag needs no branch of its own here. Lowering this default to
        # INFO would change what every run prints, not just verbose ones -- see
        # tests/unit/core/test_progress.py, which pins the mapping.
        log_level = 15
        if debug:
            log_level = logging.DEBUG

        self.log_handler = LiveDisplayLogHandler(self.log_panel, level=log_level)
        self.log_handler.setFormatter(logging.Formatter("%(message)s"))

        # Add the handler to the ASH logger, marked as ASH's own, so a later
        # get_logger replaces it as it replaces its own; inside a run it is the
        # run's, so it shows that run's lines and comes off with the run. Only
        # when the display will show: the handler feeds the panel and nothing
        # else, so with show_progress=False it would hold lines nobody is
        # shown -- and the MCP server's workspace scans build one display per
        # project on a pool thread with no run's scope, where it joined the
        # logger unscoped and took every session's lines as their home,
        # keeping them from the last resort.
        if show_progress:
            ASH_LOGGER.addHandler(run_handler(self.log_handler))

        # Update layout with the logs (on top) and progress (below)
        self.layout["logs"].update(
            Panel(
                self.log_panel,
                title="Log Messages",
                border_style="green",
                box=box.ROUNDED,
                expand=True,  # Allow logs panel to expand
                padding=(0, 1),
            )
        )

        self.layout["progress"].update(
            Panel(
                self.progress,
                title="ASH Security Scan Progress",
                border_style="blue",
                box=box.ROUNDED,
                expand=True,  # Allow progress panel to expand
                padding=(1, 1),
            )
        )

        # Task tracking
        self.tasks = {
            ExecutionPhase.CONVERT: {},
            ExecutionPhase.SCAN: {},
            ExecutionPhase.REPORT: {},
        }

        # Status emojis for different states
        self.status_emojis = {
            "success": "✅",
            "failure": "❌",
            "warning": "⚠️",
            "skipped": "⏭️",
            "running": "🚀",
        }

        # Track task start times
        self.task_start_times = {}

        # Phase tasks
        self.phase_tasks = {}

        # Live display
        self.live = None

        # The console sink put on the logger when a shown display ends.
        self._sink_after_stop: logging.Handler | None = None

    def _restore_panel_handler(self) -> None:
        """Put the panel's handler back on the logger for a display that starts again.

        A display that has ended took the panel handler off and, if it was
        shown, put a console sink in its place. Started again, it builds a new
        ``Live`` over the same panel, so the panel's handler goes back on and the
        sink comes off: the sink wrote to the standard error it captured before
        the new ``Live`` redirected the streams, and left on, it would mix its
        lines into the redraws and print every line twice beside the panel.
        """
        sink, self._sink_after_stop = self._sink_after_stop, None
        if sink is not None and sink in ASH_LOGGER.handlers:
            ASH_LOGGER.removeHandler(sink)
        handler = self.log_handler
        if isinstance(handler, LiveDisplayLogHandler) and (
            handler not in ASH_LOGGER.handlers
        ):
            ASH_LOGGER.addHandler(handler)

    def start(self):
        """Start the live display if progress is enabled."""
        if self.show_progress and (self.live is None):
            self._restore_panel_handler()
            try:
                # Use auto_refresh=True and vertical_overflow="visible" to allow the panel to adjust its height
                self.live = Live(
                    self.layout,
                    console=self.console,
                    refresh_per_second=4,
                    auto_refresh=True,
                    vertical_overflow="visible",
                    screen=False,
                )
                self.live.__enter__()
            except Exception as e:
                print(
                    shown_not_obeyed(f"ERROR initializing live display: {e}"),
                    file=sys.stderr,
                )
                import traceback

                # The traceback quotes the error's text, which can quote a path.
                print(shown_not_obeyed(traceback.format_exc()), file=sys.stderr, end="")
                # Fall back to non-progress mode. The panel handler __init__
                # attached fed a panel that will never be rendered, and with
                # show_progress on, get_logger added no console handler, so
                # every later log line went to the unrendered panel and nowhere
                # else. The panel handler comes off and a console sink at the
                # same level takes its place, marked as the run's handler so
                # stop() and the run's end remove it as they would the panel's.
                self._discard_failed_live()
                self.show_progress = False
                self._replace_panel_handler_with_console()
                ASH_LOGGER.error(f"Failed to initialize progress display: {str(e)}")
                ASH_LOGGER.info("Continuing without progress display")

        # Log a message to show in the log panel
        ASH_LOGGER.info("ASH Security Scan started")

    def _discard_failed_live(self) -> None:
        """Exit a Live whose ``__enter__`` raised, and forget it.

        ``Live.__enter__`` can fail after it has taken the console (it hides
        the cursor and redirects the standard streams before it returns), so
        the object start() assigned may be half started. Leaving it in
        ``self.live`` meant stop(), which acts only on a shown display, never
        exited it.
        """
        failed, self.live = self.live, None
        if failed is None:
            return
        try:
            failed.stop()
        except Exception as stop_error:
            ASH_LOGGER.debug(
                f"Could not stop the live display that failed to start: {stop_error}"
            )

    @staticmethod
    def _console_sink(level: int) -> logging.Handler:
        """A standard-error log sink at *level*, marked as the run's handler.

        The console's formatter (the one the last-resort handler uses): each
        message and traceback shown, not obeyed. The lines this sink takes are
        the ones the panel would have shown, the error that ended the live
        display among them, and that error quotes the exception's text, which can
        carry a terminal control or a line that starts a CI command. A plain
        ``%(message)s`` formatter wrote them to the console as given.
        """
        sink = _ConsoleSink(sys.stderr)
        sink.setLevel(level)
        sink.setFormatter(TextFileFormatter("%(message)s", unfiltered=False))
        return run_handler(sink)

    def _replace_panel_handler_with_console(self) -> None:
        """Swap the panel's log handler for a console sink at the same level.

        For the fallback start() takes when the live display cannot be built:
        the lines the panel would have shown go to standard error instead, with
        the panel handler's level and formatter. The new handler becomes
        ``self.log_handler`` so stop() removes it as it removes the panel's.
        """
        panel_handler = self.log_handler
        if panel_handler is not None and panel_handler in ASH_LOGGER.handlers:
            ASH_LOGGER.removeHandler(panel_handler)
        # A display whose handler was already taken off (a run that stopped
        # and started again) has no level to copy; the panel's default level
        # from __init__ stands in.
        self.log_handler = self._console_sink(getattr(panel_handler, "level", 15))
        ASH_LOGGER.addHandler(self.log_handler)

    def stop(self, interrupted: bool = False):
        """Stop the live display if it's running.

        *interrupted* for a scan stopped by Ctrl-C, which did not complete.

        The log handler comes off whether or not a display is showing, so the
        console sink a failed start() put in the panel's place is removed too.
        When a shown display ends, a console sink at the panel's level takes
        over: in progress mode the logger has no other console handler, and the
        lines logged after the display ends (the completion banner, a later
        warning or error) would otherwise reach no terminal.
        """
        shown = bool(self.show_progress and self.live)
        if shown:
            # Log a final message
            ASH_LOGGER.info(
                "ASH Security Scan interrupted"
                if interrupted
                else "ASH Security Scan completed"
            )

        # Remove our log handler before stopping the display
        handler = getattr(self, "log_handler", None)
        if handler is not None and handler in ASH_LOGGER.handlers:
            ASH_LOGGER.removeHandler(handler)

        if shown:
            if self.live is not None:
                self.live.__exit__(None, None, None)
            self.live = None
            # Kept, so a display that starts again takes it off (start()), and
            # the end of a second shown display replaces it where it used to add
            # another.
            previous, self._sink_after_stop = self._sink_after_stop, None
            if previous is not None and previous in ASH_LOGGER.handlers:
                ASH_LOGGER.removeHandler(previous)
            self._sink_after_stop = self._console_sink(getattr(handler, "level", 15))
            ASH_LOGGER.addHandler(self._sink_after_stop)

    def add_task(
        self, phase: ExecutionPhase, description: str, total: int = 100
    ) -> TaskID:
        """Add a task to the progress display.

        Args:
            phase: The execution phase this task belongs to
            description: Description of the task
            total: Total steps for the task

        Returns:
            TaskID: ID of the created task
        """
        if not self.show_progress:
            return None

        # Format the description with the phase
        full_description = f"[{phase.value.upper()}] {description}"

        # Add task to progress
        task_id = self.progress.add_task(full_description, total=total)

        # Store start time
        self.task_start_times[task_id] = time.time()

        return task_id

    def update_task(
        self,
        phase: ExecutionPhase,
        task_id: TaskID,
        advance: int | None = None,
        completed: int | None = None,
        description: str | None = None,
        visible: bool | None = None,
    ):
        """Update a task in the progress display.

        Args:
            phase: The execution phase this task belongs to
            task_id: ID of the task to update
            advance: Amount to advance the task
            completed: Set the task to this completion amount
            description: Update the task description
            visible: Set task visibility
        """
        if not self.show_progress or task_id is None:
            return

        update_kwargs = {}

        if advance is not None:
            update_kwargs["advance"] = advance
        if completed is not None:
            update_kwargs["completed"] = completed
            # A task that has reached its own total is finished: stop its timer.
            # The total is the task's, not a literal 100 (add_task takes one).
            task = next((t for t in self.progress.tasks if t.id == task_id), None)
            if task is not None and task.total is not None and completed >= task.total:
                self.progress.stop_task(task_id)
        if description is not None:
            # Format the description with the phase
            full_description = f"[{phase.value.upper()}] {description}"
            update_kwargs["description"] = full_description
        if visible is not None:
            update_kwargs["visible"] = visible

        # Update the task
        self.progress.update(task_id, **update_kwargs)

    def add_summary_row(self, phase: str, status: str, details: str):
        """Add a summary row to the progress display.

        Args:
            phase: Name of the phase
            status: Status of the phase
            details: Additional details
        """
        if not self.show_progress:
            return

        # Add a task with 100% completion to show the summary
        status_emoji = self.status_emojis["success"]
        if "Failed" in status:
            status_emoji = self.status_emojis["failure"]
        elif "Warning" in status:
            status_emoji = self.status_emojis["warning"]

        self.progress.add_task(
            f"[{phase.upper()}] {details} - {status_emoji} {status}",
            total=100,
            completed=100,
        )
