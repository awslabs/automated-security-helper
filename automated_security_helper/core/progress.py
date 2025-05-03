from enum import Enum
import logging
import os
import sys
import time
from typing import Literal

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)

from rich import box
from rich.console import Console
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


class ExecutionPhase(str, Enum):
    """Phases of ASH execution."""

    CONVERT = "convert"
    SCAN = "scan"
    REPORT = "report"
    INSPECT = "inspect"


class ExecutionStrategy(str, Enum):
    """Strategy for executing scanners."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


class LiveProgressDisplay:
    """Manages a rich live display with a unified task table for ASH execution phases."""

    def __init__(
        self,
        show_progress: bool = True,
        color_system: str = "auto",
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
        self.show_progress = show_progress and os.environ.get(
            "ASH_IN_CONTAINER", "NO"
        ).upper() not in ["YES", "1", "TRUE"]
        self.console = Console(color_system=color_system)
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

        # Set up a log handler to capture logs with appropriate level based on flags
        log_level = logging.DEBUG
        # if verbose:
        #     log_level = 15  # VERBOSE level
        # if debug:
        #     log_level = logging.DEBUG

        self.log_handler = LiveDisplayLogHandler(self.log_panel, level=log_level)
        self.log_handler.setFormatter(logging.Formatter("%(message)s"))

        # Add the handler to the ASH logger
        ASH_LOGGER.addHandler(self.log_handler)

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

    def start(self):
        """Start the live display if progress is enabled."""
        if self.show_progress and (self.live is None):
            try:
                # Use auto_refresh=True and vertical_overflow="visible" to allow the panel to adjust its height
                print("Setting Live setup", file=sys.stderr)

                # Create a simpler layout for testing
                self.live = Live(
                    self.layout,
                    console=self.console,
                    refresh_per_second=4,
                    auto_refresh=True,
                    vertical_overflow="visible",
                    screen=False,  # Try without screen mode
                )
                print("Entering Live setup", file=sys.stderr)
                self.live.__enter__()
                print("Entered Live setup", file=sys.stderr)
            except Exception as e:
                print(f"ERROR initializing live display: {str(e)}", file=sys.stderr)
                import traceback

                traceback.print_exc()
                # Fall back to non-progress mode
                self.show_progress = False
                ASH_LOGGER.error(f"Failed to initialize progress display: {str(e)}")
                ASH_LOGGER.info("Continuing without progress display")

        # Log a message to show in the log panel
        ASH_LOGGER.info("ASH Security Scan started")

    def stop(self):
        """Stop the live display if it's running."""
        if self.show_progress and self.live:
            # Log a final message
            ASH_LOGGER.info("ASH Security Scan completed")

            # Remove our log handler before stopping the display
            if hasattr(self, "log_handler") and self.log_handler in ASH_LOGGER.handlers:
                ASH_LOGGER.removeHandler(self.log_handler)
            self.live.__exit__(None, None, None)
            self.live = None

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
        advance: int = None,
        completed: int = None,
        description: str = None,
        visible: bool = None,
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
            # If task is completed at 100%, also mark it as finished to stop the timer
            if completed == 100:
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

    def complete_task(
        self,
        phase: ExecutionPhase,
        task_id: TaskID,
        success: bool = True,
        description: str = None,
        warning: bool = False,
        skipped: bool = False,
    ):
        """Mark a task as completed in the task table.

        Args:
            phase: The execution phase this task belongs to
            task_id: ID of the task to complete
            success: Whether the task completed successfully
            description: Final description for the task
            warning: Whether to mark the task with a warning
            skipped: Whether the task was skipped
        """
        if not self.show_progress or task_id is None or task_id not in self.task_rows:
            return

        # Get the row index for this task
        row_index = self.task_rows[task_id]

        # Calculate elapsed time
        elapsed = time.time() - self.task_start_times[task_id]
        elapsed_str = f"{elapsed:.2f}s"

        # Determine status
        status_key = (
            "skipped"
            if skipped
            else "warning"
            if warning
            else "success"
            if success
            else "failure"
        )
        status_text = (
            "Skipped"
            if skipped
            else "Warning"
            if warning
            else "Success"
            if success
            else "Failed"
        )

        # Clean up description for display
        clean_desc = description or self.task_table.rows[row_index][1]
        for color in [
            "[red]",
            "[green]",
            "[blue]",
            "[yellow]",
            "[magenta]",
            "[cyan]",
            "[bold]",
        ]:
            clean_desc = clean_desc.replace(color, "")
        for color in [
            "[/red]",
            "[/green]",
            "[/blue]",
            "[/yellow]",
            "[/magenta]",
            "[/cyan]",
            "[/bold]",
        ]:
            clean_desc = clean_desc.replace(color, "")

        # Update the row with completed status
        self.task_table.rows[row_index] = (
            phase.value.upper(),
            clean_desc,
            elapsed_str,
            f"{self.status_emojis[status_key]} {status_text}",
        )
