"""Execution engine for security scanners."""

import multiprocessing
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
import time
from typing import Dict, List, Optional, Any, Literal

from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskID,
    TimeRemainingColumn,
)
from rich import box

from automated_security_helper.core.plugin_registry import PluginRegistry, PluginType
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.rich_log_handler import (
    RichLogPanel,
    LiveDisplayLogHandler,
)

# Define valid execution phases
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.config.ash_config import (
    ASHConfig,
)
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.core.scanner_factory import ScannerFactory
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.utils.log import ASH_LOGGER

ExecutionPhaseType = Literal["convert", "scan", "report"]


class ExecutionPhase(str, Enum):
    """Phases of ASH execution."""

    CONVERT = "convert"
    SCAN = "scan"
    REPORT = "report"


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
        log_level = logging.INFO
        if verbose:
            log_level = 15  # VERBOSE level
        if debug:
            log_level = logging.DEBUG

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
        if self.show_progress:
            # Use auto_refresh=True and vertical_overflow="visible" to allow the panel to adjust its height
            self.live = Live(
                self.layout,
                console=self.console,
                refresh_per_second=4,
                auto_refresh=True,
                vertical_overflow="visible",
                screen=True,  # Use alternate screen mode to ensure proper display
            )
            self.live.__enter__()

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


class ScanProgress:
    """Tracks progress of security scans."""

    def __init__(self, total: int):
        """Initialize scan progress tracker."""
        self.completed = 0
        self.total = total

    def increment(self):
        """Increment the completed count."""
        self.completed += 1


class ScanExecutionEngine:
    """Manages the execution of security scanners."""

    def __init__(
        self,
        source_dir: Path = None,
        output_dir: Path = None,
        work_dir: Path = None,
        # enabled_scanners is the list of scanner names that were explicitly passed
        # in from the Orchestrator. This allows ASH users to specify the scanners via CLI
        # at runtime for a more focused scan (e.g. during finding remediation where
        # there is only a single scanner failing, isolating scans to just that
        # scanner will allow quicker retesting until passing and a full scan can be )
        enabled_scanners: Optional[List[str]] = [],
        strategy: Optional[ExecutionStrategy] = ExecutionStrategy.PARALLEL,
        asharp_model: Optional[ASHARPModel] = None,
        config: Optional[ASHConfig] = None,
        show_progress: bool = True,
        global_ignore_paths: List[IgnorePathWithReason] = [],
        color_system: str = "auto",
        verbose: bool = False,
        debug: bool = False,
    ):
        """Initialize the execution engine.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for scan results
            work_dir: Working directory for temporary files
            enabled_scanners: List of scanner names to enable. If None, all scanners are enabled.
                If empty list, no scanners are enabled.
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
            asharp_model: Optional ASHARPModel to use for results
            config: Optional ASHConfig to use for configuration
            show_progress: Whether to show progress bars
            global_ignore_paths: List of paths to ignore globally
            color_system: Color system to use for the console
            verbose: Enable verbose logging
            debug: Enable debug logging
        """
        # Set up logging and initial state
        ASH_LOGGER.debug("Initializing ScanExecutionEngine")
        self._asharp_model = (
            asharp_model
            if asharp_model is not None
            else ASHARPModel(
                name=f"ASH Scan {datetime.now().isoformat()}",
                description="Aggregated security scan results",
                ash_config=config,
            )
        )
        self._config = config
        self._scanners = {}
        self._scan_results = {}
        self._strategy = strategy
        self.show_progress = show_progress
        self._initialized = False  # Track initialization state
        self._init_enabled_scanners = [
            subitem.strip()
            for item in enabled_scanners
            if item is not None
            for subitem in item.split(",")
        ]
        self._enabled_scanners = []
        self._global_ignore_paths = global_ignore_paths
        self._queue = multiprocessing.Queue()

        # Get debug and verbose flags from environment or config
        debug_flag = debug or os.environ.get("ASH_DEBUG", "").lower() in [
            "true",
            "1",
            "yes",
        ]
        verbose_flag = verbose or os.environ.get("ASH_VERBOSE", "").lower() in [
            "true",
            "1",
            "yes",
        ]

        # Config can override environment
        if config:
            if hasattr(config, "debug") and config.debug is not None:
                debug_flag = config.debug
            if hasattr(config, "verbose") and config.verbose is not None:
                verbose_flag = config.verbose

        # Initialize progress display with debug/verbose flags
        self.progress_display = LiveProgressDisplay(
            show_progress=show_progress,
            color_system=color_system,
            verbose=verbose_flag,
            debug=debug_flag,
        )

        # Phase tracking
        self.current_phase = None
        self.phase_tasks = {
            ExecutionPhase.CONVERT: None,
            ExecutionPhase.SCAN: None,
            ExecutionPhase.REPORT: None,
        }

        # Initialize basic configuration

        # Convert and set up paths
        self.source_dir = Path(source_dir) if source_dir else None
        try:
            # Convert and validate source directory

            # Convert and validate output directory
            if output_dir:
                self.output_dir = Path(output_dir)
                if work_dir:
                    self.work_dir = Path(work_dir)
                else:
                    self.work_dir = self.output_dir / "converted"
                self.work_dir.mkdir(parents=True, exist_ok=True)
            else:
                self.output_dir = None
                self.work_dir = None

            # Log directory setup
            ASH_LOGGER.debug(f"Source directory: {self.source_dir}")
            ASH_LOGGER.debug(f"Output directory: {self.output_dir}")
            ASH_LOGGER.debug(f"Work directory: {self.work_dir}")

        except Exception as e:
            ASH_LOGGER.error(f"Failed to setup directories: {e}")
            raise

        # Initialize base components
        self._completed_scanners = []
        self._results = {"scanners": {}}
        self._progress = None
        self._max_workers = min(4, multiprocessing.cpu_count())

        # Initialize scanner components
        self._scanners = {}
        self._registered_scanners = {}
        self._initialized = False
        self._plugin_registry = PluginRegistry(
            config=config,
        )
        self._scanner_factory = ScannerFactory(
            config=config,
            source_dir=source_dir,
            output_dir=output_dir,
            registered_scanner_plugins=self._plugin_registry.get_plugin(
                plugin_type=PluginType.scanner
            ),
        )

        self.ensure_initialized(config=config)

        self._registered_scanners = {}
        self._enabled_from_config = []
        for key, val in self._scanner_factory.available_scanners().items():
            val_instance = val()
            ASH_LOGGER.debug(
                f"Evaluating key {key} with val: {val_instance.model_dump_json()}"
            )
            self._registered_scanners[key] = val_instance
            if (hasattr(val_instance, "enabled") and val_instance.enabled) or (
                hasattr(val_instance, "config")
                and hasattr(val_instance.config, "enabled")
                and val_instance.config.enabled
            ):
                ASH_LOGGER.debug(
                    f"Scanner {key} is enabled via config, adding to enabled scanner list"
                )
                self._enabled_from_config.append(key)

        # Get all enabled scanners from SAST and SBOM configurations using helper
        scanner_configs = self._scanner_factory.available_scanners()
        ASH_LOGGER.debug(f"Scanner configs: {scanner_configs}")

    def get_scanner(
        self, scanner_name: str, check_enabled: bool = True
    ) -> ScannerPluginBase:
        """Get a scanner instance by name.

        Attempts to find and instantiate a scanner in the following order:
        1. First validates if scanner is enabled if check_enabled=True
        2. Looks up scanner in registered scanners (including placeholders)
        3. Tries base name without 'scanner' suffix
        4. Attempts to get implementation from scanner factory
        5. Auto-registers from factory if found

        Args:
            scanner_name: Name of the scanner to retrieve
            check_enabled: If True, validate against enabled scanners list first

        Returns:
            Scanner instance configured with current engine paths

        Raises:
            ValueError: If scanner does not exist or is not enabled
        """
        # Normalize scanner name
        lookup_name = scanner_name.lower().strip()
        if not lookup_name:
            ASH_LOGGER.warning("Scanner name cannot be empty")

        # Ensure initialized and verify enabled status
        self.ensure_initialized(config=self._config)

        if check_enabled and lookup_name not in (self._enabled_scanners or set()):
            ASH_LOGGER.warning(f"Scanner {lookup_name} is not enabled")

        # Create scanner using factory
        try:
            scanner = self._scanner_factory.create_scanner(
                scanner_name=lookup_name,
                source_dir=self.source_dir,
                output_dir=self.output_dir,
            )
            return scanner
        except ValueError as e:
            raise ValueError(f"Scanner {lookup_name} could not be created: {str(e)}")

    def ensure_initialized(self, config: Optional[ASHConfig] = None) -> None:
        """Ensure scanner factory and scanners are properly initialized.

        This method:
        1. Registers and enables all default scanners from factory
        2. Processes config if provided to override scanner settings
        3. Maintains all scanners enabled by default if no explicit config

        Args:
            config: ASH configuration object for initialization
        """
        if not self._initialized or (self._config is None and config is not None):
            ASH_LOGGER.info("Initializing execution engine")
            if config is not None:
                self._config = config
            if not self._config or self._config is None:
                self._config = ASHConfig(
                    project_name="ASH Default Project Config",
                )
            if not isinstance(self._config, ASHConfig):
                raise ValueError("Configuration must be an ASHConfig instance")

            # Mark initialization complete
            self._initialized = True

    def run_prepare_phase(self, config: Optional[ASHConfig] = None) -> List[Path]:
        """The Prepare phase of ASH runs any tasks that need to be ran before scanning
        starts. This typically includes running any registered Converters to make
        unscannable content scannable, resolving any remaining configuration items, or
        preparing other scanner peripherals such as sidecar containers for reporter
        storage.

        Args:
            config (Optional[ASHConfig], optional): An override configuration to be
            provided at the start of this phase.
            Defaults to None.

        Returns:
            List[Path]: List of converted paths
        """
        ASH_LOGGER.debug("Entering: ScanExecutionEngine.run_prepare_phase()")
        self.ensure_initialized(config=config)

        # Start progress display - only if not already started
        if not self.progress_display.live:
            self.progress_display.start()

        self.current_phase = ExecutionPhase.CONVERT

        # Create main prepare phase task
        self.phase_tasks[ExecutionPhase.CONVERT] = self.progress_display.add_task(
            phase=ExecutionPhase.CONVERT, description="Preparing for scan...", total=100
        )

        # Update progress to 10%
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=self.phase_tasks[ExecutionPhase.CONVERT],
            completed=10,
            description="Identifying converters...",
        )

        converters = self._plugin_registry.get_plugin(plugin_type=PluginType.converter)
        converted_paths = []

        # Update progress to 20%
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=self.phase_tasks[ExecutionPhase.CONVERT],
            completed=20,
            description=f"Found {len(converters) if converters else 0} converters",
        )

        converter_tasks = {}

        # If no converters found, still update progress to 100%
        if not converters or not isinstance(converters, dict) or len(converters) == 0:
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=self.phase_tasks[ExecutionPhase.CONVERT],
                completed=100,
                description="No converters to run",
            )

            # Add summary row
            self.progress_display.add_summary_row(
                "Prepare", "Complete", "No converters to run"
            )

            return converted_paths

        # We have converters to run
        total_converters = len(converters)
        completed_converters = 0

        for converter_name, converter_config in converters.items():
            # Create task for this converter
            converter_task = self.progress_display.add_task(
                phase=ExecutionPhase.CONVERT,
                description=f"Running converter: {converter_name}",
                total=100,
            )
            converter_tasks[converter_name] = converter_task

            # Update main task progress - distribute progress from 20% to 80% based on converter completion
            progress_percent = 20 + (completed_converters / total_converters * 60)
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=self.phase_tasks[ExecutionPhase.CONVERT],
                completed=int(progress_percent),
                description=f"Running converter {completed_converters + 1}/{total_converters}: {converter_name}",
            )

            ASH_LOGGER.debug(
                f"Running converter {converter_name} with config {converter_config}"
            )

            # Update converter task to 50%
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=converter_task,
                completed=50,
                description=f"Running converter: {converter_name}",
            )

            converter = converter_config.plugin_class(
                source_dir=self.source_dir,
                output_dir=self.output_dir,
            )
            out = converter.convert()

            # Update converter task to 100%
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=converter_task,
                completed=100,
                description=f"Completed converter: {converter_name}",
            )

            if out:
                ASH_LOGGER.debug(f"Converter {converter_name} returned: {out}")
                if isinstance(out, list):
                    converted_paths.extend(out)
                else:
                    converted_paths.append(out)

            completed_converters += 1

            # Update main task progress after each converter completes
            progress_percent = 20 + (completed_converters / total_converters * 60)
            self.progress_display.update_task(
                phase=ExecutionPhase.CONVERT,
                task_id=self.phase_tasks[ExecutionPhase.CONVERT],
                completed=int(progress_percent),
                description=f"Completed {completed_converters}/{total_converters} converters",
            )

        # Update main task to 100%
        self.progress_display.update_task(
            phase=ExecutionPhase.CONVERT,
            task_id=self.phase_tasks[ExecutionPhase.CONVERT],
            completed=100,
            description=f"Preparation complete: {len(converted_paths)} paths converted",
        )

        # Add summary row
        self.progress_display.add_summary_row(
            "Convert", "Complete", f"Converted {len(converted_paths)} paths"
        )

        return converted_paths

    def run_scan_phase(self, config: Optional[ASHConfig] = None) -> ASHARPModel:
        """Execute registered scanners based on provided configuration.

        Args:
            config (Optional[ASHConfig], optional): An override configuration to be
            provided at the start of this phase.
            Defaults to None.

        Returns:
            Dict[str, Any]: Results dictionary with scanner results and ASHARPModel

        Raises:
            ValueError: If config is invalid or mode is invalid
            RuntimeError: If scanner execution fails critically
        """
        ASH_LOGGER.debug("Entering: ScanExecutionEngine.run_scan_phase()")
        self.ensure_initialized(config=config)

        # Start progress display - only if not already started
        if not self.progress_display.live:
            self.progress_display.start()

        # Set current phase
        self.current_phase = ExecutionPhase.SCAN

        return self._run_scan_phase_internal(config)

    def _run_scan_phase_internal(
        self, config: Optional[ASHConfig] = None
    ) -> ASHARPModel:
        """Internal implementation of the scan phase.

        Args:
            config (Optional[ASHConfig], optional): An override configuration.
                Defaults to None.

        Returns:
            ASHARPModel: Results of the scan
        """

        # Create main scan phase task
        self.phase_tasks[ExecutionPhase.SCAN] = self.progress_display.add_task(
            phase=ExecutionPhase.SCAN,
            description="Initializing scan phase...",
            total=100,
        )

        # Reset state for new execution
        self._completed_scanners = []
        self._scan_results = {}

        # Execute scanners based on mode
        enabled_scanners = set()
        try:
            # Update progress
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=10,
                description="Building scanner queue...",
            )

            # Print progress update
            ASH_LOGGER.info("Building scanner queue...")

            # Build queue of scanner tuples for execution
            self._queue = multiprocessing.Queue()

            # Get all enabled scanners from SAST and SBOM configurations using helper
            scanner_configs = self._scanner_factory.available_scanners()
            ASH_LOGGER.debug(f"Scanner configs: {scanner_configs}")

            # Update progress
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=20,
                description=f"Found {len(scanner_configs)} scanner configurations",
            )

            final_enabled_scanners = set()
            # Process SAST and SBOM scanners
            if scanner_configs:
                for scanner_name, scanner_config in scanner_configs.items():
                    if scanner_config:
                        # Add scanner to execution queue with default target
                        scanner_config_instance = scanner_config()
                        if (
                            hasattr(scanner_config_instance.config, "enabled")
                            and bool(scanner_config_instance.config.enabled)
                            and (
                                len(self._init_enabled_scanners) == 0
                                or scanner_name.lower().strip()
                                in self._init_enabled_scanners
                            )
                        ):
                            if "cdk" in scanner_name:
                                ASH_LOGGER.debug(
                                    f"(scanner_name: {scanner_name}) scanner_config_instance: {scanner_config_instance} scanner_config: {scanner_config_instance}"
                                )
                            # Add a single task per scanner that will handle both source and converted directories
                            self._queue.put(
                                (
                                    scanner_name,
                                    scanner_config_instance,
                                    [
                                        {"path": self.source_dir, "type": "source"},
                                        {"path": self.work_dir, "type": "converted"},
                                    ],
                                )
                            )
                            final_enabled_scanners.add(scanner_name)

            # Normalize and store enabled scanner names
            registered_names = sorted(set(self._registered_scanners.keys()))
            ASH_LOGGER.info(
                f"[yellow]Registered scanners[/yellow] : {registered_names}"
            )
            self._enabled_scanners = sorted(self._enabled_from_config)
            ASH_LOGGER.info(
                f"[bold green]Enabled scanners[/bold green]    : {list(sorted(final_enabled_scanners))}"
            )

            # Update progress
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=30,
                description=f"Prepared {len(final_enabled_scanners)} scanners for execution",
            )

            # Initialize progress tracker for execution
            self._progress = ScanProgress(len(enabled_scanners))

            # Execute scanners based on mode
            if self._strategy == ExecutionStrategy.PARALLEL:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=self.phase_tasks[ExecutionPhase.SCAN],
                    completed=40,
                    description="Executing scanners in parallel...",
                )
                out = self._execute_parallel()
            else:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=self.phase_tasks[ExecutionPhase.SCAN],
                    completed=40,
                    description="Executing scanners sequentially...",
                )
                out = self._execute_sequential()

            ASH_LOGGER.debug(f"Execution completed: {out}")

            # Update progress
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=90,
                description="Finalizing scan results...",
            )

            # Save ASHARPModel as JSON alongside results if output_dir is configured
            output_dir = getattr(self._config, "output_dir", None)
            if output_dir:
                output_path = Path(output_dir)
                ASH_LOGGER.verbose(f"Saving ASHARPModel to {output_path}")
                self._asharp_model.save_model(output_path)

            # Update progress to 100%
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=100,
                description=f"Scan complete: {len(self._completed_scanners)} scanners executed",
            )

            # Print completion message
            # ASH_LOGGER.info(f"✅ Scan complete: {len(self._completed_scanners)} scanners executed")

            # Add summary row
            self.progress_display.add_summary_row(
                "Scan", "Complete", f"Executed {len(self._completed_scanners)} scanners"
            )

            return self._asharp_model

        except Exception as e:
            # Update progress to show error
            if self.phase_tasks[ExecutionPhase.SCAN]:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=self.phase_tasks[ExecutionPhase.SCAN],
                    description=f"Scan failed: {str(e)}",
                )

            # Print error message
            # ASH_LOGGER.info(f"❌ Scan failed: {str(e)}")

            # Add error to summary
            self.progress_display.add_summary_row("Scan", "Failed", f"Error: {str(e)}")

            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            raise

    def run_report_phase(self, config: Optional[ASHConfig] = None) -> None:
        """Execute the report phase of the scan.

        This phase generates reports from the scan results.

        Args:
            config (Optional[ASHConfig], optional): An override configuration to be
            provided at the start of this phase.
            Defaults to None.
        """
        ASH_LOGGER.debug("Entering: ScanExecutionEngine.run_report_phase()")
        self.ensure_initialized(config=config)

        # Print progress update
        ASH_LOGGER.info("\n----- Starting report generation phase -----")

        # Start progress display - only if not already started
        if not self.progress_display.live:
            self.progress_display.start()

        # Set current phase
        self.current_phase = ExecutionPhase.REPORT

        self._run_report_phase_internal(config)

    def _run_report_phase_internal(self, config: Optional[ASHConfig] = None) -> None:
        """Internal implementation of the report phase.

        Args:
            config (Optional[ASHConfig], optional): An override configuration.
                Defaults to None.
        """
        # Create main report phase task if it doesn't exist
        if not self.phase_tasks.get(ExecutionPhase.REPORT):
            self.phase_tasks[ExecutionPhase.REPORT] = self.progress_display.add_task(
                phase=ExecutionPhase.REPORT,
                description="Starting report generation...",
                total=100,
            )

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=self.phase_tasks[ExecutionPhase.REPORT],
            completed=10,
            description="Preparing report data...",
        )

        # Print progress update
        ASH_LOGGER.info("Preparing report data...")

        # Get output formats from config
        output_formats = getattr(self._config, "output_formats", [])
        if not output_formats:
            ASH_LOGGER.warning("No output formats specified in configuration")
            self.progress_display.update_task(
                phase=ExecutionPhase.REPORT,
                task_id=self.phase_tasks[ExecutionPhase.REPORT],
                completed=100,
                description="No output formats specified",
            )
            return

        # Get the appropriate reporters based on the configured output formats
        from automated_security_helper.reporters.ash_default import (
            ASFFReporter,
            CSVReporter,
            CycloneDXReporter,
            HTMLReporter,
            JSONReporter,
            JUnitXMLReporter,
            SARIFReporter,
            SPDXReporter,
            TextReporter,
            YAMLReporter,
        )

        available_reporters = {
            "asff": {"reporter": ASFFReporter(), "name": "ASFF Reporter"},
            "csv": {"reporter": CSVReporter(), "name": "CSV Reporter"},
            "cyclonedx": {
                "reporter": CycloneDXReporter(),
                "name": "CycloneDX Reporter",
            },
            "html": {"reporter": HTMLReporter(), "name": "HTML Reporter"},
            "json": {"reporter": JSONReporter(), "name": "JSON Reporter"},
            "junitxml": {"reporter": JUnitXMLReporter(), "name": "JUnit XML Reporter"},
            "sarif": {"reporter": SARIFReporter(), "name": "SARIF Reporter"},
            "spdx": {"reporter": SPDXReporter(), "name": "SPDX Reporter"},
            "text": {"reporter": TextReporter(), "name": "Text Reporter"},
            "yaml": {"reporter": YAMLReporter(), "name": "YAML Reporter"},
        }

        # Filter reporters based on the configured output formats
        active_reporters = {}
        for fmt in output_formats:
            fmt_str = str(fmt).lower()
            if fmt_str in available_reporters:
                active_reporters[fmt_str] = available_reporters[fmt_str]

        if not active_reporters:
            ASH_LOGGER.warning(
                f"No matching reporters found for formats: {output_formats}"
            )
            self.progress_display.update_task(
                phase=ExecutionPhase.REPORT,
                task_id=self.phase_tasks[ExecutionPhase.REPORT],
                completed=100,
                description="No matching reporters found",
            )
            return

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=self.phase_tasks[ExecutionPhase.REPORT],
            completed=20,
            description=f"Found {len(active_reporters)} matching reporters",
        )

        ASH_LOGGER.info(
            f"Found {len(active_reporters)} matching reporters for formats: {', '.join(output_formats)}"
        )

        # Update progress
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=self.phase_tasks[ExecutionPhase.REPORT],
            completed=30,
            description=f"Generating reports in formats: {', '.join([str(fmt) for fmt in output_formats])}",
        )

        ASH_LOGGER.info(
            f"Generating reports in formats: {', '.join([str(fmt) for fmt in output_formats])}"
        )

        # Generate reports
        reporter_tasks = {}
        completed_reporters = 0
        total_reporters = len(active_reporters)
        output_dir = self.output_dir.joinpath("reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt, reporter_info in active_reporters.items():
            reporter = reporter_info["reporter"]
            reporter_name = reporter_info["name"]

            # Create task for this reporter
            task_description = f"[magenta]({reporter_name}) Generating {fmt} report..."
            reporter_task = self.progress_display.add_task(
                phase=ExecutionPhase.REPORT, description=task_description, total=100
            )
            reporter_tasks[fmt] = reporter_task

            # Update reporter task to show it's starting
            self.progress_display.update_task(
                phase=ExecutionPhase.REPORT,
                task_id=reporter_task,
                completed=10,
                description=f"[blue]({reporter_name}) Starting {fmt} report generation...",
            )

            ASH_LOGGER.info(f"Starting {fmt} report generation with {reporter_name}")

            try:
                # Generate report with this reporter
                ASH_LOGGER.debug(f"Generating {fmt} report with {reporter_name}")

                # Update reporter task to show progress
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=50,
                    description=f"[yellow]({reporter_name}) Generating {fmt} report...",
                )

                # Generate the report
                formatted = reporter.report(self._asharp_model)
                if formatted is None:
                    ASH_LOGGER.error(
                        f"Failed to format report with {fmt} reporter, returned empty string"
                    )
                    raise ValueError(f"Reporter returned empty result for {fmt}")

                # Write the report to a file
                output_filename = f"ash.{fmt}"
                if fmt == "cyclonedx":
                    output_filename = "ash.cdx.json"
                elif fmt == "junitxml":
                    output_filename = "ash.junit.xml"
                elif fmt == "sarif":
                    output_filename = "ash.sarif"
                elif fmt == "spdx":
                    output_filename = "ash.spdx.json"

                output_file = output_dir.joinpath(output_filename)
                ASH_LOGGER.info(f"Writing {fmt} report to {output_file}")
                output_file.write_text(formatted)

                # Update reporter task to show completion
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=100,
                    description=f"[green]({reporter_name}) {fmt.upper()} report generated",
                )

                ASH_LOGGER.info(
                    f"✅ {fmt.upper()} report generated successfully with {reporter_name}"
                )

                # Update main report phase progress
                completed_reporters += 1
                progress_percent = 30 + ((completed_reporters / total_reporters) * 70)
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=self.phase_tasks[ExecutionPhase.REPORT],
                    completed=int(progress_percent),
                    description=f"Generated {completed_reporters}/{total_reporters} reports",
                )

            except Exception as e:
                ASH_LOGGER.error(
                    f"Error generating reports with {reporter_name}: {str(e)}"
                )
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=100,
                    description=f"[red]({reporter_name}) Failed: {str(e)}",
                )

        # Update progress to 100%
        self.progress_display.update_task(
            phase=ExecutionPhase.REPORT,
            task_id=self.phase_tasks[ExecutionPhase.REPORT],
            completed=100,
            description=f"Generated reports with {completed_reporters}/{total_reporters} reporters",
        )

        # Print completion message
        ASH_LOGGER.info(
            f"✅ Generated reports with {completed_reporters}/{total_reporters} reporters"
        )

        # Add summary row
        self.progress_display.add_summary_row(
            "Report",
            "Complete",
            f"Generated reports with {completed_reporters}/{total_reporters} reporters",
        )

    def execute_phases(
        self,
        phases: List[ExecutionPhaseType] = ["convert", "scan", "report"],
        config: Optional[ASHConfig] = None,
    ) -> ASHARPModel:
        """Execute the specified phases in the correct order.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].
            config (Optional[ASHConfig], optional): An override configuration to be
                provided at the start of execution.
                Defaults to None.

        Returns:
            ASHARPModel: The results of the scan.
        """
        ASH_LOGGER.debug(f"Entering: ScanExecutionEngine.execute_phases({phases})")
        self.ensure_initialized(config=config)

        # Always execute phases in the correct order, regardless of input order
        ordered_phases = []
        if "convert" in phases:
            ordered_phases.append("convert")
        if "scan" in phases:
            ordered_phases.append("scan")
        if "report" in phases:
            ordered_phases.append("report")

        ASH_LOGGER.info(f"Executing phases: {ordered_phases}")

        # Log a message to show progress is happening
        ASH_LOGGER.info("\n===== ASH Security Scan Starting =====")
        ASH_LOGGER.info(f"Executing phases: {', '.join(ordered_phases)}")

        # Start the progress display before executing any phases
        self.progress_display.start()

        try:
            # Execute each phase in order
            for phase in ordered_phases:
                ASH_LOGGER.info(f"\n----- Starting phase: {phase.upper()} -----")
                if phase == "convert":
                    # Call the prepare phase but don't start the display again
                    self.current_phase = ExecutionPhase.CONVERT
                    if not self.phase_tasks.get(ExecutionPhase.CONVERT):
                        self.phase_tasks[ExecutionPhase.CONVERT] = (
                            self.progress_display.add_task(
                                phase=ExecutionPhase.CONVERT,
                                description="Starting convert phase...",
                                total=100,
                            )
                        )
                    # Use the existing run_prepare_phase method but skip starting the display
                    self.run_prepare_phase(config)

                elif phase == "scan":
                    # Call the scan phase but don't start the display again
                    self.current_phase = ExecutionPhase.SCAN
                    if not self.phase_tasks.get(ExecutionPhase.SCAN):
                        self.phase_tasks[ExecutionPhase.SCAN] = (
                            self.progress_display.add_task(
                                phase=ExecutionPhase.SCAN,
                                description="Starting scan phase...",
                                total=100,
                            )
                        )
                    # Use the existing run_scan_phase method
                    self._results = self.run_scan_phase(config)

                elif phase == "report":
                    # Call the report phase but don't start the display again
                    self.current_phase = ExecutionPhase.REPORT
                    if not self.phase_tasks.get(ExecutionPhase.REPORT):
                        self.phase_tasks[ExecutionPhase.REPORT] = (
                            self.progress_display.add_task(
                                phase=ExecutionPhase.REPORT,
                                description="Starting report phase...",
                                total=100,
                            )
                        )
                    # Use the existing run_report_phase method
                    self.run_report_phase(config)

            # Return the results
            # ASH_LOGGER.info("\n===== ASH Security Scan Complete =====")
            return self._results

        except Exception as e:
            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            ASH_LOGGER.info(f"\n❌ Execution failed: {str(e)}")
            raise
        # finally:
        #     # Ensure the progress display is stopped properly
        #     if hasattr(self.progress_display, 'live') and self.progress_display.live:
        #         self.progress_display.stop()
        finally:
            # Stop the progress display
            # self.progress_display.stop()
            ASH_LOGGER.info("\n===== ASH Security Scan Complete =====")

        return ASHARPModel(description="No results generated")

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Execute a single scanner on multiple targets and process its results.

        Args:
            scanner_name: Name of the scanner
            scanner_plugin: Scanner plugin instance
            scan_targets: List of targets to scan, each with path and type

        Returns:
            List[ScanResultsContainer]: List of scan results containers

        Raises:
            ScannerError: If scanner execution fails
        """
        results = []

        try:
            config_overridden = False
            ASH_LOGGER.debug("EVALUATING CONFIGURED SCANNERS")
            scanner_config = scanner_plugin.config
            ASH_LOGGER.debug(f"scanner_plugin.config: {scanner_plugin.config}")
            scanner_config_override = self._plugin_registry.get_plugin(
                plugin_type="scanner",
                plugin_name=scanner_name.replace("_", "-"),
            )
            if scanner_config_override is not None:
                ASH_LOGGER.debug(
                    f"Found scanner_plugin.plugin_config in registry: {scanner_config_override.plugin_config}"
                )
                scanner_config_override = scanner_config_override.plugin_config
            else:
                scanner_config_override = self._config.get_plugin_config(
                    plugin_type="scanner",
                    plugin_name=scanner_name.replace("_", "-"),
                )
            if scanner_config_override is not None:
                ASH_LOGGER.debug(
                    f"scanner_config_override override: {scanner_config_override}"
                )
                config_overridden = True

            # Force scanner_config to dict for the next section
            if hasattr(scanner_config, "model_dump") and callable(
                scanner_config.model_dump
            ):
                scanner_config = scanner_config.model_dump(by_alias=True)

            if scanner_config_override is not None:
                if hasattr(scanner_config_override, "model_dump") and callable(
                    scanner_config_override.model_dump
                ):
                    scanner_config_override = scanner_config_override.model_dump(
                        by_alias=True
                    )
                ASH_LOGGER.debug(f"({scanner_name}) scanner_config: {scanner_config}")
                ASH_LOGGER.debug(
                    f"({scanner_name}) scanner_config_override: {scanner_config_override}"
                )

                if scanner_config_override.get("enabled", None) is not None:
                    scanner_config["enabled"] = scanner_config_override.get(
                        "enabled", True
                    )
                    config_overridden = True
                for key, val in scanner_config_override.get("options", {}).items():
                    if "options" not in scanner_config or not isinstance(
                        scanner_config["options"], dict
                    ):
                        scanner_config["options"] = {}
                    scanner_config["options"][key] = val

            scanner_config = ScannerPluginConfigBase(**scanner_config)
            ASH_LOGGER.debug(
                f"({scanner_name}) scanner_config overridden: {config_overridden} -- {scanner_config}"
            )

            # Process each target sequentially
            for target_info in scan_targets:
                scan_target = target_info["path"]
                target_type = target_info["type"]

                # Skip empty or non-existent directories
                if not scan_target or not Path(scan_target).exists():
                    ASH_LOGGER.debug(
                        f"Skipping {target_type} directory {scan_target} - does not exist"
                    )
                    continue

                # Create a container for this target
                container = ScanResultsContainer(
                    scanner_name=scanner_config.name,
                    target=scan_target,
                    target_type=target_type,
                )

                # Execute scan for this target
                raw_results = None
                try:
                    if scanner_config.enabled:
                        ASH_LOGGER.debug(
                            f"Executing {scanner_config.name or scanner_plugin.__class__.__name__}.scan() on {target_type}"
                        )
                        raw_results = scanner_plugin.scan(
                            target=scan_target,
                            config=scanner_config,
                            target_type=target_type,
                            global_ignore_paths=self._global_ignore_paths,
                        )
                    else:
                        ASH_LOGGER.warning(f"{scanner_config.name} is not enabled!")
                except Exception as e:
                    err_str = f"Failed to execute {scanner_config.name or scanner_plugin.__class__.__name__} scanner on {target_type}: {e}"
                    ASH_LOGGER.error(err_str)
                    raw_results = {
                        "errors": [
                            err_str,
                            *scanner_plugin.errors,
                        ],
                        "output": scanner_plugin.output,
                    }
                finally:
                    ASH_LOGGER.debug(
                        f"{scanner_plugin.__class__.__name__} raw_results for {target_type}: {raw_results}"
                    )
                    if raw_results is None:
                        raw_results = {
                            "errors": scanner_plugin.errors or [],
                            "output": scanner_plugin.output or [],
                        }
                    container.raw_results = raw_results

                    if raw_results is not None:
                        # Extract and add metadata if present
                        if "metadata" in raw_results:
                            for key, value in raw_results["metadata"].items():
                                container.add_metadata(key, value)

                    # Add this container to our results
                    results.append(container)

            # Update progress and mark scanner as completed
            ASH_LOGGER.debug("Executing engine.progress.increment()")
            if self._progress:
                self._progress.increment()

            ASH_LOGGER.debug(
                f"Appending {scanner_plugin.__class__.__name__} to engine.completed_scanners"
            )
            self._completed_scanners.append(scanner_plugin)

            return results

        except Exception as e:
            ASH_LOGGER.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}"
            )
            raise

    def _execute_sequential(self) -> None:
        """Execute scanners sequentially and update ASHARPModel."""
        # On MacOS, qsize() raises NotImplementedError, so we need to count items differently
        # First, get all items from the queue into a list
        scanner_tuples = []
        while not self._queue.empty():
            scanner_tuples.append(self._queue.get())

        # Now we know the total count
        total_scanners = len(scanner_tuples)
        completed = 0

        # Process each scanner
        for scanner_tuple in scanner_tuples:
            scanner_name = scanner_tuple[0]
            scanner_plugin = scanner_tuple[1]
            scan_targets = scanner_tuple[2]

            # Create task for this scanner
            task_description = f"[cyan]({scanner_name}) Scanning directories..."
            scanner_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN, description=task_description, total=100
            )

            # Update main scan task progress
            progress_percent = 40 + (completed / total_scanners * 50)
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=int(progress_percent),
                description=f"Running scanner {completed + 1}/{total_scanners}: {scanner_name}",
            )

            try:
                # Update scanner task to 50%
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=50,
                )

                # Log progress
                ASH_LOGGER.info(f"Running scanner: {scanner_name}")

                results_list = self._execute_scanner(
                    scanner_name=scanner_name,
                    scanner_plugin=scanner_plugin,
                    scan_targets=scan_targets,
                )

                # Process each result
                for results in results_list:
                    self._process_results(results)

                # Update scanner task to 100%
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[green]({scanner_name}) Completed scan",
                )

                # Log completion
                ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

            except Exception as e:
                # Update scanner task to show error
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=f"[red]({scanner_name}) Failed: {str(e)}",
                )

                # Log error
                ASH_LOGGER.error(f"Scanner failed: {scanner_name} - {str(e)}")

                raise
            finally:
                completed += 1

    def _execute_parallel(self) -> None:
        """Execute scanners in parallel and update ASHARPModel."""
        # Get all scanner tasks from the queue first to avoid qsize() which is not implemented on macOS
        scanner_tuples = []
        while True:
            try:
                scanner_tuple = self._queue.get(block=False)
                scanner_tuples.append(scanner_tuple)
            except Exception:
                break

        total_scanners = len(scanner_tuples)
        ASH_LOGGER.debug(f"Total scanners: {total_scanners}")
        scanner_tasks = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []

            # Submit all scanners to the thread pool
            for scanner_tuple in scanner_tuples:
                ASH_LOGGER.debug("Processing scanner from queue")

                scanner_name = scanner_tuple[0]
                scanner_plugin = scanner_tuple[1]
                scan_targets = scanner_tuple[2]

                # Create task for this scanner
                task_key = f"{scanner_name}_task"
                task_description = f"[magenta]({scanner_name}) Scanning directories..."
                scanner_task = self.progress_display.add_task(
                    phase=ExecutionPhase.SCAN, description=task_description, total=100
                )
                scanner_tasks[task_key] = scanner_task

                # Update scanner task to show it's queued
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=10,
                    description=f"[blue]({scanner_name}) Queued scan...",
                )

                ASH_LOGGER.debug(
                    f"Submitting {scanner_name} to thread pool to scan targets"
                )
                future = executor.submit(
                    self._execute_scanner,
                    scanner_name,
                    scanner_plugin,
                    scan_targets,
                )
                # Store scanner info with future for later reference
                future.scanner_info = {
                    "name": scanner_name,
                    "task_key": task_key,
                }
                ASH_LOGGER.debug(f"Submitted {scanner_name} to thread pool")
                futures.append(future)
                ASH_LOGGER.debug(f"Appended {scanner_name} to futures")

            # Update main scan task progress
            self.progress_display.update_task(
                phase=ExecutionPhase.SCAN,
                task_id=self.phase_tasks[ExecutionPhase.SCAN],
                completed=50,
                description=f"Running {len(futures)} scanner tasks in parallel...",
            )

            # Wait for all futures to complete and handle any exceptions
            completed_count = 0
            for future in as_completed(futures):
                try:
                    ASH_LOGGER.debug("Getting results from completed future")
                    results_list = future.result()
                    ASH_LOGGER.debug("Got results from completed future, processing")

                    # Process each result in the list
                    for results in results_list:
                        self._process_results(results)

                    # Update scanner task to show completion
                    scanner_name = future.scanner_info["name"]
                    task_key = future.scanner_info["task_key"]
                    task_id = scanner_tasks.get(task_key)

                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[green]({scanner_name}) Completed scan",
                        )

                    # Log completion
                    ASH_LOGGER.info(f"Completed scanner: {scanner_name}")

                    # Update main scan task progress
                    completed_count += 1
                    if len(futures) > 0:  # Avoid division by zero
                        progress_percent = 50 + (completed_count / len(futures) * 40)
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=self.phase_tasks[ExecutionPhase.SCAN],
                            completed=int(progress_percent),
                            description=f"Completed {completed_count}/{len(futures)} scanner tasks",
                        )

                    if self._progress:
                        self._progress.increment()
                except Exception as e:
                    # Update scanner task to show error
                    scanner_name = future.scanner_info["name"]
                    task_key = future.scanner_info["task_key"]
                    task_id = scanner_tasks.get(task_key)

                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=f"[red]({scanner_name}) Failed: {str(e)}",
                        )

                    # Log error
                    ASH_LOGGER.error(f"Scanner execution failed: {str(e)}")
                    raise

    def _process_results(self, results: ScanResultsContainer) -> None:
        """Process scanner results and update ASHARPModel.

        Args:
            results: Dictionary containing scanner results
            ash_model: ASHARPModel instance to update
        """
        if isinstance(results.raw_results, SarifReport):
            self._asharp_model.sarif.merge_sarif_report(results.raw_results)
        elif isinstance(results.raw_results, ASHARPModel):
            self._asharp_model.merge_model(results.raw_results)
        elif isinstance(results.raw_results, CycloneDXReport):
            self._asharp_model.cyclonedx = results.raw_results
        else:
            if results.scanner_name not in self._asharp_model.additional_reports:
                self._asharp_model.additional_reports[results.scanner_name] = {}
            self._asharp_model.additional_reports[results.scanner_name][
                results.target_type
            ] = results.raw_results

        # Update ASHARPModel with scanner results
        # for scanner_name, data in results.items():
        #     ASH_LOGGER.debug(f"Processing results for {scanner_name}: {data}")
        #     if "container" in data:
        #         container = data["container"]
        #         # Add findings from container to model
        #         ash_model.findings.extend(container.findings)
        #         # Add scanner metadata
        #         ash_model.scanners_used.append(
        #             {
        #                 "name": scanner_name,
        #                 "version": container.metadata.get("version", "unknown"),
        #                 "metadata": container.metadata,
        #             }
        #         )

    @property
    def completed_scanners(self) -> List[ScannerPluginBase]:
        """Get list of completed scanners."""
        return self._completed_scanners

    @property
    def progress(self) -> Optional[ScanProgress]:
        """Get current scan progress."""
        return self._progress

    def _get_all_scanners(self) -> Dict[str, Any]:
        """Get all enabled scanners from available scanners that are enabled.

        Returns:
            Dict[str, Any]: Dictionary of scanner name to scanner config mappings.
        """
        all_scanners = {}
        if not self._initialized:
            return all_scanners

        # Get all available scanners that are enabled
        available = self._scanner_factory.available_scanners()
        for scanner_name in available:
            if scanner_name in (self._enabled_scanners or set()):
                all_scanners[scanner_name] = None

        # Add SAST scanners if configured
        if hasattr(self._config, "sast") and hasattr(self._config.sast, "scanners"):
            for (
                scanner_name
            ) in self._config.sast.scanners.__class__.model_fields.keys():
                config = getattr(self._config.sast.scanners, scanner_name)
                if isinstance(config, ScannerPluginConfigBase):
                    ASH_LOGGER.debug(
                        f"Found built-in SAST scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        ASH_LOGGER.debug(
                            f"Adding built-in SAST scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        ASH_LOGGER.debug(
                            f"Skipping disabled built-in SAST scanner '{scanner_name}'"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )
            for (
                scanner_name,
                config,
            ) in self._config.sast.scanners.__pydantic_extra__.items():
                if isinstance(config, ScannerPluginConfigBase):
                    ASH_LOGGER.debug(
                        f"Found custom SAST scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        ASH_LOGGER.debug(
                            f"Adding custom SAST scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        ASH_LOGGER.debug(
                            f"Skipping disabled custom SAST scanner '{scanner_name}'"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )

        # Get SBOM scanners
        if hasattr(self._config, "sbom") and hasattr(self._config.sbom, "scanners"):
            for (
                scanner_name
            ) in self._config.sbom.scanners.__class__.model_fields.keys():
                config = getattr(self._config.sbom.scanners, scanner_name)
                if isinstance(config, ScannerPluginConfigBase):
                    ASH_LOGGER.debug(
                        f"Found built-in SBOM scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        ASH_LOGGER.debug(
                            f"Adding built-in SBOM scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        ASH_LOGGER.debug(
                            f"Skipping disabled built-in SBOM scanner '{scanner_name}'"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )
            for (
                scanner_name,
                config,
            ) in self._config.sbom.scanners.__pydantic_extra__.items():
                if isinstance(config, ScannerPluginConfigBase):
                    ASH_LOGGER.debug(
                        f"Found custom SBOM scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        ASH_LOGGER.debug(
                            f"Adding custom SBOM scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        ASH_LOGGER.debug(
                            f"Skipping disabled custom SBOM scanner '{scanner_name}'"
                        )
                else:
                    ASH_LOGGER.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )

        return all_scanners

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of worker threads for parallel execution."""
        self._max_workers = workers
