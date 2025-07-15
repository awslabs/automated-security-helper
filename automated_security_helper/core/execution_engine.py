"""Execution engine for security scanners."""

import os
from datetime import datetime, timezone
from pathlib import Path
import platform
from typing import List, Optional, Literal


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.core.metrics_table import display_metrics_table
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.inspect_phase import InspectPhase
from automated_security_helper.core.progress import (
    ExecutionPhaseType,
    LiveProgressDisplay,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.interfaces import IConverter, IReporter, IScanner

# Define valid execution phases
from automated_security_helper.config.ash_config import (
    AshConfig,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.metrics_alignment import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.utils.log import ASH_LOGGER


class ScanExecutionEngine:
    """Manages the execution of security scanners."""

    def __init__(
        self,
        context: PluginContext,
        # enabled_scanners is the list of scanner names that were explicitly passed
        # in from the Orchestrator. This allows ASH users to specify the scanners via CLI
        # at runtime for a more focused scan (e.g. during finding remediation where
        # there is only a single scanner failing, isolating scans to just that
        # scanner will allow quicker retesting until passing and a full scan can be )
        enabled_scanners: List[str] = [],
        # excluded_scanners is the list of scanner names that should be excluded from running
        # This takes precedence over enabled_scanners
        excluded_scanners: List[str] = [],
        strategy: Optional[ExecutionStrategy] = ExecutionStrategy.PARALLEL,
        asharp_model: Optional[AshAggregatedResults] = None,
        show_progress: bool = True,
        global_ignore_paths: List[IgnorePathWithReason] = [],
        color_system: Literal[
            "auto", "standard", "256", "truecolor", "windows"
        ] = "auto",
        verbose: bool = False,
        debug: bool = False,
        python_based_plugins_only: bool = False,
        simple_mode: bool = False,
        ash_plugin_modules: List[str] = [],
    ):
        """Initialize the execution engine.

        Args:
            enabled_scanners: List of scanner names to enable. If None, all scanners are enabled.
                If empty list, no scanners are enabled.
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
            asharp_model: Optional AshAggregatedResults to use for results
            show_progress: Whether to show progress bars
            global_ignore_paths: List of paths to ignore globally
            color_system: Color system to use for progress display
            verbose: Whether to show verbose output
            debug: Whether to show debug output
            discover_external_plugins: Whether to discover external plugins
            color_system: Color system to use for the console
            verbose: Enable verbose logging
            debug: Enable debug logging
        """
        # Set up logging and initial state
        ASH_LOGGER.debug("Initializing ScanExecutionEngine")
        if context is None:
            raise ValueError("Context must be provided")

        self._asharp_model = (
            asharp_model
            if asharp_model is not None
            else AshAggregatedResults(
                name=f"ASH Scan {datetime.now().isoformat()}",
                description="Aggregated security scan results",
                ash_config=context.config,
            )
        )
        self._context = context
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
        self._init_excluded_scanners = [
            subitem.strip()
            for item in excluded_scanners
            if item is not None
            for subitem in item.split(",")
        ]
        self._enabled_scanners = []

        ASH_LOGGER.debug(f"Raw enabled_scanners: {enabled_scanners}")
        ASH_LOGGER.debug(
            f"Processed _init_enabled_scanners: {self._init_enabled_scanners}"
        )
        ASH_LOGGER.debug(f"Raw excluded_scanners: {excluded_scanners}")
        ASH_LOGGER.debug(
            f"Processed _init_excluded_scanners: {self._init_excluded_scanners}"
        )
        self._global_ignore_paths = global_ignore_paths
        self._python_only = (
            python_based_plugins_only  # Store the python_based_plugins_only flag
        )
        self._simple_mode = simple_mode  # Store the simple_mode flag

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

        # Discover external plugins if enabled
        ash_plugin_manager.set_context(self._context)

        # Load internal plugins first to ensure event handlers are registered
        from automated_security_helper.plugins.loader import load_internal_plugins

        load_internal_plugins()

        # Combine plugin modules from config and CLI parameters
        config_plugin_modules = (
            getattr(self._context.config, "ash_plugin_modules", [])
            if self._context.config
            and hasattr(self._context.config, "ash_plugin_modules")
            else []
        )

        # CLI parameters take precedence over config
        # evaluate ash_plugin_modules, split any entries with commas into separate items and trim surrounding whitespace
        config_plugin_modules = [
            subitem.strip()
            for item in config_plugin_modules
            if item is not None
            for subitem in item.split(", ")
        ]
        combined_plugin_modules = list(set(ash_plugin_modules + config_plugin_modules))

        if len(combined_plugin_modules) > 0:
            ASH_LOGGER.info(f"Loading plugin modules: {combined_plugin_modules}")

            # Import additional plugin modules
            from automated_security_helper.plugins.loader import (
                load_additional_plugin_modules,
            )

            load_additional_plugin_modules(combined_plugin_modules)

            # Discover plugins from specified modules
            discover_plugins(plugin_modules=combined_plugin_modules)
        # Config can override environment
        if self._context.config:
            if (
                hasattr(self._context.config, "debug")
                and self._context.config.debug is not None
            ):
                debug_flag = self._context.config.debug
            if (
                hasattr(self._context.config, "verbose")
                and self._context.config.verbose is not None
            ):
                verbose_flag = self._context.config.verbose

        # Initialize progress display with debug/verbose flags
        self.progress_display = LiveProgressDisplay(
            show_progress=show_progress,
            color_system=(
                "windows" if platform.system() == "Windows" else color_system
            ),
            verbose=verbose_flag,
            debug=debug_flag,
        )

        # Phase tracking
        self.current_phase = None
        self.phase_tasks = {
            ExecutionPhase.CONVERT: None,
            ExecutionPhase.SCAN: None,
            ExecutionPhase.REPORT: None,
            ExecutionPhase.INSPECT: None,
        }

        # Initialize basic configuration

        # Convert and set up paths
        self._context.source_dir = (
            Path(self._context.source_dir) if self._context.source_dir else None
        )
        try:
            # Log directory setup
            ASH_LOGGER.debug(f"Source directory: {self._context.source_dir}")
            ASH_LOGGER.debug(f"Output directory: {self._context.output_dir}")
            ASH_LOGGER.debug(f"Work directory: {self._context.work_dir}")

        except Exception as e:
            ASH_LOGGER.error(f"Failed to setup directories: {e}")
            raise

        # Initialize base components
        self._completed_scanners = []
        self._results = self._asharp_model
        self._progress = None
        self._max_workers = min(32, (os.cpu_count() or 1 + 4))

        # Register custom scanners from configuration
        self._register_custom_scanners()

        # Initialize scanner components
        self._scanners = {}
        self._registered_scanners = {}
        self._initialized = False

        # Get all scanner plugins
        self.plugins = {
            "converter": ash_plugin_manager.plugin_modules(IConverter),
            "scanner": ash_plugin_manager.plugin_modules(IScanner),
            "reporter": ash_plugin_manager.plugin_modules(IReporter),
        }
        for k, v in self.plugins.items():
            ASH_LOGGER.verbose(f"Discovered {len(v)} {k} plugins at runtime")

        self.ensure_initialized(self._context.config)

    def _register_custom_scanners(self):
        """Register custom scanners from configuration."""
        if not self._context.config:
            return

        # Register custom scanners from build configuration
        # for scanner_config in self._context.config.build.custom_scanners:
        #     try:
        #         from automated_security_helper.plugin_modules.ash_builtin.scanners.custom_scanner import (
        #             CustomScanner,
        #         )

        #         # Create and register the custom scanner
        #         custom_scanner = CustomScanner(
        #             config=scanner_config, context=self._context
        #         )

        #         # Register with plugin manager
        #         ash_plugin_manager.register_plugin_module(
        #             "scanner",
        #             custom_scanner.__class__,
        #             f"automated_security_helper.scanners.custom.{scanner_config.name}",
        #         )

        #         ASH_LOGGER.debug(f"Registered custom scanner: {scanner_config.name}")
        #     except Exception as e:
        #         ASH_LOGGER.error(f"Failed to register custom scanner: {e}")

    def get_scanner(
        self, scanner_name: str, check_enabled: bool = True
    ) -> ScannerPluginBase:
        """Get a scanner instance by name.

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
            raise ValueError("Scanner name cannot be empty")

        # Get all scanner plugins
        scanner_plugins = self.plugins.get("scanner", [])

        # Find the scanner by name
        for scanner_class in scanner_plugins:
            scanner_class_name = getattr(scanner_class, "__name__", "Unknown").lower()
            if scanner_class_name == lookup_name:
                # Create and return the scanner instance
                scanner = scanner_class(
                    context=self._context,
                    config=(
                        self._context.config.get_plugin_config(
                            plugin_type="scanner", plugin_name=lookup_name
                        )
                        if self._context.config
                        else None
                    ),
                )
                return scanner

        # If we get here, the scanner wasn't found
        raise ValueError(f"Scanner {lookup_name} not found")

    def ensure_initialized(self, config: Optional[AshConfig] = None) -> None:
        """Ensure scanner factory and scanners are properly initialized.

        Args:
            config: ASH configuration object for initialization
        """
        if not self._initialized or (
            self._context.config is None and config is not None
        ):
            ASH_LOGGER.info("Initializing execution engine")
            if config is not None:
                self._context.config = config
            if not self._context.config or self._context.config is None:
                self._context.config = AshConfig(
                    project_name="ASH Default Project Config",
                )
            if not isinstance(self._context.config, AshConfig):
                raise ValueError("Configuration must be an AshConfig instance")

            # Process excluded scanners - this takes precedence over enabled scanners
            if self._init_excluded_scanners:
                ASH_LOGGER.info(f"Excluding scanners: {self._init_excluded_scanners}")
                # If we have both enabled and excluded scanners, we need to filter the enabled list
                if self._init_enabled_scanners:
                    self._init_enabled_scanners = [
                        scanner
                        for scanner in self._init_enabled_scanners
                        if scanner.lower()
                        not in [s.lower() for s in self._init_excluded_scanners]
                    ]

            # Mark initialization complete
            self._initialized = True

    def execute_phases(
        self,
        phases: List[ExecutionPhaseType] = ["convert", "scan", "report"],
    ) -> AshAggregatedResults:
        """Execute the specified phases in the correct order.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].
            config (Optional[AshConfig], optional): An override configuration to be
                provided at the start of execution.
                Defaults to None.

        Returns:
            AshAggregatedResults: The results of the scan.
        """
        ASH_LOGGER.debug(f"Entering: ScanExecutionEngine.execute_phases({phases})")

        # Always execute phases in the correct order, regardless of input order
        ordered_phases = []
        if "convert" in phases:
            ordered_phases.append("convert")
        if "scan" in phases:
            ordered_phases.append("scan")
        if "report" in phases:
            ordered_phases.append("report")
        if "inspect" in phases:
            ordered_phases.append("inspect")

        ASH_LOGGER.info(f"Executing phases: {ordered_phases}")

        # Log a message to show progress is happening
        ASH_LOGGER.info("===== ASH Security Scan Starting =====")
        ASH_LOGGER.info(f"Executing phases: {', '.join(ordered_phases)}")

        # Record the start time for calculating scan duration
        scan_start_time = datetime.now(timezone.utc)
        # Start the progress display before executing any phases
        # Only start if it's not already started
        if (
            not hasattr(self.progress_display, "live")
            or self.progress_display.live is None
        ):
            self.progress_display.start()

        # If we're only running the report phase (likely with existing results),
        # we don't need to set up the work directory or clean anything up
        report_only = len(ordered_phases) in [1, 2] and ordered_phases[0] == "report"

        # Only create directories if we're not in report-only mode
        if not report_only:
            # Ensure work directory exists
            if self._context.work_dir:
                self._context.work_dir.mkdir(parents=True, exist_ok=True)

        # Always ensure reports directory exists
        reports_dir = self._context.output_dir.joinpath("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Start the progress display before executing any phases
        self.progress_display.start()

        # Notify execution start
        try:
            from automated_security_helper.plugins.events import AshEventType
            from automated_security_helper.plugins import ash_plugin_manager

            ash_plugin_manager.notify(
                AshEventType.EXECUTION_START,
                phases=ordered_phases,
                plugin_context=self._context,
                source_dir=self._context.source_dir,
                output_dir=self._context.output_dir,
                enabled_scanners=self._init_enabled_scanners,
                excluded_scanners=self._init_excluded_scanners,
                python_based_plugins_only=self._python_only,
                strategy=self._strategy,
                message=f"Starting ASH execution with phases: {', '.join(ordered_phases)}",
            )
        except Exception as event_error:
            ASH_LOGGER.error(
                f"Failed to notify execution start event: {str(event_error)}"
            )

        try:
            # Execute each phase in order using the new phase classes
            self._results = self._asharp_model
            for phase_name in ordered_phases:
                ASH_LOGGER.info(f"\n----- Starting phase: {phase_name.upper()} -----")

                if phase_name == "convert":
                    # Create and execute the Convert phase
                    convert_phase = ConvertPhase(
                        plugins=ash_plugin_manager.plugin_modules(IConverter),
                        plugin_context=self._context,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )
                    self._results = convert_phase.execute(
                        aggregated_results=self._results,
                        python_based_plugins_only=self._python_only,
                    )

                elif phase_name == "scan":
                    # Create and execute the Scan phase
                    scan_phase = ScanPhase(
                        plugins=ash_plugin_manager.plugin_modules(IScanner),
                        plugin_context=self._context,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )

                    self._results = scan_phase.execute(
                        aggregated_results=self._results,
                        enabled_scanners=self._init_enabled_scanners,
                        excluded_scanners=self._init_excluded_scanners,
                        parallel=(self._strategy == ExecutionStrategy.PARALLEL),
                        max_workers=self._max_workers,
                        global_ignore_paths=self._global_ignore_paths,
                        python_based_plugins_only=self._python_only,  # Pass the python_based_plugins_only flag to the scan phase
                    )
                    # Store the completed scanners for metrics display
                    self._completed_scanners = scan_phase._completed_scanners
                    # ASH_LOGGER.verbose(
                    #     "self._results.scanner_results after scan_phase.execute(): ",
                    #     self._results.scanner_results,
                    # )
                    # ASH_LOGGER.verbose(
                    #     "self._asharp_model.scanner_results after scan_phase.execute(): ",
                    #     self._asharp_model.scanner_results,
                    # )

                elif phase_name == "report":
                    # Create and execute the Report phase
                    report_phase = ReportPhase(
                        plugins=ash_plugin_manager.plugin_modules(IReporter),
                        plugin_context=self._context,
                        progress_display=self.progress_display,
                        asharp_model=self._results,
                    )
                    # ASH_LOGGER.verbose(
                    #     "self._results.scanner_results before report_phase.execute(): ",
                    #     self._results.scanner_results,
                    # )
                    # ASH_LOGGER.verbose(
                    #     "self._asharp_model.scanner_results before report_phase.execute(): ",
                    #     self._asharp_model.scanner_results,
                    # )
                    self._results = report_phase.execute(
                        report_dir=self._context.output_dir.joinpath("reports"),
                        cli_output_formats=(
                            self._context.config.output_formats
                            if hasattr(self._context.config, "output_formats")
                            else None
                        ),
                        aggregated_results=self._results,
                        python_based_plugins_only=self._python_only,
                    )
                    self._asharp_model = self._results
                    # ASH_LOGGER.verbose(
                    #     "self._results.scanner_results after report_phase.execute(): ",
                    #     self._results.scanner_results,
                    # )
                    # ASH_LOGGER.verbose(
                    #     "self._asharp_model.scanner_results after report_phase.execute(): ",
                    #     self._asharp_model.scanner_results,
                    # )

                elif phase_name == "inspect":
                    # Create and execute the Inspect phase
                    inspect_phase = InspectPhase(
                        plugins=[],  # No plugin support for the Inspect phase at this time.
                        plugin_context=self._context,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )
                    self._results = inspect_phase.execute(
                        aggregated_results=self._results,
                        python_based_plugins_only=self._python_only,
                    )
                    self._asharp_model = self._results

        except Exception as e:
            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            ASH_LOGGER.info(f"\nExecution failed: {str(e)}")

            # Notify execution error
            try:
                from automated_security_helper.plugins.events import AshEventType
                from automated_security_helper.plugins import ash_plugin_manager

                ash_plugin_manager.notify(
                    AshEventType.ERROR,
                    phase="execution",
                    error=str(e),
                    exception=e,
                    message=f"ASH execution failed: {str(e)}",
                )
            except Exception as event_error:
                ASH_LOGGER.error(
                    f"Failed to notify execution error event: {str(event_error)}"
                )

            raise
        finally:
            # Notify execution complete (whether successful or not)
            try:
                from automated_security_helper.plugins.events import AshEventType
                from automated_security_helper.plugins import ash_plugin_manager

                scan_end_time = datetime.now(timezone.utc)
                scan_duration = (scan_end_time - scan_start_time).total_seconds()
                minutes, seconds = divmod(int(scan_duration), 60)
                hours, minutes = divmod(minutes, 60)

                self._results.metadata.summary_stats.start = scan_start_time
                self._results.metadata.summary_stats.end = scan_end_time
                self._results.metadata.summary_stats.duration = scan_duration

                ash_plugin_manager.notify(
                    AshEventType.EXECUTION_COMPLETE,
                    phases=ordered_phases,
                    results=self._results,
                    duration=scan_duration,
                    completed_scanners=getattr(self, "_completed_scanners", []),
                    message=f"ASH execution completed in {scan_duration:.1f}s",
                )
            except Exception as event_error:
                ASH_LOGGER.error(
                    f"Failed to notify execution complete event: {str(event_error)}"
                )
            finally:
                # Stop progress display
                if (
                    hasattr(self.progress_display, "live")
                    and self.progress_display.live
                ):
                    self.progress_display.stop()

                # Display the final metrics table
                if not self._simple_mode:
                    if hours > 0:
                        duration_str = f"{hours}h {minutes}m {seconds}s"
                    elif minutes > 0:
                        duration_str = f"{minutes}m {seconds}s"
                    else:
                        duration_str = f"{seconds}s"

                    ASH_LOGGER.info(
                        f"===== ASH Security Scan Completed in {duration_str} ====="
                    )

                if self._asharp_model:
                    # Populate final metrics before displaying the table
                    # This ensures the metrics table shows the correct aligned data
                    updated_asharp_model = populate_metrics_from_unified_source(
                        aggregated_results=self._asharp_model
                    )
                    self._asharp_model = updated_asharp_model
                    # self._asharp_model._populate_final_metrics()

                    # Get color setting from progress display
                    use_color = True
                    if hasattr(self.progress_display, "console") and hasattr(
                        self.progress_display.console, "color_system"
                    ):
                        use_color = (
                            self.progress_display.console.color_system is not None
                        )

                    # Always display the metrics table, even in simple mode
                    display_metrics_table(
                        asharp_model=self._asharp_model,
                        source_dir=os.environ.get(
                            "ASH_ACTUAL_SOURCE_DIR", self._context.source_dir.as_posix()
                        ),
                        output_dir=os.environ.get(
                            "ASH_ACTUAL_OUTPUT_DIR", self._context.output_dir.as_posix()
                        ),
                        use_color=use_color,
                    )

                # Return the results
                return self._results
