"""Execution engine for security scanners."""

import multiprocessing
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional


from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.metrics_table import display_metrics_table
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.progress import (
    ExecutionPhase,
    ExecutionPhaseType,
    ExecutionStrategy,
    LiveProgressDisplay,
)
from automated_security_helper.core.plugin_registry import PluginRegistry, PluginType
from automated_security_helper.models.core import IgnorePathWithReason

# Define valid execution phases
from automated_security_helper.config.ash_config import (
    ASHConfig,
)
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.core.scanner_factory import ScannerFactory
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.utils.log import ASH_LOGGER


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
                    self.work_dir = self.output_dir.joinpath("converted")
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
        self._results = self._asharp_model
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
            plugin_context=PluginContext(
                source_dir=self.source_dir,
                output_dir=self.output_dir,
                work_dir=self.work_dir,
            ),
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            registered_scanner_plugins=self._plugin_registry.get_plugin(
                plugin_type=PluginType.scanner
            ),
        )

        self.ensure_initialized(config=config)

        self._registered_scanners = {}
        self._enabled_from_config = []
        for key, val in self._scanner_factory.available_scanners().items():
            val_instance = val(
                config=(
                    self._config.get_plugin_config(
                        plugin_type=PluginType.scanner, plugin_name=key
                    )
                    if self._config is not None
                    else None
                ),
                context=PluginContext(
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                    work_dir=self.work_dir,
                ),
                source_dir=self.source_dir,
                output_dir=self.output_dir,
            )
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
        ASH_LOGGER.info("===== ASH Security Scan Starting =====")
        ASH_LOGGER.info(f"Executing phases: {', '.join(ordered_phases)}")

        # Start the progress display before executing any phases
        # Only start if it's not already started
        if (
            not hasattr(self.progress_display, "live")
            or self.progress_display.live is None
        ):
            self.progress_display.start()

        # If we're only running the report phase (likely with existing results),
        # we don't need to set up the work directory or clean anything up
        report_only = len(ordered_phases) == 1 and ordered_phases[0] == "report"

        # Only create directories if we're not in report-only mode
        if not report_only:
            # Ensure work directory exists
            if self.work_dir:
                self.work_dir.mkdir(parents=True, exist_ok=True)

            # Clean up existing directories if needed
            for working_dir in ["scanners", "converted"]:
                path_working_dir = self.output_dir.joinpath(working_dir)
                if path_working_dir.exists():
                    ASH_LOGGER.verbose(
                        f"Cleaning up working directory from previous run: {path_working_dir.as_posix()}"
                    )
                    shutil.rmtree(path_working_dir)
                path_working_dir.mkdir(parents=True, exist_ok=True)

        # Always ensure reports directory exists
        reports_dir = self.output_dir.joinpath("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Start the progress display before executing any phases
        self.progress_display.start()

        try:
            # Execute each phase in order using the new phase classes
            for phase_name in ordered_phases:
                ASH_LOGGER.info(f"\n----- Starting phase: {phase_name.upper()} -----")

                if phase_name == "convert":
                    # Create and execute the Convert phase
                    convert_phase = ConvertPhase(
                        source_dir=self.source_dir,
                        output_dir=self.output_dir,
                        work_dir=self.work_dir,
                        config=self._config,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )
                    convert_phase.execute(plugin_registry=self._plugin_registry)

                elif phase_name == "scan":
                    # Create and execute the Scan phase
                    scan_phase = ScanPhase(
                        source_dir=self.source_dir,
                        output_dir=self.output_dir,
                        work_dir=self.work_dir,
                        config=self._config,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )
                    self._results = scan_phase.execute(
                        scanner_factory=self._scanner_factory,
                        plugin_registry=self._plugin_registry,
                        enabled_scanners=self._init_enabled_scanners,
                        parallel=(self._strategy == ExecutionStrategy.PARALLEL),
                        max_workers=self._max_workers,
                        global_ignore_paths=self._global_ignore_paths,
                    )
                    # Store the completed scanners for metrics display
                    self._completed_scanners = scan_phase._completed_scanners

                elif phase_name == "report":
                    # Create and execute the Report phase
                    report_phase = ReportPhase(
                        source_dir=self.source_dir,
                        output_dir=self.output_dir,
                        work_dir=self.work_dir,
                        config=config or self._config,
                        progress_display=self.progress_display,
                        asharp_model=self._asharp_model,
                    )
                    report_phase.execute(
                        report_dir=self.output_dir.joinpath("reports"),
                        plugin_registry=self._plugin_registry,
                        cli_output_formats=(
                            self._config.output_formats
                            if hasattr(self._config, "output_formats")
                            else None
                        ),
                    )

            # Return the results
            return self._results

        except Exception as e:
            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            ASH_LOGGER.info(f"\n❌ Execution failed: {str(e)}")
            raise
        finally:
            if hasattr(self.progress_display, "live") and self.progress_display.live:
                self.progress_display.stop()

            # Display the final metrics table
            ASH_LOGGER.info("===== ASH Security Scan Complete =====")
            if self._completed_scanners:
                # Get color setting from progress display
                use_color = True
                if hasattr(self.progress_display, "console") and hasattr(
                    self.progress_display.console, "color_system"
                ):
                    use_color = self.progress_display.console.color_system is not None

                display_metrics_table(
                    completed_scanners=self._completed_scanners,
                    asharp_model=self._asharp_model,
                    scan_results=self._scan_results,
                    use_color=use_color,
                )

        return ASHARPModel(description="No results generated")

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of worker threads for parallel execution."""
        self._max_workers = workers
