"""Execution engine for security scanners."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.progress import Progress

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.config.ash_config import (
    ASHConfig,
)
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.asharp_serializer import ASHARPModelSerializer
from automated_security_helper.core.scanner_factory import ScannerFactory
from automated_security_helper.base.scanner_plugin import ScannerPlugin
from automated_security_helper.base.scanner import (
    ScannerBaseConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


class ExecutionStrategy(Enum):
    """Strategy for executing scanners."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


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
        # enabled_scanners is the list of scanner names that were explicitly passed
        # in from the Orchestrator. This allows ASH users to specify the scanners via CLI
        # at runtime for a more focused scan (e.g. during finding remediation where
        # there is only a single scanner failing, isolating scans to just that scanner will allow quicker retesting until passing and a full scan can be )
        enabled_scanners: Optional[List[str]] = None,
        strategy: Optional[ExecutionStrategy] = ExecutionStrategy.PARALLEL,
        asharp_model: Optional[ASHARPModel] = None,
        config: Optional[ASHConfig] = None,
    ):
        """Initialize the execution engine.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for scan results
            enabled_scanners: List of scanner names to enable. If None, all scanners are enabled.
                If empty list, no scanners are enabled.
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
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
        self._initialized = False  # Track initialization state
        # self._enabled_scanners = enabled_scanners  # None means all enabled

        # Initialize basic configuration

        # Convert and set up paths
        self.source_dir = Path(source_dir) if source_dir else None
        try:
            # Convert and validate source directory

            # Convert and validate output directory
            if output_dir:
                self.output_dir = Path(output_dir)
                self.work_dir = self.output_dir / "work"
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
        self._scanner_factory = ScannerFactory(
            config=config,
        )

        self._registered_scanners = {}
        enabled_from_config = []
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
                    f"Scanner {key} is enabled, adding to enabled scanner list"
                )
                enabled_from_config.append(key)

        # Normalize and store enabled scanner names
        self._enabled_scanners = sorted(
            set(
                [
                    s.lower().strip()
                    for s in enabled_from_config
                    if isinstance(s, str)
                    and (
                        len(enabled_scanners) == 0
                        or s.lower().strip() in enabled_scanners
                    )
                ]
            )
        )
        registered_names = sorted(set(self._registered_scanners.keys()))
        ASH_LOGGER.info(f"Registered scanners: {registered_names}")
        ASH_LOGGER.info(f"Enabled scanners: {self._enabled_scanners}")

        # Mark initialization as complete
        self._initialized = True

    def get_scanner(
        self, scanner_name: str, check_enabled: bool = True
    ) -> ScannerPlugin:
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
        if not self._initialized:
            self.ensure_initialized()

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

        #     # Scanner is considered enabled if:
        #     # 1. Empty enabled list and scanner is registered
        #     # 2. Non-empty enabled list and scanner or its base name is in it
        #     if len(self._enabled_scanners) == 0:
        #         enabled = lookup_name in self._scanners or (
        #             base_name and base_name in self._scanners
        #         )
        #     else:
        #         enabled = lookup_name in self._enabled_scanners or (
        #             base_name and base_name in self._enabled_scanners
        #         )

        #     if not enabled:
        #         msg = (
        #             "No scanners enabled"
        #             if len(self._enabled_scanners) == 0
        #             else f"Scanner {scanner_name} not enabled"
        #         )
        #         ASH_LOGGER.warning(msg)
        #         # raise ValueError(msg)

        # # Prepare name variations to try
        # names_to_try = [lookup_name]

        # # Add base name without 'scanner' suffix to try
        # if lookup_name.endswith("scanner"):
        #     base_name = lookup_name[:-7].strip()
        #     if base_name:
        #         names_to_try.append(base_name)

        # # Try each possible name
        # for name in names_to_try:
        #     # Check registered scanners
        #     if name in self._scanners:
        #         scanner_fn = self._scanners[name]
        #         try:
        #             scanner = scanner_fn(
        #                 source_dir=self.source_dir,
        #                 output_dir=self.output_dir,
        #                 logger=ASH_LOGGER,
        #             )
        #             return scanner
        #         except (TypeError, ValueError):
        #             # If that fails, try without paths
        #             return scanner_fn()

        #     # Fall back to factory if not already registered
        # for fallback_name in names_to_try:
        #     if fallback_name in self._scanner_factory._scanners:
        #         scanner_class = self._scanner_factory._scanners[fallback_name]
        #         try:
        #             self.register_scanner(fallback_name, scanner_class)
        #             scanner_fn = self._scanners[fallback_name]
        #             return scanner_fn(
        #                 source_dir=self.source_dir,
        #                 output_dir=self.output_dir,
        #                 logger=ASH_LOGGER,
        #             )
        #         except Exception as e:
        #             ASH_LOGGER.warning(
        #                 f"Failed to register scanner {fallback_name} from factory: {str(e)}"
        #             )
        #             continue

        # raise ValueError(f"Scanner '{scanner_name}' not registered")

    def ensure_initialized(self, config: Optional[ASHConfig] = None) -> None:
        """Ensure scanner factory and scanners are properly initialized.

        This method:
        1. Registers and enables all default scanners from factory
        2. Processes config if provided to override scanner settings
        3. Maintains all scanners enabled by default if no explicit config

        Args:
            config: ASH configuration object for initialization
        """
        if not self._initialized:
            ASH_LOGGER.info("Initializing execution engine")

            # Add any necessary initialization code here (placeholder method)

            # Mark initialization complete
            self._initialized = True

    def execute(self, config: Optional[ASHConfig] = None, **kwargs) -> ASHARPModel:
        """Execute registered scanners based on provided configuration.

        Args:
            config: ASHConfig instance containing scanner configuration in sast/sbom sections
            **kwargs: Additional execution parameters. Supports:
                - mode: ExecutionStrategy value to override execution mode

        Returns:
            Dict[str, Any]: Results dictionary with scanner results and ASHARPModel

        Raises:
            ValueError: If config is invalid or mode is invalid
            RuntimeError: If scanner execution fails critically
        """
        ASH_LOGGER.debug("Entering: ScanExecutionEngine.execute()")
        if config is not None:
            self._config = config
        if not self._config:
            ASH_LOGGER.debug(
                "!!! NO CONFIGURATION RESOLVED BEFORE ENGINE.EXECUTE(), USING DEFAULT ASHCONFIG !!!"
            )
            self._config = ASHConfig(
                project_name="ASH Default Project Config",
            )
        if not isinstance(self._config, ASHConfig):
            raise ValueError("Configuration must be an ASHConfig instance")

        # Reset state for new execution
        self._completed_scanners = []
        self._queue = multiprocessing.Queue()
        self._scan_results = {}

        # Execute scanners based on mode
        enabled_scanners = set()
        try:
            # Build queue of scanner tuples for execution
            self._queue = multiprocessing.Queue()

            # Get all enabled scanners from SAST and SBOM configurations using helper
            scanner_configs = self._scanner_factory.available_scanners()

            # Process SAST and SBOM scanners
            if scanner_configs:
                for scanner_name, scanner_config in scanner_configs.items():
                    if scanner_config:
                        # Add scanner to execution queue with default target
                        self._queue.put(
                            (scanner_name, scanner_config(), self.source_dir, "source")
                        )
                        self._queue.put(
                            (scanner_name, scanner_config(), self.work_dir, "temp")
                        )
                        enabled_scanners.add(scanner_name)

            # Initialize progress tracker for execution
            with Progress(
                auto_refresh=True,
            ) as progress:
                self._progress = ScanProgress(len(enabled_scanners))

                # Execute scanners based on mode
                if self._strategy == ExecutionStrategy.PARALLEL:
                    out = self._execute_parallel(progress=progress)
                else:
                    out = self._execute_sequential(progress=progress)
                ASH_LOGGER.debug(f"Execution completed: {out}")

                # Save ASHARPModel as JSON alongside results if output_dir is configured
                output_dir = getattr(self._config, "output_dir", None)
                if output_dir:
                    output_path = Path(output_dir)
                    ASHARPModelSerializer.save_model(self._asharp_model, output_path)

            return self._asharp_model

        except Exception as e:
            ASH_LOGGER.error(f"Execution failed: {str(e)}")
            raise

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPlugin,
        scan_target: Path,
        target_type: str | None = None,
    ) -> ScanResultsContainer:
        """Execute a single scanner and process its results.

        Args:
            scanner_tuple: Tuple containing (scanner_name, target)

        Returns:
            ScanResultsContainer: Dictionary containing SecurityReport and raw results

        Raises:
            ScannerError: If scanner execution fails


        """
        try:
            config_overridden = False
            scanner_config = scanner_plugin.config
            ASH_LOGGER.debug("EVALUATING CONFIGURED SCANNERS")
            scanner_config_override: ScannerBaseConfig = (
                self._config.scanners.model_dump().get(scanner_name, None)
            )
            if scanner_config_override is not None:
                if hasattr(scanner_config_override, "model_dump") and callable(
                    scanner_config_override.model_dump
                ):
                    scanner_config_override = scanner_config_override.model_dump()

                ASH_LOGGER.debug(f"scanner_name: {scanner_name}")
                ASH_LOGGER.debug(f"scanner_config: {scanner_config}")
                ASH_LOGGER.debug(f"scanner_config_override: {scanner_config_override}")

                if scanner_config_override.get("enabled", None) is not None:
                    setattr(
                        scanner_config,
                        "enabled",
                        scanner_config_override.get("enabled"),
                    )
                    config_overridden = True
                for key, val in scanner_config_override.get("options", {}).items():
                    setattr(scanner_config, key, val)
                    config_overridden = True

            ASH_LOGGER.debug(f"scanner_name: {scanner_name}")
            ASH_LOGGER.debug(f"scanner_config overridden: {config_overridden}")

            container = ScanResultsContainer(
                scanner_name=scanner_config.name,
                target=scan_target,
                target_type=target_type,
            )
            if not scanner_config.enabled:
                ASH_LOGGER.warning(f"{scanner_config.name}")

            # Execute scan
            ASH_LOGGER.debug(
                f"Executing {scanner_config.name or scanner_plugin.__class__.__name__}.scan()"
            )
            try:
                raw_results = scanner_plugin.scan(
                    target=scan_target,
                    config=scanner_config,
                )
            except Exception as e:
                ASH_LOGGER.error(
                    f"Failed to execute {scanner_config.name or scanner_plugin.__class__.__name__} scanner: {e}"
                )
                raw_results = {"error": str(e)}
            finally:
                # ASH_LOGGER.debug(
                #     f"{scanner_plugin.__class__.__name__} raw_results: {raw_results}"
                # )
                container.raw_results = raw_results

                if raw_results is not None:
                    # Extract and add metadata if present
                    if "metadata" in raw_results:
                        for key, value in raw_results["metadata"].items():
                            container.add_metadata(key, value)

                ASH_LOGGER.debug("Executing engine.progress.increment()")
                if self._progress:
                    self._progress.increment()

                ASH_LOGGER.debug(
                    f"Appending {scanner_plugin.__class__.__name__} to engine.completed_scanners"
                )
                self._completed_scanners.append(scanner_plugin)

                return container

        except Exception as e:
            ASH_LOGGER.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}"
            )
            raise

    def _execute_sequential(self, progress: Progress) -> None:
        """Execute scanners sequentially and update ASHARPModel."""
        while not self._queue.empty():
            scanner_tuple = self._queue.get()

            scanner_name = scanner_tuple[0]
            scanner_plugin = scanner_tuple[1]
            scan_target = scanner_tuple[2]
            target_type = scanner_tuple[3]

            task = progress.add_task(
                f"[cyan]({scanner_name}) Scanning {target_type} dir...", total=100
            )

            results = self._execute_scanner(
                scanner_name=scanner_name,
                scanner_plugin=scanner_plugin,
                scan_target=scan_target,
                target_type=target_type,
            )
            self._process_results(results)
            progress.update(task, completed=100)
            if self._progress:
                self._progress.increment()

    def _execute_parallel(self, progress: Progress) -> None:
        """Execute scanners in parallel and update ASHARPModel."""
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            tasks = {}
            # Submit all scanners to the thread pool
            while not self._queue.empty():
                ASH_LOGGER.debug("Getting scanners from queue")
                scanner_tuple = self._queue.get()

                scanner_name = scanner_tuple[0]
                scanner_plugin = scanner_tuple[1]
                scan_target = scanner_tuple[2]
                target_type = scanner_tuple[3]

                if scanner_name not in tasks:
                    tasks[scanner_name] = {}
                tasks[scanner_name][Path(scan_target).as_posix()] = progress.add_task(
                    f"[magenta]({scanner_name}) Scanning {target_type} directory...",
                    total=100,
                )

                ASH_LOGGER.debug(
                    f"Submitting {scanner_name} to thread pool to scan target: {scan_target}"
                )
                future = executor.submit(
                    self._execute_scanner,
                    scanner_name,
                    scanner_plugin,
                    scan_target,
                    target_type,
                )
                ASH_LOGGER.debug(f"Submitted {scanner_name} to thread pool")
                futures.append(future)
                ASH_LOGGER.debug(f"Appended {scanner_name} to futures")

            # Wait for all futures to complete and handle any exceptions
            for future in as_completed(futures):
                try:
                    ASH_LOGGER.debug("Getting results from completed future")
                    results: ScanResultsContainer | None = future.result()
                    ASH_LOGGER.debug("Got results from completed future, processing")
                    self._process_results(results)

                    task_scan_target = Path(results.target).as_posix()

                    task = tasks.get(results.scanner_name, {}).get(
                        task_scan_target, None
                    )
                    if task is not None:
                        progress.update(task, completed=100)

                    if self._progress:
                        self._progress.increment()
                except Exception as e:
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
            self._asharp_model.sbom = results.raw_results
        else:
            self._asharp_model.additional_reports[results.scanner_name] = (
                results.raw_results
            )

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
    def completed_scanners(self) -> List[ScannerPlugin]:
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
                if isinstance(config, ScannerBaseConfig):
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
                if isinstance(config, ScannerBaseConfig):
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
                if isinstance(config, ScannerBaseConfig):
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
                if isinstance(config, ScannerBaseConfig):
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
