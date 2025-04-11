"""Execution engine for security scanners."""

import json
import logging
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

from automated_security_helper.models.scan_results import ScanResultsContainer
from automated_security_helper.config.config import (
    ASHConfig,
    SASTScannerConfig,
    SASTScannerListConfig,
    SBOMScannerConfig,
    SBOMScannerListConfig,
)
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.json_serializer import ASHARPModelSerializer
from automated_security_helper.core.scanner_factory import ScannerFactory
from automated_security_helper.models.scanner_plugin import ScannerPlugin
from automated_security_helper.models.core import (
    ScannerBaseConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER as logger, get_logger


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
        config: Optional[ASHConfig] = None,
        logger: Optional[logging.Logger] = get_logger(),
    ):
        """Initialize the execution engine.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for scan results
            enabled_scanners: List of scanner names to enable. If None, all scanners are enabled.
                If empty list, no scanners are enabled.
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
            logger: Logger instance to use for logging
        """
        # Set up logging and initial state
        self.logger = logger
        self._config = config
        self._scanners = {}
        self._scan_results = {}
        self._enabled_scanners = enabled_scanners  # None means all enabled
        self.logger.info("Initializing ScanExecutionEngine")

        # Initialize basic configuration
        self._scan_results = {}
        self._strategy = strategy
        self._initialized = False  # Track initialization state

        # Normalize and store enabled scanner names
        self._enabled_scanners = {
            s.lower().strip() for s in (enabled_scanners or set())
        }

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
            self.logger.debug(f"Source directory: {self.source_dir}")
            self.logger.debug(f"Output directory: {self.output_dir}")
            self.logger.debug(f"Work directory: {self.work_dir}")

        except Exception as e:
            self.logger.error(f"Failed to setup directories: {e}")
            raise

        # Initialize base components
        self._completed_scanners = []
        self._results = {"scanners": {}}
        self._progress = None
        self._max_workers = min(4, multiprocessing.cpu_count())

        # Initialize scanner components
        self._scanners = {}  # Maps scanner names to factory functions
        self._initialized = False  # Track initialization state
        self._scanner_factory = ScannerFactory(
            config=config,
            logger=logger,
        )

        # # Initialize all scanners
        # self._register_default_scanners()

        # # Enable all scanners by default if no specific ones requested
        # if not self._enabled_scanners:
        #     self._enabled_scanners = [
        #         k.lower().strip() for k in self._scanner_factory._scanners.keys()
        #     ]

        # Log registration status
        # Log scanner registration status
        enabled = ", ".join(sorted(set(self._enabled_scanners)))
        registered = ", ".join(sorted(k for k in self._scanners.keys() if k.strip()))
        self.logger.info(f"Enabled scanners: {enabled}")
        self.logger.info(f"Registered scanners: {registered}")

        # Mark initialization as complete
        self._initialized = True

    # def _register_default_scanners(self) -> None:
    #     """Register all default scanners from the factory and enable them.

    #     This method:
    #     1. Initializes enabled_scanners set if needed
    #     2. Gets all available scanners from factory
    #     3. Registers each scanner with force=True to enable it
    #     4. Logs registration status for debugging

    #     By default, all registered scanners are enabled unless explicitly disabled via config.
    #     """
    #     self.logger.debug("Registering default scanners from factory")
    #     self.logger.info("Registering default scanners")

    #     # Initialize enabled scanners set if needed
    #     if self._enabled_scanners is None:
    #         self._enabled_scanners = set()
    #         self.logger.debug("Initialized enabled scanners set")

    #     # Initialize scanners dict if needed
    #     if not self._scanners:
    #         self._scanners = {}

    #     # First register all scanners in factory
    #     self._scanner_factory._register_default_scanners()

    #     # Normalize enabled scanner names if provided
    #     if self._enabled_scanners:
    #         enabled = set()
    #         for name in self._enabled_scanners:
    #             normalized = name.lower().strip()
    #             if "scanner" in normalized.lower():
    #                 normalized = normalized.split("scanner")[0].strip()
    #             enabled.add(normalized)
    #         self._enabled_scanners = enabled

    #     # Get initial set of scanners from factory
    #     registered = set()
    #     all_scanners = {}

    #     # Ensure factory has latest scanners registered
    #     self._scanner_factory._register_default_scanners()

    #     # Collect scanners from factory first
    #     for name, scanner in self._scanner_factory._scanners.items():
    #         normalized = name.lower().strip()
    #         all_scanners[normalized] = scanner
    #         # Also add base name if it's a scanner suffix
    #         if normalized.endswith("scanner"):
    #             base = normalized[:-7].strip()
    #             if base and base not in all_scanners:
    #                 all_scanners[base] = scanner

    #     # Add any missing default scanners
    #     for scanner_class in self._scanner_factory.default_scanners:
    #         if not hasattr(scanner_class, "_default_config"):
    #             self.logger.warning(
    #                 f"Scanner {scanner_class} missing _default_config (engine)"
    #             )
    #             continue

    #         config = scanner_class._default_config
    #         if not hasattr(config, "name") or not config.name:
    #             self.logger.warning(
    #                 f"Scanner {scanner_class.__name__} missing name in config"
    #             )
    #             continue

    #         scanner_name = config.name.lower().strip()
    #         if not scanner_name:
    #             continue

    #         if scanner_name not in all_scanners:
    #             all_scanners[scanner_name] = scanner_class

    #         # Also add base name variant
    #         if scanner_name.endswith("scanner"):
    #             base_name = scanner_name[:-7].strip()
    #             if base_name and base_name not in all_scanners:
    #                 all_scanners[base_name] = scanner_class

    #     # Register all scanners - filtering happens at usage time
    #     for name, scanner_class in all_scanners.items():
    #         try:
    #             # Force registration since this is initial setup
    #             self._scanners[name] = scanner_class
    #             registered.add(name)

    #             # Register base name variant
    #             if name.endswith("scanner"):
    #                 base = name[:-7].strip()
    #                 if base and base not in registered:
    #                     # Also force register base name variant
    #                     self._scanners[base] = scanner_class
    #                     registered.add(base)
    #         except Exception as e:
    #             self.logger.warning(f"Failed to register {name}: {str(e)}")

    #     # Log the registered scanners
    #     registered_names = ", ".join(sorted(registered))
    #     self.logger.info(f"Registered scanners: {registered_names}")

    #     # Log placeholders separately
    #     placeholders = [
    #         name
    #         for name, factory in self._scanners.items()
    #         if factory is None or not callable(factory)
    #     ]
    #     if placeholders:
    #         placeholder_names = ", ".join(sorted(placeholders))
    #         self.logger.info(
    #             f"Placeholder scanners (not implemented): {placeholder_names}"
    #         )

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
            self.logger.warning("Scanner name cannot be empty")

        # Ensure initialized and verify enabled status
        if not self._initialized:
            self.ensure_initialized()

        if check_enabled and lookup_name not in (self._enabled_scanners or set()):
            self.logger.warning(f"Scanner {lookup_name} is not enabled")

        # Create scanner using factory
        try:
            scanner = self._scanner_factory.create_scanner(
                scanner_name=lookup_name,
                source_dir=self.source_dir,
                output_dir=self.output_dir,
                logger=self.logger,
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
        #         self.logger.warning(msg)
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
        #                 logger=self.logger,
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
        #                 logger=self.logger,
        #             )
        #         except Exception as e:
        #             self.logger.warning(
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
            self.logger.info("Initializing execution engine")

            # Store config and set initial scanner state
            self._config = config
            self._enabled_scanners = None  # Default to all enabled

            # # Process scanners in order:
            # # 1. Register factory defaults (with force=True)
            # # 2. Process config overrides if present
            # # self._register_default_scanners()  # This registers with force=True

            # # Process config if provided to override default scanner settings
            # if config and hasattr(config, "sast") and hasattr(config.sast, "scanners"):
            #     # Switch to explicit enable list and process scanner configs
            #     self._enabled_scanners = set()
            #     for scanner in vars(config.sast.scanners).values():
            #         if not hasattr(scanner, "name"):
            #             continue

            #         name = scanner.name.lower().strip()
            #         enabled = getattr(scanner, "enabled", False)
            #         self.logger.debug(
            #             f"Processing scanner config: {name} (enabled={enabled})"
            #         )

            #         # Ensure scanner is registered
            #         if name not in self._scanners and self._scanner_factory:
            #             try:
            #                 scanner_class = self._scanner_factory.get_scanner_class(
            #                     name
            #                 )
            #                 if scanner_class:
            #                     self.register_scanner(name, scanner_class, force=True)
            #             except Exception as e:
            #                 self.logger.warning(
            #                     f"Failed to get scanner class for {name}: {e}"
            #                 )

            #         # Enable scanner if configured
            #         if enabled:
            #             self._enabled_scanners.add(name)
            #             # Also enable base name without 'scanner' suffix
            #             if name.endswith("scanner"):
            #                 base = name[:-7].strip()
            #                 if base:
            #                     self._enabled_scanners.add(base)

            # # If no explicit configuration, enable all registered scanners
            # if not self._enabled_scanners:
            #     self.logger.debug(
            #         "No explicit scanner configuration - enabling all registered scanners"
            #     )
            #     self._enabled_scanners = set()
            #     for scanner in vars(config.sast.scanners).values():
            #         if hasattr(scanner, "name"):
            #             name = scanner.name.lower().strip()

            #             # Register scanner (as placeholder if not implemented)
            #             self.register_scanner(name, None, force=True)

            #             # Also handle base name variant
            #             base_name = (
            #                 name[:-7].strip() if name.endswith("scanner") else ""
            #             )
            #             if base_name:
            #                 self.register_scanner(base_name, None, force=True)

            #             # Track enabled scanners
            #             if getattr(scanner, "enabled", False):
            #                 self._enabled_scanners.add(name)
            #                 if base_name:
            #                     self._enabled_scanners.add(base_name)

            # # If no scanners were explicitly enabled, enable all registered ones
            # if self._enabled_scanners is None:
            #     self._enabled_scanners = list(sorted(self._scanners.keys()))

            # Mark initialization complete
            self._initialized = True

    def execute(self, config: Optional[ASHConfig] = None, **kwargs) -> Dict[str, Any]:
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
        self.logger.debug("Entering: ScanExecutionEngine.execute()")
        if config:
            self._config = config
        if not self._config:
            self._config = ASHConfig(
                project_name="",
                sast=SASTScannerConfig(scanners=SASTScannerListConfig()),
                sbom=SBOMScannerConfig(scanners=SBOMScannerListConfig()),
            )
        if not isinstance(self._config, ASHConfig):
            raise ValueError("Configuration must be an ASHConfig instance")

        # Reset state for new execution
        self._completed_scanners = []
        self._queue = multiprocessing.Queue()
        self._scan_results = {}

        # Create ASHARPModel for this execution
        ash_model = ASHARPModel(
            name=f"ASH Scan {datetime.now().isoformat()}",
            description="Aggregated security scan results",
        )

        # Execute scanners based on mode
        enabled_scanners = set()
        try:
            # Build queue of scanner tuples for execution
            self._queue = multiprocessing.Queue()

            # Get all enabled scanners from SAST and SBOM configurations using helper
            scanner_configs = self._get_all_scanners()

            # Process SAST and SBOM scanners
            if scanner_configs:
                for scanner_name, scanner_config in scanner_configs.items():
                    scanner = self.get_scanner(scanner_name)
                    if scanner_config:
                        scanner.configure(scanner_config)
                        # Add scanner to execution queue with default target
                        self._queue.put((scanner_name, "."))
                        enabled_scanners.add(scanner_name)

            # Initialize progress tracker for execution
            self._progress = ScanProgress(len(enabled_scanners))

            # Execute scanners based on mode
            if self._strategy == ExecutionStrategy.PARALLEL:
                self._execute_parallel(ash_model)
            else:
                self._execute_sequential(ash_model)

            # Save ASHARPModel as JSON alongside results if output_dir is configured
            output_dir = getattr(self._config, "output_dir", None)
            if output_dir:
                output_path = Path(output_dir)
                ASHARPModelSerializer.save_model(ash_model, output_path)

                # Save aggregated results if not present
                results_file = output_path / "ash_aggregated_results.txt"
                if not results_file.exists():
                    with open(results_file, "w") as f:
                        json.dump(ash_model.model_dump(), f, indent=2, default=str)

            self._scan_results["asharp_model"] = ash_model
            return ash_model

        except Exception as e:
            self.logger.error(f"Execution failed: {str(e)}")
            raise

        # # Process registered scanners first
        # self.logger.debug("Processing registered scanners")
        # for scanner_name, scanner_class in registered_scanners.items():
        #     try:
        #         self.logger.debug(f"Processing registered scanner: {scanner_name}")
        #         # Get scanner config from class or instance
        #         if hasattr(scanner_class, "_default_config"):
        #             # Use class default config
        #             config = scanner_class._default_config
        #         else:
        #             # Create instance to get config
        #             scanner = scanner_class()
        #             config = scanner._config or ScannerPluginConfig(
        #                 name=scanner_name,
        #                 type=scanner_name,
        #                 command="",
        #                 invocation_mode="directory",
        #                 enabled=True,
        #             )

        #         # Ensure name matches registration
        #         config_dict = config.model_dump()
        #         config_dict["name"] = scanner_name
        #         config_dict["enabled"] = True

        #         enabled_scanners.append((scanner_name, config_dict))

        #     except Exception as e:
        #         self.logger.debug(
        #             f"Failed to get config for scanner {scanner_name}: {str(e)}"
        #         )

        # Process scanner configs from ASH config if provided
        # if config and hasattr(config, "sast") and config.sast and config.sast.scanners:
        #     scanner_configs = config.sast.scanners
        #     if not isinstance(scanner_configs, list):
        #         scanner_configs = [scanner_configs]

        #     # Clear any default configs
        #     enabled_scanners = []

        #     for scanner_config in scanner_configs:
        #         if not getattr(scanner_config, "enabled", True):
        #             continue

        #         # Get scanner type from config class name
        #         scanner_type = scanner_config.type
        #         scanner_name = scanner_config.name

        #         if "scanner" in scanner_type:
        #             scanner_type = scanner_type.split("scanner")[0]

        #         # Try to find scanner in factory
        #         if scanner_name in self._scanner_factory._scanners:
        #             # Convert scanner config to dict
        #             if hasattr(scanner_config, "model_dump"):
        #                 config_dict = scanner_config.model_dump()
        #             else:
        #                 config_dict = {
        #                     k: v
        #                     for k, v in vars(scanner_config).items()
        #                     if not k.startswith("_")
        #                 }

        #             config_dict["type"] = scanner_type
        #             enabled_scanners.append((scanner_name, config_dict))
        #         else:
        #             # Try normalized name as fallback
        #             normalized_type = (
        #                 scanner_type.replace("scanner", "").lower().strip()
        #             )
        #             if normalized_type in self._scanner_factory._scanners:
        #                 if hasattr(scanner_config, "model_dump"):
        #                     config_dict = scanner_config.model_dump()
        #                 else:
        #                     config_dict = {
        #                         k: v
        #                         for k, v in vars(scanner_config).items()
        #                         if not k.startswith("_")
        #                     }
        #                 config_dict["type"] = normalized_type
        #                 enabled_scanners.append((normalized_type, config_dict))
        #             else:
        #                 self.logger.debug(
        #                     f"Scanner type '{scanner_type}' not registered. Available scanners: {list(self._scanner_factory.available_scanners())}"
        #                 )

        # Skip execution mode update here since it's handled at the start

        # # Setup progress tracking
        # total = len(enabled_scanners)
        # self._progress = ScanProgress(total=total)
        # self._completed_scanners = []

        # # Reset results and track which scanners have been processed
        # results = {"scanners": {}}
        # processed_scanners = set()

        # # Execute enabled scanners from config first
        # if enabled_scanners:
        #     for scanner_type, scanner_config in enabled_scanners:
        #         # Skip if already processed this type
        #         if scanner_type in processed_scanners:
        #             continue

        #         processed_scanners.add(scanner_type)
        #         try:
        #             # Validate scanner is registered
        #             if scanner_type not in self._scanner_factory._scanners:
        #                 self.logger.debug(
        #                     f"Scanner {scanner_type} not registered, skipping"
        #                 )
        #                 continue

        #             # Create new scanner instance
        #             scanner_class = self._scanner_factory._scanners[scanner_type]
        #             scanner = scanner_class(
        #                 source_dir=self.source_dir,
        #                 output_dir=self.output_dir,
        #                 logger=self.logger,
        #             )

        #             try:
        #                 # Configure scanner
        #                 config_obj = (
        #                     scanner_config
        #                     if isinstance(scanner_config, ScannerPluginConfig)
        #                     else ScannerPluginConfig(**scanner_config)
        #                 )
        #                 scanner.configure(config_obj)

        #                 # Execute scan against source directory
        #                 self.logger.info(
        #                     f"Executing {scanner_type} against directory: {self.source_dir.as_posix()}"
        #                 )
        #                 result = scanner.scan(self.source_dir.as_posix())

        #                 # Use scanner name from config for results
        #                 scanner_name = (
        #                     config_obj.name
        #                     if hasattr(config_obj, "name")
        #                     else scanner_type
        #                 )
        #                 # Store results
        #                 if result:
        #                     results["scanners"][scanner_name] = result
        #                     self.logger.info(
        #                         f"Scanner {scanner_name} completed successfully"
        #                     )

        #             except Exception as e:
        #                 self.logger.error(f"Scanner config/execution error: {str(e)}")
        #                 results["scanners"][scanner_name] = {
        #                     "status": "error",
        #                     "error": str(e),
        #                 }

        #             # Track progress
        #             self._progress.increment()
        #             self._completed_scanners.append(scanner)
        #         except Exception as e:
        #             self.logger.error(
        #                 f"Failed to execute {scanner_type} scanner: {str(e)}"
        #             )
        #             continue
        # # Return results without using any default scanner configs
        # return results

    def _execute_scanner(self, scanner_tuple: tuple) -> Dict[str, Dict[str, Any]]:
        """Execute a single scanner and process its results.

        Args:
            scanner_tuple: Tuple containing (scanner_name, target)

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary containing SecurityReport and raw results

        Raises:
            ScannerError: If scanner execution fails


        """
        scanner_plugin: ScannerPlugin = scanner_tuple[0]
        scanner_config: ScannerBaseConfig = scanner_tuple[1]
        try:
            self.logger.debug(f"scanner_name: {scanner_plugin.__class__.__name__}")
            self.logger.debug(f"scanner_config: {scanner_config}")
            # Create scanner instance
            self.logger.debug(f"Getting scanner: {scanner_plugin.__class__.__name__}")

            # Configure if needed
            if scanner_config:
                self.logger.debug(
                    f"Configuring scanner {scanner_plugin.__class__.__name__}: {scanner_config}"
                )
                scanner_plugin.configure(scanner_config)

            # Execute scan
            self.logger.debug(f"Executing {scanner_plugin.__class__.__name__}.scan()")
            raw_results = scanner_plugin.scan()

            # Wrap results in container
            container = ScanResultsContainer()
            container.set_raw_results(raw_results)

            # Extract and add findings if present
            if "findings" in raw_results:
                container.add_findings(raw_results["findings"])

            # Extract and add metadata if present
            if "metadata" in raw_results:
                for key, value in raw_results["metadata"].items():
                    container.add_metadata(key, value)

            self.logger.debug("Executing engine.progress.increment()")
            if self._progress:
                self._progress.increment()

            self.logger.debug(
                f"Appending {scanner_plugin.__class__.__name__} to engine.completed_scanners"
            )
            self._completed_scanners.append(scanner_plugin)

            return {"container": container, "raw_results": raw_results}

        except Exception as e:
            self.logger.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}"
            )
            raise

    def _execute_sequential(self, ash_model: ASHARPModel) -> None:
        """Execute scanners sequentially and update ASHARPModel."""
        while not self._queue.empty():
            scanner_tuple = self._queue.get()
            results = self._execute_scanner(scanner_tuple)
            self._process_results(results, ash_model)
            if self._progress:
                self._progress.increment()

    def _execute_parallel(self, ash_model: ASHARPModel) -> None:
        """Execute scanners in parallel and update ASHARPModel."""
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            # Submit all scanners to the thread pool
            while not self._queue.empty():
                scanner_tuple = self._queue.get()
                future = executor.submit(self._execute_scanner, scanner_tuple)
                futures.append(future)

            # Wait for all futures to complete and handle any exceptions
            for future in as_completed(futures):
                try:
                    results = future.result()
                    self._process_results(results, ash_model)
                    if self._progress:
                        self._progress.increment()
                except Exception as e:
                    self.logger.error(f"Scanner execution failed: {str(e)}")
                    raise

    def _process_results(
        self, results: Dict[str, Dict], ash_model: ASHARPModel
    ) -> None:
        """Process scanner results and update ASHARPModel.

        Args:
            results: Dictionary containing scanner results
            ash_model: ASHARPModel instance to update
        """
        self._scan_results.update(results)

        # Update ASHARPModel with scanner results
        for scanner_name, data in results.items():
            if "container" in data:
                container = data["container"]
                # Add findings from container to model
                ash_model.findings.extend(container.findings)
                # Add scanner metadata
                ash_model.scanners_used.append(
                    {
                        "name": scanner_name,
                        "version": container.metadata.get("version", "unknown"),
                        "metadata": container.metadata,
                    }
                )

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
                    logger.debug(
                        f"Found built-in SAST scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        logger.debug(
                            f"Adding built-in SAST scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        logger.debug(
                            f"Skipping disabled built-in SAST scanner '{scanner_name}'"
                        )
                else:
                    logger.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )
            for (
                scanner_name,
                config,
            ) in self._config.sast.scanners.__pydantic_extra__.items():
                if isinstance(config, ScannerBaseConfig):
                    logger.debug(
                        f"Found custom SAST scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        logger.debug(
                            f"Adding custom SAST scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        logger.debug(
                            f"Skipping disabled custom SAST scanner '{scanner_name}'"
                        )
                else:
                    logger.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )

        # Get SBOM scanners
        if hasattr(self._config, "sbom") and hasattr(self._config.sbom, "scanners"):
            for (
                scanner_name
            ) in self._config.sbom.scanners.__class__.model_fields.keys():
                config = getattr(self._config.sbom.scanners, scanner_name)
                if isinstance(config, ScannerBaseConfig):
                    logger.debug(
                        f"Found built-in SBOM scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        logger.debug(
                            f"Adding built-in SBOM scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        logger.debug(
                            f"Skipping disabled built-in SBOM scanner '{scanner_name}'"
                        )
                else:
                    logger.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )
            for (
                scanner_name,
                config,
            ) in self._config.sbom.scanners.__pydantic_extra__.items():
                if isinstance(config, ScannerBaseConfig):
                    logger.debug(
                        f"Found custom SBOM scanner '{scanner_name}' config: {config}"
                    )
                    if config.enabled:
                        logger.debug(
                            f"Adding custom SBOM scanner '{scanner_name}' to all_scanners"
                        )
                        all_scanners[scanner_name] = config
                    else:
                        logger.debug(
                            f"Skipping disabled custom SBOM scanner '{scanner_name}'"
                        )
                else:
                    logger.debug(
                        f"Item {scanner_name} does not appear to be a scanner, skipping"
                    )

        return all_scanners

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of worker threads for parallel execution."""
        self._max_workers = workers
