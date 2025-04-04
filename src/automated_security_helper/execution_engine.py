"""Execution engine for security scanners."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union
import logging
from automated_security_helper.config.config import ASHConfig, ScannerPluginConfig
from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG
from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.scanners.scanner_plugin import ScannerPlugin
from automated_security_helper.config.scanner_types import ScannerBaseConfig

import concurrent.futures
from enum import Enum


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
        source_dir: Path,
        output_dir: Path,
        work_dir: Path,
        strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL,
        logger: logging.Logger = logging.Logger(name=__name__),
    ):
        """Initialize the execution engine.

        Args:
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
            logger: Logger instance to use for logging
        """
        # Set up logging
        self.logger = logger
        self.logger.info("Initializing ScanExecutionEngine")

        # Initialize scanner components
        self._scanner_factory = ScannerFactory()
        self._scanners = {}  # Maps scanner names to factory functions
        self._completed_scanners = []
        self._results = {"scanners": {}}

        # Configure execution settings
        self._strategy = strategy
        self._max_workers = min(4, multiprocessing.cpu_count())
        self._progress = None
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.work_dir = work_dir

    def register_scanner(
        self,
        name: str,
        scanner_factory: Union[Type[ScannerPlugin], Callable[[], ScannerPlugin]],
    ) -> None:
        """Register a scanner with the execution engine.

        Args:
            name: Scanner name (will be normalized)
            scanner_factory: Scanner class or factory function that creates scanner instances
        """
        """Register a scanner with both the execution engine and scanner factory.

        Args:
            name: Name of the scanner
            scanner_factory: Scanner class or factory function
        """
        # Normalize scanner name for consistent lookup
        scanner_name = name.lower().strip()

        # Determine scanner class and factory function
        if isinstance(scanner_factory, type):
            scanner_class = scanner_factory

            def factory_fn():
                return scanner_class()
        else:
            factory_fn = scanner_factory
            scanner_instance = factory_fn()
            scanner_class = type(scanner_instance)

        # Register scanner with both factory and store
        self._scanners[scanner_name] = factory_fn
        self._scanner_factory.register_scanner(scanner_name, scanner_class)

    def get_scanner(self, scanner_name: str) -> ScannerPlugin:
        """Get a scanner instance by name.

        Args:
            scanner_name: Name of the scanner to retrieve

        Returns:
            Scanner instance

        Raises:
            ValueError: If scanner is not found
        """
        # Normalize lookup name
        lookup_name = scanner_name.lower().strip()

        # First try exact match
        if lookup_name in self._scanners:
            return self._scanners[lookup_name]()

        # Try without 'scanner' suffix
        if lookup_name.lower().endswith("scanner"):
            base_name = lookup_name[:-7]
            if base_name in self._scanners:
                return self._scanners[base_name]()

        # Finally check scanner factory
        if scanner_name in self._scanner_factory._scanners:
            return self._scanner_factory._scanners[scanner_name]()

        raise ValueError(f"Scanner '{scanner_name}' not registered")

    def execute(self, config: Optional[ASHConfig] = None, **kwargs) -> Dict[str, Any]:
        """Execute registered scanners based on the provided configuration.

        Args:
            config: ASHConfig instance containing scanner configuration
            **kwargs: Additional execution parameters. Supports:
                - mode: ExecutionStrategy value to override execution mode

        Returns:
            dict: Results dictionary with 'scanners' key containing results from all executed scanners

        Raises:
            ValueError: If config is invalid or mode is invalid
            RuntimeError: If scanner execution fails critically
        """
        # Always use ASHConfig instance
        if config is None:
            config = DEFAULT_ASH_CONFIG
        if not isinstance(config, ASHConfig):
            raise ValueError("Configuration must be an ASHConfig instance")

        # Update execution mode if specified in kwargs
        if mode := kwargs.get("mode"):
            try:
                self._strategy = ExecutionStrategy(mode)
            except ValueError:
                raise ValueError(f"Invalid execution mode: {mode}")

        # Initialize results dictionary
        results = {"scanners": {}}

        # Initialize empty list for enabled scanners
        enabled_scanners = []
        processed_scanners = set()

        # Get all registered scanners from factory
        try:
            registered_scanners = self._scanner_factory.available_scanners()
            logging.info(
                f"Using registered scanners: {list(registered_scanners.keys())}"
            )
        except AttributeError:
            registered_scanners = {}

        # Process registered scanners first
        for scanner_name, scanner_class in registered_scanners.items():
            try:
                # Get scanner config from class or instance
                if hasattr(scanner_class, "_default_config"):
                    # Use class default config
                    config = scanner_class._default_config
                else:
                    # Create instance to get config
                    scanner = scanner_class()
                    config = scanner._config or ScannerPluginConfig(
                        name=scanner_name,
                        type=scanner_name,
                        command="",
                        invocation_mode="directory",
                        enabled=True,
                    )

                # Ensure name matches registration
                config_dict = config.model_dump()
                config_dict["name"] = scanner_name
                config_dict["enabled"] = True

                enabled_scanners.append((scanner_name, config_dict))

            except Exception as e:
                logging.warning(
                    f"Failed to get config for scanner {scanner_name}: {str(e)}"
                )

        # Process scanner configs from ASH config if provided
        if config and hasattr(config, "sast") and config.sast and config.sast.scanners:
            scanner_configs = config.sast.scanners
            if not isinstance(scanner_configs, list):
                scanner_configs = [scanner_configs]

            # Clear any default configs
            enabled_scanners = []

            for scanner_config in scanner_configs:
                if not getattr(scanner_config, "enabled", True):
                    continue

                # Get scanner type from config class name
                scanner_type = scanner_config.type
                scanner_name = scanner_config.name

                if "scanner" in scanner_type:
                    scanner_type = scanner_type.split("scanner")[0]

                # Try to find scanner in factory
                if scanner_name in self._scanner_factory._scanners:
                    # Convert scanner config to dict
                    if hasattr(scanner_config, "model_dump"):
                        config_dict = scanner_config.model_dump()
                    else:
                        config_dict = {
                            k: v
                            for k, v in vars(scanner_config).items()
                            if not k.startswith("_")
                        }

                    config_dict["type"] = scanner_type
                    enabled_scanners.append((scanner_name, config_dict))
                else:
                    # Try normalized name as fallback
                    normalized_type = (
                        scanner_type.replace("scanner", "").lower().strip()
                    )
                    if normalized_type in self._scanner_factory._scanners:
                        if hasattr(scanner_config, "model_dump"):
                            config_dict = scanner_config.model_dump()
                        else:
                            config_dict = {
                                k: v
                                for k, v in vars(scanner_config).items()
                                if not k.startswith("_")
                            }
                        config_dict["type"] = normalized_type
                        enabled_scanners.append((normalized_type, config_dict))
                    else:
                        logging.debug(
                            f"Scanner type '{scanner_type}' not registered. Available scanners: {list(self._scanner_factory.available_scanners())}"
                        )

        # Skip execution mode update here since it's handled at the start

        # Setup progress tracking
        total = len(enabled_scanners)
        self._progress = ScanProgress(total=total)
        self._completed_scanners = []

        # Reset results and track which scanners have been processed
        results = {"scanners": {}}
        processed_scanners = set()

        # Execute enabled scanners from config first
        if enabled_scanners:
            for scanner_type, scanner_config in enabled_scanners:
                # Skip if already processed this type
                if scanner_type in processed_scanners:
                    continue

                processed_scanners.add(scanner_type)
                try:
                    # Validate scanner is registered
                    if scanner_type not in self._scanner_factory._scanners:
                        logging.warning(
                            f"Scanner {scanner_type} not registered, skipping"
                        )
                        continue

                    # Create new scanner instance
                    scanner_class = self._scanner_factory._scanners[scanner_type]
                    scanner = scanner_class()

                    try:
                        # Configure scanner
                        config_obj = (
                            scanner_config
                            if isinstance(scanner_config, ScannerPluginConfig)
                            else ScannerPluginConfig(**scanner_config)
                        )
                        scanner.configure(config_obj)

                        # Execute scan against source directory
                        logging.info(f"Executing {scanner_type}")
                        result = scanner.scan(str(self.source_dir))

                        # Use scanner name from config for results
                        scanner_name = (
                            config_obj.name
                            if hasattr(config_obj, "name")
                            else scanner_type
                        )
                        # Store results
                        if result:
                            results["scanners"][scanner_name] = result
                            logging.info(
                                f"Scanner {scanner_name} completed successfully"
                            )

                    except Exception as e:
                        logging.error(f"Scanner config/execution error: {str(e)}")
                        results["scanners"][scanner_name] = {
                            "status": "error",
                            "error": str(e),
                        }

                    # Track progress
                    self._progress.increment()
                    self._completed_scanners.append(scanner)
                except Exception as e:
                    logging.error(f"Failed to execute {scanner_type} scanner: {str(e)}")
                    continue
        # Return results without using any default scanner configs
        return results

    def _execute_scanner(self, scanner_tuple: tuple) -> Dict[str, Any]:
        """Execute single scanner with configuration.

        Args:
            scanner_tuple: Tuple containing (scanner, config)

        Returns:
            Dict[str, Any]: Results from scanner execution
        """
        """Execute a single scanner.

        Args:
            scanner_tuple: Tuple containing (scanner, config)

        Returns:
            Scanner results
        """
        scanner_plugin: ScannerPlugin = scanner_tuple[0]
        scanner_config: ScannerBaseConfig = scanner_tuple[1]
        try:
            self.logger.warning(f"scanner_name: {scanner_plugin.__class__.__name__}")
            self.logger.warning(f"scanner_config: {scanner_config}")
            # Create scanner instance
            self.logger.warning(f"Getting scanner: {scanner_plugin.__class__.__name__}")

            # Configure if needed
            if scanner_config:
                self.logger.warning(
                    f"Configuring scanner {scanner_plugin.__class__.__name__}: {scanner_config}"
                )
                scanner_plugin.configure(scanner_config)

            # Execute scan
            self.logger.warning(f"Executing {scanner_plugin.__class__.__name__}.scan()")
            result = scanner_plugin.scan()

            self.logger.warning("Executing engine.progress.increment()")
            self._progress.increment()

            self.logger.warning(
                f"Appending {scanner_plugin.__class__.__name__} to engine.completed_scanners"
            )
            self._completed_scanners.append(scanner_plugin)

            return result

        except Exception as e:
            self.logger.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: {e}"
            )
            return None

        except Exception as e:
            raise RuntimeError(e) from e

    def _execute_sequential(self) -> None:
        """Execute scanners sequentially."""
        while not self._queue.empty():
            scanner_tuple = self._queue.get()
            self._execute_scanner(scanner_tuple)

    def _execute_parallel(self) -> None:
        """Execute scanners in parallel using thread pool."""
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            while not self._queue.empty():
                scanner_tuple = self._queue.get()
                future = executor.submit(self._execute_scanner, scanner_tuple)
                futures.append(future)

            # Wait for all scanners to complete
            concurrent.futures.wait(futures)
            for future in futures:
                if future.exception():
                    raise future.exception()

    @property
    def completed_scanners(self) -> List[ScannerPlugin]:
        """Get list of completed scanners."""
        return self._completed_scanners

    @property
    def progress(self) -> Optional[ScanProgress]:
        """Get current scan progress."""
        return self._progress

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of worker threads for parallel execution."""
        self._max_workers = workers
