"""Execution engine for security scanners."""

from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import logging
import queue
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Type, Callable

from automated_security_helper.models.config import ASHConfig
from automated_security_helper.scanners.abstract_scanner import AbstractScanner
from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG


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

    def __init__(self, strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL):
        """Initialize the execution engine.

        Args:
            strategy: The execution strategy to use for running scanners
        """
        self._scanner_factory = ScannerFactory()
        self._scanners = {}
        self.strategy = strategy
        self._queue = queue.Queue()
        self._progress = None
        self._completed_scanners = []
        self._max_workers = 4

        # Ensure default scanners are registered
        for name, scanner_class in self._scanner_factory.available_scanners().items():
            self.register_scanner(name, scanner_class)

    def register_scanner(
        self,
        name: str,
        scanner_factory: Union[Type[AbstractScanner], Callable[[], AbstractScanner]],
    ) -> None:
        """Register a scanner with both the execution engine and scanner factory.

        Args:
            name: Name of the scanner
            scanner_factory: Scanner class or factory function
        """
        normalized_name = name.lower().replace("scanner", "")
        self._scanner_factory.register_scanner(normalized_name, scanner_factory)
        self._scanners = self._scanner_factory.available_scanners()

    def execute(self, config: Optional[ASHConfig] = None, **kwargs) -> Dict[str, Any]:
        """Execute registered scanners based on the provided configuration.

        Args:
            config: ASHConfig instance containing scanner configuration
            **kwargs: Additional execution parameters

        Returns:
            dict: Results from all executed scanners with 'scanners' as the top-level key

        Raises:
            ValueError: If config is invalid or required scanners are not registered
            RuntimeError: If scanner execution fails
        """
        # Always use ASHConfig instance
        if config is None:
            config = DEFAULT_ASH_CONFIG
        if not isinstance(config, ASHConfig):
            raise ValueError("Configuration must be an ASHConfig instance")

        # Initialize empty results dictionary
        results = {"scanners": {}}

        # Ensure default scanners are registered
        for name, scanner_class in self._scanner_factory.available_scanners().items():
            if name not in self._scanners:
                self.register_scanner(name, scanner_class)

        # Ensure required scanner types are registered from the configuration
        if config.sast and config.sast.scanners:
            for scanner in config.sast.scanners:
                scanner_name = scanner.__class__.__name__.lower()
                if "scanner" in scanner_name:
                    scanner_name = scanner_name.split("scanner")[0]
                if scanner_name.endswith("scanner"):
                    scanner_name = scanner_name[:-7]
                if scanner_name not in self._scanners:
                    self.register_scanner(scanner_name, scanner.__class__)

        # Extract enabled scanners from ASHConfig
        enabled_scanners = []
        if config and hasattr(config, "sast") and config.sast and config.sast.scanners:
            scanner_list = (
                config.sast.scanners
                if isinstance(config.sast.scanners, list)
                else [config.sast.scanners]
            )

            for scanner_config in scanner_list:
                if not getattr(scanner_config, "enabled", True):
                    continue

                # Get normalized scanner type
                scanner_type = None

                # Try to get type from class name first
                if hasattr(scanner_config, "__class__"):
                    class_name = scanner_config.__class__.__name__.lower()
                    if "scanner" in class_name:
                        scanner_type = class_name.split("scanner")[0]

                # Fallback to type field if present
                if not scanner_type and hasattr(scanner_config, "type"):
                    type_value = getattr(scanner_config, "type").lower()
                    if type_value.endswith("scanner"):
                        scanner_type = type_value[:-7]
                    else:
                        scanner_type = type_value

                if not scanner_type:
                    logging.warning(
                        f"Could not determine scanner type for config: {scanner_config}"
                    )
                    continue

                if scanner_type in self._scanners:
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
                    enabled_scanners.append((scanner_type, config_dict))
                else:
                    logging.warning(
                        f"Scanner type '{scanner_type}' not registered. Available scanners: {list(self._scanners.keys())}"
                    )

        # Update execution mode if specified
        if mode := kwargs.get("mode"):
            try:
                self.strategy = ExecutionStrategy(mode)
            except ValueError:
                raise ValueError(f"Invalid execution mode: {mode}")

        # Setup progress tracking
        total = len(enabled_scanners)
        self._progress = ScanProgress(total=total)
        self._completed_scanners = []

        # Execute enabled scanners and collect results
        if enabled_scanners:
            for scanner_type, scanner_config in enabled_scanners:
                try:
                    if scanner_type not in self._scanners:
                        logging.warning(
                            f"Scanner {scanner_type} not registered, skipping"
                        )
                        continue

                    # Create and execute scanner
                    scanner = self._scanners[scanner_type]()
                    result = self._execute_scanner((scanner, scanner_config))
                    results["scanners"][scanner_type] = result
                except Exception as e:
                    logging.error(f"Failed to execute {scanner_type} scanner: {str(e)}")
                    continue
        else:
            # If no enabled scanners found, try to create results from default config scanners
            try:
                if (
                    isinstance(config, ASHConfig)
                    and config.sast
                    and config.sast.scanners
                ):
                    for scanner in config.sast.scanners:
                        if getattr(scanner, "enabled", True):
                            scanner_type = scanner.__class__.__name__.lower().replace(
                                "scanner", ""
                            )
                            try:
                                result = self._execute_scanner(
                                    (scanner, scanner.model_dump())
                                )
                                results["scanners"][scanner_type] = result
                            except Exception as e:
                                logging.error(
                                    f"Failed to execute default scanner {scanner_type}: {str(e)}"
                                )
            except Exception as e:
                logging.warning(f"Error processing default scanners: {str(e)}")

        return results

    def _execute_scanner(self, scanner_tuple: tuple) -> Any:
        """Execute a single scanner.

        Args:
            scanner_tuple: Tuple containing (scanner, config)

        Returns:
            Scanner results
        """
        scanner, config = scanner_tuple
        try:
            result = scanner.scan(config)
            self._progress.increment()
            self._completed_scanners.append(scanner)
            return result
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
    def completed_scanners(self) -> List[AbstractScanner]:
        """Get list of completed scanners."""
        return self._completed_scanners

    @property
    def progress(self) -> Optional[ScanProgress]:
        """Get current scan progress."""
        return self._progress

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of worker threads for parallel execution."""
        self._max_workers = workers
