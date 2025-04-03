# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Execution engine for running security scanners."""

import concurrent.futures
import queue
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union, Callable

from automated_security_helper.scanners.abstract_scanner import AbstractScanner
from automated_security_helper.config.default_config import (
    DEFAULT_ASH_CONFIG,
)


@dataclass
class ScanProgress:
    """Track progress of scanner execution."""

    total: int = 0
    completed: int = 0
    failed: int = 0

    def increment(self):
        """Increment completed count."""
        self.completed += 1


class ExecutionStrategy(Enum):
    """Strategy for executing scanners."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    MIXED = "mixed"


class ScanExecutionEngine:
    """Manages the execution of security scanners."""

    def __init__(self, strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL):
        """Initialize the execution engine.

        Args:
            strategy: The execution strategy to use for running scanners
        """
        self._scanners = {}
        self.strategy = strategy
        self._queue = queue.Queue()
        self._progress = None
        self._max_workers = 4
        self._completed_scanners = []

    def get_scanner(self, name: str) -> AbstractScanner:
        """Get a registered scanner instance by name.

        Args:
            name: Name of the registered scanner

        Returns:
            An instance of the requested scanner

        Raises:
            ValueError: If scanner is not registered
        """
        if name not in self._scanners:
            raise ValueError(f"Scanner {name} not registered")
        return self._scanners[name]()

    def register_scanner(
        self,
        name: str,
        scanner_factory: Union[Type[AbstractScanner], Callable[[], AbstractScanner]],
    ) -> None:
        """Register a scanner with the execution engine.

        Args:
            name: The name of the scanner
            scanner_factory: The scanner class or factory function to register
        """
        if isinstance(scanner_factory, type):
            self._scanners[name] = lambda: scanner_factory()
        else:
            self._scanners[name] = scanner_factory

    def _execute_sequential(self) -> None:
        """Execute scanners sequentially."""
        while not self._queue.empty():
            scanner_tuple = self._queue.get()
            try:
                self._execute_scanner(scanner_tuple)
            finally:
                self._queue.task_done()

    def _execute_parallel(self) -> None:
        """Execute scanners in parallel."""
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as executor:
            futures = []
            while not self._queue.empty():
                scanner_tuple = self._queue.get()
                futures.append(executor.submit(self._execute_scanner, scanner_tuple))
                self._queue.task_done()
            concurrent.futures.wait(futures)

    def _execute_scanner(self, scanner_tuple: tuple) -> Any:
        """Execute a single scanner and update progress.

        Args:
            scanner_tuple: Tuple containing (scanner, config)

        Raises:
            RuntimeError: If scanner execution fails
        """
        scanner, config = scanner_tuple
        try:
            result = scanner.scan(config)
            self._completed_scanners.append(scanner)
            scanner.results = result
            if self._progress:
                self._progress.increment()
            return result
        except Exception as e:
            if self._progress:
                self._progress.failed += 1
            raise RuntimeError(
                f"Scanner {getattr(scanner, 'name', '<unknown>')} failed: {str(e)}"
            ) from e

    def execute(self, config: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Execute registered scanners based on the provided configuration.

        Args:
            config: Configuration dictionary containing scanner settings
            **kwargs: Additional execution parameters

        Returns:
            dict: Results from all executed scanners

        Raises:
            ValueError: If config is invalid or required scanners are not registered
            RuntimeError: If scanner execution fails
        """
        if config is None:
            config = DEFAULT_ASH_CONFIG.model_dump()

        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")

        if "scanners" not in config:
            config["scanners"] = {}

        if not config["scanners"]:
            return {}

        mode = kwargs.get("mode")
        if mode is not None:
            try:
                self.strategy = ExecutionStrategy(mode)
            except ValueError:
                raise ValueError(f"Invalid execution mode: {mode}")

        total = len(config["scanners"])
        self._progress = ScanProgress(total=total)
        self._completed_scanners = []  # Reset completed scanners

        results = {}
        for scanner_name, scanner_config in config["scanners"].items():
            if scanner_name not in self._scanners:
                raise ValueError(f"Scanner {scanner_name} not registered")

            scanner = self._scanners[scanner_name]()

            # Queue scanner for execution
            self._queue.put((scanner, scanner_config))

        try:
            # Execute according to strategy
            if self.strategy == ExecutionStrategy.SEQUENTIAL:
                self._execute_sequential()
            elif self.strategy == ExecutionStrategy.PARALLEL:
                # self._execute_parallel()
                self._execute_sequential()
            else:  # MIXED strategy
                # self._execute_parallel()
                self._execute_sequential()

            # Collect results from completed scanners
            for scanner in self._completed_scanners:
                if hasattr(scanner, "name") and hasattr(scanner, "results"):
                    results[scanner.name] = scanner.results

            return results
        finally:
            # Always drain the queue
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Exception as e:
                    print(e)
                    pass

    @property
    def completed_scanners(self) -> List[AbstractScanner]:
        """Get the list of completed scanners."""
        return self._completed_scanners.copy()

    @property
    def progress(self) -> Optional[ScanProgress]:
        """Get current execution progress."""
        return self._progress

    def set_max_workers(self, workers: int) -> None:
        """Set maximum number of parallel worker threads."""
        if workers < 1:
            raise ValueError("Workers must be >= 1")
        self._max_workers = workers
