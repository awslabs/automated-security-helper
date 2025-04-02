# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Execution engine for running security scanners."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from queue import Queue
from typing import List, Optional

from automated_security_helper.models.interfaces import IScanner


class ExecutionStrategy(Enum):
    """Execution strategy for running scanners."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    MIXED = "mixed"


@dataclass
class ScanProgress:
    """Track progress of scanner execution."""

    total_scanners: int
    completed_scanners: int = 0
    failed_scanners: int = 0
    current_scanner: Optional[str] = None


class ScanExecutionEngine:
    """Manages the execution of security scanners."""

    def __init__(self, strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL):
        """Initialize the execution engine.

        Args:
            strategy: The execution strategy to use for running scanners
        """
        self.strategy = strategy
        self._queue = Queue()
        self._progress = None
        self._max_workers = 4  # Default number of parallel workers
        self._completed_scanners = []  # List to track completed scanners

    def queue_scanner(self, scanner: IScanner) -> None:
        """Add a scanner to the execution queue.

        Args:
            scanner: The scanner to queue for execution
        """
        self._queue.put(scanner)

    def queue_scanners(self, scanners: List[IScanner]) -> None:
        """Add multiple scanners to the execution queue.

        Args:
            scanners: List of scanners to queue for execution
        """
        for scanner in scanners:
            self.queue_scanner(scanner)

    def _execute_sequential(self) -> None:
        """Execute scanners sequentially."""
        while not self._queue.empty():
            scanner = self._queue.get()
            self._progress.current_scanner = scanner.name
            try:
                scanner.execute()
                self._progress.completed_scanners += 1
            except Exception:  # pylint: disable=broad-except
                self._progress.failed_scanners += 1
            finally:
                self._queue.task_done()

    def _execute_parallel(self) -> None:
        """Execute scanners in parallel using thread pool."""
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            while not self._queue.empty():
                scanner = self._queue.get()
                future = executor.submit(self._execute_scanner, scanner)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:  # pylint: disable=broad-except
                    pass

    def _execute_scanner(self, scanner: IScanner) -> None:
        """Execute a single scanner and update progress.

        Args:
            scanner: The scanner to execute
        """
        self._progress.current_scanner = scanner.name
        try:
            scanner.execute()
            self._progress.completed_scanners += 1
            self._completed_scanners.append(scanner)
        except Exception:  # pylint: disable=broad-except
            self._progress.failed_scanners += 1
        finally:
            self._queue.task_done()

    def execute(self) -> None:
        """Execute all queued scanners according to the selected strategy."""
        total_scanners = self._queue.qsize()
        self._progress = ScanProgress(total_scanners=total_scanners)

        if self.strategy == ExecutionStrategy.SEQUENTIAL:
            self._execute_sequential()
        elif self.strategy == ExecutionStrategy.PARALLEL:
            self._execute_parallel()
        else:  # MIXED strategy
            # For mixed strategy, execute some scanners in parallel and others sequentially
            # based on scanner characteristics or requirements
            self._execute_parallel()

    @property
    def completed_scanners(self) -> List[IScanner]:
        """Get the list of completed scanners.

        Returns:
            List of scanners that have completed execution
        """
        return self._completed_scanners

    @property
    def progress(self) -> Optional[ScanProgress]:
        """Get current execution progress.

        Returns:
            Current progress information or None if execution hasn't started
        """
        return self._progress

    def set_max_workers(self, workers: int) -> None:
        """Set the maximum number of parallel workers.

        Args:
            workers: Number of parallel workers to use
        """
        self._max_workers = max(1, workers)  # Ensure at least 1 worker
