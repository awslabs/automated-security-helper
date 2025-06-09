"""Utilities for optimizing test execution.

This module provides utilities for optimizing test execution, including
test prioritization, test caching, and test result analysis.
"""

import json
import time
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime


class TestExecutionHistory:
    """Class for tracking test execution history."""

    def __init__(self, history_file: Optional[Union[str, Path]] = None):
        """Initialize the test execution history.

        Args:
            history_file: Path to the history file (defaults to .test_history.json in the project root)
        """
        self.history_file = (
            Path(history_file) if history_file else Path(".test_history.json")
        )
        self.history = self._load_history()

    def _load_history(self) -> Dict[str, Any]:
        """Load the test execution history from the history file.

        Returns:
            Dictionary containing the test execution history
        """
        if not self.history_file.exists():
            return {"tests": {}, "last_updated": datetime.now().isoformat()}

        try:
            with open(self.history_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"tests": {}, "last_updated": datetime.now().isoformat()}

    def save_history(self) -> None:
        """Save the test execution history to the history file."""
        self.history["last_updated"] = datetime.now().isoformat()

        try:
            with open(self.history_file, "w") as f:
                json.dump(self.history, f, indent=2)
        except IOError:
            # If we can't save the history, just log a warning
            print(
                f"Warning: Could not save test execution history to {self.history_file}"
            )

    def record_test_result(self, test_id: str, duration: float, passed: bool) -> None:
        """Record the result of a test execution.

        Args:
            test_id: Identifier for the test (e.g., "tests/unit/test_example.py::test_function")
            duration: Duration of the test execution in seconds
            passed: Whether the test passed or failed
        """
        if "tests" not in self.history:
            self.history["tests"] = {}

        if test_id not in self.history["tests"]:
            self.history["tests"][test_id] = {
                "executions": [],
                "avg_duration": duration,
                "pass_rate": 1.0 if passed else 0.0,
                "last_executed": datetime.now().isoformat(),
            }

        # Add the current execution to the history
        self.history["tests"][test_id]["executions"].append(
            {
                "timestamp": datetime.now().isoformat(),
                "duration": duration,
                "passed": passed,
            }
        )

        # Keep only the last 10 executions
        if len(self.history["tests"][test_id]["executions"]) > 10:
            self.history["tests"][test_id]["executions"] = self.history["tests"][
                test_id
            ]["executions"][-10:]

        # Update the average duration
        executions = self.history["tests"][test_id]["executions"]
        self.history["tests"][test_id]["avg_duration"] = sum(
            e["duration"] for e in executions
        ) / len(executions)

        # Update the pass rate
        self.history["tests"][test_id]["pass_rate"] = sum(
            1 for e in executions if e["passed"]
        ) / len(executions)

        # Update the last executed timestamp
        self.history["tests"][test_id]["last_executed"] = datetime.now().isoformat()

    def get_test_info(self, test_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a test from the history.

        Args:
            test_id: Identifier for the test

        Returns:
            Dictionary containing test information, or None if the test is not in the history
        """
        return self.history.get("tests", {}).get(test_id)

    def get_slow_tests(self, threshold: float = 1.0) -> List[Tuple[str, float]]:
        """Get a list of slow tests based on their average duration.

        Args:
            threshold: Threshold in seconds to consider a test as slow

        Returns:
            List of tuples containing test IDs and their average durations
        """
        slow_tests = []

        for test_id, info in self.history.get("tests", {}).items():
            if info.get("avg_duration", 0) >= threshold:
                slow_tests.append((test_id, info["avg_duration"]))

        # Sort by duration (descending)
        slow_tests.sort(key=lambda x: x[1], reverse=True)

        return slow_tests

    def get_flaky_tests(self, threshold: float = 0.9) -> List[Tuple[str, float]]:
        """Get a list of flaky tests based on their pass rate.

        Args:
            threshold: Threshold for pass rate to consider a test as flaky

        Returns:
            List of tuples containing test IDs and their pass rates
        """
        flaky_tests = []

        for test_id, info in self.history.get("tests", {}).items():
            pass_rate = info.get("pass_rate", 1.0)
            if 0 < pass_rate < threshold:
                flaky_tests.append((test_id, pass_rate))

        # Sort by pass rate (ascending)
        flaky_tests.sort(key=lambda x: x[1])

        return flaky_tests

    def prioritize_tests(self, test_ids: List[str]) -> List[str]:
        """Prioritize tests based on their history.

        This function prioritizes tests based on the following criteria:
        1. Tests that have failed recently
        2. Tests that have been modified recently
        3. Tests that are faster to run

        Args:
            test_ids: List of test IDs to prioritize

        Returns:
            List of test IDs sorted by priority
        """
        # Calculate priority scores for each test
        test_scores = []

        for test_id in test_ids:
            info = self.get_test_info(test_id)
            if info is None:
                # If the test is not in the history, give it a high priority
                test_scores.append((test_id, 100))
                continue

            # Start with a base score
            score = 50

            # Adjust score based on pass rate (lower pass rate = higher priority)
            pass_rate = info.get("pass_rate", 1.0)
            score += (1 - pass_rate) * 30

            # Adjust score based on last execution time (more recent = lower priority)
            last_executed = datetime.fromisoformat(
                info.get("last_executed", "2000-01-01T00:00:00")
            )
            days_since_execution = (datetime.now() - last_executed).days
            score += min(days_since_execution, 30)

            # Adjust score based on duration (faster tests get a small boost)
            avg_duration = info.get("avg_duration", 0)
            if avg_duration < 0.1:
                score += 5
            elif avg_duration < 0.5:
                score += 3
            elif avg_duration < 1.0:
                score += 1

            test_scores.append((test_id, score))

        # Sort by score (descending)
        test_scores.sort(key=lambda x: x[1], reverse=True)

        return [test_id for test_id, _ in test_scores]


class TestContentCache:
    """Class for caching test content to detect changes."""

    def __init__(self, cache_file: Optional[Union[str, Path]] = None):
        """Initialize the test content cache.

        Args:
            cache_file: Path to the cache file (defaults to .test_cache.json in the project root)
        """
        self.cache_file = Path(cache_file) if cache_file else Path(".test_cache.json")
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        """Load the test content cache from the cache file.

        Returns:
            Dictionary containing the test content cache
        """
        if not self.cache_file.exists():
            return {"files": {}, "last_updated": datetime.now().isoformat()}

        try:
            with open(self.cache_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"files": {}, "last_updated": datetime.now().isoformat()}

    def save_cache(self) -> None:
        """Save the test content cache to the cache file."""
        self.cache["last_updated"] = datetime.now().isoformat()

        try:
            with open(self.cache_file, "w") as f:
                json.dump(self.cache, f, indent=2)
        except IOError:
            # If we can't save the cache, just log a warning
            print(f"Warning: Could not save test content cache to {self.cache_file}")

    def get_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the hash of a file's content.

        Args:
            file_path: Path to the file

        Returns:
            Hash of the file's content
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return ""

        try:
            with open(file_path, "rb") as f:
                content = f.read()
                return hashlib.md5(content, usedforsecurity=False).hexdigest()
        except IOError:
            return ""

    def has_file_changed(self, file_path: Union[str, Path]) -> bool:
        """Check if a file has changed since it was last cached.

        Args:
            file_path: Path to the file

        Returns:
            True if the file has changed, False otherwise
        """
        file_path_str = str(file_path)
        current_hash = self.get_file_hash(file_path)

        if not current_hash:
            return True

        cached_hash = self.cache.get("files", {}).get(file_path_str, {}).get("hash", "")

        return current_hash != cached_hash

    def update_file_cache(self, file_path: Union[str, Path]) -> None:
        """Update the cache for a file.

        Args:
            file_path: Path to the file
        """
        file_path_str = str(file_path)
        current_hash = self.get_file_hash(file_path)

        if not current_hash:
            return

        if "files" not in self.cache:
            self.cache["files"] = {}

        self.cache["files"][file_path_str] = {
            "hash": current_hash,
            "last_updated": datetime.now().isoformat(),
        }

    def get_changed_files(self, file_paths: List[Union[str, Path]]) -> List[str]:
        """Get a list of files that have changed since they were last cached.

        Args:
            file_paths: List of file paths to check

        Returns:
            List of file paths that have changed
        """
        changed_files = []

        for file_path in file_paths:
            if self.has_file_changed(file_path):
                changed_files.append(str(file_path))
                self.update_file_cache(file_path)

        return changed_files


def optimize_test_order(test_files: List[str]) -> List[str]:
    """Optimize the order of test files for faster feedback.

    This function reorders test files to run faster tests first and
    tests that are more likely to fail first.

    Args:
        test_files: List of test file paths

    Returns:
        Reordered list of test file paths
    """
    # Use the test execution history to prioritize tests
    history = TestExecutionHistory()

    # Convert file paths to test IDs
    test_ids = [str(Path(f).absolute()) for f in test_files]

    # Prioritize tests based on their history
    prioritized_ids = history.prioritize_tests(test_ids)

    # Convert test IDs back to file paths
    prioritized_files = []
    id_to_file = {str(Path(f).absolute()): f for f in test_files}

    for test_id in prioritized_ids:
        if test_id in id_to_file:
            prioritized_files.append(id_to_file[test_id])

    # Add any remaining files that weren't in the history
    for file in test_files:
        if file not in prioritized_files:
            prioritized_files.append(file)

    return prioritized_files


def run_tests_with_optimization(
    test_files: Optional[List[str]] = None,
    markers: Optional[List[str]] = None,
    keywords: Optional[List[str]] = None,
    parallel: bool = True,
    fail_fast: bool = False,
    additional_args: Optional[List[str]] = None,
) -> int:
    """Run tests with optimization strategies.

    Args:
        test_files: List of test file paths to run
        markers: List of markers to filter tests
        keywords: List of keywords to filter tests
        parallel: Whether to run tests in parallel
        fail_fast: Whether to stop after the first failure
        additional_args: Additional pytest arguments

    Returns:
        Exit code from pytest
    """
    from tests.utils.test_selection import create_test_selection_args

    # Start with basic pytest command
    cmd = ["pytest"]

    # Add test selection arguments
    cmd.extend(
        create_test_selection_args(
            markers=markers,
            keywords=keywords,
            test_paths=test_files,
        )
    )

    # Add parallel execution if requested
    if parallel:
        cmd.append("-n")
        cmd.append("auto")

    # Add fail-fast if requested
    if fail_fast:
        cmd.append("-xvs")

    # Add additional arguments
    if additional_args:
        cmd.extend(additional_args)

    # Run the tests
    start_time = time.time()
    result = subprocess.run(cmd)
    duration = time.time() - start_time

    # Print summary
    print(
        f"\nTest execution completed in {duration:.2f} seconds with exit code {result.returncode}"
    )

    return result.returncode


def run_incremental_tests(
    changed_only: bool = True,
    base_branch: str = "main",
    include_related: bool = True,
    parallel: bool = True,
    fail_fast: bool = False,
    additional_args: Optional[List[str]] = None,
) -> int:
    """Run tests incrementally based on changes.

    Args:
        changed_only: Whether to run only tests for changed files
        base_branch: Base branch to compare against for changed files
        include_related: Whether to include related test files
        parallel: Whether to run tests in parallel
        fail_fast: Whether to stop after the first failure
        additional_args: Additional pytest arguments

    Returns:
        Exit code from pytest
    """
    from tests.utils.test_selection import get_changed_files, get_related_test_files

    if changed_only:
        # Get changed files
        changed_files = get_changed_files(base_branch)

        # Get related test files
        if include_related:
            test_files = get_related_test_files(changed_files)
        else:
            test_files = [
                f for f in changed_files if f.startswith("tests/") and f.endswith(".py")
            ]

        if not test_files:
            print("No test files found for changed files. Running all tests.")
            return run_tests_with_optimization(
                parallel=parallel,
                fail_fast=fail_fast,
                additional_args=additional_args,
            )
    else:
        # Run all test files
        test_files = None

    # Optimize the test order if we have specific test files
    if test_files:
        test_files = optimize_test_order(test_files)

    # Run the tests
    return run_tests_with_optimization(
        test_files=test_files,
        parallel=parallel,
        fail_fast=fail_fast,
        additional_args=additional_args,
    )


if __name__ == "__main__":
    # Example usage as a script
    import argparse

    parser = argparse.ArgumentParser(description="Run tests with optimization")
    parser.add_argument(
        "--changed-only", action="store_true", help="Run only tests for changed files"
    )
    parser.add_argument(
        "--base-branch", default="main", help="Base branch for changed files comparison"
    )
    parser.add_argument(
        "--include-related", action="store_true", help="Include related test files"
    )
    parser.add_argument(
        "--no-parallel", action="store_true", help="Disable parallel test execution"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="Stop after the first failure"
    )

    args, unknown_args = parser.parse_known_args()

    exit_code = run_incremental_tests(
        changed_only=args.changed_only,
        base_branch=args.base_branch,
        include_related=args.include_related,
        parallel=not args.no_parallel,
        fail_fast=args.fail_fast,
        additional_args=unknown_args,
    )

    import sys

    sys.exit(exit_code)
