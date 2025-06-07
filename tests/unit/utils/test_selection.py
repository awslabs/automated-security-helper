"""Utilities for test selection and filtering.

This module provides utilities for selecting and filtering tests based on
various criteria such as test markers, file paths, and related code changes.
"""

import os
import re
import sys
import subprocess
from typing import List, Optional


def get_changed_files(base_branch: str = "main") -> List[str]:
    """Get a list of files changed compared to the base branch.

    Args:
        base_branch: Base branch to compare against (default: main)

    Returns:
        List of changed file paths
    """
    try:
        # Get the list of changed files
        result = subprocess.run(
            ["git", "diff", "--name-only", base_branch],
            capture_output=True,
            text=True,
            check=True,
        )

        # Split the output into lines and filter out empty lines
        changed_files = [
            line.strip() for line in result.stdout.split("\n") if line.strip()
        ]

        return changed_files

    except subprocess.CalledProcessError:
        # If the git command fails, return an empty list
        return []


def get_related_test_files(changed_files: List[str]) -> List[str]:
    """Get a list of test files related to the changed files.

    Args:
        changed_files: List of changed file paths

    Returns:
        List of related test file paths
    """
    related_test_files = []

    for file_path in changed_files:
        # Skip non-Python files
        if not file_path.endswith(".py"):
            continue

        # Skip test files themselves
        if file_path.startswith("tests/"):
            related_test_files.append(file_path)
            continue

        # For source files, find corresponding test files
        if file_path.startswith("automated_security_helper/"):
            # Extract the module path
            module_path = file_path.replace("automated_security_helper/", "").replace(
                ".py", ""
            )
            module_parts = module_path.split("/")

            # Look for test files in different test directories
            potential_test_paths = [
                f"tests/unit/{'/'.join(module_parts)}/test_{module_parts[-1]}.py",
                f"tests/integration/{'/'.join(module_parts)}/test_{module_parts[-1]}.py",
                f"tests/{'/'.join(module_parts)}/test_{module_parts[-1]}.py",
            ]

            # Add existing test files to the list
            for test_path in potential_test_paths:
                if os.path.exists(test_path):
                    related_test_files.append(test_path)

    return related_test_files


def get_tests_by_marker(marker: str) -> List[str]:
    """Get a list of test files that have the specified marker.

    Args:
        marker: Pytest marker to filter by

    Returns:
        List of test file paths
    """
    try:
        # Run pytest to collect tests with the specified marker
        result = subprocess.run(
            ["pytest", "--collect-only", "-m", marker, "--quiet"],
            capture_output=True,
            text=True,
        )

        # Extract test file paths from the output
        test_files = set()
        for line in result.stdout.split("\n"):
            match = re.search(r"<Module (.+)>", line)
            if match:
                test_file = match.group(1)
                if test_file.endswith(".py"):
                    test_files.add(test_file)

        return sorted(list(test_files))

    except subprocess.CalledProcessError:
        # If the pytest command fails, return an empty list
        return []


def get_tests_by_keyword(keyword: str) -> List[str]:
    """Get a list of test files that match the specified keyword.

    Args:
        keyword: Keyword to filter tests by

    Returns:
        List of test file paths
    """
    try:
        # Run pytest to collect tests with the specified keyword
        result = subprocess.run(
            ["pytest", "--collect-only", "-k", keyword, "--quiet"],
            capture_output=True,
            text=True,
        )

        # Extract test file paths from the output
        test_files = set()
        for line in result.stdout.split("\n"):
            match = re.search(r"<Module (.+)>", line)
            if match:
                test_file = match.group(1)
                if test_file.endswith(".py"):
                    test_files.add(test_file)

        return sorted(list(test_files))

    except subprocess.CalledProcessError:
        # If the pytest command fails, return an empty list
        return []


def get_slow_tests(threshold_seconds: float = 1.0) -> List[str]:
    """Get a list of slow tests based on previous test runs.

    Args:
        threshold_seconds: Threshold in seconds to consider a test as slow

    Returns:
        List of slow test file paths
    """
    try:
        # Run pytest to collect test durations
        result = subprocess.run(
            ["pytest", "--collect-only", "--durations=0"],
            capture_output=True,
            text=True,
        )

        # Extract slow test file paths from the output
        slow_tests = []
        in_durations_section = False

        for line in result.stdout.split("\n"):
            if "slowest durations" in line:
                in_durations_section = True
                continue

            if in_durations_section and line.strip():
                # Parse the duration and test path
                match = re.search(r"(\d+\.\d+)s\s+(.+)", line)
                if match:
                    duration = float(match.group(1))
                    test_path = match.group(2)

                    if duration >= threshold_seconds:
                        slow_tests.append(test_path)

        return slow_tests

    except subprocess.CalledProcessError:
        # If the pytest command fails, return an empty list
        return []


def create_test_selection_args(
    markers: Optional[List[str]] = None,
    keywords: Optional[List[str]] = None,
    test_paths: Optional[List[str]] = None,
    exclude_markers: Optional[List[str]] = None,
    exclude_keywords: Optional[List[str]] = None,
) -> List[str]:
    """Create pytest command-line arguments for test selection.

    Args:
        markers: List of markers to include
        keywords: List of keywords to include
        test_paths: List of test paths to include
        exclude_markers: List of markers to exclude
        exclude_keywords: List of keywords to exclude

    Returns:
        List of pytest command-line arguments
    """
    args = []

    # Add markers
    if markers:
        marker_expr = " or ".join(markers)
        args.extend(["-m", marker_expr])

    # Add keywords
    if keywords:
        keyword_expr = " or ".join(keywords)
        args.extend(["-k", keyword_expr])

    # Add exclude markers
    if exclude_markers:
        exclude_marker_expr = " and ".join(f"not {m}" for m in exclude_markers)
        if markers:
            # Combine with existing marker expression
            args[args.index("-m") + 1] = (
                f"({args[args.index('-m') + 1]}) and ({exclude_marker_expr})"
            )
        else:
            args.extend(["-m", exclude_marker_expr])

    # Add exclude keywords
    if exclude_keywords:
        exclude_keyword_expr = " and ".join(f"not {k}" for k in exclude_keywords)
        if keywords:
            # Combine with existing keyword expression
            args[args.index("-k") + 1] = (
                f"({args[args.index('-k') + 1]}) and ({exclude_keyword_expr})"
            )
        else:
            args.extend(["-k", exclude_keyword_expr])

    # Add test paths
    if test_paths:
        args.extend(test_paths)

    return args


def run_selected_tests(
    markers: Optional[List[str]] = None,
    keywords: Optional[List[str]] = None,
    test_paths: Optional[List[str]] = None,
    exclude_markers: Optional[List[str]] = None,
    exclude_keywords: Optional[List[str]] = None,
    additional_args: Optional[List[str]] = None,
) -> int:
    """Run selected tests based on the specified criteria.

    Args:
        markers: List of markers to include
        keywords: List of keywords to include
        test_paths: List of test paths to include
        exclude_markers: List of markers to exclude
        exclude_keywords: List of keywords to exclude
        additional_args: Additional pytest arguments

    Returns:
        Exit code from pytest
    """
    # Create the pytest command-line arguments
    args = ["pytest"]

    # Add test selection arguments
    args.extend(
        create_test_selection_args(
            markers=markers,
            keywords=keywords,
            test_paths=test_paths,
            exclude_markers=exclude_markers,
            exclude_keywords=exclude_keywords,
        )
    )

    # Add additional arguments
    if additional_args:
        args.extend(additional_args)

    # Run pytest with the specified arguments
    result = subprocess.run(args)

    return result.returncode


def run_tests_for_changed_files(
    base_branch: str = "main",
    include_related: bool = True,
    additional_args: Optional[List[str]] = None,
) -> int:
    """Run tests for changed files compared to the base branch.

    Args:
        base_branch: Base branch to compare against
        include_related: Whether to include related test files
        additional_args: Additional pytest arguments

    Returns:
        Exit code from pytest
    """
    # Get the list of changed files
    changed_files = get_changed_files(base_branch)

    # Get related test files if requested
    test_paths = []
    if include_related:
        test_paths = get_related_test_files(changed_files)
    else:
        # Only include changed test files
        test_paths = [
            f for f in changed_files if f.startswith("tests/") and f.endswith(".py")
        ]

    # If no test files were found, run all tests
    if not test_paths:
        print("No related test files found. Running all tests.")
        return run_selected_tests(additional_args=additional_args)

    # Run the selected tests
    return run_selected_tests(test_paths=test_paths, additional_args=additional_args)


if __name__ == "__main__":
    # Example usage as a script
    import argparse

    parser = argparse.ArgumentParser(description="Run selected tests")
    parser.add_argument(
        "--marker", "-m", action="append", help="Include tests with this marker"
    )
    parser.add_argument(
        "--keyword", "-k", action="append", help="Include tests matching this keyword"
    )
    parser.add_argument(
        "--exclude-marker", action="append", help="Exclude tests with this marker"
    )
    parser.add_argument(
        "--exclude-keyword", action="append", help="Exclude tests matching this keyword"
    )
    parser.add_argument(
        "--changed", action="store_true", help="Run tests for changed files"
    )
    parser.add_argument(
        "--base-branch", default="main", help="Base branch for --changed option"
    )
    parser.add_argument(
        "--include-related",
        action="store_true",
        help="Include related test files for --changed option",
    )
    parser.add_argument("test_paths", nargs="*", help="Test paths to run")

    args, unknown_args = parser.parse_known_args()

    if args.changed:
        exit_code = run_tests_for_changed_files(
            base_branch=args.base_branch,
            include_related=args.include_related,
            additional_args=unknown_args,
        )
    else:
        exit_code = run_selected_tests(
            markers=args.marker,
            keywords=args.keyword,
            test_paths=args.test_paths or None,
            exclude_markers=args.exclude_marker,
            exclude_keywords=args.exclude_keyword,
            additional_args=unknown_args,
        )

    sys.exit(exit_code)
